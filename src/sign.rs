//! Signature generation for Falcon.
//! Ported from sign.c (non-AVX2 paths).

#![allow(clippy::too_many_arguments)]

use alloc::vec::Vec;

use crate::common::is_short_half;
use crate::fft;
use crate::fpr::*;
use crate::rng::{prng_get_u64, prng_get_u8, prng_init, Prng};
use crate::shake::InnerShake256Context;

// ======================================================================
// LDL tree
// ======================================================================

/// Get the size of the LDL tree for an input with polynomials of size
/// 2^logn. The size is expressed in the number of elements.
fn ffldl_treesize(logn: u32) -> usize {
    ((logn + 1) as usize) << logn
}

/// Inner function for ffLDL_fft(). It expects the matrix to be both
/// auto-adjoint and quasicyclic; also, it uses the source operands
/// as modifiable temporaries.
///
/// tmp[] must have room for at least one polynomial.
fn ffldl_fft_inner(tree: &mut [Fpr], g0: &mut [Fpr], g1: &mut [Fpr], logn: u32, tmp: &mut [Fpr]) {
    let n: usize = 1 << logn;
    if n == 1 {
        tree[0] = g0[0];
        return;
    }
    let hn = n >> 1;

    // LDL decomposition: d11 into tmp, l10 into tree[..n].
    fft::poly_ldlmv_fft(tmp, tree, g0, g1, g0, logn);

    // Split d00 (in g0) into (g1, g1+hn).
    // Split d11 (in tmp) into (g0, g0+hn).
    {
        let (g1_lo, g1_hi) = g1.split_at_mut(hn);
        fft::poly_split_fft(g1_lo, g1_hi, &g0[..n], logn);
    }
    {
        let (g0_lo, g0_hi) = g0.split_at_mut(hn);
        fft::poly_split_fft(g0_lo, g0_hi, &tmp[..n], logn);
    }

    // Recurse on left sub-tree (d00 split, in g1).
    {
        let (g1_lo, g1_rest) = g1.split_at_mut(hn);
        ffldl_fft_inner(&mut tree[n..], g1_lo, g1_rest, logn - 1, tmp);
    }

    // Recurse on right sub-tree (d11 split, in g0).
    let off = n + ffldl_treesize(logn - 1);
    {
        let (g0_lo, g0_rest) = g0.split_at_mut(hn);
        ffldl_fft_inner(&mut tree[off..], g0_lo, g0_rest, logn - 1, tmp);
    }
}

/// Compute the ffLDL tree of an auto-adjoint matrix G. The matrix
/// is provided as three polynomials (FFT representation).
fn ffldl_fft(tree: &mut [Fpr], g00: &[Fpr], g01: &[Fpr], g11: &[Fpr], logn: u32, tmp: &mut [Fpr]) {
    let n: usize = 1 << logn;
    if n == 1 {
        tree[0] = g00[0];
        return;
    }
    let hn = n >> 1;

    let d00 = &mut tmp[..n];
    d00.copy_from_slice(&g00[..n]);

    // tmp layout: d00 (n) | d11 (n) | scratch (n)
    let (d00_slice, rest) = tmp.split_at_mut(n);
    let (d11_slice, scratch) = rest.split_at_mut(n);

    fft::poly_ldlmv_fft(d11_slice, tree, g00, g01, g11, logn);

    // Split d00 into scratch, scratch+hn.
    {
        let (s0, s1) = scratch.split_at_mut(hn);
        fft::poly_split_fft(s0, s1, d00_slice, logn);
    }
    // Split d11 into d00, d00+hn.
    {
        let (d0, d1) = d00_slice.split_at_mut(hn);
        fft::poly_split_fft(d0, d1, d11_slice, logn);
    }
    // Copy scratch into d11.
    d11_slice[..n].copy_from_slice(&scratch[..n]);

    // Left sub-tree: d11, d11+hn.
    {
        let (d11_lo, d11_hi) = d11_slice.split_at_mut(hn);
        ffldl_fft_inner(&mut tree[n..], d11_lo, d11_hi, logn - 1, scratch);
    }

    // Right sub-tree: d00, d00+hn.
    let off = n + ffldl_treesize(logn - 1);
    {
        let (d00_lo, d00_hi) = d00_slice.split_at_mut(hn);
        ffldl_fft_inner(&mut tree[off..], d00_lo, d00_hi, logn - 1, scratch);
    }
}

/// Normalize an ffLDL tree: each leaf of value x is replaced with
/// sigma / sqrt(x).
fn ffldl_binary_normalize(tree: &mut [Fpr], orig_logn: u32, logn: u32) {
    let n: usize = 1 << logn;
    if n == 1 {
        tree[0] = fpr_mul(fpr_sqrt(tree[0]), FPR_INV_SIGMA[orig_logn as usize]);
    } else {
        ffldl_binary_normalize(&mut tree[n..], orig_logn, logn - 1);
        let off = n + ffldl_treesize(logn - 1);
        ffldl_binary_normalize(&mut tree[off..], orig_logn, logn - 1);
    }
}

// ======================================================================
// Key expansion helpers
// ======================================================================

/// Convert an integer polynomial (with small values) into the
/// representation with complex numbers.
fn smallints_to_fpr(r: &mut [Fpr], t: &[i8], logn: u32) {
    let n: usize = 1 << logn;
    for u in 0..n {
        r[u] = fpr_of(t[u] as i64);
    }
}

/// Offset helpers for the expanded private key layout.
#[inline(always)]
fn skoff_b00(_logn: u32) -> usize {
    0
}
#[inline(always)]
fn skoff_b01(logn: u32) -> usize {
    1 << logn
}
#[inline(always)]
fn skoff_b10(logn: u32) -> usize {
    2 << logn
}
#[inline(always)]
fn skoff_b11(logn: u32) -> usize {
    3 << logn
}
#[inline(always)]
fn skoff_tree(logn: u32) -> usize {
    4 << logn
}

/// Expand a private key into the B0 matrix in FFT representation and
/// the LDL tree.
pub fn expand_privkey(
    expanded_key: &mut [Fpr],
    f: &[i8],
    g: &[i8],
    big_f: &[i8],
    big_g: &[i8],
    logn: u32,
    tmp: &mut [u8],
) {
    let n: usize = 1 << logn;

    let b00_off = skoff_b00(logn);
    let b01_off = skoff_b01(logn);
    let b10_off = skoff_b10(logn);
    let b11_off = skoff_b11(logn);
    let tree_off = skoff_tree(logn);

    // B0 = [[g, -f], [G, -F]]
    smallints_to_fpr(&mut expanded_key[b01_off..], f, logn);
    smallints_to_fpr(&mut expanded_key[b00_off..], g, logn);
    smallints_to_fpr(&mut expanded_key[b11_off..], big_f, logn);
    smallints_to_fpr(&mut expanded_key[b10_off..], big_g, logn);

    fft::fft(&mut expanded_key[b01_off..b01_off + n], logn);
    fft::fft(&mut expanded_key[b00_off..b00_off + n], logn);
    fft::fft(&mut expanded_key[b11_off..b11_off + n], logn);
    fft::fft(&mut expanded_key[b10_off..b10_off + n], logn);
    fft::poly_neg(&mut expanded_key[b01_off..b01_off + n], logn);
    fft::poly_neg(&mut expanded_key[b11_off..b11_off + n], logn);

    // Compute Gram matrix.
    let ftmp: &mut [Fpr] = unsafe {
        core::slice::from_raw_parts_mut(
            tmp.as_mut_ptr() as *mut Fpr,
            tmp.len() / core::mem::size_of::<Fpr>(),
        )
    };

    let (g00, rest) = ftmp.split_at_mut(n);
    let (g01_g, rest) = rest.split_at_mut(n);
    let (g11_g, gxx) = rest.split_at_mut(n);

    g00.copy_from_slice(&expanded_key[b00_off..b00_off + n]);
    fft::poly_mulselfadj_fft(g00, logn);
    gxx[..n].copy_from_slice(&expanded_key[b01_off..b01_off + n]);
    fft::poly_mulselfadj_fft(&mut gxx[..n], logn);
    fft::poly_add(g00, &gxx[..n], logn);

    g01_g.copy_from_slice(&expanded_key[b00_off..b00_off + n]);
    fft::poly_muladj_fft(g01_g, &expanded_key[b10_off..b10_off + n], logn);
    gxx[..n].copy_from_slice(&expanded_key[b01_off..b01_off + n]);
    fft::poly_muladj_fft(&mut gxx[..n], &expanded_key[b11_off..b11_off + n], logn);
    fft::poly_add(g01_g, &gxx[..n], logn);

    g11_g.copy_from_slice(&expanded_key[b10_off..b10_off + n]);
    fft::poly_mulselfadj_fft(g11_g, logn);
    gxx[..n].copy_from_slice(&expanded_key[b11_off..b11_off + n]);
    fft::poly_mulselfadj_fft(&mut gxx[..n], logn);
    fft::poly_add(g11_g, &gxx[..n], logn);

    ffldl_fft(&mut expanded_key[tree_off..], g00, g01_g, g11_g, logn, gxx);
    ffldl_binary_normalize(&mut expanded_key[tree_off..], logn, logn);
}

// ======================================================================
// Sampler types
// ======================================================================

/// Sampler context wraps a PRNG and the sigma_min value.
pub struct SamplerContext {
    pub p: Prng,
    pub sigma_min: Fpr,
}

/// Function type for the integer sampler.
type SamplerZ = fn(&mut SamplerContext, Fpr, Fpr) -> i32;

// ======================================================================
// Fast Fourier Sampling (dynamic tree)
// ======================================================================

/// Perform Fast Fourier Sampling for target vector t (dynamic tree variant).
fn ff_sampling_fft_dyntree(
    samp: SamplerZ,
    samp_ctx: &mut SamplerContext,
    t0: &mut [Fpr],
    t1: &mut [Fpr],
    g00: &mut [Fpr],
    g01: &mut [Fpr],
    g11: &mut [Fpr],
    orig_logn: u32,
    logn: u32,
    tmp: &mut [Fpr],
) {
    if logn == 0 {
        let leaf = fpr_mul(fpr_sqrt(g00[0]), FPR_INV_SIGMA[orig_logn as usize]);
        t0[0] = fpr_of(samp(samp_ctx, t0[0], leaf) as i64);
        t1[0] = fpr_of(samp(samp_ctx, t1[0], leaf) as i64);
        return;
    }

    let n: usize = 1 << logn;
    let hn = n >> 1;

    // Decompose G into LDL.
    fft::poly_ldl_fft(g00, g01, g11, logn);

    // Split d00 and d11 and expand them.
    {
        let (t_lo, t_hi) = tmp.split_at_mut(hn);
        fft::poly_split_fft(t_lo, t_hi, g00, logn);
    }
    g00[..n].copy_from_slice(&tmp[..n]);
    {
        let (t_lo, t_hi) = tmp.split_at_mut(hn);
        fft::poly_split_fft(t_lo, t_hi, g11, logn);
    }
    g11[..n].copy_from_slice(&tmp[..n]);
    tmp[..n].copy_from_slice(&g01[..n]);
    g01[..hn].copy_from_slice(&g00[..hn]);
    g01[hn..n].copy_from_slice(&g11[..hn]);

    // Split t1 and recurse on right sub-tree.
    {
        let z1 = &mut tmp[n..];
        let (z1_lo, z1_hi_and_rest) = z1.split_at_mut(hn);
        let (z1_hi, scratch) = z1_hi_and_rest.split_at_mut(hn);
        fft::poly_split_fft(z1_lo, z1_hi, t1, logn);

        let (g11_lo, g11_hi) = g11.split_at_mut(hn);
        ff_sampling_fft_dyntree(
            samp,
            samp_ctx,
            z1_lo,
            z1_hi,
            g11_lo,
            g11_hi,
            &mut g01[hn..],
            orig_logn,
            logn - 1,
            scratch,
        );

        // Merge z1 back into tmp + 2n.
        // We need a place to merge; use scratch as target.
        // But scratch overlaps with z1+n — we need to be careful.
        // Actually in the C code, merge target is tmp + (n << 1).
        // z1 = tmp[n..2n], merge target is tmp[2n..3n].
        // Let's copy z1 results.
        let z1_lo_copy: Vec<Fpr> = z1_lo.to_vec();
        let z1_hi_copy: Vec<Fpr> = z1_hi.to_vec();

        // Write merged result to scratch[..n].
        fft::poly_merge_fft(&mut scratch[..n], &z1_lo_copy, &z1_hi_copy, logn);

        // Compute tb0 = t0 + (t1 - z1_merged) * l10.
        // z1 = tmp[n..2n] now free, reuse as (t1 - z1_merged).
        z1_lo.copy_from_slice(&t1[..hn]);
        z1_hi.copy_from_slice(&t1[hn..n]);
        // Save merged result before we lose the scratch borrow.
        let merged_copy: Vec<Fpr> = scratch[..n].to_vec();
        // Now drop the z1/scratch borrows by ending this scope.
        // We will use the copies below.
        // Write merged into t1.
        t1[..n].copy_from_slice(&merged_copy);
    }
    // Now subtract merged from the (t1 - merged) in tmp[n..2n].
    {
        let (l10, z1_full) = tmp.split_at_mut(n);
        let _ = l10;
        fft::poly_sub(&mut z1_full[..n], &t1[..n], logn);
    }

    // Now l10 is in tmp[..n], (t1-z1) is in tmp[n..2n].
    // Multiply l10 by (t1-z1), result replaces l10.
    {
        let (l10, diff) = tmp.split_at_mut(n);
        fft::poly_mul_fft(l10, &diff[..n], logn);
    }
    fft::poly_add(t0, &tmp[..n], logn);

    // Second recursive invocation on split of tb0 (in t0).
    {
        let (z0, rest_tmp) = tmp.split_at_mut(n);
        let (z0_lo, z0_hi) = z0.split_at_mut(hn);
        fft::poly_split_fft(z0_lo, z0_hi, t0, logn);
        let (g00_lo, g00_hi) = g00.split_at_mut(hn);
        ff_sampling_fft_dyntree(
            samp,
            samp_ctx,
            z0_lo,
            z0_hi,
            g00_lo,
            g00_hi,
            g01,
            orig_logn,
            logn - 1,
            rest_tmp,
        );
        let z0_lo_copy: Vec<Fpr> = z0_lo.to_vec();
        let z0_hi_copy: Vec<Fpr> = z0_hi.to_vec();
        fft::poly_merge_fft(t0, &z0_lo_copy, &z0_hi_copy, logn);
    }
}

// ======================================================================
// Fast Fourier Sampling (precomputed tree)
// ======================================================================

/// Perform Fast Fourier Sampling for target vector t and LDL tree T.
/// tmp[] must have size for at least two polynomials of size 2^logn.
fn ff_sampling_fft(
    samp: SamplerZ,
    samp_ctx: &mut SamplerContext,
    z0: &mut [Fpr],
    z1: &mut [Fpr],
    tree: &[Fpr],
    t0: &[Fpr],
    t1: &[Fpr],
    logn: u32,
    tmp: &mut [Fpr],
) {
    // When logn == 2, we inline the last two recursion levels.
    if logn == 2 {
        let tree0 = &tree[4..];
        let tree1 = &tree[8..];

        // ---- First half: process t1 ----
        let a_re = t1[0];
        let a_im = t1[2];
        let b_re = t1[1];
        let b_im = t1[3];
        let c_re = fpr_add(a_re, b_re);
        let c_im = fpr_add(a_im, b_im);
        let mut w0 = fpr_half(c_re);
        let mut w1 = fpr_half(c_im);
        let c_re = fpr_sub(a_re, b_re);
        let c_im = fpr_sub(a_im, b_im);
        let mut w2 = fpr_mul(fpr_add(c_re, c_im), FPR_INVSQRT8);
        let mut w3 = fpr_mul(fpr_sub(c_im, c_re), FPR_INVSQRT8);

        let x0 = w2;
        let x1 = w3;
        let sigma = tree1[3];
        w2 = fpr_of(samp(samp_ctx, x0, sigma) as i64);
        w3 = fpr_of(samp(samp_ctx, x1, sigma) as i64);
        let a_re = fpr_sub(x0, w2);
        let a_im = fpr_sub(x1, w3);
        let b_re = tree1[0];
        let b_im = tree1[1];
        let c_re = fpr_sub(fpr_mul(a_re, b_re), fpr_mul(a_im, b_im));
        let c_im = fpr_add(fpr_mul(a_re, b_im), fpr_mul(a_im, b_re));
        let x0 = fpr_add(c_re, w0);
        let x1 = fpr_add(c_im, w1);
        let sigma = tree1[2];
        w0 = fpr_of(samp(samp_ctx, x0, sigma) as i64);
        w1 = fpr_of(samp(samp_ctx, x1, sigma) as i64);

        let a_re = w0;
        let a_im = w1;
        let c_re = fpr_mul(fpr_sub(w2, w3), FPR_INVSQRT2);
        let c_im = fpr_mul(fpr_add(w2, w3), FPR_INVSQRT2);
        z1[0] = fpr_add(a_re, c_re);
        z1[2] = fpr_add(a_im, c_im);
        z1[1] = fpr_sub(a_re, c_re);
        z1[3] = fpr_sub(a_im, c_im);

        // ---- Compute tb0 = t0 + (t1 - z1) * L ----
        w0 = fpr_sub(t1[0], z1[0]);
        w1 = fpr_sub(t1[1], z1[1]);
        w2 = fpr_sub(t1[2], z1[2]);
        w3 = fpr_sub(t1[3], z1[3]);

        {
            let (a_re, a_im) = (w0, w2);
            let (b_re, b_im) = (tree[0], tree[2]);
            w0 = fpr_sub(fpr_mul(a_re, b_re), fpr_mul(a_im, b_im));
            w2 = fpr_add(fpr_mul(a_re, b_im), fpr_mul(a_im, b_re));
        }
        {
            let (a_re, a_im) = (w1, w3);
            let (b_re, b_im) = (tree[1], tree[3]);
            w1 = fpr_sub(fpr_mul(a_re, b_re), fpr_mul(a_im, b_im));
            w3 = fpr_add(fpr_mul(a_re, b_im), fpr_mul(a_im, b_re));
        }

        w0 = fpr_add(w0, t0[0]);
        w1 = fpr_add(w1, t0[1]);
        w2 = fpr_add(w2, t0[2]);
        w3 = fpr_add(w3, t0[3]);

        // ---- Second recursive invocation ----
        let a_re = w0;
        let a_im = w2;
        let b_re = w1;
        let b_im = w3;
        let c_re = fpr_add(a_re, b_re);
        let c_im = fpr_add(a_im, b_im);
        w0 = fpr_half(c_re);
        w1 = fpr_half(c_im);
        let c_re = fpr_sub(a_re, b_re);
        let c_im = fpr_sub(a_im, b_im);
        w2 = fpr_mul(fpr_add(c_re, c_im), FPR_INVSQRT8);
        w3 = fpr_mul(fpr_sub(c_im, c_re), FPR_INVSQRT8);

        let x0 = w2;
        let x1 = w3;
        let sigma = tree0[3];
        let y0 = fpr_of(samp(samp_ctx, x0, sigma) as i64);
        let y1 = fpr_of(samp(samp_ctx, x1, sigma) as i64);
        w2 = y0;
        w3 = y1;
        let a_re = fpr_sub(x0, y0);
        let a_im = fpr_sub(x1, y1);
        let b_re = tree0[0];
        let b_im = tree0[1];
        let c_re = fpr_sub(fpr_mul(a_re, b_re), fpr_mul(a_im, b_im));
        let c_im = fpr_add(fpr_mul(a_re, b_im), fpr_mul(a_im, b_re));
        let x0 = fpr_add(c_re, w0);
        let x1 = fpr_add(c_im, w1);
        let sigma = tree0[2];
        w0 = fpr_of(samp(samp_ctx, x0, sigma) as i64);
        w1 = fpr_of(samp(samp_ctx, x1, sigma) as i64);

        let a_re = w0;
        let a_im = w1;
        let c_re = fpr_mul(fpr_sub(w2, w3), FPR_INVSQRT2);
        let c_im = fpr_mul(fpr_add(w2, w3), FPR_INVSQRT2);
        z0[0] = fpr_add(a_re, c_re);
        z0[2] = fpr_add(a_im, c_im);
        z0[1] = fpr_sub(a_re, c_re);
        z0[3] = fpr_sub(a_im, c_im);

        return;
    }

    // Case logn == 1.
    if logn == 1 {
        let x0 = t1[0];
        let x1 = t1[1];
        let sigma = tree[3];
        let y0 = fpr_of(samp(samp_ctx, x0, sigma) as i64);
        let y1 = fpr_of(samp(samp_ctx, x1, sigma) as i64);
        z1[0] = y0;
        z1[1] = y1;
        let a_re = fpr_sub(x0, y0);
        let a_im = fpr_sub(x1, y1);
        let b_re = tree[0];
        let b_im = tree[1];
        let c_re = fpr_sub(fpr_mul(a_re, b_re), fpr_mul(a_im, b_im));
        let c_im = fpr_add(fpr_mul(a_re, b_im), fpr_mul(a_im, b_re));
        let x0 = fpr_add(c_re, t0[0]);
        let x1 = fpr_add(c_im, t0[1]);
        let sigma = tree[2];
        z0[0] = fpr_of(samp(samp_ctx, x0, sigma) as i64);
        z0[1] = fpr_of(samp(samp_ctx, x1, sigma) as i64);
        return;
    }

    // General recursive case (logn >= 3).
    let n: usize = 1 << logn;
    let hn = n >> 1;
    let tree0 = &tree[n..];
    let tree1 = &tree[n + ffldl_treesize(logn - 1)..];

    // Split t1 into z1, recurse, merge back.
    {
        let (z1_lo, z1_hi) = z1.split_at_mut(hn);
        fft::poly_split_fft(z1_lo, z1_hi, t1, logn);
    }

    // Recursive call on right sub-tree.
    {
        let (tmp_lo, tmp_rest) = tmp.split_at_mut(hn);
        let (tmp_hi, scratch) = tmp_rest.split_at_mut(hn);
        let (z1_lo, z1_hi) = z1.split_at_mut(hn);
        ff_sampling_fft(
            samp,
            samp_ctx,
            tmp_lo,
            tmp_hi,
            tree1,
            z1_lo,
            z1_hi,
            logn - 1,
            scratch,
        );
    }
    {
        let tmp_lo_copy: Vec<Fpr> = tmp[..hn].to_vec();
        let tmp_hi_copy: Vec<Fpr> = tmp[hn..n].to_vec();
        fft::poly_merge_fft(z1, &tmp_lo_copy, &tmp_hi_copy, logn);
    }

    // Compute tb0 = t0 + (t1 - z1) * L.
    tmp[..n].copy_from_slice(&t1[..n]);
    fft::poly_sub(&mut tmp[..n], &z1[..n], logn);
    fft::poly_mul_fft(&mut tmp[..n], tree, logn);
    fft::poly_add(&mut tmp[..n], t0, logn);

    // Second recursive invocation.
    {
        let (z0_lo, z0_hi) = z0.split_at_mut(hn);
        fft::poly_split_fft(z0_lo, z0_hi, &tmp[..n], logn);
    }
    {
        let (tmp_lo, tmp_rest) = tmp.split_at_mut(hn);
        let (tmp_hi, scratch) = tmp_rest.split_at_mut(hn);
        let (z0_lo, z0_hi) = z0.split_at_mut(hn);
        ff_sampling_fft(
            samp,
            samp_ctx,
            tmp_lo,
            tmp_hi,
            tree0,
            z0_lo,
            z0_hi,
            logn - 1,
            scratch,
        );
    }
    {
        let tmp_lo_copy: Vec<Fpr> = tmp[..hn].to_vec();
        let tmp_hi_copy: Vec<Fpr> = tmp[hn..n].to_vec();
        fft::poly_merge_fft(z0, &tmp_lo_copy, &tmp_hi_copy, logn);
    }
}

// ======================================================================
// Signing core (expanded key)
// ======================================================================

/// Compute a signature using an expanded key.
/// Returns true if the signature is short enough (s2 is written).
fn do_sign_tree(
    samp: SamplerZ,
    samp_ctx: &mut SamplerContext,
    s2: &mut [i16],
    expanded_key: &[Fpr],
    hm: &[u16],
    logn: u32,
    tmp: &mut [Fpr],
) -> bool {
    let n: usize = 1 << logn;

    let b00 = &expanded_key[skoff_b00(logn)..];
    let b01 = &expanded_key[skoff_b01(logn)..];
    let b10 = &expanded_key[skoff_b10(logn)..];
    let b11 = &expanded_key[skoff_b11(logn)..];
    let tree = &expanded_key[skoff_tree(logn)..];

    // t0 = tmp[0..n], t1 = tmp[n..2n]
    for u in 0..n {
        tmp[u] = fpr_of(hm[u] as i64);
    }

    // Apply the lattice basis for the real target vector.
    fft::fft(&mut tmp[0..n], logn);
    let ni = FPR_INVERSE_OF_Q;
    unsafe {
        let p = tmp.as_mut_ptr();
        core::ptr::copy_nonoverlapping(p, p.add(n), n);
    }
    fft::poly_mul_fft(&mut tmp[n..2 * n], &b01[..n], logn);
    fft::poly_mulconst(&mut tmp[n..2 * n], fpr_neg(ni), logn);
    fft::poly_mul_fft(&mut tmp[0..n], &b11[..n], logn);
    fft::poly_mulconst(&mut tmp[0..n], ni, logn);

    // tx = tmp[2n..3n], ty = tmp[3n..4n], scratch = tmp[4n..]
    // Apply sampling: output in (tx, ty).
    {
        // We need t0 and t1 as source, tx and ty as output, and scratch.
        // Use raw pointers since the borrow checker can't prove disjointness.
        let ptr = tmp.as_mut_ptr();
        let t0 = unsafe { core::slice::from_raw_parts(ptr, n) };
        let t1 = unsafe { core::slice::from_raw_parts(ptr.add(n), n) };
        let tx = unsafe { core::slice::from_raw_parts_mut(ptr.add(2 * n), n) };
        let ty = unsafe { core::slice::from_raw_parts_mut(ptr.add(3 * n), n) };
        let scratch = unsafe { core::slice::from_raw_parts_mut(ptr.add(4 * n), tmp.len() - 4 * n) };
        ff_sampling_fft(samp, samp_ctx, tx, ty, tree, t0, t1, logn, scratch);
    }

    // Get the lattice point.
    // t0 = tmp[0..n] <- tx, t1 = tmp[n..2n] stays
    {
        let ptr = tmp.as_mut_ptr();
        unsafe {
            // t0 <- tx
            core::ptr::copy_nonoverlapping(ptr.add(2 * n), ptr, n);
            // t1 <- ty
            core::ptr::copy_nonoverlapping(ptr.add(3 * n), ptr.add(n), n);
        }
    }
    // tx *= b00
    fft::poly_mul_fft(&mut tmp[2 * n..3 * n], &b00[..n], logn);
    // ty *= b10
    fft::poly_mul_fft(&mut tmp[3 * n..4 * n], &b10[..n], logn);
    // tx += ty
    {
        let (front, back) = tmp.split_at_mut(3 * n);
        fft::poly_add(&mut front[2 * n..], &back[..n], logn);
    }
    // ty <- t0 * b01
    {
        let ptr = tmp.as_mut_ptr();
        unsafe {
            core::ptr::copy_nonoverlapping(ptr, ptr.add(3 * n), n);
        }
    }
    fft::poly_mul_fft(&mut tmp[3 * n..4 * n], &b01[..n], logn);

    // t0 <- tx
    {
        let ptr = tmp.as_mut_ptr();
        unsafe {
            core::ptr::copy_nonoverlapping(ptr.add(2 * n), ptr, n);
        }
    }
    // t1 *= b11
    fft::poly_mul_fft(&mut tmp[n..2 * n], &b11[..n], logn);
    // t1 += ty
    {
        let (front, back) = tmp.split_at_mut(3 * n);
        fft::poly_add(&mut front[n..2 * n], &back[..n], logn);
    }

    fft::ifft(&mut tmp[0..n], logn);
    fft::ifft(&mut tmp[n..2 * n], logn);

    // Compute the signature.
    let s1tmp: &mut [i16] =
        unsafe { core::slice::from_raw_parts_mut(tmp[2 * n..].as_mut_ptr() as *mut i16, n) };
    let mut sqn: u32 = 0;
    let mut ng: u32 = 0;
    for u in 0..n {
        let z = (hm[u] as i32) - (fpr_rint(tmp[u]) as i32);
        sqn = sqn.wrapping_add((z * z) as u32);
        ng |= sqn;
        s1tmp[u] = z as i16;
    }
    sqn |= (ng >> 31).wrapping_neg();

    // Read t1 values we need before overwriting tmp.
    let mut s2_vals: Vec<i16> = Vec::with_capacity(n);
    for u in 0..n {
        s2_vals.push(-(fpr_rint(tmp[n + u]) as i16));
    }

    if is_short_half(sqn, &s2_vals, logn) {
        s2[..n].copy_from_slice(&s2_vals);
        // Write s1 into the start of tmp (as i16).
        let s1_out: &mut [i16] =
            unsafe { core::slice::from_raw_parts_mut(tmp.as_mut_ptr() as *mut i16, n) };
        s1_out[..n].copy_from_slice(&s1tmp[..n]);
        return true;
    }
    false
}

// ======================================================================
// Signing core (dynamic / raw key)
// ======================================================================

/// Compute a signature using the raw private key.
/// Returns true if the signature is short.
///
/// This function uses a large `tmp` buffer with complex overlapping usage.
/// We use `unsafe` raw pointer operations to match the C semantics exactly.
fn do_sign_dyn(
    samp: SamplerZ,
    samp_ctx: &mut SamplerContext,
    s2: &mut [i16],
    f: &[i8],
    g: &[i8],
    big_f: &[i8],
    big_g: &[i8],
    hm: &[u16],
    logn: u32,
    tmp: &mut [Fpr],
) -> bool {
    let n: usize = 1 << logn;
    let ptr = tmp.as_mut_ptr();

    // Phase 1: Build lattice basis B = [[g, -f], [G, -F]] in FFT form.
    // Layout: b00(n) | b01(n) | b10(n) | b11(n) | ...
    {
        let b00 = unsafe { core::slice::from_raw_parts_mut(ptr, n) };
        let b01 = unsafe { core::slice::from_raw_parts_mut(ptr.add(n), n) };
        let b10 = unsafe { core::slice::from_raw_parts_mut(ptr.add(2 * n), n) };
        let b11 = unsafe { core::slice::from_raw_parts_mut(ptr.add(3 * n), n) };

        smallints_to_fpr(b01, f, logn);
        smallints_to_fpr(b00, g, logn);
        smallints_to_fpr(b11, big_f, logn);
        smallints_to_fpr(b10, big_g, logn);
        fft::fft(b01, logn);
        fft::fft(b00, logn);
        fft::fft(b11, logn);
        fft::fft(b10, logn);
        fft::poly_neg(b01, logn);
        fft::poly_neg(b11, logn);
    }

    // Phase 2: Compute Gram matrix.
    // t0 = ptr+4n, t1 = ptr+5n
    {
        let b00 = unsafe { core::slice::from_raw_parts_mut(ptr, n) };
        let b01 = unsafe { core::slice::from_raw_parts_mut(ptr.add(n), n) };
        let b10 = unsafe { core::slice::from_raw_parts_mut(ptr.add(2 * n), n) };
        let b11 = unsafe { core::slice::from_raw_parts_mut(ptr.add(3 * n), n) };
        let t0 = unsafe { core::slice::from_raw_parts_mut(ptr.add(4 * n), n) };
        let t1 = unsafe { core::slice::from_raw_parts_mut(ptr.add(5 * n), n) };

        // t0 <- b01*adj(b01)
        t0.copy_from_slice(b01);
        fft::poly_mulselfadj_fft(t0, logn);

        // t1 <- b00*adj(b10)
        t1.copy_from_slice(b00);
        fft::poly_muladj_fft(t1, b10, logn);

        // b00 <- g00
        fft::poly_mulselfadj_fft(b00, logn);
        fft::poly_add(b00, t0, logn);

        // Save b01 to t0, then b01 <- g01
        t0.copy_from_slice(b01);
        fft::poly_muladj_fft(b01, b11, logn);
        fft::poly_add(b01, t1, logn);

        // b10 <- g11
        fft::poly_mulselfadj_fft(b10, logn);
        t1.copy_from_slice(b11);
        fft::poly_mulselfadj_fft(t1, logn);
        fft::poly_add(b10, t1, logn);
    }

    // Phase 3: Rename variables.
    // g00 = [0..n], g01 = [n..2n], g11 = [2n..3n]
    // b11 = [3n..4n], b01_saved = [4n..5n]
    // Set target vector.
    // t0 = [5n..6n], t1 = [6n..7n]
    {
        let t0 = unsafe { core::slice::from_raw_parts_mut(ptr.add(5 * n), n) };
        for u in 0..n {
            t0[u] = fpr_of(hm[u] as i64);
        }
    }

    // Apply the lattice basis to get real target.
    {
        let t0 = unsafe { core::slice::from_raw_parts_mut(ptr.add(5 * n), n) };
        let t1 = unsafe { core::slice::from_raw_parts_mut(ptr.add(6 * n), n) };
        let b01_saved = unsafe { core::slice::from_raw_parts(ptr.add(4 * n), n) };
        let b11 = unsafe { core::slice::from_raw_parts(ptr.add(3 * n), n) };

        fft::fft(t0, logn);
        let ni = FPR_INVERSE_OF_Q;
        t1.copy_from_slice(t0);
        fft::poly_mul_fft(t1, b01_saved, logn);
        fft::poly_mulconst(t1, fpr_neg(ni), logn);
        fft::poly_mul_fft(t0, b11, logn);
        fft::poly_mulconst(t0, ni, logn);
    }

    // Move (t0, t1) from [5n..7n] to [3n..5n].
    unsafe {
        core::ptr::copy(ptr.add(5 * n), ptr.add(3 * n), 2 * n);
    }

    // Phase 4: Apply sampling.
    // t0 = [3n..4n], t1 = [4n..5n]
    // g00 = [0..n], g01 = [n..2n], g11 = [2n..3n]
    // scratch = [5n..]
    {
        let g00 = unsafe { core::slice::from_raw_parts_mut(ptr, n) };
        let g01 = unsafe { core::slice::from_raw_parts_mut(ptr.add(n), n) };
        let g11 = unsafe { core::slice::from_raw_parts_mut(ptr.add(2 * n), n) };
        let t0 = unsafe { core::slice::from_raw_parts_mut(ptr.add(3 * n), n) };
        let t1 = unsafe { core::slice::from_raw_parts_mut(ptr.add(4 * n), n) };
        let scratch = unsafe { core::slice::from_raw_parts_mut(ptr.add(5 * n), tmp.len() - 5 * n) };
        ff_sampling_fft_dyntree(samp, samp_ctx, t0, t1, g00, g01, g11, logn, logn, scratch);
    }

    // Phase 5: Recompute basis and extract signature.
    // Move t0,t1 from [3n..5n] to [4n+n..6n+n] = [5n..7n].
    unsafe {
        core::ptr::copy(ptr.add(3 * n), ptr.add(5 * n), 2 * n);
    }

    // Recompute basis in [0..4n].
    {
        let b00 = unsafe { core::slice::from_raw_parts_mut(ptr, n) };
        let b01 = unsafe { core::slice::from_raw_parts_mut(ptr.add(n), n) };
        let b10 = unsafe { core::slice::from_raw_parts_mut(ptr.add(2 * n), n) };
        let b11 = unsafe { core::slice::from_raw_parts_mut(ptr.add(3 * n), n) };

        smallints_to_fpr(b01, f, logn);
        smallints_to_fpr(b00, g, logn);
        smallints_to_fpr(b11, big_f, logn);
        smallints_to_fpr(b10, big_g, logn);
        fft::fft(b01, logn);
        fft::fft(b00, logn);
        fft::fft(b11, logn);
        fft::fft(b10, logn);
        fft::poly_neg(b01, logn);
        fft::poly_neg(b11, logn);
    }

    // tx = [7n..8n], ty = [8n..9n]
    // tx <- t0 (at [5n..6n]), ty <- t1 (at [6n..7n])
    unsafe {
        core::ptr::copy_nonoverlapping(ptr.add(5 * n), ptr.add(7 * n), n);
        core::ptr::copy_nonoverlapping(ptr.add(6 * n), ptr.add(8 * n), n);
    }

    // Get the lattice point.
    {
        let b00 = unsafe { core::slice::from_raw_parts(ptr, n) };
        let b01 = unsafe { core::slice::from_raw_parts(ptr.add(n), n) };
        let b10 = unsafe { core::slice::from_raw_parts(ptr.add(2 * n), n) };
        let _b11 = unsafe { core::slice::from_raw_parts(ptr.add(3 * n), n) };
        let tx = unsafe { core::slice::from_raw_parts_mut(ptr.add(7 * n), n) };
        let ty = unsafe { core::slice::from_raw_parts_mut(ptr.add(8 * n), n) };

        fft::poly_mul_fft(tx, b00, logn);
        fft::poly_mul_fft(ty, b10, logn);
        fft::poly_add(tx, ty, logn);

        // ty <- t0 * b01
        let t0_slice = unsafe { core::slice::from_raw_parts(ptr.add(5 * n), n) };
        ty.copy_from_slice(t0_slice);
        fft::poly_mul_fft(ty, b01, logn);
    }

    // t0 <- tx
    unsafe {
        core::ptr::copy_nonoverlapping(ptr.add(7 * n), ptr.add(5 * n), n);
    }

    // t1 *= b11
    {
        let t1 = unsafe { core::slice::from_raw_parts_mut(ptr.add(6 * n), n) };
        let b11 = unsafe { core::slice::from_raw_parts(ptr.add(3 * n), n) };
        fft::poly_mul_fft(t1, b11, logn);
    }

    // t1 += ty
    {
        let t1 = unsafe { core::slice::from_raw_parts_mut(ptr.add(6 * n), n) };
        let ty = unsafe { core::slice::from_raw_parts(ptr.add(8 * n), n) };
        fft::poly_add(t1, ty, logn);
    }

    // iFFT on t0, t1
    {
        let t0 = unsafe { core::slice::from_raw_parts_mut(ptr.add(5 * n), n) };
        fft::ifft(t0, logn);
    }
    {
        let t1 = unsafe { core::slice::from_raw_parts_mut(ptr.add(6 * n), n) };
        fft::ifft(t1, logn);
    }

    // Compute the signature.
    let s1tmp: &mut [i16] =
        unsafe { core::slice::from_raw_parts_mut(ptr.add(7 * n) as *mut i16, n) };
    let mut sqn: u32 = 0;
    let mut ng: u32 = 0;
    for u in 0..n {
        let t0_u = unsafe { *ptr.add(5 * n + u) };
        let z = (hm[u] as i32) - (fpr_rint(t0_u) as i32);
        sqn = sqn.wrapping_add((z * z) as u32);
        ng |= sqn;
        s1tmp[u] = z as i16;
    }
    sqn |= (ng >> 31).wrapping_neg();

    let mut s2_vals: Vec<i16> = Vec::with_capacity(n);
    for u in 0..n {
        let t1_u = unsafe { *ptr.add(6 * n + u) };
        s2_vals.push(-(fpr_rint(t1_u) as i16));
    }

    if is_short_half(sqn, &s2_vals, logn) {
        s2[..n].copy_from_slice(&s2_vals);
        let s1_out: &mut [i16] = unsafe { core::slice::from_raw_parts_mut(ptr as *mut i16, n) };
        s1_out[..n].copy_from_slice(&s1tmp[..n]);
        return true;
    }
    false
}

// ======================================================================
// Discrete Gaussian sampler
// ======================================================================

/// Distribution table for the half-Gaussian sampler (72-bit precision).
static GAUSS0_DIST: [u32; 54] = [
    10745844, 3068844, 3741698, 5559083, 1580863, 8248194, 2260429, 13669192, 2736639, 708981,
    4421575, 10046180, 169348, 7122675, 4136815, 30538, 13063405, 7650655, 4132, 14505003, 7826148,
    417, 16768101, 11363290, 31, 8444042, 8086568, 1, 12844466, 265321, 0, 1232676, 13644283, 0,
    38047, 9111839, 0, 870, 6138264, 0, 14, 12545723, 0, 0, 3104126, 0, 0, 28824, 0, 0, 198, 0, 0,
    1,
];

/// Sample an integer value along a half-gaussian distribution centered
/// on zero and standard deviation 1.8205, with a precision of 72 bits.
pub fn gaussian0_sampler(p: &mut Prng) -> i32 {
    let lo = prng_get_u64(p);
    let hi = prng_get_u8(p);
    let v0 = (lo as u32) & 0xFFFFFF;
    let v1 = ((lo >> 24) as u32) & 0xFFFFFF;
    let v2 = ((lo >> 48) as u32) | (hi << 16);

    let mut z: i32 = 0;
    let mut u = 0;
    while u < GAUSS0_DIST.len() {
        let w0 = GAUSS0_DIST[u + 2];
        let w1 = GAUSS0_DIST[u + 1];
        let w2 = GAUSS0_DIST[u];
        let cc = v0.wrapping_sub(w0) >> 31;
        let cc = v1.wrapping_sub(w1).wrapping_sub(cc) >> 31;
        let cc = v2.wrapping_sub(w2).wrapping_sub(cc) >> 31;
        z += cc as i32;
        u += 3;
    }
    z
}

/// Sample a bit with probability exp(-x) for some x >= 0.
fn ber_exp(p: &mut Prng, x: Fpr, ccs: Fpr) -> bool {
    let s = fpr_trunc(fpr_mul(x, FPR_INV_LOG2)) as i32;
    let r = fpr_sub(x, fpr_mul(fpr_of(s as i64), FPR_LOG2));

    // Saturate s at 63.
    let mut sw = s as u32;
    sw ^= (sw ^ 63) & (63u32.wrapping_sub(sw) >> 31).wrapping_neg();
    let s = sw as i32;

    let z = ((fpr_expm_p63(r, ccs) << 1).wrapping_sub(1)) >> (s as u32);

    let mut i: i32 = 64;
    let mut w: u32;
    loop {
        i -= 8;
        w = prng_get_u8(p).wrapping_sub(((z >> (i as u32)) & 0xFF) as u32);
        if w != 0 || i <= 0 {
            break;
        }
    }
    (w >> 31) != 0
}

/// The sampler produces a random integer that follows a discrete Gaussian
/// distribution, centered on mu, and with standard deviation sigma.
pub fn sampler(ctx: &mut SamplerContext, mu: Fpr, isigma: Fpr) -> i32 {
    let s = fpr_floor(mu) as i32;
    let r = fpr_sub(mu, fpr_of(s as i64));
    let dss = fpr_half(fpr_sqr(isigma));
    let ccs = fpr_mul(isigma, ctx.sigma_min);

    loop {
        let z0 = gaussian0_sampler(&mut ctx.p);
        let b = (prng_get_u8(&mut ctx.p) & 1) as i32;
        let z = b + ((b << 1) - 1) * z0;

        let x = fpr_mul(fpr_sqr(fpr_sub(fpr_of(z as i64), r)), dss);
        let x = fpr_sub(x, fpr_mul(fpr_of((z0 * z0) as i64), FPR_INV_2SQRSIGMA0));
        if ber_exp(&mut ctx.p, x, ccs) {
            return s + z;
        }
    }
}

// ======================================================================
// Public API
// ======================================================================

/// Compute a signature using an expanded key.
pub fn sign_tree(
    sig: &mut [i16],
    rng: &mut InnerShake256Context,
    expanded_key: &[Fpr],
    hm: &[u16],
    logn: u32,
    tmp: &mut [u8],
) {
    let ftmp: &mut [Fpr] = unsafe {
        core::slice::from_raw_parts_mut(
            tmp.as_mut_ptr() as *mut Fpr,
            tmp.len() / core::mem::size_of::<Fpr>(),
        )
    };
    loop {
        let mut spc = SamplerContext {
            p: Prng::new(),
            sigma_min: FPR_SIGMA_MIN[logn as usize],
        };
        prng_init(&mut spc.p, rng);

        if do_sign_tree(sampler, &mut spc, sig, expanded_key, hm, logn, ftmp) {
            break;
        }
    }
}

/// Compute a signature using the raw private key.
pub fn sign_dyn(
    sig: &mut [i16],
    rng: &mut InnerShake256Context,
    f: &[i8],
    g: &[i8],
    big_f: &[i8],
    big_g: &[i8],
    hm: &[u16],
    logn: u32,
    tmp: &mut [u8],
) {
    let ftmp: &mut [Fpr] = unsafe {
        core::slice::from_raw_parts_mut(
            tmp.as_mut_ptr() as *mut Fpr,
            tmp.len() / core::mem::size_of::<Fpr>(),
        )
    };
    loop {
        let mut spc = SamplerContext {
            p: Prng::new(),
            sigma_min: FPR_SIGMA_MIN[logn as usize],
        };
        prng_init(&mut spc.p, rng);

        if do_sign_dyn(sampler, &mut spc, sig, f, g, big_f, big_g, hm, logn, ftmp) {
            break;
        }
    }
}
