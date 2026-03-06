//! FFT operations for Falcon.
//! Ported from fft.c (non-AVX2 path).

use crate::fpr::*;

// ======================================================================
// Complex number operations (inline equivalents of C macros)
// ======================================================================

#[inline(always)]
fn fpc_add(a_re: Fpr, a_im: Fpr, b_re: Fpr, b_im: Fpr) -> (Fpr, Fpr) {
    (fpr_add(a_re, b_re), fpr_add(a_im, b_im))
}

#[inline(always)]
fn fpc_sub(a_re: Fpr, a_im: Fpr, b_re: Fpr, b_im: Fpr) -> (Fpr, Fpr) {
    (fpr_sub(a_re, b_re), fpr_sub(a_im, b_im))
}

#[inline(always)]
fn fpc_mul(a_re: Fpr, a_im: Fpr, b_re: Fpr, b_im: Fpr) -> (Fpr, Fpr) {
    let d_re = fpr_sub(fpr_mul(a_re, b_re), fpr_mul(a_im, b_im));
    let d_im = fpr_add(fpr_mul(a_re, b_im), fpr_mul(a_im, b_re));
    (d_re, d_im)
}

#[inline(always)]
fn fpc_div(a_re: Fpr, a_im: Fpr, b_re: Fpr, b_im: Fpr) -> (Fpr, Fpr) {
    let m = fpr_inv(fpr_add(fpr_sqr(b_re), fpr_sqr(b_im)));
    let b_re2 = fpr_mul(b_re, m);
    let b_im2 = fpr_mul(fpr_neg(b_im), m);
    let d_re = fpr_sub(fpr_mul(a_re, b_re2), fpr_mul(a_im, b_im2));
    let d_im = fpr_add(fpr_mul(a_re, b_im2), fpr_mul(a_im, b_re2));
    (d_re, d_im)
}

// ======================================================================
// FFT and iFFT
// ======================================================================

/// Forward FFT.
pub fn fft(f: &mut [Fpr], logn: u32) {
    let n: usize = 1 << logn;
    let hn = n >> 1;
    let mut t = hn;
    let mut m: usize = 2;
    for _u in 1..logn {
        let ht = t >> 1;
        let hm = m >> 1;
        let mut j1: usize = 0;
        for i1 in 0..hm {
            let j2 = j1 + ht;
            let s_re = FPR_GM_TAB[((m + i1) << 1) + 0];
            let s_im = FPR_GM_TAB[((m + i1) << 1) + 1];
            for j in j1..j2 {
                let x_re = f[j];
                let x_im = f[j + hn];
                let y_re = f[j + ht];
                let y_im = f[j + ht + hn];
                let (yr, yi) = fpc_mul(y_re, y_im, s_re, s_im);
                f[j] = fpr_add(x_re, yr);
                f[j + hn] = fpr_add(x_im, yi);
                f[j + ht] = fpr_sub(x_re, yr);
                f[j + ht + hn] = fpr_sub(x_im, yi);
            }
            j1 += t;
        }
        t = ht;
        m <<= 1;
    }
}

/// Inverse FFT.
pub fn ifft(f: &mut [Fpr], logn: u32) {
    let n: usize = 1 << logn;
    let hn = n >> 1;
    let mut t: usize = 1;
    let mut m: usize = n;
    for _u in (2..=logn).rev() {
        let hm = m >> 1;
        let dt = t << 1;
        let mut j1: usize = 0;
        for i1 in 0..hm {
            if j1 >= hn {
                break;
            }
            let j2 = j1 + t;
            let s_re = FPR_GM_TAB[((hm + i1) << 1) + 0];
            let s_im = fpr_neg(FPR_GM_TAB[((hm + i1) << 1) + 1]);
            for j in j1..j2 {
                let x_re = f[j];
                let x_im = f[j + hn];
                let y_re = f[j + t];
                let y_im = f[j + t + hn];
                f[j] = fpr_add(x_re, y_re);
                f[j + hn] = fpr_add(x_im, y_im);
                let (xr, xi) = fpc_sub(x_re, x_im, y_re, y_im);
                let (mr, mi) = fpc_mul(xr, xi, s_re, s_im);
                f[j + t] = mr;
                f[j + t + hn] = mi;
            }
            j1 += dt;
            let _ = i1;
        }
        t = dt;
        m = hm;
    }

    if logn > 0 {
        let ni = FPR_P2_TAB[logn as usize];
        for u in 0..n {
            f[u] = fpr_mul(f[u], ni);
        }
    }
}

// ======================================================================
// Polynomial operations
// ======================================================================

/// Polynomial addition: a += b.
pub fn poly_add(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n: usize = 1 << logn;
    for u in 0..n {
        a[u] = fpr_add(a[u], b[u]);
    }
}

/// Polynomial subtraction: a -= b.
pub fn poly_sub(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n: usize = 1 << logn;
    for u in 0..n {
        a[u] = fpr_sub(a[u], b[u]);
    }
}

/// Polynomial negation: a = -a.
pub fn poly_neg(a: &mut [Fpr], logn: u32) {
    let n: usize = 1 << logn;
    for u in 0..n {
        a[u] = fpr_neg(a[u]);
    }
}

/// Compute the adjoint of a polynomial in FFT representation.
pub fn poly_adj_fft(a: &mut [Fpr], logn: u32) {
    let n: usize = 1 << logn;
    for u in (n >> 1)..n {
        a[u] = fpr_neg(a[u]);
    }
}

/// Multiply two polynomials in FFT representation: a *= b.
pub fn poly_mul_fft(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n: usize = 1 << logn;
    let hn = n >> 1;
    for u in 0..hn {
        let (d_re, d_im) = fpc_mul(a[u], a[u + hn], b[u], b[u + hn]);
        a[u] = d_re;
        a[u + hn] = d_im;
    }
}

/// Multiply polynomial a by the adjoint of b in FFT representation.
pub fn poly_muladj_fft(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n: usize = 1 << logn;
    let hn = n >> 1;
    for u in 0..hn {
        let (d_re, d_im) = fpc_mul(a[u], a[u + hn], b[u], fpr_neg(b[u + hn]));
        a[u] = d_re;
        a[u + hn] = d_im;
    }
}

/// Multiply polynomial a by its own adjoint (auto-adjoint product).
pub fn poly_mulselfadj_fft(a: &mut [Fpr], logn: u32) {
    let n: usize = 1 << logn;
    let hn = n >> 1;
    for u in 0..hn {
        a[u] = fpr_add(fpr_sqr(a[u]), fpr_sqr(a[u + hn]));
        a[u + hn] = FPR_ZERO;
    }
}

/// Multiply polynomial by a constant scalar.
pub fn poly_mulconst(a: &mut [Fpr], x: Fpr, logn: u32) {
    let n: usize = 1 << logn;
    for u in 0..n {
        a[u] = fpr_mul(a[u], x);
    }
}

/// Divide polynomial a by b in FFT representation: a /= b.
pub fn poly_div_fft(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n: usize = 1 << logn;
    let hn = n >> 1;
    for u in 0..hn {
        let (d_re, d_im) = fpc_div(a[u], a[u + hn], b[u], b[u + hn]);
        a[u] = d_re;
        a[u + hn] = d_im;
    }
}

/// Compute 1/(|a|² + |b|²) for each coefficient pair (inverse squared norm).
pub fn poly_invnorm2_fft(d: &mut [Fpr], a: &[Fpr], b: &[Fpr], logn: u32) {
    let n: usize = 1 << logn;
    let hn = n >> 1;
    for u in 0..hn {
        d[u] = fpr_inv(fpr_add(
            fpr_add(fpr_sqr(a[u]), fpr_sqr(a[u + hn])),
            fpr_add(fpr_sqr(b[u]), fpr_sqr(b[u + hn])),
        ));
    }
}

/// Compute d = F·adj(f) + G·adj(g) in FFT representation.
pub fn poly_add_muladj_fft(
    d: &mut [Fpr],
    f_big: &[Fpr],
    g_big: &[Fpr],
    f_small: &[Fpr],
    g_small: &[Fpr],
    logn: u32,
) {
    let n: usize = 1 << logn;
    let hn = n >> 1;
    for u in 0..hn {
        let (a_re, a_im) = fpc_mul(
            f_big[u],
            f_big[u + hn],
            f_small[u],
            fpr_neg(f_small[u + hn]),
        );
        let (b_re, b_im) = fpc_mul(
            g_big[u],
            g_big[u + hn],
            g_small[u],
            fpr_neg(g_small[u + hn]),
        );
        d[u] = fpr_add(a_re, b_re);
        d[u + hn] = fpr_add(a_im, b_im);
    }
}

/// Multiply polynomial a by auto-adjoint polynomial b.
pub fn poly_mul_autoadj_fft(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n: usize = 1 << logn;
    let hn = n >> 1;
    for u in 0..hn {
        a[u] = fpr_mul(a[u], b[u]);
        a[u + hn] = fpr_mul(a[u + hn], b[u]);
    }
}

/// Divide polynomial a by auto-adjoint polynomial b.
pub fn poly_div_autoadj_fft(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n: usize = 1 << logn;
    let hn = n >> 1;
    for u in 0..hn {
        let ib = fpr_inv(b[u]);
        a[u] = fpr_mul(a[u], ib);
        a[u + hn] = fpr_mul(a[u + hn], ib);
    }
}

/// LDL decomposition of a 2×2 Gram matrix in FFT representation (in-place).
pub fn poly_ldl_fft(g00: &[Fpr], g01: &mut [Fpr], g11: &mut [Fpr], logn: u32) {
    let n: usize = 1 << logn;
    let hn = n >> 1;
    for u in 0..hn {
        let g00_re = g00[u];
        let g00_im = g00[u + hn];
        let g01_re = g01[u];
        let g01_im = g01[u + hn];
        let g11_re = g11[u];
        let g11_im = g11[u + hn];
        let (mu_re, mu_im) = fpc_div(g01_re, g01_im, g00_re, g00_im);
        let (xi_re, xi_im) = fpc_mul(mu_re, mu_im, g01_re, fpr_neg(g01_im));
        let (d_re, d_im) = fpc_sub(g11_re, g11_im, xi_re, xi_im);
        g11[u] = d_re;
        g11[u + hn] = d_im;
        g01[u] = mu_re;
        g01[u + hn] = fpr_neg(mu_im);
    }
}

/// LDL decomposition with separate output buffers for d11 and l10.
pub fn poly_ldlmv_fft(
    d11: &mut [Fpr],
    l10: &mut [Fpr],
    g00: &[Fpr],
    g01: &[Fpr],
    g11: &[Fpr],
    logn: u32,
) {
    let n: usize = 1 << logn;
    let hn = n >> 1;
    for u in 0..hn {
        let g00_re = g00[u];
        let g00_im = g00[u + hn];
        let g01_re = g01[u];
        let g01_im = g01[u + hn];
        let g11_re = g11[u];
        let g11_im = g11[u + hn];
        let (mu_re, mu_im) = fpc_div(g01_re, g01_im, g00_re, g00_im);
        let (xi_re, xi_im) = fpc_mul(mu_re, mu_im, g01_re, fpr_neg(g01_im));
        let (d_re, d_im) = fpc_sub(g11_re, g11_im, xi_re, xi_im);
        d11[u] = d_re;
        d11[u + hn] = d_im;
        l10[u] = mu_re;
        l10[u + hn] = fpr_neg(mu_im);
    }
}

/// Split a polynomial in FFT representation into two half-size polynomials.
pub fn poly_split_fft(f0: &mut [Fpr], f1: &mut [Fpr], f: &[Fpr], logn: u32) {
    let n: usize = 1 << logn;
    let hn = n >> 1;
    let qn = hn >> 1;

    f0[0] = f[0];
    f1[0] = f[hn];

    for u in 0..qn {
        let a_re = f[(u << 1) + 0];
        let a_im = f[(u << 1) + 0 + hn];
        let b_re = f[(u << 1) + 1];
        let b_im = f[(u << 1) + 1 + hn];

        let (t_re, t_im) = fpc_add(a_re, a_im, b_re, b_im);
        f0[u] = fpr_half(t_re);
        f0[u + qn] = fpr_half(t_im);

        let (t_re, t_im) = fpc_sub(a_re, a_im, b_re, b_im);
        let (t_re, t_im) = fpc_mul(
            t_re,
            t_im,
            FPR_GM_TAB[((u + hn) << 1) + 0],
            fpr_neg(FPR_GM_TAB[((u + hn) << 1) + 1]),
        );
        f1[u] = fpr_half(t_re);
        f1[u + qn] = fpr_half(t_im);
    }
}

/// Merge two half-size polynomials back into a full polynomial in FFT representation.
pub fn poly_merge_fft(f: &mut [Fpr], f0: &[Fpr], f1: &[Fpr], logn: u32) {
    let n: usize = 1 << logn;
    let hn = n >> 1;
    let qn = hn >> 1;

    f[0] = f0[0];
    f[hn] = f1[0];

    for u in 0..qn {
        let a_re = f0[u];
        let a_im = f0[u + qn];
        let (b_re, b_im) = fpc_mul(
            f1[u],
            f1[u + qn],
            FPR_GM_TAB[((u + hn) << 1) + 0],
            FPR_GM_TAB[((u + hn) << 1) + 1],
        );
        let (t_re, t_im) = fpc_add(a_re, a_im, b_re, b_im);
        f[(u << 1) + 0] = t_re;
        f[(u << 1) + 0 + hn] = t_im;
        let (t_re, t_im) = fpc_sub(a_re, a_im, b_re, b_im);
        f[(u << 1) + 1] = t_re;
        f[(u << 1) + 1 + hn] = t_im;
    }
}
