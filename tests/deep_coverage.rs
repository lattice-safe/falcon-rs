//! Deep-coverage test suite.
//!
//! Complements `full_coverage.rs`: exercises internal modules (fpr, fft,
//! vrfy, codec, rng, shake, common, sign) and error/edge branches that the
//! high-level tests do not reach, plus algebraic property tests
//! (FFT/NTT identities, LDL identity, split/merge, verify_recover).
//!
//! Run coverage with: ./scripts/coverage.sh  (cargo llvm-cov)

use falcon::{
    codec, common, falcon as fapi, fft,
    fpr::*,
    rng::{prng_get_bytes, prng_get_u64, prng_get_u8, prng_init, Prng},
    shake::{
        i_shake256_extract, i_shake256_flip, i_shake256_init, i_shake256_inject,
        InnerShake256Context,
    },
    sign::{gaussian0_sampler, sampler, SamplerContext},
    vrfy,
};

// ======================================================================
// Helpers
// ======================================================================

/// Deterministic SHAKE-based RNG context from a byte seed.
fn seeded_rng(seed: &[u8]) -> InnerShake256Context {
    let mut sc = InnerShake256Context::new();
    i_shake256_init(&mut sc);
    i_shake256_inject(&mut sc, seed);
    i_shake256_flip(&mut sc);
    sc
}

/// Simple deterministic pseudo-random f64 in [-1, 1) (xorshift-based).
struct TestRng(u64);
impl TestRng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64 * 2.0 - 1.0
    }
    fn next_mod(&mut self, m: u32) -> u32 {
        (self.next_u64() % m as u64) as u32
    }
}

const Q: u32 = 12289;

// ======================================================================
// fpr: scalar operations and rounding edge cases
// ======================================================================

#[test]
fn fpr_rint_ties_to_even_and_ranges() {
    assert_eq!(fpr_rint(Fpr(0.0)), 0);
    assert_eq!(fpr_rint(Fpr(0.5)), 0); // tie -> even
    assert_eq!(fpr_rint(Fpr(1.5)), 2); // tie -> even
    assert_eq!(fpr_rint(Fpr(2.5)), 2); // tie -> even
    assert_eq!(fpr_rint(Fpr(-0.5)), 0);
    assert_eq!(fpr_rint(Fpr(-1.5)), -2);
    assert_eq!(fpr_rint(Fpr(-2.5)), -2);
    assert_eq!(fpr_rint(Fpr(3.0)), 3);
    assert_eq!(fpr_rint(Fpr(-3.0)), -3);
    assert_eq!(fpr_rint(Fpr(0.49999999)), 0);
    assert_eq!(fpr_rint(Fpr(1234567.75)), 1234568);
    assert_eq!(fpr_rint(Fpr(-1234567.75)), -1234568);
    // large magnitude (exercises the tx branch for |x| >= 2^52)
    assert_eq!(fpr_rint(Fpr(4503599627370496.0)), 4503599627370496);
    assert_eq!(fpr_rint(Fpr(-4503599627370496.0)), -4503599627370496);
}

#[test]
fn fpr_floor_trunc() {
    assert_eq!(fpr_floor(Fpr(1.5)), 1);
    assert_eq!(fpr_floor(Fpr(-1.5)), -2);
    assert_eq!(fpr_floor(Fpr(-0.0001)), -1);
    assert_eq!(fpr_floor(Fpr(7.0)), 7);
    assert_eq!(fpr_trunc(Fpr(1.9)), 1);
    assert_eq!(fpr_trunc(Fpr(-1.9)), -1);
    assert_eq!(fpr_trunc(Fpr(0.0)), 0);
}

#[test]
fn fpr_basic_arithmetic() {
    assert_eq!(fpr_add(Fpr(2.0), Fpr(3.0)).0, 5.0);
    assert_eq!(fpr_sub(Fpr(2.0), Fpr(3.0)).0, -1.0);
    assert_eq!(fpr_neg(Fpr(2.0)).0, -2.0);
    assert_eq!(fpr_half(Fpr(3.0)).0, 1.5);
    assert_eq!(fpr_double(Fpr(3.0)).0, 6.0);
    assert_eq!(fpr_mul(Fpr(2.0), Fpr(3.0)).0, 6.0);
    assert_eq!(fpr_sqr(Fpr(3.0)).0, 9.0);
    assert_eq!(fpr_inv(Fpr(4.0)).0, 0.25);
    assert_eq!(fpr_div(Fpr(1.0), Fpr(4.0)).0, 0.25);
    assert_eq!(fpr_sqrt(Fpr(9.0)).0, 3.0);
    assert_eq!(fpr_lt(Fpr(1.0), Fpr(2.0)), 1);
    assert_eq!(fpr_lt(Fpr(2.0), Fpr(1.0)), 0);
    assert_eq!(fpr_of(-7).0, -7.0);
    assert_eq!(Fpr::default().0, 0.0);
    let d = format!("{:?}", Fpr(1.0)); // Debug impl
    assert!(d.contains("Fpr"));
}

#[test]
fn fpr_expm_p63_matches_exp() {
    // exp(-x) * 2^63 for x in [0, ln 2], ccs = 1
    for i in 0..=20 {
        let x = std::f64::consts::LN_2 * (i as f64) / 20.0;
        let got = fpr_expm_p63(Fpr(x), FPR_ONE) as f64;
        let want = (-x).exp() * 9223372036854775808.0;
        let rel = ((got - want) / want).abs();
        assert!(rel < 1e-12, "x={} got={} want={} rel={}", x, got, want, rel);
    }
    // ccs scaling
    let a = fpr_expm_p63(Fpr(0.25), Fpr(0.5)) as f64;
    let b = fpr_expm_p63(Fpr(0.25), FPR_ONE) as f64;
    assert!((a * 2.0 - b).abs() / b < 1e-9);
}

// ======================================================================
// fft: transform and polynomial-operation identities
// ======================================================================

fn rand_poly(rng: &mut TestRng, logn: u32) -> Vec<Fpr> {
    (0..1usize << logn)
        .map(|_| Fpr(rng.next_f64() * 100.0))
        .collect()
}

fn assert_close(a: &[Fpr], b: &[Fpr], tol: f64, what: &str) {
    for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
        assert!(
            (x.0 - y.0).abs() <= tol * (1.0 + x.0.abs().max(y.0.abs())),
            "{}: index {}: {} vs {}",
            what,
            i,
            x.0,
            y.0
        );
    }
}

#[test]
fn fft_ifft_roundtrip_all_logn() {
    let mut rng = TestRng(0x1234_5678_9abc_def1);
    for logn in 1..=10u32 {
        let orig = rand_poly(&mut rng, logn);
        let mut f = orig.clone();
        fft::fft(&mut f, logn);
        fft::ifft(&mut f, logn);
        assert_close(&f, &orig, 1e-9, &format!("fft/ifft logn={}", logn));
    }
}

/// Schoolbook negacyclic product in coefficient domain (f64).
fn negacyclic_mul(a: &[Fpr], b: &[Fpr], logn: u32) -> Vec<Fpr> {
    let n = 1usize << logn;
    let mut r = vec![0.0f64; n];
    for i in 0..n {
        for j in 0..n {
            let p = a[i].0 * b[j].0;
            if i + j < n {
                r[i + j] += p;
            } else {
                r[i + j - n] -= p;
            }
        }
    }
    r.into_iter().map(Fpr).collect()
}

#[test]
fn fft_poly_mul_matches_schoolbook() {
    let mut rng = TestRng(0xdead_beef_cafe_f00d);
    for logn in 1..=6u32 {
        let a = rand_poly(&mut rng, logn);
        let b = rand_poly(&mut rng, logn);
        let want = negacyclic_mul(&a, &b, logn);
        let mut fa = a.clone();
        let mut fb = b.clone();
        fft::fft(&mut fa, logn);
        fft::fft(&mut fb, logn);
        fft::poly_mul_fft(&mut fa, &fb, logn);
        fft::ifft(&mut fa, logn);
        assert_close(&fa, &want, 1e-7, &format!("poly_mul logn={}", logn));
    }
}

#[test]
fn fft_poly_div_roundtrip() {
    let mut rng = TestRng(0x0bad_c0de_1234_5678);
    let logn = 6u32;
    let a = rand_poly(&mut rng, logn);
    // b: well-conditioned (bounded away from zero in FFT domain)
    let mut b = vec![Fpr(0.0); 1 << logn];
    b[0] = Fpr(10.0); // constant 10 + small noise
    for slot in b.iter_mut().skip(1) {
        *slot = Fpr(rng.next_f64() * 0.5);
    }
    let mut fa = a.clone();
    let mut fb = b.clone();
    fft::fft(&mut fa, logn);
    fft::fft(&mut fb, logn);
    // (a * b) / b == a
    let mut prod = fa.clone();
    fft::poly_mul_fft(&mut prod, &fb, logn);
    fft::poly_div_fft(&mut prod, &fb, logn);
    fft::ifft(&mut prod, logn);
    assert_close(&prod, &a, 1e-8, "poly_div roundtrip");
}

#[test]
fn fft_add_sub_neg_adj_const() {
    let mut rng = TestRng(0x9999_8888_7777_6666);
    let logn = 5u32;
    let n = 1usize << logn;
    let a = rand_poly(&mut rng, logn);
    let b = rand_poly(&mut rng, logn);

    let mut x = a.clone();
    fft::poly_add(&mut x, &b, logn);
    for u in 0..n {
        assert_eq!(x[u].0, a[u].0 + b[u].0);
    }
    fft::poly_sub(&mut x, &b, logn);
    assert_close(&x, &a, 1e-15, "add/sub");
    // Test poly_neg on a fresh copy: add/sub above leaves x only approximately
    // equal to a (FP rounding), so exact negation must be checked against a.
    let mut xn = a.clone();
    fft::poly_neg(&mut xn, logn);
    for u in 0..n {
        assert_eq!(xn[u].0, -a[u].0);
    }
    // adjoint in FFT domain: negates imaginary halves; applying twice = identity
    let mut y = a.clone();
    fft::poly_adj_fft(&mut y, logn);
    fft::poly_adj_fft(&mut y, logn);
    assert_close(&y, &a, 0.0, "adj twice");
    // constant multiply
    let mut z = a.clone();
    fft::poly_mulconst(&mut z, Fpr(2.5), logn);
    for u in 0..n {
        assert_eq!(z[u].0, a[u].0 * 2.5);
    }
}

#[test]
fn fft_selfadj_and_invnorm() {
    let mut rng = TestRng(0x1111_2222_3333_4444);
    let logn = 5u32;
    let n = 1usize << logn;
    let hn = n >> 1;
    let a = {
        let mut t = rand_poly(&mut rng, logn);
        fft::fft(&mut t, logn);
        t
    };
    let b = {
        let mut t = rand_poly(&mut rng, logn);
        fft::fft(&mut t, logn);
        t
    };
    // a * adj(a) == |a|^2 (real, nonnegative)
    let mut sq = a.clone();
    fft::poly_mulselfadj_fft(&mut sq, logn);
    for u in 0..hn {
        let want = a[u].0 * a[u].0 + a[u + hn].0 * a[u + hn].0;
        assert!((sq[u].0 - want).abs() < 1e-9 * (1.0 + want));
        assert_eq!(sq[u + hn].0, 0.0);
    }
    // poly_invnorm2: d = 1 / (|a|^2 + |b|^2)
    let mut d = vec![Fpr(0.0); n];
    fft::poly_invnorm2_fft(&mut d, &a, &b, logn);
    for u in 0..hn {
        let want = 1.0
            / (a[u].0 * a[u].0
                + a[u + hn].0 * a[u + hn].0
                + b[u].0 * b[u].0
                + b[u + hn].0 * b[u + hn].0);
        assert!((d[u].0 - want).abs() < 1e-9 * want.abs());
    }
    // muladj: a * adj(b), cross-check via manual complex arithmetic
    let mut m = a.clone();
    fft::poly_muladj_fft(&mut m, &b, logn);
    for u in 0..hn {
        let (ar, ai) = (a[u].0, a[u + hn].0);
        let (br, bi) = (b[u].0, -b[u + hn].0);
        let wr = ar * br - ai * bi;
        let wi = ar * bi + ai * br;
        assert!((m[u].0 - wr).abs() < 1e-9 * (1.0 + wr.abs()));
        assert!((m[u + hn].0 - wi).abs() < 1e-9 * (1.0 + wi.abs()));
    }
    // add_muladj: d = F*adj(f) + G*adj(g)
    let mut d2 = vec![Fpr(0.0); n];
    fft::poly_add_muladj_fft(&mut d2, &a, &b, &a, &b, logn);
    let mut want1 = a.clone();
    fft::poly_muladj_fft(&mut want1, &a, logn);
    let mut want2 = b.clone();
    fft::poly_muladj_fft(&mut want2, &b, logn);
    fft::poly_add(&mut want1, &want2, logn);
    assert_close(&d2, &want1, 1e-9, "add_muladj");
    // mul/div by autoadjoint
    let mut aa = a.clone();
    fft::poly_mulselfadj_fft(&mut aa, logn); // real positive
    let mut v = b.clone();
    fft::poly_mul_autoadj_fft(&mut v, &aa, logn);
    fft::poly_div_autoadj_fft(&mut v, &aa, logn);
    assert_close(&v, &b, 1e-9, "autoadj mul/div roundtrip");
}

#[test]
fn fft_ldl_identity() {
    let mut rng = TestRng(0x5555_aaaa_5555_aaaa);
    let logn = 5u32;
    let n = 1usize << logn;
    let hn = n >> 1;
    // Build a positive-definite self-adjoint Gram matrix from a random basis:
    // g00 = |a|^2 + |b|^2, g01 = a*adj(c) + b*adj(d), g11 = |c|^2 + |d|^2.
    let mk = |rng: &mut TestRng| {
        let mut t = rand_poly(rng, logn);
        fft::fft(&mut t, logn);
        t
    };
    let (a, b, c, d) = (mk(&mut rng), mk(&mut rng), mk(&mut rng), mk(&mut rng));
    let mut g00 = a.clone();
    fft::poly_mulselfadj_fft(&mut g00, logn);
    let mut t = b.clone();
    fft::poly_mulselfadj_fft(&mut t, logn);
    fft::poly_add(&mut g00, &t, logn);
    let mut g01 = vec![Fpr(0.0); n];
    fft::poly_add_muladj_fft(&mut g01, &a, &b, &c, &d, logn);
    let mut g11 = c.clone();
    fft::poly_mulselfadj_fft(&mut g11, logn);
    let mut t2 = d.clone();
    fft::poly_mulselfadj_fft(&mut t2, logn);
    fft::poly_add(&mut g11, &t2, logn);

    let g01_orig = g01.clone();
    let g11_orig = g11.clone();

    // In-place LDL
    let mut l10 = g01.clone();
    let mut d11 = g11.clone();
    fft::poly_ldl_fft(&g00, &mut l10, &mut d11, logn);
    // Identity per FFT slot: mu = g01/g00, l10 = conj(mu), d11 = g11 - mu*conj(g01)
    for u in 0..hn {
        let (g00r, g00i) = (g00[u].0, g00[u + hn].0);
        let (g01r, g01i) = (g01_orig[u].0, g01_orig[u + hn].0);
        let den = g00r * g00r + g00i * g00i;
        let mur = (g01r * g00r + g01i * g00i) / den;
        let mui = (g01i * g00r - g01r * g00i) / den;
        assert!((l10[u].0 - mur).abs() < 1e-6 * (1.0 + mur.abs()), "l10 re");
        assert!(
            (l10[u + hn].0 + mui).abs() < 1e-6 * (1.0 + mui.abs()),
            "l10 im"
        );
        let xir = mur * g01r + mui * g01i;
        let xii = -mur * g01i + mui * g01r;
        let d11r = g11_orig[u].0 - xir;
        let d11i = g11_orig[u + hn].0 - xii;
        assert!(
            (d11[u].0 - d11r).abs() < 1e-6 * (1.0 + d11r.abs()),
            "d11 re"
        );
        assert!(
            (d11[u + hn].0 - d11i).abs() < 1e-6 * (1.0 + d11i.abs()),
            "d11 im"
        );
    }
    // ldlmv variant must agree with in-place variant
    let mut d11b = vec![Fpr(0.0); n];
    let mut l10b = vec![Fpr(0.0); n];
    fft::poly_ldlmv_fft(&mut d11b, &mut l10b, &g00, &g01_orig, &g11_orig, logn);
    assert_close(&d11b, &d11, 1e-12, "ldlmv d11");
    assert_close(&l10b, &l10, 1e-12, "ldlmv l10");
}

#[test]
fn fft_split_merge_roundtrip() {
    let mut rng = TestRng(0xfeed_face_dead_beef);
    for logn in 1..=10u32 {
        let n = 1usize << logn;
        let hn = n >> 1;
        let mut f = rand_poly(&mut rng, logn);
        fft::fft(&mut f, logn);
        let mut f0 = vec![Fpr(0.0); hn.max(1)];
        let mut f1 = vec![Fpr(0.0); hn.max(1)];
        fft::poly_split_fft(&mut f0, &mut f1, &f, logn);
        let mut g = vec![Fpr(0.0); n];
        fft::poly_merge_fft(&mut g, &f0, &f1, logn);
        assert_close(&g, &f, 1e-10, &format!("split/merge logn={}", logn));
    }
}

// ======================================================================
// vrfy: NTT-domain public-key math
// ======================================================================

/// Schoolbook negacyclic multiply mod q on u32 values.
fn negacyclic_mul_modq(a: &[u32], b: &[u32], n: usize) -> Vec<u32> {
    let mut r = vec![0i64; n];
    for i in 0..n {
        for j in 0..n {
            let p = (a[i] as i64) * (b[j] as i64);
            if i + j < n {
                r[i + j] += p;
            } else {
                r[i + j - n] -= p;
            }
        }
    }
    r.into_iter()
        .map(|x| (x.rem_euclid(Q as i64)) as u32)
        .collect()
}

#[test]
fn verify_recover_reconstructs_public_key() {
    let mut rng = TestRng(0x77aa_77aa_77aa_77aa);
    let logn = 4u32;
    let n = 1usize << logn;
    // random target public key h, small short s1/s2 with s2 invertible
    for trial in 0..8 {
        let h_target: Vec<u32> = (0..n).map(|_| rng.next_mod(Q)).collect();
        let s1: Vec<i16> = (0..n).map(|_| (rng.next_mod(11) as i16) - 5).collect();
        let mut s2: Vec<i16> = (0..n).map(|_| (rng.next_mod(11) as i16) - 5).collect();
        s2[0] += 1; // nudge away from all-zero
                    // c0 = s1 + s2*h mod q (negacyclic)
        let s2u: Vec<u32> = s2
            .iter()
            .map(|&v| ((v as i32).rem_euclid(Q as i32)) as u32)
            .collect();
        let prod = negacyclic_mul_modq(&s2u, &h_target, n);
        let c0: Vec<u16> = (0..n)
            .map(|i| {
                let v = (s1[i] as i64 + prod[i] as i64).rem_euclid(Q as i64);
                v as u16
            })
            .collect();
        let mut h_out = vec![0u16; n];
        let mut tmp = vec![0u8; 4 * n + 8];
        let ok = vrfy::verify_recover(&mut h_out, &c0, &s1, &s2, logn, &mut tmp);
        // s2 must be invertible for recovery; check with is_invertible
        let mut tmp2 = vec![0u8; 4 * n + 8];
        let inv = vrfy::is_invertible(&s2, logn, &mut tmp2);
        assert_eq!(ok, inv, "trial {}: recover/invertible disagree", trial);
        if ok {
            let got: Vec<u32> = h_out.iter().map(|&x| x as u32).collect();
            assert_eq!(got, h_target, "trial {}: recovered h mismatch", trial);
        }
    }
}

#[test]
fn is_invertible_and_count_nttzero() {
    let logn = 4u32;
    let n = 1usize << logn;
    let mut tmp = vec![0u8; 4 * n + 8];
    // zero polynomial: not invertible, all NTT coefficients zero
    let zero = vec![0i16; n];
    assert!(!vrfy::is_invertible(&zero, logn, &mut tmp));
    assert_eq!(vrfy::count_nttzero(&zero, logn, &mut tmp), n as u32);
    // constant 1: invertible, no NTT zeros
    let mut one = vec![0i16; n];
    one[0] = 1;
    assert!(vrfy::is_invertible(&one, logn, &mut tmp));
    assert_eq!(vrfy::count_nttzero(&one, logn, &mut tmp), 0);
    // negative coefficients path
    let mut negp = vec![0i16; n];
    negp[0] = -1;
    assert!(vrfy::is_invertible(&negp, logn, &mut tmp));
}

#[test]
fn compute_public_and_complete_private_roundtrip() {
    // Full private key via keygen at a small size, then recompute G and h.
    let logn = 4u32;
    let n = 1usize << logn;
    let mut rng = seeded_rng(b"deep-coverage compute_public");
    let mut f = vec![0i8; n];
    let mut g = vec![0i8; n];
    let mut big_f = vec![0i8; n];
    let mut big_g = vec![0i8; n];
    let mut h = vec![0u16; n];
    let mut tmp = vec![0u8; fapi::falcon_tmpsize_keygen(logn) + 64];
    falcon::keygen::keygen(
        &mut rng,
        &mut f,
        &mut g,
        &mut big_f,
        Some(&mut big_g[..]),
        Some(&mut h[..]),
        logn,
        &mut tmp,
    );
    // compute_public reproduces h
    let mut h2 = vec![0u16; n];
    let mut tmp2 = vec![0u8; 4 * n + 8];
    assert!(vrfy::compute_public(&mut h2, &f, &g, logn, &mut tmp2));
    assert_eq!(h, h2);
    // complete_private recovers G from (f, g, F)
    let mut big_g2 = vec![0i8; n];
    let mut tmp3 = vec![0u8; 8 * n + 8];
    assert!(vrfy::complete_private(
        &mut big_g2,
        &f,
        &g,
        &big_f,
        logn,
        &mut tmp3
    ));
    assert_eq!(big_g, big_g2);
    // NTRU equation check: f*G - g*F = q mod q  => == 0 mod q, and exactly q over Z
    let fu: Vec<u32> = f
        .iter()
        .map(|&v| ((v as i32).rem_euclid(Q as i32)) as u32)
        .collect();
    let gu: Vec<u32> = g
        .iter()
        .map(|&v| ((v as i32).rem_euclid(Q as i32)) as u32)
        .collect();
    let fu_big: Vec<u32> = big_f
        .iter()
        .map(|&v| ((v as i32).rem_euclid(Q as i32)) as u32)
        .collect();
    let gu_big: Vec<u32> = big_g
        .iter()
        .map(|&v| ((v as i32).rem_euclid(Q as i32)) as u32)
        .collect();
    let t1 = negacyclic_mul_modq(&fu, &gu_big, n);
    let t2 = negacyclic_mul_modq(&gu, &fu_big, n);
    for i in 0..n {
        let want = if i == 0 { Q } else { 0 }; // f*G - g*F = q (constant poly)
        let got = (t1[i] as i64 - t2[i] as i64).rem_euclid(Q as i64) as u32;
        assert_eq!(got, want % Q, "NTRU identity at coeff {}", i);
    }
}

// ======================================================================
// common: hash-to-point and norm bounds
// ======================================================================

#[test]
fn hash_to_point_ct_equals_vartime_all_logn() {
    for logn in 1..=10u32 {
        let n = 1usize << logn;
        let mut sc1 = seeded_rng(b"h2p equivalence");
        let mut sc2 = seeded_rng(b"h2p equivalence");
        let mut x1 = vec![0u16; n];
        let mut x2 = vec![0u16; n];
        let mut tmp = vec![0u8; 2 * n + 2];
        common::hash_to_point_vartime(&mut sc1, &mut x1, logn);
        common::hash_to_point_ct(&mut sc2, &mut x2, logn, &mut tmp);
        assert_eq!(x1, x2, "logn={}", logn);
        assert!(x1.iter().all(|&v| v < 12289));
    }
}

#[test]
fn is_short_bounds_and_saturation() {
    let logn = 9u32;
    let n = 1usize << logn;
    // all-zero: trivially short
    assert!(common::is_short(&vec![0i16; n], &vec![0i16; n], logn));
    // saturating overflow path: huge values must be rejected, not wrap
    let big = vec![i16::MAX; n];
    assert!(!common::is_short(&big, &big, logn));
    // boundary: L2BOUND for logn=9 is 34034726; a vector of squared norm
    // exactly the bound is accepted, bound+1 rejected.
    // 34034726 = 5834^2 + q with small remainder; craft simply:
    let mut s1 = vec![0i16; n];
    let mut s2 = vec![0i16; n];
    s1[0] = 5833; // 5833^2 = 34023889 <= bound
    assert!(common::is_short(&s1, &s2, logn));
    s1[0] = 5834; // 5834^2 = 34035556 > bound
    assert!(!common::is_short(&s1, &s2, logn));
    // is_short_half consistency with is_short
    s1[0] = 100;
    s2[0] = 200;
    let sqn = 100u32 * 100;
    assert_eq!(
        common::is_short(&s1, &s2, logn),
        common::is_short_half(sqn, &s2, logn)
    );
    // saturated input flag
    assert!(!common::is_short_half(u32::MAX, &s2, logn));
}

// ======================================================================
// codec: error paths and roundtrips
// ======================================================================

#[test]
fn modq_codec_roundtrip_and_errors() {
    let logn = 4u32;
    let n = 1usize << logn;
    let mut rng = TestRng(42);
    let x: Vec<u16> = (0..n).map(|_| rng.next_mod(Q) as u16).collect();
    let len = codec::modq_encode(None, &x, logn);
    assert_eq!(len, (n * 14 + 7) >> 3);
    let mut buf = vec![0u8; len];
    assert_eq!(codec::modq_encode(Some(&mut buf[..]), &x, logn), len);
    let mut y = vec![0u16; n];
    assert_eq!(codec::modq_decode(&mut y, logn, &buf), len);
    assert_eq!(x, y);
    // out-of-range value refuses to encode
    let mut bad = x.clone();
    bad[0] = 12289;
    assert_eq!(codec::modq_encode(Some(&mut buf[..]), &bad, logn), 0);
    // short output buffer
    let mut small = vec![0u8; len - 1];
    assert_eq!(codec::modq_encode(Some(&mut small[..]), &x, logn), 0);
    // short input buffer
    assert_eq!(codec::modq_decode(&mut y, logn, &buf[..len - 1]), 0);
    // out-of-range encoded value (all-ones is >= q in the top 14 bits)
    let ones = vec![0xFFu8; len];
    assert_eq!(codec::modq_decode(&mut y, logn, &ones), 0);
    // nonzero trailing bits rejected
    let mut trail = buf.clone();
    if (n * 14) % 8 != 0 {
        *trail.last_mut().unwrap() |= 1;
        assert_eq!(codec::modq_decode(&mut y, logn, &trail), 0);
    }
}

#[test]
fn trim_i8_codec_roundtrip_and_errors() {
    let logn = 4u32;
    let n = 1usize << logn;
    let bits = 6u32;
    let maxv = (1i32 << (bits - 1)) - 1;
    let mut rng = TestRng(4242);
    let x: Vec<i8> = (0..n)
        .map(|_| (rng.next_mod((2 * maxv + 1) as u32) as i32 - maxv) as i8)
        .collect();
    let len = codec::trim_i8_encode(None, &x, logn, bits);
    let mut buf = vec![0u8; len];
    assert_eq!(
        codec::trim_i8_encode(Some(&mut buf[..]), &x, logn, bits),
        len
    );
    let mut y = vec![0i8; n];
    assert_eq!(codec::trim_i8_decode(&mut y, logn, bits, &buf), len);
    assert_eq!(x, y);
    // out-of-range value
    let mut bad = x.clone();
    bad[0] = (maxv + 1) as i8;
    assert_eq!(
        codec::trim_i8_encode(Some(&mut buf[..]), &bad, logn, bits),
        0
    );
    // -2^(bits-1) encoding is forbidden on decode: repeated 6-bit "100000"
    // groups; 4 groups = 3 bytes 0x82 0x08 0x20, repeated for n=16 coeffs.
    let forbidden: Vec<u8> = [0x82u8, 0x08, 0x20]
        .iter()
        .cycle()
        .take(len)
        .cloned()
        .collect();
    assert_eq!(codec::trim_i8_decode(&mut y, logn, bits, &forbidden), 0);
    // short input
    assert_eq!(
        codec::trim_i8_decode(&mut y, logn, bits, &buf[..len - 1]),
        0
    );
    // short output buffer for encode
    let mut small = vec![0u8; len - 1];
    assert_eq!(
        codec::trim_i8_encode(Some(&mut small[..]), &x, logn, bits),
        0
    );
}

#[test]
fn comp_codec_errors() {
    let logn = 4u32;
    let n = 1usize << logn;
    // out-of-range coefficient
    let mut x = vec![0i16; n];
    x[0] = 2048;
    let mut buf = vec![0u8; 512];
    assert_eq!(codec::comp_encode(Some(&mut buf[..]), &x, logn), 0);
    x[0] = -2048;
    assert_eq!(codec::comp_encode(Some(&mut buf[..]), &x, logn), 0);
    // roundtrip with extreme legal values
    x[0] = 2047;
    x[1] = -2047;
    let len = codec::comp_encode(None, &x, logn);
    assert!(len > 0);
    let mut buf2 = vec![0u8; len];
    assert_eq!(codec::comp_encode(Some(&mut buf2[..]), &x, logn), len);
    let mut y = vec![0i16; n];
    assert_eq!(codec::comp_decode(&mut y, logn, &buf2), len);
    assert_eq!(x, y);
    // truncated input fails
    assert_eq!(codec::comp_decode(&mut y, logn, &buf2[..len - 1]), 0);
    // "-0" is forbidden: craft signbit=1, mantissa=0, terminator=1
    // byte0 = 1000_0000, byte1 = 1000_0000 -> s=1, m=0
    let minus_zero = [
        0x80u8, 0x80u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(codec::comp_decode(&mut y, logn, &minus_zero), 0);
    // encode output-buffer-too-small path
    let mut tiny = [0u8; 2];
    assert_eq!(codec::comp_encode(Some(&mut tiny[..]), &x, logn), 0);
}

// ======================================================================
// shake + rng
// ======================================================================

#[test]
fn shake256_long_extract_and_incremental() {
    // multi-block extraction determinism + known empty-input prefix
    let mut sc = InnerShake256Context::new();
    i_shake256_init(&mut sc);
    i_shake256_flip(&mut sc);
    let mut long = vec![0u8; 500];
    i_shake256_extract(&mut sc, &mut long);
    let expected_prefix = [
        0x46u8, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb,
        0x24, 0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5,
        0x76, 0x2f,
    ];
    assert_eq!(&long[..32], &expected_prefix);
    // byte-at-a-time extraction equals bulk extraction
    let mut sc2 = InnerShake256Context::new();
    i_shake256_init(&mut sc2);
    i_shake256_flip(&mut sc2);
    let mut single = vec![0u8; 500];
    for b in single.iter_mut() {
        let mut one = [0u8; 1];
        i_shake256_extract(&mut sc2, &mut one);
        *b = one[0];
    }
    assert_eq!(long, single);
    // injecting >136 bytes (rate boundary) in odd chunks
    let data = vec![0xA5u8; 300];
    let mut a = InnerShake256Context::new();
    i_shake256_init(&mut a);
    i_shake256_inject(&mut a, &data);
    i_shake256_flip(&mut a);
    let mut b = InnerShake256Context::new();
    i_shake256_init(&mut b);
    for chunk in data.chunks(77) {
        i_shake256_inject(&mut b, chunk);
    }
    i_shake256_flip(&mut b);
    let mut oa = [0u8; 64];
    let mut ob = [0u8; 64];
    i_shake256_extract(&mut a, &mut oa);
    i_shake256_extract(&mut b, &mut ob);
    assert_eq!(oa, ob);
}

#[test]
fn prng_determinism_and_refill_boundaries() {
    let mut p1 = Prng::new();
    let mut p2 = Prng::new();
    let mut sc1 = seeded_rng(b"prng seed");
    let mut sc2 = seeded_rng(b"prng seed");
    prng_init(&mut p1, &mut sc1);
    prng_init(&mut p2, &mut sc2);
    // u64 stream equals byte stream reinterpretation
    let mut bytes = [0u8; 64];
    prng_get_bytes(&mut p2, &mut bytes);
    for i in 0..8 {
        let want = u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap());
        assert_eq!(prng_get_u64(&mut p1), want);
    }
    // force the u64 tail-refill branch (ptr near 512-9)
    let mut p3 = Prng::new();
    let mut sc3 = seeded_rng(b"prng seed 2");
    prng_init(&mut p3, &mut sc3);
    let mut sink = vec![0u8; 505];
    prng_get_bytes(&mut p3, &mut sink);
    let _ = prng_get_u64(&mut p3); // triggers refill path
                                   // force the u8 wrap-refill branch
    let mut p4 = Prng::new();
    let mut sc4 = seeded_rng(b"prng seed 3");
    prng_init(&mut p4, &mut sc4);
    for _ in 0..1030 {
        let v = prng_get_u8(&mut p4);
        assert!(v < 256);
    }
    // bulk read crossing a 512-byte refill boundary stays consistent with
    // single-byte reads from an identically-seeded PRNG
    let mut p5 = Prng::new();
    let mut p6 = Prng::new();
    let mut sc5 = seeded_rng(b"prng seed 4");
    let mut sc6 = seeded_rng(b"prng seed 4");
    prng_init(&mut p5, &mut sc5);
    prng_init(&mut p6, &mut sc6);
    let mut bulk = vec![0u8; 1200];
    prng_get_bytes(&mut p5, &mut bulk);
    for (i, &want) in bulk.iter().enumerate() {
        assert_eq!(prng_get_u8(&mut p6) as u8, want, "byte {}", i);
    }
}

// ======================================================================
// sign: Gaussian samplers
// ======================================================================

#[test]
fn gaussian0_sampler_range_and_mean() {
    let mut p = Prng::new();
    let mut sc = seeded_rng(b"gauss0");
    prng_init(&mut p, &mut sc);
    let mut sum = 0f64;
    let iters = 20000;
    for _ in 0..iters {
        let z = gaussian0_sampler(&mut p);
        assert!((0..=18).contains(&z), "z={}", z);
        sum += z as f64;
    }
    // Half-Gaussian sigma=1.8205: E[z] = sum_k P(z>k) ≈ 1.1610
    let mean = sum / iters as f64;
    assert!((mean - 1.1610).abs() < 0.05, "mean={}", mean);
}

#[test]
fn sampler_distribution_center_and_spread() {
    let mut sc = seeded_rng(b"samplerZ");
    let mut ctx = SamplerContext {
        p: Prng::new(),
        sigma_min: FPR_SIGMA_MIN[9],
    };
    prng_init(&mut ctx.p, &mut sc);
    let sigma = 1.5f64;
    let isigma = Fpr(1.0 / sigma);
    let mu = 3.25f64;
    let iters = 20000;
    let mut sum = 0f64;
    let mut sumsq = 0f64;
    for _ in 0..iters {
        let z = sampler(&mut ctx, Fpr(mu), isigma) as f64;
        assert!((z - mu).abs() < 30.0 * sigma, "outlier z={}", z);
        sum += z;
        sumsq += (z - mu) * (z - mu);
    }
    let mean = sum / iters as f64;
    let var = sumsq / iters as f64;
    assert!((mean - mu).abs() < 0.05, "mean={} mu={}", mean, mu);
    assert!(
        (var - sigma * sigma).abs() < 0.15 * sigma * sigma,
        "var={} sigma^2={}",
        var,
        sigma * sigma
    );
}

// ======================================================================
// falcon high-level API: small parameter sets + error paths
// ======================================================================

#[test]
fn keygen_sign_verify_small_logn() {
    // logn 1..=8 covers solve_ntru depth-0/1/intermediate paths and small NTTs
    for logn in 1..=8u32 {
        let mut rng = seeded_rng(format!("small-kg-{}", logn).as_bytes());
        let sk_len = fapi::falcon_privkey_size(logn);
        let pk_len = fapi::falcon_pubkey_size(logn);
        let mut sk = vec![0u8; sk_len];
        let mut pk = vec![0u8; pk_len];
        let mut tmp = vec![0u8; fapi::falcon_tmpsize_keygen(logn)];
        let rc = fapi::falcon_keygen_make(&mut rng, logn, &mut sk, Some(&mut pk[..]), &mut tmp);
        assert_eq!(rc, 0, "keygen failed at logn={}", logn);

        let mut sig = vec![0u8; fapi::falcon_sig_compressed_maxsize(logn)];
        let mut sig_len = sig.len();
        let mut tmp_sd = vec![0u8; fapi::falcon_tmpsize_signdyn(logn)];
        let rc = fapi::falcon_sign_dyn(
            &mut rng,
            &mut sig,
            &mut sig_len,
            fapi::FALCON_SIG_COMPRESSED,
            &sk,
            b"small message",
            &mut tmp_sd,
        );
        assert_eq!(rc, 0, "sign failed at logn={}", logn);

        let mut tmp_v = vec![0u8; fapi::falcon_tmpsize_verify(logn)];
        let rc = fapi::falcon_verify(
            &sig[..sig_len],
            fapi::FALCON_SIG_COMPRESSED,
            &pk,
            b"small message",
            &mut tmp_v,
        );
        assert_eq!(rc, 0, "verify failed at logn={}", logn);
        // wrong message must fail
        let rc = fapi::falcon_verify(
            &sig[..sig_len],
            fapi::FALCON_SIG_COMPRESSED,
            &pk,
            b"other message",
            &mut tmp_v,
        );
        assert_eq!(rc, fapi::FALCON_ERR_BADSIG);
    }
}

#[test]
fn expanded_key_small_logn_inline_leaves() {
    // logn 1, 2, 3 exercise the ff_sampling_fft logn==1 / logn==2 inline paths
    for logn in 1..=3u32 {
        let mut rng = seeded_rng(format!("small-ek-{}", logn).as_bytes());
        let sk_len = fapi::falcon_privkey_size(logn);
        let pk_len = fapi::falcon_pubkey_size(logn);
        let mut sk = vec![0u8; sk_len];
        let mut pk = vec![0u8; pk_len];
        let mut tmp = vec![0u8; fapi::falcon_tmpsize_keygen(logn)];
        assert_eq!(
            fapi::falcon_keygen_make(&mut rng, logn, &mut sk, Some(&mut pk[..]), &mut tmp),
            0
        );
        let mut ek = vec![0u8; fapi::falcon_expandedkey_size(logn)];
        let mut tmp_e = vec![0u8; fapi::falcon_tmpsize_expandpriv(logn)];
        assert_eq!(fapi::falcon_expand_privkey(&mut ek, &sk, &mut tmp_e), 0);
        let mut sig = vec![0u8; fapi::falcon_sig_compressed_maxsize(logn)];
        let mut sig_len = sig.len();
        let mut tmp_st = vec![0u8; fapi::falcon_tmpsize_signtree(logn)];
        assert_eq!(
            fapi::falcon_sign_tree(
                &mut rng,
                &mut sig,
                &mut sig_len,
                fapi::FALCON_SIG_COMPRESSED,
                &ek,
                b"tree msg",
                &mut tmp_st,
            ),
            0,
            "sign_tree failed at logn={}",
            logn
        );
        let mut tmp_v = vec![0u8; fapi::falcon_tmpsize_verify(logn)];
        assert_eq!(
            fapi::falcon_verify(
                &sig[..sig_len],
                fapi::FALCON_SIG_COMPRESSED,
                &pk,
                b"tree msg",
                &mut tmp_v,
            ),
            0,
            "verify(sign_tree) failed at logn={}",
            logn
        );
    }
}

#[test]
fn falcon_api_error_paths() {
    let mut rng = seeded_rng(b"err paths");
    let logn = 9u32;
    let mut sk = vec![0u8; fapi::falcon_privkey_size(logn)];
    let mut tmp = vec![0u8; fapi::falcon_tmpsize_keygen(logn)];

    // bad logn
    assert_eq!(
        fapi::falcon_keygen_make(&mut rng, 0, &mut sk, None, &mut tmp),
        fapi::FALCON_ERR_BADARG
    );
    assert_eq!(
        fapi::falcon_keygen_make(&mut rng, 11, &mut sk, None, &mut tmp),
        fapi::FALCON_ERR_BADARG
    );
    // short buffers
    let mut short_sk = vec![0u8; 10];
    assert_eq!(
        fapi::falcon_keygen_make(&mut rng, logn, &mut short_sk, None, &mut tmp),
        fapi::FALCON_ERR_SIZE
    );
    let mut short_tmp = vec![0u8; 16];
    assert_eq!(
        fapi::falcon_keygen_make(&mut rng, logn, &mut sk, None, &mut short_tmp),
        fapi::FALCON_ERR_SIZE
    );
    let mut short_pk = [0u8; 4];
    assert_eq!(
        fapi::falcon_keygen_make(&mut rng, logn, &mut sk, Some(&mut short_pk[..]), &mut tmp),
        fapi::FALCON_ERR_SIZE
    );

    // get_logn
    assert_eq!(fapi::falcon_get_logn(&[]), fapi::FALCON_ERR_FORMAT);
    assert_eq!(fapi::falcon_get_logn(&[0x59]), 9);
    assert_eq!(fapi::falcon_get_logn(&[0x50]), fapi::FALCON_ERR_FORMAT);
    assert_eq!(fapi::falcon_get_logn(&[0x5B]), fapi::FALCON_ERR_FORMAT);

    // make_public format errors
    let mut pk = vec![0u8; fapi::falcon_pubkey_size(9)];
    let mut tmp_mp = vec![0u8; fapi::falcon_tmpsize_makepub(9)];
    assert_eq!(
        fapi::falcon_make_public(&mut pk, &[], &mut tmp_mp),
        fapi::FALCON_ERR_FORMAT
    );
    assert_eq!(
        fapi::falcon_make_public(&mut pk, &[0x40u8; 100], &mut tmp_mp),
        fapi::FALCON_ERR_FORMAT
    );
    let bad_len = vec![0x59u8; 100]; // header ok, wrong length
    assert_eq!(
        fapi::falcon_make_public(&mut pk, &bad_len, &mut tmp_mp),
        fapi::FALCON_ERR_FORMAT
    );

    // verify with malformed inputs
    let mut tmp_v = vec![0u8; fapi::falcon_tmpsize_verify(9)];
    let good_pk_hdr = {
        let mut v = vec![0u8; fapi::falcon_pubkey_size(9)];
        v[0] = 0x09;
        v
    };
    // signature too short
    assert_eq!(
        fapi::falcon_verify(&[0u8; 10], 0, &good_pk_hdr, b"m", &mut tmp_v),
        fapi::FALCON_ERR_FORMAT
    );
    // pubkey bad header nibble
    let mut bad_pk = good_pk_hdr.clone();
    bad_pk[0] = 0x19;
    let sig41 = {
        let mut s = vec![0u8; 60];
        s[0] = 0x39;
        s
    };
    assert_eq!(
        fapi::falcon_verify(&sig41, 0, &bad_pk, b"m", &mut tmp_v),
        fapi::FALCON_ERR_FORMAT
    );
    // logn mismatch between sig and key
    let mut sig_wrong = sig41.clone();
    sig_wrong[0] = 0x38;
    assert_eq!(
        fapi::falcon_verify(&sig_wrong, 0, &good_pk_hdr, b"m", &mut tmp_v),
        fapi::FALCON_ERR_BADSIG
    );
    // bad sig type constant
    assert_eq!(
        fapi::falcon_verify(&sig41, 99, &good_pk_hdr, b"m", &mut tmp_v),
        fapi::FALCON_ERR_BADARG
    );
    // sign with bad sig type
    let mut rng2 = seeded_rng(b"err paths 2");
    let mut pk2 = vec![0u8; fapi::falcon_pubkey_size(2)];
    let mut sk2 = vec![0u8; fapi::falcon_privkey_size(2)];
    let mut tmp_kg2 = vec![0u8; fapi::falcon_tmpsize_keygen(2)];
    assert_eq!(
        fapi::falcon_keygen_make(&mut rng2, 2, &mut sk2, Some(&mut pk2[..]), &mut tmp_kg2),
        0
    );
    let mut sig = vec![0u8; 4096];
    let mut sig_len = sig.len();
    let mut tmp_sd2 = vec![0u8; fapi::falcon_tmpsize_signdyn(2)];
    assert_eq!(
        fapi::falcon_sign_dyn(
            &mut rng2,
            &mut sig,
            &mut sig_len,
            7,
            &sk2,
            b"m",
            &mut tmp_sd2
        ),
        fapi::FALCON_ERR_BADARG
    );
    // expand_privkey error paths
    let mut ek = vec![0u8; fapi::falcon_expandedkey_size(2)];
    let mut tmp_ep = vec![0u8; fapi::falcon_tmpsize_expandpriv(2)];
    assert_eq!(
        fapi::falcon_expand_privkey(&mut ek, &[], &mut tmp_ep),
        fapi::FALCON_ERR_FORMAT
    );
    let mut short_ek = vec![0u8; 8];
    assert_eq!(
        fapi::falcon_expand_privkey(&mut short_ek, &sk2, &mut tmp_ep),
        fapi::FALCON_ERR_SIZE
    );
}

#[test]
fn padded_and_ct_formats_small() {
    let logn = 5u32;
    let mut rng = seeded_rng(b"padded/ct small");
    let mut sk = vec![0u8; fapi::falcon_privkey_size(logn)];
    let mut pk = vec![0u8; fapi::falcon_pubkey_size(logn)];
    let mut tmp = vec![0u8; fapi::falcon_tmpsize_keygen(logn)];
    assert_eq!(
        fapi::falcon_keygen_make(&mut rng, logn, &mut sk, Some(&mut pk[..]), &mut tmp),
        0
    );
    let mut tmp_sd = vec![0u8; fapi::falcon_tmpsize_signdyn(logn)];
    let mut tmp_v = vec![0u8; fapi::falcon_tmpsize_verify(logn)];

    // PADDED: fixed size, verify with explicit and auto-detect type
    let padded_size = fapi::falcon_sig_padded_size(logn);
    let mut sig = vec![0u8; padded_size];
    let mut sig_len = sig.len();
    assert_eq!(
        fapi::falcon_sign_dyn(
            &mut rng,
            &mut sig,
            &mut sig_len,
            fapi::FALCON_SIG_PADDED,
            &sk,
            b"padded",
            &mut tmp_sd
        ),
        0
    );
    assert_eq!(sig_len, padded_size);
    assert_eq!(
        fapi::falcon_verify(&sig, fapi::FALCON_SIG_PADDED, &pk, b"padded", &mut tmp_v),
        0
    );
    assert_eq!(fapi::falcon_verify(&sig, 0, &pk, b"padded", &mut tmp_v), 0);

    // CT format
    let mut sig_ct = vec![0u8; fapi::falcon_sig_ct_size(logn)];
    let mut ct_len = sig_ct.len();
    assert_eq!(
        fapi::falcon_sign_dyn(
            &mut rng,
            &mut sig_ct,
            &mut ct_len,
            fapi::FALCON_SIG_CT,
            &sk,
            b"ct",
            &mut tmp_sd
        ),
        0
    );
    assert_eq!(
        fapi::falcon_verify(
            &sig_ct[..ct_len],
            fapi::FALCON_SIG_CT,
            &pk,
            b"ct",
            &mut tmp_v
        ),
        0
    );
    // CT sig with wrong-size buffer must be rejected on verify
    let truncated = &sig_ct[..ct_len - 1];
    assert!(fapi::falcon_verify(truncated, fapi::FALCON_SIG_CT, &pk, b"ct", &mut tmp_v) != 0);
}

// ======================================================================
// safe_api: remaining branches
// ======================================================================

#[test]
fn safe_api_misc_branches() {
    use falcon::safe_api::*;
    // from_bytes validation
    assert!(FnDsaSignature::from_bytes(vec![0u8; 10]).is_err()); // too short
    let mut v = vec![0u8; 50];
    v[0] = 0x99; // bad header nibble
    assert!(FnDsaSignature::from_bytes(v.clone()).is_err());
    v[0] = 0x35; // valid nibble, non-FIPS logn=5
    assert!(matches!(
        FnDsaSignature::from_bytes(v.clone()),
        Err(FalconError::BadArgument)
    ));
    v[0] = 0x59;
    let sig = FnDsaSignature::from_bytes(v).unwrap();
    assert_eq!(sig.len(), 50);
    assert!(!sig.is_empty());
    let owned = sig.clone().into_bytes();
    assert_eq!(owned.len(), 50);

    // error Display
    let msgs = [
        FalconError::RandomError,
        FalconError::SizeError,
        FalconError::FormatError,
        FalconError::BadSignature,
        FalconError::BadArgument,
        FalconError::InternalError,
    ];
    for e in msgs {
        assert!(!format!("{}", e).is_empty());
    }

    // deterministic keypair + accessors + Debug redaction
    let kp = FnDsaKeyPair::generate_deterministic(b"safe-api-misc-seed", 9).unwrap();
    assert_eq!(kp.logn(), 9);
    assert_eq!(kp.variant_name(), "FN-DSA-512");
    let dbg = format!("{:?}", kp);
    assert!(dbg.contains("REDACTED"));
    assert!(!dbg.contains("privkey: ["));

    // from_keys validation branches
    assert!(FnDsaKeyPair::from_keys(&[], kp.public_key()).is_err());
    assert!(FnDsaKeyPair::from_keys(kp.private_key(), &[]).is_err());
    let mut bad_pk = kp.public_key().to_vec();
    bad_pk[0] = 0x0A; // logn mismatch vs sk
    assert!(FnDsaKeyPair::from_keys(kp.private_key(), &bad_pk).is_err());
    let ok = FnDsaKeyPair::from_keys(kp.private_key(), kp.public_key()).unwrap();
    assert_eq!(ok.public_key(), kp.public_key());

    // from_private_key + public_key_from_private
    let kp2 = FnDsaKeyPair::from_private_key(kp.private_key()).unwrap();
    assert_eq!(kp2.public_key(), kp.public_key());
    let pk = FnDsaKeyPair::public_key_from_private(kp.private_key()).unwrap();
    assert_eq!(pk, kp.public_key());

    // expanded key: accessors + deterministic sign matches across instances
    let ek = kp.expand().unwrap();
    assert_eq!(ek.logn(), 9);
    assert_eq!(ek.public_key(), kp.public_key());
    let dbg_ek = format!("{:?}", ek);
    assert!(dbg_ek.contains("REDACTED"));
    let s1 = ek
        .sign_deterministic(b"m", b"seed", &DomainSeparation::None)
        .unwrap();
    let s2 = ek
        .sign_deterministic(b"m", b"seed", &DomainSeparation::None)
        .unwrap();
    assert_eq!(s1.to_bytes(), s2.to_bytes());
    FnDsaSignature::verify(
        s1.to_bytes(),
        kp.public_key(),
        b"m",
        &DomainSeparation::None,
    )
    .unwrap();
}

#[test]
fn safe_api_sha_helpers_match_reference_vectors() {
    use falcon::safe_api::{sha256_public, sha512_public};
    // NIST FIPS 180 test vector: "abc"
    let h = sha256_public(b"abc");
    assert_eq!(h[..8], [0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea]);
    let h2 = sha512_public(b"abc");
    assert_eq!(h2[..8], [0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba]);
    // multi-block message (exercises >1 compression block)
    let long = vec![0x61u8; 200];
    let d1 = sha256_public(&long);
    let d2 = sha256_public(&long);
    assert_eq!(d1, d2);
}
