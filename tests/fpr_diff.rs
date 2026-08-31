// The oracle polynomial below is transcribed verbatim from the reference
// implementation; the extra digits are part of the constants.
#![allow(clippy::excessive_precision)]

//! Differential tests for the floating-point backends.
//!
//! Every `Fpr` operation is compared, bit for bit, against the same
//! operation performed with native `f64` arithmetic. Under the default
//! backend this is a tautology; under `--features fpemu` it is the proof
//! that the branchless integer backend implements IEEE-754 binary64
//! round-to-nearest-even exactly, which is what keeps the KAT vectors —
//! and therefore FIPS 206 compliance — valid in both builds.

use falcon::fpr::*;

/// xorshift64*; test-local so the tests do not depend on the crate PRNG.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A finite, normal `f64` with a biased exponent in `lo..hi`.
    ///
    /// `trailing` occasionally clears low mantissa bits, which is what makes
    /// exact rounding ties (the hard case for round-to-nearest-even) show up
    /// often enough to be tested.
    fn f64_in(&mut self, lo: u64, hi: u64) -> f64 {
        let r = self.next();
        let sign = r & 1;
        let exp = lo + (self.next() % (hi - lo));
        let mut mant = self.next() & ((1u64 << 52) - 1);
        let trailing = self.next() % 4;
        if trailing != 0 {
            let t = self.next() % 53;
            mant &= !((1u64 << t) - 1);
        }
        f64::from_bits((sign << 63) | (exp << 52) | mant)
    }
}

/// Values that exercise the edges: signed zeros, unit values, powers of two
/// and mantissas that are all-ones or one-bit.
fn edge_values() -> Vec<f64> {
    let mut v = vec![
        0.0,
        -0.0,
        1.0,
        -1.0,
        0.5,
        2.0,
        -2.0,
        3.0,
        12289.0,
        1.0 / 12289.0,
        4503599627370496.0,    // 2^52
        9007199254740992.0,    // 2^53
        9223372036854775808.0, // 2^63
        1.7976931348623157e100,
        2.2250738585072014e-100,
        0.999999999999999888977698, // 1 - 2^-53
        1.0000000000000002,         // 1 + 2^-52
    ];
    for e in [-60i32, -30, -1, 0, 1, 30, 60] {
        v.push(libm_pow2(e));
        v.push(-libm_pow2(e));
        v.push(libm_pow2(e) * 1.5);
    }
    v
}

fn libm_pow2(e: i32) -> f64 {
    f64::from_bits(((1023 + e) as u64) << 52)
}

fn check(name: &str, got: Fpr, want: f64, args: &[f64]) {
    let g = got.to_f64();
    assert_eq!(
        g.to_bits(),
        want.to_bits(),
        "{name}{args:?}: got {g:?} ({:#018x}), want {want:?} ({:#018x})",
        g.to_bits(),
        want.to_bits()
    );
}

#[test]
fn diff_add_sub() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    let edges = edge_values();

    for a in &edges {
        for b in &edges {
            check("add", fpr_add(Fpr::new(*a), Fpr::new(*b)), a + b, &[*a, *b]);
            check("sub", fpr_sub(Fpr::new(*a), Fpr::new(*b)), a - b, &[*a, *b]);
        }
    }

    for _ in 0..300_000 {
        // Same exponent window: maximal cancellation and tie pressure.
        let a = rng.f64_in(1000, 1060);
        let b = rng.f64_in(1000, 1060);
        check("add", fpr_add(Fpr::new(a), Fpr::new(b)), a + b, &[a, b]);
        check("sub", fpr_sub(Fpr::new(a), Fpr::new(b)), a - b, &[a, b]);

        // Wide exponent gap: alignment and sticky-bit handling.
        let a = rng.f64_in(900, 1150);
        let b = rng.f64_in(900, 1150);
        check("add", fpr_add(Fpr::new(a), Fpr::new(b)), a + b, &[a, b]);
        check("sub", fpr_sub(Fpr::new(a), Fpr::new(b)), a - b, &[a, b]);

        // x + (-x), and near-equal magnitudes.
        check("add", fpr_add(Fpr::new(a), Fpr::new(-a)), a + -a, &[a, -a]);
        let c = f64::from_bits(a.to_bits() ^ 1);
        check("sub", fpr_sub(Fpr::new(a), Fpr::new(c)), a - c, &[a, c]);
    }
}

#[test]
fn diff_mul_div_sqrt() {
    let mut rng = Rng(0xDEAD_BEEF_CAFE_0001);
    let edges = edge_values();

    for a in &edges {
        for b in &edges {
            check("mul", fpr_mul(Fpr::new(*a), Fpr::new(*b)), a * b, &[*a, *b]);
            if *b != 0.0 {
                check("div", fpr_div(Fpr::new(*a), Fpr::new(*b)), a / b, &[*a, *b]);
            }
        }
        if *a >= 0.0 {
            check("sqrt", fpr_sqrt(Fpr::new(*a)), a.sqrt(), &[*a]);
        }
        check("sqr", fpr_sqr(Fpr::new(*a)), a * a, &[*a]);
        check("neg", fpr_neg(Fpr::new(*a)), -a, &[*a]);
        check("half", fpr_half(Fpr::new(*a)), a * 0.5, &[*a]);
        check("double", fpr_double(Fpr::new(*a)), a + a, &[*a]);
    }

    for _ in 0..300_000 {
        let a = rng.f64_in(950, 1100);
        let b = rng.f64_in(950, 1100);
        check("mul", fpr_mul(Fpr::new(a), Fpr::new(b)), a * b, &[a, b]);
        check("sqr", fpr_sqr(Fpr::new(a)), a * a, &[a]);
        check("div", fpr_div(Fpr::new(a), Fpr::new(b)), a / b, &[a, b]);
        check("inv", fpr_inv(Fpr::new(b)), 1.0 / b, &[b]);
        check("half", fpr_half(Fpr::new(a)), a * 0.5, &[a]);
        check("double", fpr_double(Fpr::new(a)), a + a, &[a]);
        check("neg", fpr_neg(Fpr::new(a)), -a, &[a]);

        let p = a.abs();
        check("sqrt", fpr_sqrt(Fpr::new(p)), p.sqrt(), &[p]);
    }
}

#[test]
fn diff_conversions() {
    let mut rng = Rng(0x0BAD_C0DE_0000_0007);

    for i in [
        0i64,
        1,
        -1,
        2,
        -2,
        12289,
        i32::MAX as i64,
        i32::MIN as i64,
        (1i64 << 52) - 1,
        1i64 << 52,
        (1i64 << 53) + 1,
        (1i64 << 62) + 12345,
        i64::MAX,
        i64::MIN,
    ] {
        check("of", fpr_of(i), i as f64, &[i as f64]);
    }

    for _ in 0..300_000 {
        let i = rng.next() as i64;
        check("of", fpr_of(i), i as f64, &[i as f64]);
        check("of", fpr_of(i >> 20), (i >> 20) as f64, &[]);

        // rint / floor / trunc, on values that fit comfortably in i64.
        let x = rng.f64_in(1000, 1085);
        assert_eq!(
            fpr_rint(Fpr::new(x)),
            x.round_ties_even() as i64,
            "rint({x})"
        );
        assert_eq!(fpr_floor(Fpr::new(x)), x.floor() as i64, "floor({x})");
        assert_eq!(fpr_trunc(Fpr::new(x)), x.trunc() as i64, "trunc({x})");

        // Fractional values, where the rounding mode actually shows.
        let y = rng.f64_in(1010, 1030);
        assert_eq!(
            fpr_rint(Fpr::new(y)),
            y.round_ties_even() as i64,
            "rint({y})"
        );
        assert_eq!(fpr_floor(Fpr::new(y)), y.floor() as i64, "floor({y})");
        assert_eq!(fpr_trunc(Fpr::new(y)), y.trunc() as i64, "trunc({y})");

        // Exact halves: the ties-to-even path.
        let h = (rng.next() % 4096) as f64 - 2048.0 + 0.5;
        assert_eq!(
            fpr_rint(Fpr::new(h)),
            h.round_ties_even() as i64,
            "rint({h})"
        );
    }

    for x in edge_values() {
        if x.abs() < 4.611686018427388e18 {
            assert_eq!(
                fpr_rint(Fpr::new(x)),
                x.round_ties_even() as i64,
                "rint({x})"
            );
            assert_eq!(fpr_floor(Fpr::new(x)), x.floor() as i64, "floor({x})");
            assert_eq!(fpr_trunc(Fpr::new(x)), x.trunc() as i64, "trunc({x})");
        }
    }
}

#[test]
fn diff_compare() {
    let mut rng = Rng(0xFEED_FACE_1234_5678);
    let edges = edge_values();

    for a in &edges {
        for b in &edges {
            assert_eq!(
                fpr_lt(Fpr::new(*a), Fpr::new(*b)),
                (a < b) as i32,
                "lt({a}, {b})"
            );
        }
    }

    for _ in 0..300_000 {
        let a = rng.f64_in(900, 1150);
        let b = rng.f64_in(900, 1150);
        assert_eq!(
            fpr_lt(Fpr::new(a), Fpr::new(b)),
            (a < b) as i32,
            "lt({a},{b})"
        );
        assert_eq!(fpr_lt(Fpr::new(a), Fpr::new(a)), 0, "lt({a},{a})");
        assert_eq!(fpr_lt(Fpr::new(-a), Fpr::new(a)), (-a < a) as i32);
    }
}

/// `fpr_expm_p63` is the sampler's Bernoulli core: a difference here would
/// change signatures, so it is checked against the same polynomial
/// evaluated in native `f64`.
#[test]
fn diff_expm_p63() {
    let mut rng = Rng(0x5EED_0000_0BAD_BEEF);

    fn oracle(x: f64, ccs: f64) -> u64 {
        let d = x;
        let mut y: f64 = 0.000000002073772366009083061987;
        y = 0.000000025299506379442070029551 - y * d;
        y = 0.000000275607356160477811864927 - y * d;
        y = 0.000002755586350219122514855659 - y * d;
        y = 0.000024801566833585381209939524 - y * d;
        y = 0.000198412739277311890541063977 - y * d;
        y = 0.001388888894063186997887560103 - y * d;
        y = 0.008333333327800835146903501993 - y * d;
        y = 0.041666666666110491190622155955 - y * d;
        y = 0.166666666666984014666397229121 - y * d;
        y = 0.500000000000019206858326015208 - y * d;
        y = 0.999999999999994892974086724280 - y * d;
        y = 1.000000000000000000000000000000 - y * d;
        y *= ccs;
        (y * 9223372036854775808.0) as u64
    }

    // The sampler calls this with 0 <= x <= ln 2 and ccs in (0, 1].
    for _ in 0..200_000 {
        let x = (rng.next() >> 11) as f64 / (1u64 << 53) as f64 * core::f64::consts::LN_2;
        let ccs = (rng.next() >> 11) as f64 / (1u64 << 53) as f64;
        assert_eq!(
            fpr_expm_p63(Fpr::new(x), Fpr::new(ccs)),
            oracle(x, ccs),
            "expm_p63({x}, {ccs})"
        );
    }

    for x in [0.0, core::f64::consts::LN_2, 0.25, 0.5] {
        for ccs in [1.0, 0.5, 0.9999999, 1e-9] {
            assert_eq!(
                fpr_expm_p63(Fpr::new(x), Fpr::new(ccs)),
                oracle(x, ccs),
                "expm_p63({x}, {ccs})"
            );
        }
    }
}

/// Pin the documented deviations of the emulated backend.
///
/// These are the only inputs where `fpemu` deliberately differs from the
/// hardware. They are unreachable from Falcon, but pinning them means a
/// future change to the rounding or clamping logic has to be deliberate
/// rather than silent — and it keeps the module documentation honest.
#[cfg(feature = "fpemu")]
#[test]
fn documented_deviations_from_ieee() {
    // A product that IEEE rounds *up* to the smallest normal is clamped to
    // zero, because the flush happens before rounding.
    let a = Fpr::new(f64::from_bits(0x1E00_0000_0000_0000));
    let b = Fpr::new(f64::from_bits(0x21FF_FFFF_FFFF_FFFF));
    assert_eq!(
        fpr_mul(a, b).to_f64().to_bits(),
        0,
        "expected the pre-rounding flush to zero"
    );
    assert_eq!(
        (a.to_f64() * b.to_f64()).to_bits(),
        0x0010_0000_0000_0000,
        "hardware rounds this up to the smallest normal"
    );

    // Subnormal operands are zero on entry.
    let sub = Fpr::new(f64::from_bits(0x0000_0000_0001_0001));
    assert_eq!(fpr_add(sub, sub).to_f64().to_bits(), 0);
    assert_eq!(fpr_mul(sub, Fpr::new(1.0)).to_f64().to_bits(), 0);

    // Division by zero yields zero rather than an infinity.
    assert_eq!(fpr_div(Fpr::new(1.0), Fpr::new(0.0)).to_f64().to_bits(), 0);
}
