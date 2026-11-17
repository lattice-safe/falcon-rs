#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use core::ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign};

use zeroize::DefaultIsZeroes;

// ========================================================================
// Floating-point operations
// ========================================================================

// The FLR type represents an IEEE-754:2008 'binary64' value, or more
// specifically a subset of such values.
//
//    A value is conceptually the packing of three binary field in a
//    64-bit word, equal to:
//        s*2^64 + e*2^52 + m
//    with:
//      field  size  meaning
//        s      1   sign bit (0 = positive, 1 = negative)
//        e     11   encoded exponent
//        m     52   encoded mantissa
//    If e = 0 then the value is either a zero or a denormal. If e = 2047
//    then the value is either an infinite or a NaN (not-a-number). In all
//    other cases (1 <= e <= 2046), the represented real number is equal to:
//        (-1)^s * 2^(e - 1023) * (1 + m/2^52)
//
//    In FN-DSA, denormals, infinites and NaNs are not used, and need not
//    be supported. It has been demonstrated that all non-zero values
//    are in [2^(−476), 2^27*(2^52 + 605182448294568)] (in absolute value),
//    thus the exponent field e is always in the [547, 1102] range, except
//    for zero. See: https://eprint.iacr.org/2024/321
//
//    There are nominally two zeros, a positive zero and a negative
//    zero, depending on the sign bit.
//
//    FLR values are meant for in-memory use only; the packing into a
//    64-bit word and then conversion to bytes is meant only for test
//    purposes. Nevertheless, each FLR instance should strive to use
//    relatively little RAM, for better performance.
//
//    All implemented operations should follow the strict IEEE-754 rules,
//    with rounding policy roundTiesToEven:
//      - The operation is (conceptually) computed with infinite precision.
//      - The result is rounded to the nearest representable value.
//      - If the result is not representable exactly, and the two nearest
//        representable values are equidistant from the result, then the
//        "even" representable value (the one for which the m field is an
//        even integer) is used.
//    These rules leave no room for ambiguousness, i.e. for every operation
//    there is a single correctly rounded output. Note also that rounding
//    of the absolute value yields the same result as taking the absolute
//    value of the rounding, i.e. we can round mantissas independently of
//    the sign bit.
//
//    The rounding rules imply that additions and multiplications are
//    not associative. The order of operations thus matters for full
//    reproducibility, and should not be changed. Similarly, if
//    computations are internally performed with a higher precision,
//    rounding should still be enforced after each operation; a
//    fused-multiply-add operation, if supported by a hardware platform,
//    shall not be used. Moreover, operations are over secret values and
//    thus should take care not to leak information through
//    side-channels, in particular timing.

// Default: hardware binary64 arithmetic (strict IEEE-754, no FMA).
// With the `fpemu` feature: integer-only emulation, which removes the
// floating-point timing side channel. Both produce bit-identical results.
#[cfg(not(feature = "fpemu"))]
#[path = "flr_native.rs"]
mod backend;

#[cfg(feature = "fpemu")]
#[path = "flr_emu.rs"]
mod backend;

pub(crate) use backend::FLR;

impl Default for FLR {
    fn default() -> Self {
        FLR::ZERO
    }
}

impl DefaultIsZeroes for FLR {}

impl Add<FLR> for FLR {
    type Output = FLR;

    #[inline(always)]
    fn add(self, other: FLR) -> FLR {
        let mut r = self;
        r.set_add(other);
        r
    }
}

impl AddAssign<FLR> for FLR {
    #[inline(always)]
    fn add_assign(&mut self, other: FLR) {
        self.set_add(other);
    }
}

impl Div<FLR> for FLR {
    type Output = FLR;

    #[inline(always)]
    fn div(self, other: FLR) -> FLR {
        let mut r = self;
        r.set_div(other);
        r
    }
}

impl Mul<FLR> for FLR {
    type Output = FLR;

    #[inline(always)]
    fn mul(self, other: FLR) -> FLR {
        let mut r = self;
        r.set_mul(other);
        r
    }
}

impl MulAssign<FLR> for FLR {
    #[inline(always)]
    fn mul_assign(&mut self, other: FLR) {
        self.set_mul(other);
    }
}

impl Neg for FLR {
    type Output = FLR;

    #[inline(always)]
    fn neg(self) -> FLR {
        let mut r = self;
        r.set_neg();
        r
    }
}

impl Sub<FLR> for FLR {
    type Output = FLR;

    #[inline(always)]
    fn sub(self, other: FLR) -> FLR {
        let mut r = self;
        r.set_sub(other);
        r
    }
}

impl SubAssign<FLR> for FLR {
    #[inline(always)]
    fn sub_assign(&mut self, other: FLR) {
        self.set_sub(other);
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::shake::{Shake256 as SHAKE256, Shake256Prng as SHAKE256_PRNG};

    fn rand_u64(rng: &mut SHAKE256_PRNG) -> u64 {
        let mut x = 0;
        for _ in 0..4 {
            x = (x << 16) | (rng.next_u16() as u64);
        }
        x
    }

    fn rand_fp(rng: &mut SHAKE256_PRNG) -> FLR {
        // For tests, we randomize sign, mantissa and exponent, but we
        // force the exponent to be in [-80,+80] so that we do not get
        // overflows or underflows. We thus force the _encoded_ exponent
        // into [943,1103].
        let m = rand_u64(rng);
        let e = (((m >> 52) & 0x7FF) % 161) + 943;
        let m = (m & 0x800FFFFFFFFFFFFF) | (e << 52);
        FLR::decode(&m.to_le_bytes()).unwrap()
    }

    #[test]
    fn test_spec() {
        let mut sh = SHAKE256::new();
        sh.inject(&FLR::ZERO.encode());
        sh.inject(&(-FLR::ZERO).encode());
        sh.inject(&FLR::ZERO.half().encode());
        sh.inject(&FLR::ZERO.double().encode());
        let zero = FLR::ZERO;
        let nzero = -FLR::ZERO;
        sh.inject(&(zero + zero).encode());
        sh.inject(&(zero + nzero).encode());
        sh.inject(&(nzero + zero).encode());
        sh.inject(&(nzero + nzero).encode());
        sh.inject(&(zero - zero).encode());
        sh.inject(&(zero - nzero).encode());
        sh.inject(&(nzero - zero).encode());
        sh.inject(&(nzero - nzero).encode());

        for e in -60..=60 {
            for i in -5..=5 {
                let a = FLR::from_i64((1i64 << 53) + i);
                sh.inject(&a.encode());
                for j in -5..=5 {
                    let b = FLR::scaled((1i64 << 53) + j, e);
                    sh.inject(&b.encode());
                    sh.inject(&(a + b).encode());
                    let a = a.neg();
                    sh.inject(&(a + b).encode());
                    let b = b.neg();
                    sh.inject(&(a + b).encode());
                    let a = a.neg();
                    sh.inject(&(a + b).encode());
                }
            }
        }

        let mut rng = SHAKE256_PRNG::new(&b"fpemu"[..]);
        for ctr in 1..=65536 {
            let j = (rand_u64(&mut rng) as i64) >> (ctr & 63);
            assert!(j != -9223372036854775808);
            let a = FLR::from_i64(j);
            sh.inject(&a.encode());

            let sc = ((rng.next_u16() as i32) & 0xFF) - 128;
            sh.inject(&FLR::scaled(j, sc).encode());

            let j = rand_u64(&mut rng) as i64;
            let a = FLR::scaled(j, -8);
            sh.inject(&a.rint().to_le_bytes());

            let a = FLR::scaled(j, -52);
            sh.inject(&a.trunc().to_le_bytes());
            sh.inject(&a.floor().to_le_bytes());

            let a = rand_fp(&mut rng);
            let b = rand_fp(&mut rng);

            sh.inject(&(a + b).encode());
            sh.inject(&(b + a).encode());
            sh.inject(&(a + zero).encode());
            sh.inject(&(zero + a).encode());
            sh.inject(&(a + (-a)).encode());
            sh.inject(&((-a) + a).encode());

            sh.inject(&(a - b).encode());
            sh.inject(&(b - a).encode());
            sh.inject(&(a - zero).encode());
            sh.inject(&(zero - a).encode());
            sh.inject(&(a - a).encode());

            sh.inject(&(-a).encode());
            sh.inject(&a.half().encode());
            sh.inject(&a.double().encode());

            sh.inject(&(a * b).encode());
            sh.inject(&(b * a).encode());
            sh.inject(&(a * zero).encode());
            sh.inject(&(zero * a).encode());

            sh.inject(&(a / b).encode());

            sh.inject(&a.abs().sqrt().encode());
        }

        // Reference hash was computed on 64-bit x86, where all
        // operations have been verified by comparing with the native
        // SSE2 support.
        let mut buf = [0u8; 32];
        sh.flip();
        sh.extract(&mut buf);
        assert!(
            buf[..]
                == hex::decode("5948a632a0797439aa8e7ed9abc554512a9374812057684565f60e6a42702994")
                    .unwrap()
        );
    }
}

/* unused
   This can be used for debug purposes if the test above mismatches.
   This code uses libm, which must thus be added in the dev-dependencies.

// On 64-bit x86, we compare the implementation with the native support
// for the f64 type, which is backed by SSE2 and implements strict
// IEEE-754:2008 rules with roundTiesToEven policy.
*/

#[cfg(test)]
mod codec_tests {
    use super::FLR;

    #[test]
    fn decode_needs_eight_bytes() {
        assert!(FLR::decode(&[0u8; 7]).is_none());
        assert!(FLR::decode(&[0u8; 9]).is_none());
        assert_eq!(FLR::decode(&[0u8; 8]).unwrap().encode(), [0u8; 8]);
    }
}
