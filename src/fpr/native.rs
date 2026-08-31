// These constants are ported verbatim from the C reference implementation
// and must remain exact for bit-for-bit NIST KAT compatibility.
#![allow(clippy::approx_constant)]

//! Native floating-point backend (`FPNATIVE`).
//!
//! `Fpr` wraps a native `f64`; every operation maps to a hardware
//! floating-point instruction. This is the default backend: it is the
//! fastest, and it matches the C reference in `FPNATIVE` mode.
//!
//! Timing caveat: floating-point instruction timing is data-dependent on
//! some architectures. Enable the `fpemu` feature for the branchless
//! integer backend (`fpr::emu`) when that matters.

use super::{FPR_PTWO63, FPR_ZERO};

/// Floating-point representation type (wrapping `f64`).
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct Fpr(pub f64);

impl Fpr {
    #[inline(always)]
    pub const fn new(v: f64) -> Self {
        Fpr(v)
    }

    /// The value as an `f64`. Mirrors `fpr::emu::Fpr::to_f64` so that
    /// backend-agnostic code (and the differential tests) can convert.
    #[inline(always)]
    pub const fn to_f64(self) -> f64 {
        self.0
    }
}

/// Wiping a value is a plain overwrite of the underlying f64: an `Fpr` has
/// no indirection, so this is sufficient to clear the secret it held.
impl zeroize::Zeroize for Fpr {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Default for Fpr {
    fn default() -> Self {
        FPR_ZERO
    }
}

// ======================================================================
// Arithmetic operations
// ======================================================================

#[inline(always)]
pub fn fpr_of(i: i64) -> Fpr {
    Fpr(i as f64)
}

#[inline(always)]
pub fn fpr_add(x: Fpr, y: Fpr) -> Fpr {
    Fpr(x.0 + y.0)
}

#[inline(always)]
pub fn fpr_sub(x: Fpr, y: Fpr) -> Fpr {
    Fpr(x.0 - y.0)
}

#[inline(always)]
pub fn fpr_neg(x: Fpr) -> Fpr {
    Fpr(-x.0)
}

#[inline(always)]
pub fn fpr_half(x: Fpr) -> Fpr {
    Fpr(x.0 * 0.5)
}

#[inline(always)]
pub fn fpr_double(x: Fpr) -> Fpr {
    Fpr(x.0 + x.0)
}

#[inline(always)]
pub fn fpr_mul(x: Fpr, y: Fpr) -> Fpr {
    Fpr(x.0 * y.0)
}

#[inline(always)]
pub fn fpr_sqr(x: Fpr) -> Fpr {
    Fpr(x.0 * x.0)
}

#[inline(always)]
pub fn fpr_inv(x: Fpr) -> Fpr {
    Fpr(1.0 / x.0)
}

#[inline(always)]
pub fn fpr_div(x: Fpr, y: Fpr) -> Fpr {
    Fpr(x.0 / y.0)
}

#[inline(always)]
pub fn fpr_sqrt(x: Fpr) -> Fpr {
    Fpr(libm::sqrt(x.0))
}

#[inline(always)]
pub fn fpr_lt(x: Fpr, y: Fpr) -> i32 {
    if x.0 < y.0 {
        1
    } else {
        0
    }
}

#[inline(always)]
pub fn fpr_mulconst(x: Fpr, c: f64) -> Fpr {
    Fpr(x.0 * c)
}

/// Round to nearest integer (ties to even).
#[inline]
pub fn fpr_rint(x: Fpr) -> i64 {
    // Match the C FPNATIVE implementation exactly.
    let sx = (x.0 - 1.0) as i64;
    let tx = x.0 as i64;
    let rp = (x.0 + 4503599627370496.0) as i64 - 4503599627370496;
    let rn = (x.0 - 4503599627370496.0) as i64 + 4503599627370496;

    let m = sx >> 63;
    let rn = rn & m;
    let rp = rp & !m;

    let ub = (tx as u64 >> 52) as u32;
    let m = -(((((ub.wrapping_add(1)) & 0xFFF).wrapping_sub(2)) >> 31) as i64);
    let rp = rp & m;
    let rn = rn & m;
    let tx = tx & !m;

    tx | rn | rp
}

/// Floor function.
#[inline]
pub fn fpr_floor(x: Fpr) -> i64 {
    let r = x.0 as i64;
    r - (if x.0 < (r as f64) { 1 } else { 0 })
}

/// Truncate toward zero.
#[inline]
pub fn fpr_trunc(x: Fpr) -> i64 {
    x.0 as i64
}

/// Compute exp(-x) * ccs * 2^63, with |x| <= ln 2.
/// Polynomial approximation from FACCT.
#[inline]
pub fn fpr_expm_p63(x: Fpr, ccs: Fpr) -> u64 {
    let d = x.0;
    let mut y: f64;
    y = 0.000000002073772366009083061987;
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
    y *= ccs.0;
    (y * FPR_PTWO63.0) as u64
}

#[cfg(test)]
mod mulconst_tests {
    use super::*;

    /// `fpr_mulconst` scales by a plain `f64` constant, checked against the
    /// hardware product.
    #[test]
    fn mulconst_matches_hardware_product() {
        for (x, c) in [(1.5f64, 2.0f64), (-3.25, 0.5), (0.0, 7.0), (1e100, 1e-100)] {
            assert_eq!(
                fpr_mulconst(Fpr::new(x), c).to_f64().to_bits(),
                (x * c).to_bits(),
                "fpr_mulconst({x}, {c})"
            );
        }
    }
}
