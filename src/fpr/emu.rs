//! Emulated floating-point backend (`FPEMU`), enabled by the `fpemu` feature.
//!
//! `Fpr` holds the IEEE-754 binary64 *bit pattern* of the value in a `u64`,
//! and every operation is implemented with branchless integer arithmetic:
//! no data-dependent branch, no data-dependent memory access, and no
//! hardware floating-point instruction is executed. Timing therefore does
//! not depend on the values being processed, which removes the
//! floating-point side-channel surface of the `fpr::native` backend.
//!
//! Semantics are IEEE-754 binary64 with round-to-nearest, ties-to-even, so
//! results are bit-for-bit identical to the native backend — that is what
//! keeps the NIST / FIPS 206 KAT vectors passing. The deviations below are
//! inherited from the C reference's `FPEMU` mode, and all of them sit
//! outside the range Falcon ever reaches:
//!
//! * Anything smaller than the smallest normal, `2^-1022`, becomes zero.
//!   The clamp happens *before* rounding (see [`fpr_new`]), so it is
//!   marginally wider than "subnormals flush to zero": a true result in
//!   `[2^-1022 * (1 - 2^-55), 2^-1022)` would round up to the smallest
//!   normal under IEEE, and here becomes zero instead. Verified example:
//!   `fpr_mul(0x1E00000000000000, 0x21FFFFFFFFFFFFFF)` is `2^-1022` on
//!   hardware and zero here.
//! * Infinities and NaN are not supported: a result at or above `2^1024`
//!   wraps its exponent instead of becoming infinity, `fpr_div` by zero
//!   yields zero, and `fpr_sqrt` expects a non-negative operand.
//! * `fpr_trunc`, `fpr_floor` and `fpr_rint` are defined for `|x| < 2^63`,
//!   as in the C reference. Beyond that they wrap modulo `2^64` where the
//!   native backend's `as i64` saturates.
//!
//! Timing: on aarch64 and x86_64 every operation compiles to straight-line
//! code, the only branches being the fixed trip counts of the division,
//! square-root and `expm_p63` loops. Two hardware assumptions remain on
//! other targets: `leading_zeros` (see [`normalize_top`]) must not be a
//! variable-time libcall, and the `u128` multiply in [`fpr_mul`] must not
//! lower to an early-terminating multiplier, as found on some small cores.
//!
//! Ported from fpr.h / fpr.c (`FALCON_FPEMU`).

use super::{FPR_ONE, FPR_PTWO63, FPR_ZERO};

/// Floating-point representation type (IEEE-754 binary64 bit pattern).
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct Fpr(pub u64);

impl Fpr {
    /// Build an `Fpr` from an `f64` literal. `const` so that the shared
    /// constant tables in [`super`] are compiled to bit patterns.
    #[inline(always)]
    pub const fn new(v: f64) -> Self {
        Fpr(v.to_bits())
    }

    /// The value as an `f64`. Used by tests and by callers that need to
    /// interoperate with native floating point; performs no arithmetic.
    #[inline(always)]
    pub const fn to_f64(self) -> f64 {
        f64::from_bits(self.0)
    }
}

/// Wiping a value is a plain overwrite of the underlying u64: an `Fpr` has
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
// Branchless helpers
// ======================================================================

/// 1 if `x != 0`, else 0.
#[inline(always)]
fn nz(x: u64) -> u64 {
    (x | x.wrapping_neg()) >> 63
}

/// Right shift by `n` (0..=63) without a variable-latency 64-bit shift on
/// 32-bit targets: shift by 32 conditionally, then by `n & 31`.
#[inline(always)]
fn ursh(x: u64, n: i32) -> u64 {
    let m = ((n >> 5) as u64).wrapping_neg();
    let x = x ^ ((x ^ (x >> 32)) & m);
    x >> (n & 31)
}

/// Left shift by `n` (0..=63), same technique as [`ursh`].
#[inline(always)]
fn ulsh(x: u64, n: i32) -> u64 {
    let m = ((n >> 5) as u64).wrapping_neg();
    let x = x ^ ((x ^ (x << 32)) & m);
    x << (n & 31)
}

/// `max(v, 0)` for `i32`, branchless.
#[inline(always)]
fn pos(v: i32) -> i32 {
    v & !(v >> 31)
}

/// `min(v, 63)` for a non-negative `i32`, branchless.
#[inline(always)]
fn cap63(v: i32) -> i32 {
    let big = (63 - v) >> 31; // -1 if v > 63, else 0
    (v & !big) | (63 & big)
}

/// Normalize `a` so that its top bit is bit 63; returns the shifted value
/// and the shift count. For `a == 0` returns `(0, 63)`.
///
/// Uses a count-leading-zeros instruction only where the target guarantees
/// one with fixed latency: `clz` on aarch64, and `lzcnt` on x86_64 when the
/// feature is enabled. Baseline x86-64 has neither, and `leading_zeros()`
/// there lowers to `bsr`, whose latency is data-dependent on some
/// implementations — so that case takes [`normalize_top_portable`], which is
/// branchless by construction rather than by hardware assumption. The two
/// paths are checked against each other in this module's tests.
#[inline(always)]
fn normalize_top(a: u64) -> (u64, i32) {
    #[cfg(any(
        target_arch = "aarch64",
        all(target_arch = "x86_64", target_feature = "lzcnt")
    ))]
    {
        // `a | 1` reproduces the portable version's answer for a == 0.
        let k = (a | 1).leading_zeros() as i32;
        (ulsh(a, k), k)
    }
    #[cfg(not(any(
        target_arch = "aarch64",
        all(target_arch = "x86_64", target_feature = "lzcnt")
    )))]
    {
        normalize_top_portable(a)
    }
}

/// Branchless normalization without a count-leading-zeros instruction: a
/// fixed six-step binary search, so the cost does not depend on `a`.
#[inline(always)]
fn normalize_top_portable(a: u64) -> (u64, i32) {
    let mut a = a;
    let mut k = 0i32;
    let mut sh = 32u32;
    while sh > 0 {
        let hi = a >> (64 - sh);
        let m = (nz(hi) ^ 1).wrapping_neg(); // all ones when the top `sh` bits are zero
        a = (a & !m) | ((a << sh) & m);
        k += (sh as i32) & (m as i32);
        sh >>= 1;
    }
    (a, k)
}

/// Assemble `(-1)^s * m * 2^e` into an IEEE-754 binary64 bit pattern.
///
/// `m` is a 55-bit significand in `[2^54, 2^55)` whose three low bits are
/// the guard / round / sticky bits, or 0 for a zero result. Rounding is
/// round-to-nearest, ties-to-even; values too small to be normal are
/// flushed to zero.
#[inline(always)]
fn fpr_new(s: i32, e: i32, m: u64) -> Fpr {
    // Bias the exponent; a negative biased exponent means the result is
    // below the smallest normal, which we clamp to zero by clearing the
    // significand. This happens before rounding, matching the C reference:
    // a value that IEEE would round *up* to the smallest normal becomes
    // zero here. See the deviations listed in the module docs.
    let mut e = e + 1076;
    let sub = ((e as u32) >> 31) as u64; // 1 if e < 0
    let m = m & sub.wrapping_sub(1);

    // A zero significand must carry a zero exponent field (sign is kept).
    let norm = (m >> 54) as i32; // 1 if m is normalized, 0 if m == 0
    e &= -norm;

    let x = (((s as u64) << 63) | (m >> 2)).wrapping_add((e as u32 as u64) << 52);

    // Round to nearest, ties to even: with (lsb, round, sticky) = m & 7,
    // increment for 011, 110 and 111.
    let f = (m & 7) as u32;
    Fpr(x.wrapping_add(((0xC8u32 >> f) & 1) as u64))
}

/// Split a bit pattern into sign, exponent and significand such that the
/// value is `(-1)^s * m * 2^e`, with `m` in `[2^52, 2^53)` for a normal
/// value and `m == 0` for zero (and for a flushed subnormal).
#[inline(always)]
fn decomp(x: u64) -> (i32, i32, u64) {
    let s = (x >> 63) as i32;
    let ef = ((x >> 52) & 0x7FF) as i32;
    let live = nz(ef as u64); // 0 for zero / subnormal, 1 for a normal value
    let m = ((x & ((1u64 << 52) - 1)) | (live << 52)) & live.wrapping_neg();
    (s, ef - 1075, m)
}

// ======================================================================
// Arithmetic operations
// ======================================================================

#[inline(always)]
pub fn fpr_of(i: i64) -> Fpr {
    fpr_scaled(i, 0)
}

/// Convert `i * 2^sc` to a floating-point value.
#[inline]
pub fn fpr_scaled(i: i64, sc: i32) -> Fpr {
    let s = ((i as u64) >> 63) as i32;
    // Absolute value, branchless (works for i64::MIN as well).
    let a = ((i as u64) ^ (s as u64).wrapping_neg()).wrapping_add(s as u64);

    // Normalize to bit 63, then keep 55 bits with a sticky bit.
    let (na, k) = normalize_top(a);
    let m = (na >> 9) | nz(na & 0x1FF);
    fpr_new(s, sc + 9 - k, m)
}

#[inline(always)]
pub fn fpr_neg(x: Fpr) -> Fpr {
    Fpr(x.0 ^ (1u64 << 63))
}

#[inline]
pub fn fpr_half(x: Fpr) -> Fpr {
    // Decrement the exponent field, then clamp zero and underflow.
    let t = x.0.wrapping_sub(1u64 << 52);
    let ef = ((t >> 52) & 0x7FF) as u64;
    // The subtraction borrowed (x was zero) iff the field is now 0x7FF.
    let borrow = ((ef + 1) >> 11) & 1;
    let live = nz(ef) & (borrow ^ 1);
    // Keep the sign when the result is zero: -0.0 halved is -0.0.
    Fpr((t & live.wrapping_neg()) | (x.0 & (1u64 << 63)))
}

#[inline]
pub fn fpr_double(x: Fpr) -> Fpr {
    // Increment the exponent field, unless the value is zero.
    let ef = (x.0 >> 52) & 0x7FF;
    Fpr(x.0.wrapping_add(nz(ef) << 52))
}

#[inline]
pub fn fpr_add(x: Fpr, y: Fpr) -> Fpr {
    let mut xb = x.0;
    let mut yb = y.0;

    // Order the operands so that |x| >= |y|; on equal magnitudes the
    // positive one comes first, which gives the IEEE sign for x + (-x).
    let absmask = (1u64 << 63) - 1;
    let za = (xb & absmask).wrapping_sub(yb & absmask);
    let lt = za >> 63; // 1 if |x| < |y|
    let eq = nz(za) ^ 1; // 1 if |x| == |y|
    let cs = lt | (eq & (xb >> 63));
    let sw = (xb ^ yb) & cs.wrapping_neg();
    xb ^= sw;
    yb ^= sw;

    let (sx, ex, mx) = decomp(xb);
    let (sy, ey, my) = decomp(yb);

    // Three guard bits below the significand.
    let xu = mx << 3;
    let yu = my << 3;
    let ex = ex - 3;
    let ey = ey - 3;

    // Align the smaller operand, collapsing the bits shifted out into a
    // sticky bit. |x| >= |y| guarantees cc >= 0.
    let cc = cap63(ex - ey);
    let low = yu & ((1u64 << cc) - 1);
    let yu = ursh(yu, cc) | nz(low);

    // Same signs: add magnitudes. Different signs: subtract (no borrow,
    // since |x| >= |y|).
    let sd = (sx ^ sy) as u64;
    let yv = (yu ^ sd.wrapping_neg()).wrapping_add(sd);
    let zu = xu.wrapping_add(yv);

    // Renormalize to a 55-bit significand, keeping the sticky bit.
    let (na, k) = normalize_top(zu);
    let m = (na >> 9) | nz(na & 0x1FF);
    fpr_new(sx, ex + 9 - k, m)
}

#[inline(always)]
pub fn fpr_sub(x: Fpr, y: Fpr) -> Fpr {
    fpr_add(x, fpr_neg(y))
}

#[inline]
pub fn fpr_mul(x: Fpr, y: Fpr) -> Fpr {
    let (sx, ex, mx) = decomp(x.0);
    let (sy, ey, my) = decomp(y.0);

    // 53 x 53 -> 106 bits; keep the top 55 plus a sticky bit.
    let z = (mx as u128) * (my as u128);
    let sticky = nz((z as u64) & ((1u64 << 50) - 1));
    let m0 = ((z >> 50) as u64) | sticky;

    // The product may span 56 bits; shift down by one, keeping sticky.
    let hi = (m0 >> 55) & 1;
    let mask = hi.wrapping_neg();
    let m = (m0 & !mask) | (((m0 >> 1) | (m0 & 1)) & mask);

    fpr_new(sx ^ sy, ex + ey + 50 + hi as i32, m)
}

#[inline(always)]
pub fn fpr_sqr(x: Fpr) -> Fpr {
    fpr_mul(x, x)
}

#[inline]
pub fn fpr_div(x: Fpr, y: Fpr) -> Fpr {
    let (sx, ex, mx) = decomp(x.0);
    let (sy, ey, my) = decomp(y.0);

    // Restoring long division, 56 quotient bits: q = floor(mx * 2^55 / my).
    // The loop count is fixed, and each step is branchless.
    let mut num = mx;
    let mut q: u64 = 0;
    let mut i = 0;
    while i < 56 {
        let b = (num.wrapping_sub(my) >> 63) ^ 1; // 1 if num >= my
        q = (q << 1) | b;
        num = num.wrapping_sub(my & b.wrapping_neg()) << 1;
        i += 1;
    }
    let m0 = (q | nz(num)) & nz(my).wrapping_neg(); // division by zero yields zero

    let hi = (m0 >> 55) & 1;
    let mask = hi.wrapping_neg();
    let m = (m0 & !mask) | (((m0 >> 1) | (m0 & 1)) & mask);

    fpr_new(sx ^ sy, ex - ey - 55 + hi as i32, m)
}

#[inline(always)]
pub fn fpr_inv(x: Fpr) -> Fpr {
    fpr_div(FPR_ONE, x)
}

/// Square root. The operand must be non-negative (as in the C reference).
#[inline]
pub fn fpr_sqrt(x: Fpr) -> Fpr {
    let (_, e, m) = decomp(x.0);
    // sqrt(-0.0) is -0.0; for any other operand the result is non-negative.
    let s = ((x.0 >> 63) & (nz(m) ^ 1)) as i32;

    // Make the exponent even so that the square root of the power of two
    // is exact, then scale so the integer square root has 55 bits.
    let odd = (e & 1) as u32;
    let m = m << odd;
    let e = e - odd as i32;
    let a = (m as u128) << 56;

    // Digit-by-digit square root: fixed 56 steps, branchless.
    let mut rem: u128 = 0;
    let mut root: u128 = 0;
    let mut i = 56i32;
    while i > 0 {
        i -= 1;
        root <<= 1;
        rem = (rem << 2) | ((a >> (2 * i)) & 3);
        let t = (root << 1) | 1;
        let ge = (rem.wrapping_sub(t) >> 127) ^ 1; // 1 if rem >= t
        root |= ge;
        rem = rem.wrapping_sub(t & 0u128.wrapping_sub(ge));
    }

    let sticky = nz((rem as u64) | ((rem >> 64) as u64));
    let mr = (root as u64) | sticky;
    fpr_new(s, (e >> 1) - 28, mr)
}

#[inline(always)]
pub fn fpr_mulconst(x: Fpr, c: f64) -> Fpr {
    fpr_mul(x, Fpr::new(c))
}

#[inline(always)]
pub fn fpr_lt(x: Fpr, y: Fpr) -> i32 {
    // For equal signs a signed comparison of the bit patterns matches the
    // value order (reversed when both are negative); when the signs differ
    // the sign bit alone decides.
    // Collapse -0.0 to +0.0: IEEE orders the two zeros as equal, while a
    // bare bit-pattern comparison would place -0.0 below +0.0.
    let absmask = (1u64 << 63) - 1;
    let xb = x.0 & nz(x.0 & absmask).wrapping_neg();
    let yb = y.0 & nz(y.0 & absmask).wrapping_neg();
    let sx = xb as i64;
    let sy = yb as i64;
    let sy = sy & !((sx ^ sy) >> 63);
    let cc0 = ((sx.wrapping_sub(sy) >> 63) & 1) as i32;
    let cc1 = ((sy.wrapping_sub(sx) >> 63) & 1) as i32;
    cc0 ^ ((cc0 ^ cc1) & ((xb & yb) >> 63) as i32)
}

/// Split off the integer part: returns the sign, the truncated magnitude,
/// the round bit and the sticky bit of the discarded fraction.
#[inline(always)]
fn int_parts(x: u64) -> (u64, u64, u64, u64) {
    let s = x >> 63;
    let (_, e, m) = decomp(x);

    let lsh = cap63(pos(e));
    let rsh = cap63(pos(-e));

    let ip = ulsh(ursh(m, rsh), lsh);

    // Round bit and sticky bit only exist when something was shifted out.
    let live = nz(rsh as u64);
    let below = (rsh - 1) & 63;
    let rb = (ursh(m, below) & 1) & live;
    let st = nz(m & ((1u64 << below) - 1)) & live;

    (s, ip, rb, st)
}

/// Truncate toward zero.
#[inline]
pub fn fpr_trunc(x: Fpr) -> i64 {
    let (s, ip, _, _) = int_parts(x.0);
    ((ip ^ s.wrapping_neg()).wrapping_add(s)) as i64
}

/// Truncate toward zero into a `u64` (operand must be non-negative).
#[inline]
fn fpr_trunc_u64(x: Fpr) -> u64 {
    int_parts(x.0).1
}

/// Floor function.
#[inline]
pub fn fpr_floor(x: Fpr) -> i64 {
    let (s, ip, rb, st) = int_parts(x.0);
    // Negative values with a non-zero fraction round away from zero.
    let ip = ip + (s & nz(rb | st));
    ((ip ^ s.wrapping_neg()).wrapping_add(s)) as i64
}

/// Round to nearest integer (ties to even).
#[inline]
pub fn fpr_rint(x: Fpr) -> i64 {
    let (s, ip, rb, st) = int_parts(x.0);
    let ip = ip + (rb & (st | (ip & 1)));
    ((ip ^ s.wrapping_neg()).wrapping_add(s)) as i64
}

/// Compute exp(-x) * ccs * 2^63, with |x| <= ln 2.
/// Polynomial approximation from FACCT — the same evaluation order as the
/// native backend, so the two agree bit for bit.
#[inline]
pub fn fpr_expm_p63(x: Fpr, ccs: Fpr) -> u64 {
    // Compile-time bit patterns: no floating-point value is ever converted
    // at run time.
    const C: [Fpr; 12] = [
        Fpr::new(0.000000025299506379442070029551),
        Fpr::new(0.000000275607356160477811864927),
        Fpr::new(0.000002755586350219122514855659),
        Fpr::new(0.000024801566833585381209939524),
        Fpr::new(0.000198412739277311890541063977),
        Fpr::new(0.001388888894063186997887560103),
        Fpr::new(0.008333333327800835146903501993),
        Fpr::new(0.041666666666110491190622155955),
        Fpr::new(0.166666666666984014666397229121),
        Fpr::new(0.500000000000019206858326015208),
        Fpr::new(0.999999999999994892974086724280),
        Fpr::new(1.000000000000000000000000000000),
    ];

    let mut y = Fpr::new(0.000000002073772366009083061987);
    let mut i = 0;
    while i < C.len() {
        y = fpr_sub(C[i], fpr_mul(y, x));
        i += 1;
    }
    y = fpr_mul(y, ccs);
    fpr_trunc_u64(fpr_mul(y, FPR_PTWO63))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The count-leading-zeros path and the portable fallback must agree on
    /// every value, including zero — only one of them is exercised by the
    /// differential tests on any given target.
    #[test]
    fn normalize_top_paths_agree() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for i in 0..64 {
            for a in [0u64, 1 << i, (1u64 << i) - 1, x, x >> i, x << i] {
                assert_eq!(normalize_top(a), normalize_top_portable(a), "a = {a:#x}");
            }
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
        }
    }
}

#[cfg(test)]
mod mulconst_tests {
    use super::*;

    /// `fpr_mulconst` scales by a plain `f64` constant; it must agree with
    /// multiplying by the converted value.
    #[test]
    fn mulconst_matches_mul() {
        for (x, c) in [(1.5f64, 2.0f64), (-3.25, 0.5), (0.0, 7.0), (1e100, 1e-100)] {
            assert_eq!(
                fpr_mulconst(Fpr::new(x), c).to_f64().to_bits(),
                fpr_mul(Fpr::new(x), Fpr::new(c)).to_f64().to_bits(),
                "fpr_mulconst({x}, {c})"
            );
        }
    }
}
