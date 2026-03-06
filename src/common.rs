//! Common utilities for Falcon.
//! Ported from common.c.

use crate::shake::InnerShake256Context;
use crate::shake::i_shake256_extract;

// ======================================================================
// Hash-to-point
// ======================================================================

/// Hash-to-point (variable-time version).
///
/// From a SHAKE256 context (must be already flipped), produce a new
/// point modulo q = 12289 by rejection sampling.
pub fn hash_to_point_vartime(
    sc: &mut InnerShake256Context,
    x: &mut [u16],
    logn: u32,
) {
    let n: usize = 1 << logn;
    let mut remaining = n;
    let mut pos = 0usize;
    while remaining > 0 {
        let mut buf = [0u8; 2];
        i_shake256_extract(sc, &mut buf);
        let w: u32 = ((buf[0] as u32) << 8) | (buf[1] as u32);
        if w < 61445 {
            let mut val = w;
            while val >= 12289 {
                val -= 12289;
            }
            x[pos] = val as u16;
            pos += 1;
            remaining -= 1;
        }
    }
}

/// Hash-to-point (constant-time version).
///
/// From a SHAKE256 context (must be already flipped), produce a new
/// point modulo q = 12289 using oversampling + constant-time squeeze.
/// tmp must have room for at least 2*2^logn bytes (interpreted as u16).
pub fn hash_to_point_ct(
    sc: &mut InnerShake256Context,
    x: &mut [u16],
    logn: u32,
    tmp: &mut [u8],
) {
    static OVERTAB: [u16; 11] = [
        0, // unused
        65, 67, 71, 77, 86, 100, 122, 154, 205, 287,
    ];

    let n = 1usize << logn;
    let n2 = n << 1;
    let over = OVERTAB[logn as usize] as usize;
    let m = n + over;

    // Interpret tmp as &mut [u16] (tt1).
    // tt1 covers indices n..n2, tt2 is a stack buffer for n2..m.
    let tt1: &mut [u16] = unsafe {
        core::slice::from_raw_parts_mut(tmp.as_mut_ptr() as *mut u16, n)
    };
    let mut tt2 = [0u16; 63];

    // Generate m 16-bit values with rejection.
    for u in 0..m {
        let mut buf = [0u8; 2];
        i_shake256_extract(sc, &mut buf);
        let w: u32 = ((buf[0] as u32) << 8) | (buf[1] as u32);

        // Constant-time reduction modulo q = 12289 with rejection.
        let mut wr = w;
        wr = wr.wrapping_sub(24578 & ((wr.wrapping_sub(24578) >> 31).wrapping_sub(1)));
        wr = wr.wrapping_sub(24578 & ((wr.wrapping_sub(24578) >> 31).wrapping_sub(1)));
        wr = wr.wrapping_sub(12289 & ((wr.wrapping_sub(12289) >> 31).wrapping_sub(1)));
        wr |= (w.wrapping_sub(61445) >> 31).wrapping_sub(1);

        if u < n {
            x[u] = wr as u16;
        } else if u < n2 {
            tt1[u - n] = wr as u16;
        } else {
            tt2[u - n2] = wr as u16;
        }
    }

    // Squeeze out invalid values (marked as 0xFFFF).
    let mut p: usize = 1;
    while p <= over {
        let mut v: usize = 0;
        for u in 0..m {
            let sv = if u < n {
                x[u]
            } else if u < n2 {
                tt1[u - n]
            } else {
                tt2[u - n2]
            };

            // j = u - v: how far the value should jump back.
            let j = u - v;

            // mk = -1 if valid, 0 otherwise (bit 15 set means invalid)
            let mk = (sv >> 15).wrapping_sub(1u16);
            // Increment v only if valid (subtract mk which is -1 or 0 as u16)
            v = v.wrapping_add(mk as usize & 1);

            if u < p {
                continue;
            }

            // Destination for the swap: value at address u-p.
            let dv = if (u - p) < n {
                x[u - p]
            } else if (u - p) < n2 {
                tt1[(u - p) - n]
            } else {
                tt2[(u - p) - n2]
            };

            // Swap if source is valid AND j has its 'p' bit set.
            let mk2 = mk & ((((j & p) as u32 + 0x1FF) >> 9) as u16).wrapping_neg();

            let new_s = sv ^ (mk2 & (sv ^ dv));
            let new_d = dv ^ (mk2 & (sv ^ dv));

            if u < n {
                x[u] = new_s;
            } else if u < n2 {
                tt1[u - n] = new_s;
            } else {
                tt2[u - n2] = new_s;
            }

            if (u - p) < n {
                x[u - p] = new_d;
            } else if (u - p) < n2 {
                tt1[(u - p) - n] = new_d;
            } else {
                tt2[(u - p) - n2] = new_d;
            }
        }

        p <<= 1;
    }
}

// ======================================================================
// Signature norm checks
// ======================================================================

/// Acceptance bounds for the (squared) L2-norm of the signature,
/// indexed by logn (1 to 10). These bounds are inclusive.
static L2BOUND: [u32; 11] = [
    0, // unused
    101498,
    208714,
    428865,
    892039,
    1852696,
    3842630,
    7959734,
    16468416,
    34034726,
    70265242,
];

/// Check whether a signature vector (s1, s2) is short enough.
/// Returns true if the L2-norm squared is within bounds.
pub fn is_short(s1: &[i16], s2: &[i16], logn: u32) -> bool {
    let n: usize = 1 << logn;
    let mut s: u32 = 0;
    let mut ng: u32 = 0;
    for u in 0..n {
        let z = s1[u] as i32;
        s = s.wrapping_add((z * z) as u32);
        ng |= s;
        let z = s2[u] as i32;
        s = s.wrapping_add((z * z) as u32);
        ng |= s;
    }
    s |= (ng >> 31).wrapping_neg();

    s <= L2BOUND[logn as usize]
}

/// Check whether a signature vector is short enough, given the
/// precomputed squared norm of s1 (saturated).
/// Returns true if the combined norm is within bounds.
pub fn is_short_half(sqn: u32, s2: &[i16], logn: u32) -> bool {
    let n: usize = 1 << logn;
    let mut sqn = sqn;
    let mut ng: u32 = (sqn >> 31).wrapping_neg();
    for u in 0..n {
        let z = s2[u] as i32;
        sqn = sqn.wrapping_add((z * z) as u32);
        ng |= sqn;
    }
    sqn |= (ng >> 31).wrapping_neg();

    sqn <= L2BOUND[logn as usize]
}
