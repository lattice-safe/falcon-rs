//! Encoding/decoding for Falcon keys and signatures.
//! Ported from codec.c.

// ======================================================================
// modq: 14-bit packed encoding for values mod q = 12289
// ======================================================================

/// Encode a polynomial of mod-q values into packed 14-bit format.
/// Returns the number of bytes written, or 0 on error.
/// If `out` is `None`, returns the required output length.
pub fn modq_encode(out: Option<&mut [u8]>, x: &[u16], logn: u32) -> usize {
    let n: usize = 1 << logn;
    for u in 0..n {
        if x[u] >= 12289 {
            return 0;
        }
    }
    let out_len = ((n * 14) + 7) >> 3;
    let buf = match out {
        None => return out_len,
        Some(b) => {
            if out_len > b.len() {
                return 0;
            }
            b
        }
    };
    let mut acc: u32 = 0;
    let mut acc_len: i32 = 0;
    let mut pos = 0usize;
    for u in 0..n {
        acc = (acc << 14) | x[u] as u32;
        acc_len += 14;
        while acc_len >= 8 {
            acc_len -= 8;
            buf[pos] = (acc >> acc_len) as u8;
            pos += 1;
        }
    }
    if acc_len > 0 {
        buf[pos] = (acc << (8 - acc_len)) as u8;
    }
    out_len
}

/// Decode packed 14-bit mod-q values into a polynomial.
/// Returns the number of bytes consumed, or 0 on error.
pub fn modq_decode(x: &mut [u16], logn: u32, input: &[u8]) -> usize {
    let n: usize = 1 << logn;
    let in_len = ((n * 14) + 7) >> 3;
    if in_len > input.len() {
        return 0;
    }
    let mut acc: u32 = 0;
    let mut acc_len: i32 = 0;
    let mut u: usize = 0;
    let mut buf_pos: usize = 0;
    while u < n {
        acc = (acc << 8) | input[buf_pos] as u32;
        buf_pos += 1;
        acc_len += 8;
        if acc_len >= 14 {
            acc_len -= 14;
            let w = (acc >> acc_len) & 0x3FFF;
            if w >= 12289 {
                return 0;
            }
            x[u] = w as u16;
            u += 1;
        }
    }
    if (acc & (((1u32) << acc_len) - 1)) != 0 {
        return 0;
    }
    in_len
}

// ======================================================================
// trim_i16: variable-width signed 16-bit encoding
// ======================================================================

/// Encode signed 16-bit integers with a given bit width.
/// Returns bytes written, or 0 on error.
/// If `out` is `None`, returns the required output length.
pub fn trim_i16_encode(out: Option<&mut [u8]>, x: &[i16], logn: u32, bits: u32) -> usize {
    let n: usize = 1 << logn;
    let maxv = (1i32 << (bits - 1)) - 1;
    let minv = -maxv;
    for u in 0..n {
        if (x[u] as i32) < minv || (x[u] as i32) > maxv {
            return 0;
        }
    }
    let out_len = ((n * bits as usize) + 7) >> 3;
    let buf = match out {
        None => return out_len,
        Some(b) => {
            if out_len > b.len() {
                return 0;
            }
            b
        }
    };
    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mask: u32 = (1u32 << bits) - 1;
    let mut pos = 0usize;
    for u in 0..n {
        acc = (acc << bits) | ((x[u] as u16) as u32 & mask);
        acc_len += bits;
        while acc_len >= 8 {
            acc_len -= 8;
            buf[pos] = (acc >> acc_len) as u8;
            pos += 1;
        }
    }
    if acc_len > 0 {
        buf[pos] = (acc << (8 - acc_len)) as u8;
    }
    out_len
}

/// Decode variable-width signed 16-bit integers.
/// Returns bytes consumed, or 0 on error.
pub fn trim_i16_decode(x: &mut [i16], logn: u32, bits: u32, input: &[u8]) -> usize {
    let n: usize = 1 << logn;
    let in_len = ((n * bits as usize) + 7) >> 3;
    if in_len > input.len() {
        return 0;
    }
    let mut u: usize = 0;
    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mask1: u32 = (1u32 << bits) - 1;
    let mask2: u32 = 1u32 << (bits - 1);
    let mut buf_pos: usize = 0;
    while u < n {
        acc = (acc << 8) | input[buf_pos] as u32;
        buf_pos += 1;
        acc_len += 8;
        while acc_len >= bits && u < n {
            acc_len -= bits;
            let mut w: u32 = (acc >> acc_len) & mask1;
            w |= (w & mask2).wrapping_neg();
            if w == mask2.wrapping_neg() {
                // The -2^(bits-1) value is forbidden.
                return 0;
            }
            w |= (w & mask2).wrapping_neg();
            x[u] = w as i32 as i16;
            u += 1;
        }
    }
    if (acc & ((1u32 << acc_len) - 1)) != 0 {
        // Extra bits in the last byte must be zero.
        return 0;
    }
    in_len
}

// ======================================================================
// trim_i8: variable-width signed 8-bit encoding
// ======================================================================

/// Encode signed 8-bit integers with a given bit width.
/// Returns bytes written, or 0 on error.
/// If `out` is `None`, returns the required output length.
pub fn trim_i8_encode(out: Option<&mut [u8]>, x: &[i8], logn: u32, bits: u32) -> usize {
    let n: usize = 1 << logn;
    let maxv = (1i32 << (bits - 1)) - 1;
    let minv = -maxv;
    for u in 0..n {
        if (x[u] as i32) < minv || (x[u] as i32) > maxv {
            return 0;
        }
    }
    let out_len = ((n * bits as usize) + 7) >> 3;
    let buf = match out {
        None => return out_len,
        Some(b) => {
            if out_len > b.len() {
                return 0;
            }
            b
        }
    };
    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mask: u32 = (1u32 << bits) - 1;
    let mut pos = 0usize;
    for u in 0..n {
        acc = (acc << bits) | ((x[u] as u8) as u32 & mask);
        acc_len += bits;
        while acc_len >= 8 {
            acc_len -= 8;
            buf[pos] = (acc >> acc_len) as u8;
            pos += 1;
        }
    }
    if acc_len > 0 {
        buf[pos] = (acc << (8 - acc_len)) as u8;
    }
    out_len
}

/// Decode variable-width signed 8-bit integers.
/// Returns bytes consumed, or 0 on error.
pub fn trim_i8_decode(x: &mut [i8], logn: u32, bits: u32, input: &[u8]) -> usize {
    let n: usize = 1 << logn;
    let in_len = ((n * bits as usize) + 7) >> 3;
    if in_len > input.len() {
        return 0;
    }
    let mut u: usize = 0;
    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mask1: u32 = (1u32 << bits) - 1;
    let mask2: u32 = 1u32 << (bits - 1);
    let mut buf_pos: usize = 0;
    while u < n {
        acc = (acc << 8) | input[buf_pos] as u32;
        buf_pos += 1;
        acc_len += 8;
        while acc_len >= bits && u < n {
            acc_len -= bits;
            let mut w: u32 = (acc >> acc_len) & mask1;
            w |= (w & mask2).wrapping_neg();
            if w == mask2.wrapping_neg() {
                // The -2^(bits-1) value is forbidden.
                return 0;
            }
            x[u] = w as i32 as i8;
            u += 1;
        }
    }
    if (acc & ((1u32 << acc_len) - 1)) != 0 {
        // Extra bits in the last byte must be zero.
        return 0;
    }
    in_len
}

// ======================================================================
// comp: variable-length compressed signature encoding
// ======================================================================

/// Encode signature coefficients using compressed format.
/// Values must be in -2047..+2047 range.
/// Returns bytes written, or 0 on error.
/// If `out` is `None`, computes and returns the required length.
pub fn comp_encode(mut out: Option<&mut [u8]>, x: &[i16], logn: u32) -> usize {
    let n: usize = 1 << logn;

    // Verify values within range.
    for u in 0..n {
        if x[u] < -2047 || x[u] > 2047 {
            return 0;
        }
    }

    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mut v: usize = 0;
    for u in 0..n {
        // Get sign and absolute value; push the sign bit.
        acc <<= 1;
        let mut t = x[u] as i32;
        if t < 0 {
            t = -t;
            acc |= 1;
        }
        let mut w = t as u32;

        // Push the low 7 bits of the absolute value.
        acc <<= 7;
        acc |= w & 127;
        w >>= 7;

        // We pushed exactly 8 bits.
        acc_len += 8;

        // Push as many zeros as necessary, then a one.
        acc <<= w + 1;
        acc |= 1;
        acc_len += w + 1;

        // Produce all full bytes.
        while acc_len >= 8 {
            acc_len -= 8;
            if let Some(ref buf) = out {
                if v >= buf.len() {
                    return 0;
                }
            }
            if let Some(ref mut buf) = out {
                buf[v] = (acc >> acc_len) as u8;
            }
            v += 1;
        }
    }

    // Flush remaining bits (if any).
    if acc_len > 0 {
        if let Some(ref buf) = out {
            if v >= buf.len() {
                return 0;
            }
        }
        if let Some(ref mut buf) = out {
            buf[v] = (acc << (8 - acc_len)) as u8;
        }
        v += 1;
    }

    v
}

/// Decode compressed signature coefficients.
/// Returns bytes consumed, or 0 on error.
pub fn comp_decode(x: &mut [i16], logn: u32, input: &[u8]) -> usize {
    let n: usize = 1 << logn;
    let max_in_len = input.len();
    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mut v: usize = 0;
    for u in 0..n {
        // Get next eight bits: sign and low seven bits of the absolute value.
        if v >= max_in_len {
            return 0;
        }
        acc = (acc << 8) | input[v] as u32;
        v += 1;
        let b = acc >> acc_len;
        let s = b & 128;
        let mut m = b & 127;

        // Get next bits until a 1 is reached.
        loop {
            if acc_len == 0 {
                if v >= max_in_len {
                    return 0;
                }
                acc = (acc << 8) | input[v] as u32;
                v += 1;
                acc_len = 8;
            }
            acc_len -= 1;
            if ((acc >> acc_len) & 1) != 0 {
                break;
            }
            m += 128;
            if m > 2047 {
                return 0;
            }
        }

        // "-0" is forbidden.
        if s != 0 && m == 0 {
            return 0;
        }

        x[u] = if s != 0 { -(m as i32) } else { m as i32 } as i16;
    }

    // Unused bits in the last byte must be zero.
    if (acc & ((1u32 << acc_len) - 1)) != 0 {
        return 0;
    }

    v
}

// ======================================================================
// Bit-width limits for key/signature elements (indexed by logn, 0..10)
// ======================================================================

/// Maximum number of bits for f, g coefficients.
pub static MAX_FG_BITS: [u8; 11] = [
    0, // unused
    8, 8, 8, 8, 8, 7, 7, 6, 6, 5,
];

/// Maximum number of bits for F, G coefficients.
pub static MAX_FG_BITS_UPPER: [u8; 11] = [
    0, // unused
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
];

/// Maximum number of bits for signature coefficients (including sign bit).
pub static MAX_SIG_BITS: [u8; 11] = [
    0, // unused
    10, 11, 11, 12, 12, 12, 12, 12, 12, 12,
];
