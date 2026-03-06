//! SHAKE256 implementation (Keccak-f\[1600\]).
//!
//! Ported from shake.c in the Falcon reference implementation.

/// SHAKE256 rate in bytes (1600 - 2*256) / 8 = 136
const SHAKE256_RATE: usize = 136;

/// Keccak round constants.
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Inner SHAKE256 context, matching C's `inner_shake256_context`.
#[derive(Clone)]
pub struct InnerShake256Context {
    pub st: [u64; 25],
    pub dptr: u64,
}

impl InnerShake256Context {
    pub const fn new() -> Self {
        InnerShake256Context {
            st: [0u64; 25],
            dptr: 0,
        }
    }

    /// Get the state as a byte buffer (little-endian view).
    #[inline]
    fn dbuf_byte(&self, idx: usize) -> u8 {
        (self.st[idx >> 3] >> ((idx & 7) << 3)) as u8
    }

    /// XOR a byte into the state at position idx.
    #[inline]
    fn dbuf_xor_byte(&mut self, idx: usize, val: u8) {
        self.st[idx >> 3] ^= (val as u64) << ((idx & 7) << 3);
    }
}

impl Default for InnerShake256Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Keccak-f[1600] permutation (process_block).
///
/// This is a faithful translation of the C reference code, including the
/// bit-interleaved lane strategy with inverted words for reduced operations.
fn process_block(a: &mut [u64; 25]) {
    // Invert some words (alternate internal representation).
    a[1] = !a[1];
    a[2] = !a[2];
    a[8] = !a[8];
    a[12] = !a[12];
    a[17] = !a[17];
    a[20] = !a[20];

    for j in (0..24).step_by(2) {
        // --- Round 1 of pair (index j) ---
        let mut tt0;
        let mut tt1;
        let mut tt2;
        let mut tt3;

        tt0 = a[1] ^ a[6];
        tt1 = a[11] ^ a[16];
        tt0 ^= a[21] ^ tt1;
        tt0 = tt0.rotate_left(1);
        tt2 = a[4] ^ a[9];
        tt3 = a[14] ^ a[19];
        tt0 ^= a[24];
        tt2 ^= tt3;
        let t0 = tt0 ^ tt2;

        tt0 = a[2] ^ a[7];
        tt1 = a[12] ^ a[17];
        tt0 ^= a[22] ^ tt1;
        tt0 = tt0.rotate_left(1);
        tt2 = a[0] ^ a[5];
        tt3 = a[10] ^ a[15];
        tt0 ^= a[20];
        tt2 ^= tt3;
        let t1 = tt0 ^ tt2;

        tt0 = a[3] ^ a[8];
        tt1 = a[13] ^ a[18];
        tt0 ^= a[23] ^ tt1;
        tt0 = tt0.rotate_left(1);
        tt2 = a[1] ^ a[6];
        tt3 = a[11] ^ a[16];
        tt0 ^= a[21];
        tt2 ^= tt3;
        let t2 = tt0 ^ tt2;

        tt0 = a[4] ^ a[9];
        tt1 = a[14] ^ a[19];
        tt0 ^= a[24] ^ tt1;
        tt0 = tt0.rotate_left(1);
        tt2 = a[2] ^ a[7];
        tt3 = a[12] ^ a[17];
        tt0 ^= a[22];
        tt2 ^= tt3;
        let t3 = tt0 ^ tt2;

        tt0 = a[0] ^ a[5];
        tt1 = a[10] ^ a[15];
        tt0 ^= a[20] ^ tt1;
        tt0 = tt0.rotate_left(1);
        tt2 = a[3] ^ a[8];
        tt3 = a[13] ^ a[18];
        tt0 ^= a[23];
        tt2 ^= tt3;
        let t4 = tt0 ^ tt2;

        a[0] ^= t0;
        a[5] ^= t0;
        a[10] ^= t0;
        a[15] ^= t0;
        a[20] ^= t0;
        a[1] ^= t1;
        a[6] ^= t1;
        a[11] ^= t1;
        a[16] ^= t1;
        a[21] ^= t1;
        a[2] ^= t2;
        a[7] ^= t2;
        a[12] ^= t2;
        a[17] ^= t2;
        a[22] ^= t2;
        a[3] ^= t3;
        a[8] ^= t3;
        a[13] ^= t3;
        a[18] ^= t3;
        a[23] ^= t3;
        a[4] ^= t4;
        a[9] ^= t4;
        a[14] ^= t4;
        a[19] ^= t4;
        a[24] ^= t4;

        a[5] = a[5].rotate_left(36);
        a[10] = a[10].rotate_left(3);
        a[15] = a[15].rotate_left(41);
        a[20] = a[20].rotate_left(18);
        a[1] = a[1].rotate_left(1);
        a[6] = a[6].rotate_left(44);
        a[11] = a[11].rotate_left(10);
        a[16] = a[16].rotate_left(45);
        a[21] = a[21].rotate_left(2);
        a[2] = a[2].rotate_left(62);
        a[7] = a[7].rotate_left(6);
        a[12] = a[12].rotate_left(43);
        a[17] = a[17].rotate_left(15);
        a[22] = a[22].rotate_left(61);
        a[3] = a[3].rotate_left(28);
        a[8] = a[8].rotate_left(55);
        a[13] = a[13].rotate_left(25);
        a[18] = a[18].rotate_left(21);
        a[23] = a[23].rotate_left(56);
        a[4] = a[4].rotate_left(27);
        a[9] = a[9].rotate_left(20);
        a[14] = a[14].rotate_left(39);
        a[19] = a[19].rotate_left(8);
        a[24] = a[24].rotate_left(14);

        // Chi step — round 1
        {
            let bnn = !a[12];
            let c0 = a[0] ^ (a[6] | a[12]);
            let c1 = a[6] ^ (bnn | a[18]);
            let c2 = a[12] ^ (a[18] & a[24]);
            let c3 = a[18] ^ (a[24] | a[0]);
            let c4 = a[24] ^ (a[0] & a[6]);
            a[0] = c0;
            a[6] = c1;
            a[12] = c2;
            a[18] = c3;
            a[24] = c4;
        }
        {
            let bnn = !a[22];
            let c0 = a[3] ^ (a[9] | a[10]);
            let c1 = a[9] ^ (a[10] & a[16]);
            let c2 = a[10] ^ (a[16] | bnn);
            let c3 = a[16] ^ (a[22] | a[3]);
            let c4 = a[22] ^ (a[3] & a[9]);
            a[3] = c0;
            a[9] = c1;
            a[10] = c2;
            a[16] = c3;
            a[22] = c4;
        }
        {
            let bnn = !a[19];
            let c0 = a[1] ^ (a[7] | a[13]);
            let c1 = a[7] ^ (a[13] & a[19]);
            let c2 = a[13] ^ (bnn & a[20]);
            let c3 = bnn ^ (a[20] | a[1]);
            let c4 = a[20] ^ (a[1] & a[7]);
            a[1] = c0;
            a[7] = c1;
            a[13] = c2;
            a[19] = c3;
            a[20] = c4;
        }
        {
            let bnn = !a[17];
            let c0 = a[4] ^ (a[5] & a[11]);
            let c1 = a[5] ^ (a[11] | a[17]);
            let c2 = a[11] ^ (bnn | a[23]);
            let c3 = bnn ^ (a[23] & a[4]);
            let c4 = a[23] ^ (a[4] | a[5]);
            a[4] = c0;
            a[5] = c1;
            a[11] = c2;
            a[17] = c3;
            a[23] = c4;
        }
        {
            let bnn = !a[8];
            let c0 = a[2] ^ (bnn & a[14]);
            let c1 = bnn ^ (a[14] | a[15]);
            let c2 = a[14] ^ (a[15] & a[21]);
            let c3 = a[15] ^ (a[21] | a[2]);
            let c4 = a[21] ^ (a[2] & a[8]);
            a[2] = c0;
            a[8] = c1;
            a[14] = c2;
            a[15] = c3;
            a[21] = c4;
        }

        a[0] ^= RC[j];

        // --- Round 2 of pair (index j+1) ---
        tt0 = a[6] ^ a[9];
        tt1 = a[7] ^ a[5];
        tt0 ^= a[8] ^ tt1;
        tt0 = tt0.rotate_left(1);
        tt2 = a[24] ^ a[22];
        tt3 = a[20] ^ a[23];
        tt0 ^= a[21];
        tt2 ^= tt3;
        let t0 = tt0 ^ tt2;

        tt0 = a[12] ^ a[10];
        tt1 = a[13] ^ a[11];
        tt0 ^= a[14] ^ tt1;
        tt0 = tt0.rotate_left(1);
        tt2 = a[0] ^ a[3];
        tt3 = a[1] ^ a[4];
        tt0 ^= a[2];
        tt2 ^= tt3;
        let t1 = tt0 ^ tt2;

        tt0 = a[18] ^ a[16];
        tt1 = a[19] ^ a[17];
        tt0 ^= a[15] ^ tt1;
        tt0 = tt0.rotate_left(1);
        tt2 = a[6] ^ a[9];
        tt3 = a[7] ^ a[5];
        tt0 ^= a[8];
        tt2 ^= tt3;
        let t2 = tt0 ^ tt2;

        tt0 = a[24] ^ a[22];
        tt1 = a[20] ^ a[23];
        tt0 ^= a[21] ^ tt1;
        tt0 = tt0.rotate_left(1);
        tt2 = a[12] ^ a[10];
        tt3 = a[13] ^ a[11];
        tt0 ^= a[14];
        tt2 ^= tt3;
        let t3 = tt0 ^ tt2;

        tt0 = a[0] ^ a[3];
        tt1 = a[1] ^ a[4];
        tt0 ^= a[2] ^ tt1;
        tt0 = tt0.rotate_left(1);
        tt2 = a[18] ^ a[16];
        tt3 = a[19] ^ a[17];
        tt0 ^= a[15];
        tt2 ^= tt3;
        let t4 = tt0 ^ tt2;

        a[0] ^= t0;
        a[3] ^= t0;
        a[1] ^= t0;
        a[4] ^= t0;
        a[2] ^= t0;
        a[6] ^= t1;
        a[9] ^= t1;
        a[7] ^= t1;
        a[5] ^= t1;
        a[8] ^= t1;
        a[12] ^= t2;
        a[10] ^= t2;
        a[13] ^= t2;
        a[11] ^= t2;
        a[14] ^= t2;
        a[18] ^= t3;
        a[16] ^= t3;
        a[19] ^= t3;
        a[17] ^= t3;
        a[15] ^= t3;
        a[24] ^= t4;
        a[22] ^= t4;
        a[20] ^= t4;
        a[23] ^= t4;
        a[21] ^= t4;

        a[3] = a[3].rotate_left(36);
        a[1] = a[1].rotate_left(3);
        a[4] = a[4].rotate_left(41);
        a[2] = a[2].rotate_left(18);
        a[6] = a[6].rotate_left(1);
        a[9] = a[9].rotate_left(44);
        a[7] = a[7].rotate_left(10);
        a[5] = a[5].rotate_left(45);
        a[8] = a[8].rotate_left(2);
        a[12] = a[12].rotate_left(62);
        a[10] = a[10].rotate_left(6);
        a[13] = a[13].rotate_left(43);
        a[11] = a[11].rotate_left(15);
        a[14] = a[14].rotate_left(61);
        a[18] = a[18].rotate_left(28);
        a[16] = a[16].rotate_left(55);
        a[19] = a[19].rotate_left(25);
        a[17] = a[17].rotate_left(21);
        a[15] = a[15].rotate_left(56);
        a[24] = a[24].rotate_left(27);
        a[22] = a[22].rotate_left(20);
        a[20] = a[20].rotate_left(39);
        a[23] = a[23].rotate_left(8);
        a[21] = a[21].rotate_left(14);

        // Chi step — round 2
        {
            let bnn = !a[13];
            let c0 = a[0] ^ (a[9] | a[13]);
            let c1 = a[9] ^ (bnn | a[17]);
            let c2 = a[13] ^ (a[17] & a[21]);
            let c3 = a[17] ^ (a[21] | a[0]);
            let c4 = a[21] ^ (a[0] & a[9]);
            a[0] = c0;
            a[9] = c1;
            a[13] = c2;
            a[17] = c3;
            a[21] = c4;
        }
        {
            let bnn = !a[14];
            let c0 = a[18] ^ (a[22] | a[1]);
            let c1 = a[22] ^ (a[1] & a[5]);
            let c2 = a[1] ^ (a[5] | bnn);
            let c3 = a[5] ^ (a[14] | a[18]);
            let c4 = a[14] ^ (a[18] & a[22]);
            a[18] = c0;
            a[22] = c1;
            a[1] = c2;
            a[5] = c3;
            a[14] = c4;
        }
        {
            let bnn = !a[23];
            let c0 = a[6] ^ (a[10] | a[19]);
            let c1 = a[10] ^ (a[19] & a[23]);
            let c2 = a[19] ^ (bnn & a[2]);
            let c3 = bnn ^ (a[2] | a[6]);
            let c4 = a[2] ^ (a[6] & a[10]);
            a[6] = c0;
            a[10] = c1;
            a[19] = c2;
            a[23] = c3;
            a[2] = c4;
        }
        {
            let bnn = !a[11];
            let c0 = a[24] ^ (a[3] & a[7]);
            let c1 = a[3] ^ (a[7] | a[11]);
            let c2 = a[7] ^ (bnn | a[15]);
            let c3 = bnn ^ (a[15] & a[24]);
            let c4 = a[15] ^ (a[24] | a[3]);
            a[24] = c0;
            a[3] = c1;
            a[7] = c2;
            a[11] = c3;
            a[15] = c4;
        }
        {
            let bnn = !a[16];
            let c0 = a[12] ^ (bnn & a[20]);
            let c1 = bnn ^ (a[20] | a[4]);
            let c2 = a[20] ^ (a[4] & a[8]);
            let c3 = a[4] ^ (a[8] | a[12]);
            let c4 = a[8] ^ (a[12] & a[16]);
            a[12] = c0;
            a[16] = c1;
            a[20] = c2;
            a[4] = c3;
            a[8] = c4;
        }

        a[0] ^= RC[j + 1];

        // Final permutation of the second round.
        let t = a[5];
        a[5] = a[18];
        a[18] = a[11];
        a[11] = a[10];
        a[10] = a[6];
        a[6] = a[22];
        a[22] = a[20];
        a[20] = a[12];
        a[12] = a[19];
        a[19] = a[15];
        a[15] = a[24];
        a[24] = a[8];
        a[8] = t;
        let t = a[1];
        a[1] = a[9];
        a[9] = a[14];
        a[14] = a[2];
        a[2] = a[13];
        a[13] = a[23];
        a[23] = a[4];
        a[4] = a[21];
        a[21] = a[16];
        a[16] = a[3];
        a[3] = a[17];
        a[17] = a[7];
        a[7] = t;
    }

    // Invert some words back to normal representation.
    a[1] = !a[1];
    a[2] = !a[2];
    a[8] = !a[8];
    a[12] = !a[12];
    a[17] = !a[17];
    a[20] = !a[20];
}

// ============================================================
// Public SHAKE256 API
// ============================================================

/// Initialize a SHAKE256 context.
pub fn i_shake256_init(sc: &mut InnerShake256Context) {
    sc.dptr = 0;
    sc.st = [0u64; 25];
}

/// Inject data into the SHAKE256 context (absorb phase).
pub fn i_shake256_inject(sc: &mut InnerShake256Context, data: &[u8]) {
    let mut dptr = sc.dptr as usize;
    let mut off = 0usize;
    let mut remaining = data.len();

    while remaining > 0 {
        let clen = core::cmp::min(SHAKE256_RATE - dptr, remaining);

        // XOR input bytes into state (little-endian lane access).
        for u in 0..clen {
            let v = u + dptr;
            sc.st[v >> 3] ^= (data[off + u] as u64) << ((v & 7) << 3);
        }

        dptr += clen;
        off += clen;
        remaining -= clen;
        if dptr == SHAKE256_RATE {
            process_block(&mut sc.st);
            dptr = 0;
        }
    }
    sc.dptr = dptr as u64;
}

/// Flip the SHAKE256 context from absorb to squeeze mode.
pub fn i_shake256_flip(sc: &mut InnerShake256Context) {
    let v = sc.dptr as usize;
    sc.st[v >> 3] ^= 0x1Fu64 << ((v & 7) << 3);
    sc.st[16] ^= 0x80u64 << 56;
    sc.dptr = SHAKE256_RATE as u64;
}

/// Extract bytes from SHAKE256 context (squeeze phase).
pub fn i_shake256_extract(sc: &mut InnerShake256Context, out: &mut [u8]) {
    let mut dptr = sc.dptr as usize;
    let mut off = 0usize;
    let mut remaining = out.len();

    while remaining > 0 {
        if dptr == SHAKE256_RATE {
            process_block(&mut sc.st);
            dptr = 0;
        }
        let clen = core::cmp::min(SHAKE256_RATE - dptr, remaining);

        for u in 0..clen {
            out[off + u] = (sc.st[(dptr + u) >> 3] >> (((dptr + u) & 7) << 3)) as u8;
        }

        dptr += clen;
        off += clen;
        remaining -= clen;
    }
    sc.dptr = dptr as u64;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec::Vec;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn bytes_to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    /// Test SHAKE256 against a known test vector.
    #[test]
    fn test_shake256_basic() {
        // Empty input → known SHAKE256 output
        let mut sc = InnerShake256Context::new();
        i_shake256_init(&mut sc);
        i_shake256_flip(&mut sc);
        let mut out = [0u8; 32];
        i_shake256_extract(&mut sc, &mut out);
        let expected = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f";
        assert_eq!(bytes_to_hex(&out), expected, "SHAKE256 empty input failed");
    }

    /// Test injection in multiple parts.
    #[test]
    fn test_shake256_multipart() {
        let data = b"The quick brown fox jumps over the lazy dog";

        // Single inject
        let mut sc1 = InnerShake256Context::new();
        i_shake256_init(&mut sc1);
        i_shake256_inject(&mut sc1, data);
        i_shake256_flip(&mut sc1);
        let mut out1 = [0u8; 64];
        i_shake256_extract(&mut sc1, &mut out1);

        // Multi-part inject (split at various points)
        let mut sc2 = InnerShake256Context::new();
        i_shake256_init(&mut sc2);
        i_shake256_inject(&mut sc2, &data[..10]);
        i_shake256_inject(&mut sc2, &data[10..30]);
        i_shake256_inject(&mut sc2, &data[30..]);
        i_shake256_flip(&mut sc2);
        let mut out2 = [0u8; 64];
        i_shake256_extract(&mut sc2, &mut out2);

        assert_eq!(out1, out2, "Multi-part injection mismatch");
    }
}
