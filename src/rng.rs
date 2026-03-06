//! PRNG for Falcon (ChaCha20-based).
//! Ported from rng.c + inline helpers from inner.h.

use crate::shake::{i_shake256_extract, InnerShake256Context};

// ======================================================================
// PRNG state
// ======================================================================

/// PRNG state structure. Uses ChaCha20 internally.
/// Buffer is 512 bytes (8 ChaCha20 blocks with interleaved output).
pub struct Prng {
    pub buf: [u8; 512],
    pub ptr: usize,
    pub state: [u8; 256],
}

impl Prng {
    pub fn new() -> Self {
        Prng {
            buf: [0u8; 512],
            ptr: 0,
            state: [0u8; 256],
        }
    }
}

impl Default for Prng {
    fn default() -> Self {
        Self::new()
    }
}

/// Zeroize PRNG state on drop to prevent key material from lingering in memory.
impl Drop for Prng {
    fn drop(&mut self) {
        // Volatile writes to prevent the optimizer from eliding these.
        for b in self.buf.iter_mut() {
            unsafe {
                core::ptr::write_volatile(b, 0);
            }
        }
        for b in self.state.iter_mut() {
            unsafe {
                core::ptr::write_volatile(b, 0);
            }
        }
        self.ptr = 0;
    }
}

// ======================================================================
// System entropy
// ======================================================================

/// Get a random seed from the operating system.
/// Returns true on success, false on error.
/// Requires the `std` feature to be enabled.
pub fn get_seed(seed: &mut [u8]) -> bool {
    if seed.is_empty() {
        return true;
    }
    #[cfg(all(unix, feature = "std"))]
    {
        use std::{fs::File, io::Read};
        if let Ok(mut f) = File::open("/dev/urandom") {
            let mut remaining = seed.len();
            let mut offset = 0;
            while remaining > 0 {
                match f.read(&mut seed[offset..]) {
                    Ok(0) => break,
                    Ok(n) => {
                        offset += n;
                        remaining -= n;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            if remaining == 0 {
                return true;
            }
        }
    }
    false
}

// ======================================================================
// PRNG init / refill
// ======================================================================

/// Initialize PRNG from a flipped SHAKE256 context.
pub fn prng_init(p: &mut Prng, src: &mut InnerShake256Context) {
    // Extract 56 bytes of seed directly into state (little-endian).
    // On little-endian systems (x86, ARM), this matches the C FALCON_LE path.
    let mut tmp = [0u8; 56];
    i_shake256_extract(src, &mut tmp);
    p.state[..56].copy_from_slice(&tmp);

    prng_refill(p);
}

/// ChaCha20 constants "expand 32-byte k".
const CW: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

/// Refill the PRNG buffer with 8 ChaCha20 blocks (512 bytes).
/// Output words are interleaved to match the AVX2 layout.
pub fn prng_refill(p: &mut Prng) {
    // Read the 64-bit counter from state bytes 48..56 (little-endian).
    let cc = u64::from_le_bytes([
        p.state[48],
        p.state[49],
        p.state[50],
        p.state[51],
        p.state[52],
        p.state[53],
        p.state[54],
        p.state[55],
    ]);

    // Pre-load the key + nonce from p.state (first 48 bytes = 12 u32s).
    let mut init_state = [0u32; 12];
    for i in 0..12 {
        let off = i * 4;
        init_state[i] = u32::from_le_bytes([
            p.state[off],
            p.state[off + 1],
            p.state[off + 2],
            p.state[off + 3],
        ]);
    }

    for u in 0..8u64 {
        let mut state = [0u32; 16];

        // Load ChaCha20 constants.
        state[0] = CW[0];
        state[1] = CW[1];
        state[2] = CW[2];
        state[3] = CW[3];

        // Load cached key + nonce.
        state[4..16].copy_from_slice(&init_state);

        // XOR counter into state[14..16].
        let counter = cc.wrapping_add(u);
        state[14] ^= counter as u32;
        state[15] ^= (counter >> 32) as u32;

        // Save initial state for add-back.
        let s0 = state;

        // 20 rounds (10 double-rounds).
        for _ in 0..10 {
            // Column round
            quarter_round(&mut state, 0, 4, 8, 12);
            quarter_round(&mut state, 1, 5, 9, 13);
            quarter_round(&mut state, 2, 6, 10, 14);
            quarter_round(&mut state, 3, 7, 11, 15);
            // Diagonal round
            quarter_round(&mut state, 0, 5, 10, 15);
            quarter_round(&mut state, 1, 6, 11, 12);
            quarter_round(&mut state, 2, 7, 8, 13);
            quarter_round(&mut state, 3, 4, 9, 14);
        }

        // Add initial state back.
        for i in 0..16 {
            state[i] = state[i].wrapping_add(s0[i]);
        }

        // Write output with interleaving: buf[u + (v << 3)]
        // Each u32 is written in little-endian.
        // Safety: u_idx < 8, v < 16, so off = u_idx*4 + v*32 <= 28 + 480 = 508 < 512
        let u_idx = u as usize;
        for v in 0..16 {
            let off = (u_idx << 2) + (v << 5);
            let bytes = state[v].to_le_bytes();
            unsafe {
                *p.buf.get_unchecked_mut(off) = bytes[0];
                *p.buf.get_unchecked_mut(off + 1) = bytes[1];
                *p.buf.get_unchecked_mut(off + 2) = bytes[2];
                *p.buf.get_unchecked_mut(off + 3) = bytes[3];
            }
        }
    }

    // Update the stored counter.
    let new_cc = cc.wrapping_add(8);
    p.state[48..56].copy_from_slice(&new_cc.to_le_bytes());

    p.ptr = 0;
}

/// ChaCha20 quarter round.
#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

// ======================================================================
// PRNG extraction
// ======================================================================

/// Get a 64-bit random value from the PRNG.
#[inline]
pub fn prng_get_u64(p: &mut Prng) -> u64 {
    let u = p.ptr;
    // If there are less than 9 bytes in the buffer, refill.
    if u >= 512 - 9 {
        prng_refill(p);
        return prng_get_u64(p);
    }
    p.ptr = u + 8;

    unsafe {
        let ptr = p.buf.as_ptr().add(u);
        u64::from_le_bytes(*(ptr as *const [u8; 8]))
    }
}

/// Get an 8-bit random value from the PRNG.
#[inline]
pub fn prng_get_u8(p: &mut Prng) -> u32 {
    let v = p.buf[p.ptr] as u32;
    p.ptr += 1;
    if p.ptr == 512 {
        prng_refill(p);
    }
    v
}

/// Get bulk random bytes from the PRNG.
pub fn prng_get_bytes(p: &mut Prng, dst: &mut [u8]) {
    let mut offset = 0;
    let mut remaining = dst.len();
    while remaining > 0 {
        let mut clen = 512 - p.ptr;
        if clen > remaining {
            clen = remaining;
        }
        dst[offset..offset + clen].copy_from_slice(&p.buf[p.ptr..p.ptr + clen]);
        offset += clen;
        remaining -= clen;
        p.ptr += clen;
        if p.ptr == 512 {
            prng_refill(p);
        }
    }
}
