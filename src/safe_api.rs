//! High-level safe Rust SDK for FN-DSA (FIPS 206) post-quantum digital signatures.
//!
//! FN-DSA (FFT over NTRU-Lattice-Based Digital Signature Algorithm) is the
//! NIST standardization of the Falcon signature scheme as FIPS 206.
//!
//! # Quick Start
//!
//! ```rust
//! use falcon::safe_api::{FnDsaKeyPair, FnDsaSignature, DomainSeparation};
//!
//! let kp = FnDsaKeyPair::generate(9).unwrap();
//! let sig = kp.sign(b"Hello, post-quantum world!", &DomainSeparation::None).unwrap();
//! FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), b"Hello, post-quantum world!", &DomainSeparation::None).unwrap();
//! ```
//!
//! # Domain Separation (FIPS 206 §6)
//!
//! FIPS 206 defines two signing modes:
//!
//! * **FN-DSA** (`ph_flag = 0x00`) — pure signing; the raw message is hashed
//!   inside the algorithm. Use [`DomainSeparation::None`] or
//!   [`DomainSeparation::Context`] for optional domain binding.
//!
//! * **HashFN-DSA** (`ph_flag = 0x01`) — hash-and-sign; the message is
//!   pre-hashed with SHA-256 or SHA-512 *before* signing.  Use
//!   [`DomainSeparation::Prehashed`] with a [`PreHashAlgorithm`] selector.
//!
//! ```rust
//! # use falcon::safe_api::{FnDsaKeyPair, FnDsaSignature, DomainSeparation, PreHashAlgorithm};
//! let kp = FnDsaKeyPair::generate(9).unwrap();
//!
//! // Pure FN-DSA with an application context string
//! let ctx = DomainSeparation::Context(b"my-protocol-v1");
//! let sig = kp.sign(b"msg", &ctx).unwrap();
//! FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), b"msg", &ctx).unwrap();
//!
//! // HashFN-DSA (pre-hash with SHA-256)
//! let ph = DomainSeparation::Prehashed { alg: PreHashAlgorithm::Sha256, context: b"" };
//! let sig2 = kp.sign(b"msg", &ph).unwrap();
//! FnDsaSignature::verify(sig2.to_bytes(), kp.public_key(), b"msg", &ph).unwrap();
//! ```
//!
//! # Security Levels
//!
//! | logn | Variant     | NIST Level | Private Key | Public Key | Signature |
//! |------|-------------|------------|-------------|------------|-----------|
//! | 9    | FN-DSA-512  | I          | 1281 B      | 897 B      | 666 B     |
//! | 10   | FN-DSA-1024 | V          | 2305 B      | 1793 B     | 1280 B    |

#![deny(missing_docs)]

use alloc::{vec, vec::Vec};
use core::fmt;

use zeroize::Zeroizing;

use crate::{
    falcon as falcon_api,
    rng::get_seed,
    shake::{i_shake256_flip, i_shake256_init, i_shake256_inject, InnerShake256Context},
};

// ======================================================================
// SHA-2 pure-Rust helpers (no external dependency)
// ======================================================================

/// Compute SHA-256 of `data`. Pure Rust, no_std compatible.
///
/// Exposed for integration-test NIST-vector validation.
/// Do not use directly in protocol code — use [`DomainSeparation::Prehashed`].
#[doc(hidden)]
pub fn sha256_public(data: &[u8]) -> [u8; 32] {
    sha256(data)
}

/// Compute SHA-512 of `data`. Pure Rust, no_std compatible.
///
/// Exposed for integration-test NIST-vector validation.
#[doc(hidden)]
pub fn sha512_public(data: &[u8]) -> [u8; 64] {
    sha512(data)
}

/// Compute SHA-256 of `data`. Pure Rust, no_std compatible.
fn sha256(data: &[u8]) -> [u8; 32] {
    // Initial hash values (first 32 bits of fractional parts of sqrt of primes 2..19)
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    // Round constants
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    // Pad the message: append 0x80, then zeros, then 64-bit bit-length (big-endian)
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg: Vec<u8> = Vec::with_capacity(data.len() + 64);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit (64-byte) chunk
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] =
            [h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, &v) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// Compute SHA-512 of `data`. Pure Rust, no_std compatible.
fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];
    const K: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];

    let bit_len = (data.len() as u128).wrapping_mul(8);
    let mut msg: Vec<u8> = Vec::with_capacity(data.len() + 128);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while (msg.len() % 128) != 112 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&[0u8; 8]); // high 64 bits of 128-bit length
    msg.extend_from_slice(&(bit_len as u64).to_be_bytes());

    for chunk in msg.chunks(128) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            let b = &chunk[8 * i..8 * i + 8];
            w[i] = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] =
            [h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]];
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 64];
    for (i, &v) in h.iter().enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&v.to_be_bytes());
    }
    out
}

// ======================================================================
// OID constants for HashFN-DSA (FIPS 206 Table 3)
// ======================================================================

/// ASN.1 DER OID for id-sha256 (2.16.840.1.101.3.4.2.1)
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// ASN.1 DER OID for id-sha512 (2.16.840.1.101.3.4.2.3)
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

// ======================================================================
// Domain Separation (FIPS 206)
// ======================================================================

/// Pre-hash algorithm selector for `HashFN-DSA` (FIPS 206 §6.2).
///
/// The message is hashed with the chosen algorithm before signing.
/// The algorithm OID is injected into the hash context so that sign
/// and verify must use matching algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PreHashAlgorithm {
    /// SHA-256 (32-byte digest, OID 2.16.840.1.101.3.4.2.1)
    Sha256,
    /// SHA-512 (64-byte digest, OID 2.16.840.1.101.3.4.2.3)
    Sha512,
}

impl PreHashAlgorithm {
    fn oid(self) -> &'static [u8] {
        match self {
            PreHashAlgorithm::Sha256 => OID_SHA256,
            PreHashAlgorithm::Sha512 => OID_SHA512,
        }
    }

    fn hash(self, msg: &[u8]) -> Vec<u8> {
        match self {
            PreHashAlgorithm::Sha256 => sha256(msg).to_vec(),
            PreHashAlgorithm::Sha512 => sha512(msg).to_vec(),
        }
    }
}

/// Domain separation context for FN-DSA / HashFN-DSA (FIPS 206 §6).
///
/// # Variants
///
/// * [`None`](DomainSeparation::None) — Pure FN-DSA, no context string
///   (`ph_flag = 0x00`, context length = 0).
///
/// * [`Context`](DomainSeparation::Context) — Pure FN-DSA with an
///   application context string (1–255 bytes, `ph_flag = 0x00`).
///
/// * [`Prehashed`](DomainSeparation::Prehashed) — HashFN-DSA mode
///   (`ph_flag = 0x01`). The message is pre-hashed; the algorithm OID
///   and optional context string are injected into the hash context.
///
/// # FIPS 206 Wire Format
///
/// For all variants the bytes injected into the hash context (after the
/// 40-byte nonce) are:
///
/// * Pure:  `ph_flag(0x00) || len(ctx) || ctx`
/// * Hashed: `ph_flag(0x01) || len(ctx) || ctx || OID || hash(msg)`
///
/// The context string **must not exceed 255 bytes**; passing a longer
/// slice returns `Err(FalconError::BadArgument)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DomainSeparation<'a> {
    /// No context string (pure FN-DSA, empty context).
    None,
    /// Application context string — max 255 bytes, pure FN-DSA.
    Context(&'a [u8]),
    /// HashFN-DSA mode: pre-hash the message with `alg`, optionally
    /// bind with `context` (max 255 bytes).
    Prehashed {
        /// Pre-hash algorithm.
        alg: PreHashAlgorithm,
        /// Optional context string (max 255 bytes).
        context: &'a [u8],
    },
}

impl<'a> DomainSeparation<'a> {
    /// Return `Err(BadArgument)` if the context string exceeds 255 bytes.
    fn validate_context(ctx: &[u8]) -> Result<(), FalconError> {
        if ctx.len() > 255 {
            return Err(FalconError::BadArgument);
        }
        Ok(())
    }

    /// Validate lengths. Call before sign/verify.
    pub(crate) fn validate(&self) -> Result<(), FalconError> {
        match self {
            DomainSeparation::None => Ok(()),
            DomainSeparation::Context(ctx) => Self::validate_context(ctx),
            DomainSeparation::Prehashed { context, .. } => Self::validate_context(context),
        }
    }

    /// `ph_flag` byte: 0x00 for pure FN-DSA, 0x01 for HashFN-DSA.
    fn ph_flag(&self) -> u8 {
        match self {
            DomainSeparation::Prehashed { .. } => 0x01,
            _ => 0x00,
        }
    }

    /// Inject `ph_flag || len(ctx) || ctx [|| OID]` into a SHAKE256 context.
    ///
    /// For `Prehashed`, the caller must subsequently inject the digest
    /// via `inject_prehash_digest`.
    pub(crate) fn inject_header(&self, sc: &mut InnerShake256Context) {
        let (ctx, oid) = match self {
            DomainSeparation::None => (&b""[..], None),
            DomainSeparation::Context(c) => (*c, None),
            DomainSeparation::Prehashed { alg, context } => (*context, Some(alg.oid())),
        };
        // ph_flag || len(ctx) || ctx
        let len = ctx.len().min(255) as u8;
        i_shake256_inject(sc, &[self.ph_flag(), len]);
        if len > 0 {
            i_shake256_inject(sc, &ctx[..len as usize]);
        }
        // For HashFN-DSA also inject the OID
        if let Some(o) = oid {
            i_shake256_inject(sc, o);
        }
    }

    /// For `Prehashed`, compute and inject `hash(message)`.
    /// For pure modes, inject `message` directly.
    pub(crate) fn inject_message(&self, sc: &mut InnerShake256Context, message: &[u8]) {
        match self {
            DomainSeparation::Prehashed { alg, .. } => {
                let digest = alg.hash(message);
                falcon_api::shake256_inject(sc, &digest);
            }
            _ => {
                falcon_api::shake256_inject(sc, message);
            }
        }
    }

    /// Convenience: inject the full domain + message into `sc`.
    pub(crate) fn inject(&self, sc: &mut InnerShake256Context, message: &[u8]) {
        self.inject_header(sc);
        self.inject_message(sc, message);
    }
}

// ======================================================================
// Error type
// ======================================================================

/// Errors returned by the FN-DSA API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FalconError {
    /// Random number generation failed.
    RandomError,
    /// A buffer was too small.
    SizeError,
    /// Invalid key or signature format.
    FormatError,
    /// Signature verification failed.
    BadSignature,
    /// An argument was invalid (e.g., logn out of range, context too long).
    BadArgument,
    /// Internal error in the algorithm.
    InternalError,
}

impl fmt::Display for FalconError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FalconError::RandomError => write!(f, "random number generation failed"),
            FalconError::SizeError => write!(f, "buffer size error"),
            FalconError::FormatError => write!(f, "invalid format"),
            FalconError::BadSignature => write!(f, "invalid signature"),
            FalconError::BadArgument => write!(f, "invalid argument"),
            FalconError::InternalError => write!(f, "internal error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FalconError {}

fn translate_error(rc: i32) -> FalconError {
    match rc {
        falcon_api::FALCON_ERR_RANDOM => FalconError::RandomError,
        falcon_api::FALCON_ERR_SIZE => FalconError::SizeError,
        falcon_api::FALCON_ERR_FORMAT => FalconError::FormatError,
        falcon_api::FALCON_ERR_BADSIG => FalconError::BadSignature,
        falcon_api::FALCON_ERR_BADARG => FalconError::BadArgument,
        falcon_api::FALCON_ERR_INTERNAL => FalconError::InternalError,
        _ => FalconError::InternalError,
    }
}

// ======================================================================
// Key pair
// ======================================================================

/// An FN-DSA key pair (private key + public key).
///
/// Use `logn = 9` for FN-DSA-512 (NIST Level I) or `logn = 10`
/// for FN-DSA-1024 (NIST Level V).
///
/// The private key bytes are **automatically zeroized on drop**.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FnDsaKeyPair {
    /// Private key bytes — zeroized on drop.
    privkey: Zeroizing<Vec<u8>>,
    /// Public key bytes.
    pubkey: Vec<u8>,
    /// Parameter: log2 of the lattice dimension (9 = FN-DSA-512, 10 = FN-DSA-1024).
    logn: u32,
}

/// Type alias for backward compatibility.
pub type FalconKeyPair = FnDsaKeyPair;

impl FnDsaKeyPair {
    /// Generate a new FN-DSA key pair using OS entropy.
    ///
    /// * `logn` — 9 for FN-DSA-512, 10 for FN-DSA-1024.
    pub fn generate(logn: u32) -> Result<Self, FalconError> {
        if logn < 1 || logn > 10 {
            return Err(FalconError::BadArgument);
        }
        let mut seed = [0u8; 48];
        if !get_seed(&mut seed) {
            return Err(FalconError::RandomError);
        }
        let result = Self::generate_deterministic(&seed, logn);
        for b in seed.iter_mut() {
            unsafe {
                core::ptr::write_volatile(b, 0);
            }
        }
        result
    }

    /// Generate a key pair deterministically from `seed`.
    pub fn generate_deterministic(seed: &[u8], logn: u32) -> Result<Self, FalconError> {
        if logn < 1 || logn > 10 {
            return Err(FalconError::BadArgument);
        }
        let sk_len = falcon_api::falcon_privkey_size(logn);
        let pk_len = falcon_api::falcon_pubkey_size(logn);
        let tmp_len = falcon_api::falcon_tmpsize_keygen(logn);

        let mut rng = InnerShake256Context::new();
        i_shake256_init(&mut rng);
        i_shake256_inject(&mut rng, seed);
        i_shake256_flip(&mut rng);

        let mut privkey = vec![0u8; sk_len];
        let mut pubkey = vec![0u8; pk_len];
        let mut tmp = vec![0u8; tmp_len];

        let rc = falcon_api::falcon_keygen_make(
            &mut rng,
            logn,
            &mut privkey,
            Some(&mut pubkey),
            &mut tmp,
        );
        if rc != 0 {
            return Err(translate_error(rc));
        }
        Ok(FnDsaKeyPair {
            privkey: Zeroizing::new(privkey),
            pubkey,
            logn,
        })
    }

    /// Reconstruct from previously exported private + public key bytes.
    pub fn from_keys(privkey: &[u8], pubkey: &[u8]) -> Result<Self, FalconError> {
        if privkey.is_empty() || pubkey.is_empty() {
            return Err(FalconError::FormatError);
        }
        let sk_logn = falcon_api::falcon_get_logn(privkey);
        let pk_logn = falcon_api::falcon_get_logn(pubkey);
        if sk_logn < 0 || pk_logn < 0 {
            return Err(FalconError::FormatError);
        }
        if (privkey[0] & 0xF0) != 0x50 {
            return Err(FalconError::FormatError);
        }
        if (pubkey[0] & 0xF0) != 0x00 {
            return Err(FalconError::FormatError);
        }
        let logn = (sk_logn & 0x0F) as u32;
        if logn != (pk_logn & 0x0F) as u32 {
            return Err(FalconError::FormatError);
        }
        if privkey.len() != falcon_api::falcon_privkey_size(logn) {
            return Err(FalconError::FormatError);
        }
        if pubkey.len() != falcon_api::falcon_pubkey_size(logn) {
            return Err(FalconError::FormatError);
        }
        Ok(FnDsaKeyPair {
            privkey: Zeroizing::new(privkey.to_vec()),
            pubkey: pubkey.to_vec(),
            logn,
        })
    }

    /// Reconstruct from a private key only (public key is recomputed).
    pub fn from_private_key(privkey: &[u8]) -> Result<Self, FalconError> {
        if privkey.is_empty() {
            return Err(FalconError::FormatError);
        }
        if (privkey[0] & 0xF0) != 0x50 {
            return Err(FalconError::FormatError);
        }
        let logn_val = falcon_api::falcon_get_logn(privkey);
        if logn_val < 0 {
            return Err(FalconError::FormatError);
        }
        let logn = logn_val as u32;
        if privkey.len() != falcon_api::falcon_privkey_size(logn) {
            return Err(FalconError::FormatError);
        }
        let pk_len = falcon_api::falcon_pubkey_size(logn);
        let tmp_len = falcon_api::falcon_tmpsize_makepub(logn);
        let mut pubkey = vec![0u8; pk_len];
        let mut tmp = vec![0u8; tmp_len];
        let rc = falcon_api::falcon_make_public(&mut pubkey, privkey, &mut tmp);
        if rc != 0 {
            return Err(translate_error(rc));
        }
        Ok(FnDsaKeyPair {
            privkey: Zeroizing::new(privkey.to_vec()),
            pubkey,
            logn,
        })
    }

    /// Compute the public key bytes from a private key without creating a key pair.
    pub fn public_key_from_private(privkey: &[u8]) -> Result<Vec<u8>, FalconError> {
        Ok(Self::from_private_key(privkey)?.pubkey)
    }

    /// Sign `message` using FIPS 206 domain separation.
    ///
    /// Supports both pure FN-DSA ([`DomainSeparation::None`] /
    /// [`DomainSeparation::Context`]) and HashFN-DSA
    /// ([`DomainSeparation::Prehashed`]).
    ///
    /// # Errors
    ///
    /// * [`FalconError::BadArgument`] — context string > 255 bytes.
    /// * [`FalconError::RandomError`] — OS RNG unavailable.
    pub fn sign(
        &self,
        message: &[u8],
        domain: &DomainSeparation,
    ) -> Result<FnDsaSignature, FalconError> {
        domain.validate()?;

        let sig_max = falcon_api::falcon_sig_ct_size(self.logn);
        let tmp_len = falcon_api::falcon_tmpsize_signdyn(self.logn);

        let mut seed = [0u8; 48];
        if !get_seed(&mut seed) {
            return Err(FalconError::RandomError);
        }
        let mut rng = InnerShake256Context::new();
        i_shake256_init(&mut rng);
        i_shake256_inject(&mut rng, &seed);
        i_shake256_flip(&mut rng);
        for b in seed.iter_mut() {
            unsafe {
                core::ptr::write_volatile(b, 0);
            }
        }

        let mut sig = vec![0u8; sig_max];
        let mut sig_len = sig_max;
        let mut tmp = vec![0u8; tmp_len];

        let mut nonce = [0u8; 40];
        falcon_api::shake256_extract(&mut rng, &mut nonce);
        let mut hd = InnerShake256Context::new();
        falcon_api::shake256_init(&mut hd);
        falcon_api::shake256_inject(&mut hd, &nonce);
        domain.inject(&mut hd, message);

        let rc = falcon_api::falcon_sign_dyn_finish(
            &mut rng,
            &mut sig,
            &mut sig_len,
            falcon_api::FALCON_SIG_CT,
            &self.privkey,
            &mut hd,
            &nonce,
            &mut tmp,
        );
        if rc != 0 {
            return Err(translate_error(rc));
        }
        sig.truncate(sig_len);
        Ok(FnDsaSignature { data: sig })
    }

    /// Sign with a deterministic seed (testing / reproducibility).
    ///
    /// The same `(key, message, seed, domain)` tuple always produces
    /// the same signature.
    ///
    /// # Errors
    ///
    /// * [`FalconError::BadArgument`] — context string > 255 bytes.
    pub fn sign_deterministic(
        &self,
        message: &[u8],
        seed: &[u8],
        domain: &DomainSeparation,
    ) -> Result<FnDsaSignature, FalconError> {
        domain.validate()?;

        let sig_max = falcon_api::falcon_sig_ct_size(self.logn);
        let tmp_len = falcon_api::falcon_tmpsize_signdyn(self.logn);

        let mut rng = InnerShake256Context::new();
        i_shake256_init(&mut rng);
        i_shake256_inject(&mut rng, seed);
        i_shake256_flip(&mut rng);

        let mut sig = vec![0u8; sig_max];
        let mut sig_len = sig_max;
        let mut tmp = vec![0u8; tmp_len];

        let mut nonce = [0u8; 40];
        falcon_api::shake256_extract(&mut rng, &mut nonce);
        let mut hd = InnerShake256Context::new();
        falcon_api::shake256_init(&mut hd);
        falcon_api::shake256_inject(&mut hd, &nonce);
        domain.inject(&mut hd, message);

        let rc = falcon_api::falcon_sign_dyn_finish(
            &mut rng,
            &mut sig,
            &mut sig_len,
            falcon_api::FALCON_SIG_CT,
            &self.privkey,
            &mut hd,
            &nonce,
            &mut tmp,
        );
        if rc != 0 {
            return Err(translate_error(rc));
        }
        sig.truncate(sig_len);
        Ok(FnDsaSignature { data: sig })
    }

    /// Get the encoded public key bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.pubkey
    }

    /// Get the encoded private key bytes.
    ///
    /// ⚠️ **Secret material** — handle with care.
    pub fn private_key(&self) -> &[u8] {
        &self.privkey
    }

    /// Get the FN-DSA degree parameter.
    ///
    /// Returns 9 for FN-DSA-512, 10 for FN-DSA-1024.
    pub fn logn(&self) -> u32 {
        self.logn
    }

    /// Get the security variant name.
    pub fn variant_name(&self) -> &'static str {
        match self.logn {
            9 => "FN-DSA-512",
            10 => "FN-DSA-1024",
            n => match n {
                1 => "FN-DSA-2",
                2 => "FN-DSA-4",
                3 => "FN-DSA-8",
                4 => "FN-DSA-16",
                5 => "FN-DSA-32",
                6 => "FN-DSA-64",
                7 => "FN-DSA-128",
                8 => "FN-DSA-256",
                _ => "FN-DSA-unknown",
            },
        }
    }
}

// ======================================================================
// Signature
// ======================================================================

/// An FN-DSA / HashFN-DSA digital signature.
///
/// Signature bytes are in constant-time (CT) format:
/// 666 bytes for FN-DSA-512, 1280 bytes for FN-DSA-1024.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FnDsaSignature {
    data: Vec<u8>,
}

/// Type alias for backward compatibility.
pub type FalconSignature = FnDsaSignature;

impl FnDsaSignature {
    /// Deserialize a signature from raw bytes.
    pub fn from_bytes(data: Vec<u8>) -> Self {
        FnDsaSignature { data }
    }

    /// Verify a signature against `pubkey` and `message`.
    ///
    /// The `domain` must exactly match what was used during signing
    /// (same variant, same context string, same pre-hash algorithm).
    ///
    /// Supports pure FN-DSA and HashFN-DSA transparently.
    ///
    /// # Errors
    ///
    /// * [`FalconError::BadArgument`]  — context string > 255 bytes.
    /// * [`FalconError::BadSignature`] — signature is invalid.
    /// * [`FalconError::FormatError`]  — malformed key or signature.
    pub fn verify(
        sig: &[u8],
        pubkey: &[u8],
        message: &[u8],
        domain: &DomainSeparation,
    ) -> Result<(), FalconError> {
        domain.validate()?;

        if pubkey.is_empty() || sig.is_empty() {
            return Err(FalconError::FormatError);
        }
        let logn_val = falcon_api::falcon_get_logn(pubkey);
        if logn_val < 0 {
            return Err(FalconError::FormatError);
        }
        let logn = logn_val as u32;
        let tmp_len = falcon_api::falcon_tmpsize_verify(logn);
        let mut tmp = vec![0u8; tmp_len];

        let mut hd = InnerShake256Context::new();
        let r = falcon_api::falcon_verify_start(&mut hd, sig);
        if r < 0 {
            return Err(translate_error(r));
        }
        domain.inject(&mut hd, message);
        let rc = falcon_api::falcon_verify_finish(sig, 0, pubkey, &mut hd, &mut tmp);
        if rc != 0 {
            return Err(translate_error(rc));
        }
        Ok(())
    }

    /// Get the raw signature bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Consume and return the owned byte vector.
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Signature length in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the signature byte vector is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// ======================================================================
// Expanded key (amortized multi-signature)
// ======================================================================

/// A precomputed Falcon signing tree for fast repeated signing.
///
/// Expanding a private key takes ~2.5× longer than a single sign operation,
/// but each subsequent `sign`/`sign_deterministic` call is ~1.5× faster
/// (no re-expansion). Use this when signing many messages with the same key.
///
/// The expanded key bytes are **automatically zeroized on drop**.
///
/// # Example
/// ```rust
/// use falcon::prelude::*;
///
/// let kp = FnDsaKeyPair::generate(9).unwrap();
/// let ek = kp.expand().unwrap();
///
/// let sig = ek.sign(b"message", &DomainSeparation::None).unwrap();
/// FnDsaSignature::verify(sig.to_bytes(), ek.public_key(), b"message",
///     &DomainSeparation::None).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct FnDsaExpandedKey {
    /// Expanded key bytes — contains the Falcon LDL tree; zeroized on drop.
    expanded: Zeroizing<Vec<u8>>,
    /// Public key bytes.
    pubkey: Vec<u8>,
    /// log2 lattice dimension.
    logn: u32,
}

impl FnDsaKeyPair {
    /// Expand the private key into a precomputed signing tree.
    ///
    /// The resulting [`FnDsaExpandedKey`] is ~1.5× faster per sign operation
    /// at the cost of a one-time expansion (~2.5× a single sign).
    pub fn expand(&self) -> Result<FnDsaExpandedKey, FalconError> {
        let logn = self.logn;
        let ek_len = falcon_api::falcon_expandedkey_size(logn);
        let tmp_len = falcon_api::falcon_tmpsize_expandpriv(logn);
        let mut expanded = vec![0u8; ek_len];
        let mut tmp = vec![0u8; tmp_len];
        let rc = falcon_api::falcon_expand_privkey(&mut expanded, &self.privkey, &mut tmp);
        if rc != 0 {
            return Err(translate_error(rc));
        }
        Ok(FnDsaExpandedKey {
            expanded: Zeroizing::new(expanded),
            pubkey: self.pubkey.clone(),
            logn,
        })
    }
}

impl FnDsaExpandedKey {
    /// Sign a message using OS entropy.
    pub fn sign(
        &self,
        message: &[u8],
        domain: &DomainSeparation<'_>,
    ) -> Result<FnDsaSignature, FalconError> {
        domain.validate()?;
        let logn = self.logn;
        let sig_max = falcon_api::falcon_sig_ct_size(logn);
        let tmp_len = falcon_api::falcon_tmpsize_signtree(logn);
        let mut sig = vec![0u8; sig_max];
        let mut sig_len = sig_max;
        let mut tmp = vec![0u8; tmp_len];

        let mut seed = [0u8; 48];
        if !get_seed(&mut seed) {
            return Err(FalconError::RandomError);
        }
        let mut rng = InnerShake256Context::new();
        i_shake256_init(&mut rng);
        i_shake256_inject(&mut rng, &seed);
        i_shake256_flip(&mut rng);
        for b in seed.iter_mut() {
            unsafe {
                core::ptr::write_volatile(b, 0);
            }
        }

        let mut hd = InnerShake256Context::new();
        let mut nonce = [0u8; 40];
        falcon_api::falcon_sign_start(&mut rng, &mut nonce, &mut hd);
        domain.inject(&mut hd, message);

        let rc = falcon_api::falcon_sign_tree_finish(
            &mut rng,
            &mut sig,
            &mut sig_len,
            falcon_api::FALCON_SIG_CT,
            &self.expanded,
            &mut hd,
            &nonce,
            &mut tmp,
        );
        if rc != 0 {
            return Err(translate_error(rc));
        }
        sig.truncate(sig_len);
        Ok(FnDsaSignature { data: sig })
    }

    /// Sign a message deterministically from a seed (for testing / `no_std`).
    pub fn sign_deterministic(
        &self,
        message: &[u8],
        sign_seed: &[u8],
        domain: &DomainSeparation<'_>,
    ) -> Result<FnDsaSignature, FalconError> {
        let logn = self.logn;
        let sig_max = falcon_api::falcon_sig_ct_size(logn);
        let tmp_len = falcon_api::falcon_tmpsize_signtree(logn);
        let mut sig = vec![0u8; sig_max];
        let mut sig_len = sig_max;
        let mut tmp = vec![0u8; tmp_len];

        let mut rng = InnerShake256Context::new();
        i_shake256_init(&mut rng);
        i_shake256_inject(&mut rng, sign_seed);
        i_shake256_flip(&mut rng);

        let mut hd = InnerShake256Context::new();
        let mut nonce = [0u8; 40];
        falcon_api::falcon_sign_start(&mut rng, &mut nonce, &mut hd);
        domain.inject(&mut hd, message);

        let rc = falcon_api::falcon_sign_tree_finish(
            &mut rng,
            &mut sig,
            &mut sig_len,
            falcon_api::FALCON_SIG_CT,
            &self.expanded,
            &mut hd,
            &nonce,
            &mut tmp,
        );
        if rc != 0 {
            return Err(translate_error(rc));
        }
        sig.truncate(sig_len);
        Ok(FnDsaSignature { data: sig })
    }

    /// The public key corresponding to this expanded key.
    pub fn public_key(&self) -> &[u8] {
        &self.pubkey
    }

    /// The `logn` parameter (9 = FN-DSA-512, 10 = FN-DSA-1024).
    pub fn logn(&self) -> u32 {
        self.logn
    }
}
