//! High-level safe Rust SDK for FN-DSA (draft FIPS 206) post-quantum
//! digital signatures.
//!
//! This layer wraps the [`crate::fndsa`] core (a port of c-fn-dsa) with
//! owned key and signature types, OS entropy, input validation, and a
//! fault-detection self-check on every signature.
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
//! # Message representative
//!
//! Every mode signs a 64-byte message representative `mu`, which binds the
//! SHAKE256 hash of the public key:
//!
//! * **FN-DSA** (pure): `mu = SHAKE256(H(pk) || 0x00 || len(ctx) || ctx || msg)`.
//!   Use [`DomainSeparation::None`] or [`DomainSeparation::Context`].
//! * **HashFN-DSA** (pre-hashed): `mu = SHAKE256(H(pk) || 0x01 || len(ctx) || ctx || OID || hash(msg))`.
//!   Use [`DomainSeparation::Prehashed`] with a [`PreHashAlgorithm`].
//! * **External mu**: [`DomainSeparation::ExternalMu`] signs a `mu` the caller
//!   computed (see [`crate::fndsa::compute_mu`]); the message argument is
//!   ignored.
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
//! | 9    | FN-DSA-512  | I          | 1345 B      | 897 B      | 666 B     |
//! | 10   | FN-DSA-1024 | V          | 2369 B      | 1793 B     | 1280 B    |

#![deny(missing_docs)]
#![deny(unsafe_code)]

use alloc::vec::Vec;
use core::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::{
    fndsa::{self, kgen, sign::DecodedSignKey, vrfy::DecodedVrfyKey, HashId},
    sha3::{sha3_256, sha3_512},
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
// OS entropy
// ======================================================================

/// Lets tests force the entropy source to fail.
#[cfg(all(test, feature = "getrandom"))]
pub(crate) static FORCE_RNG_FAILURE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "getrandom")]
fn forced_rng_failure() -> bool {
    #[cfg(test)]
    {
        FORCE_RNG_FAILURE.load(core::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(not(test))]
    {
        false
    }
}

/// Fill `buf` from the operating system's RNG.
#[cfg(feature = "getrandom")]
fn os_random(buf: &mut [u8]) -> Result<(), FalconError> {
    if !forced_rng_failure() && getrandom::getrandom(buf).is_ok() {
        Ok(())
    } else {
        Err(FalconError::RandomError)
    }
}

/// Without `std` there is no entropy source: use the `_deterministic`
/// entry points with caller-provided randomness.
#[cfg(not(feature = "getrandom"))]
fn os_random(_buf: &mut [u8]) -> Result<(), FalconError> {
    Err(FalconError::RandomError)
}

// ======================================================================
// Domain Separation
// ======================================================================

/// Pre-hash algorithm for HashFN-DSA.
///
/// The message is hashed with the chosen function, and the function's DER
/// OID is bound into `mu`, so signer and verifier must agree on it. Other
/// hash functions with a registered identifier (SHA-384, SHA-512/256,
/// SHAKE128/256, ...) are available through [`crate::fndsa`] with a digest
/// the caller computes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PreHashAlgorithm {
    /// SHA-256 (2.16.840.1.101.3.4.2.1)
    Sha256,
    /// SHA-512 (2.16.840.1.101.3.4.2.3)
    Sha512,
    /// SHA3-256 (2.16.840.1.101.3.4.2.8)
    Sha3_256,
    /// SHA3-512 (2.16.840.1.101.3.4.2.10)
    Sha3_512,
}

impl PreHashAlgorithm {
    fn id(self) -> HashId<'static> {
        match self {
            PreHashAlgorithm::Sha256 => fndsa::HASH_ID_SHA256,
            PreHashAlgorithm::Sha512 => fndsa::HASH_ID_SHA512,
            PreHashAlgorithm::Sha3_256 => fndsa::HASH_ID_SHA3_256,
            PreHashAlgorithm::Sha3_512 => fndsa::HASH_ID_SHA3_512,
        }
    }

    fn hash(self, msg: &[u8]) -> Vec<u8> {
        match self {
            PreHashAlgorithm::Sha256 => sha256(msg).to_vec(),
            PreHashAlgorithm::Sha512 => sha512(msg).to_vec(),
            PreHashAlgorithm::Sha3_256 => sha3_256(msg).to_vec(),
            PreHashAlgorithm::Sha3_512 => sha3_512(msg).to_vec(),
        }
    }
}

/// How the message is turned into the signed representative `mu`.
///
/// Context strings are at most 255 bytes; a longer one is rejected with
/// [`FalconError::BadArgument`], never truncated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DomainSeparation<'a> {
    /// Pure FN-DSA, empty context.
    None,
    /// Pure FN-DSA with an application context string.
    Context(&'a [u8]),
    /// HashFN-DSA: the message is pre-hashed with `alg`.
    Prehashed {
        /// Pre-hash algorithm.
        alg: PreHashAlgorithm,
        /// Context string (may be empty).
        context: &'a [u8],
    },
    /// Sign or verify a caller-computed 64-byte `mu` (see
    /// [`crate::fndsa::compute_mu`]); the message argument is ignored. Any
    /// other length is rejected with [`FalconError::BadArgument`].
    ExternalMu(&'a [u8]),
}

impl DomainSeparation<'_> {
    /// Check lengths. Called by every sign and verify entry point.
    pub(crate) fn validate(&self) -> Result<(), FalconError> {
        let ok = match self {
            DomainSeparation::None => true,
            DomainSeparation::Context(ctx) | DomainSeparation::Prehashed { context: ctx, .. } => {
                ctx.len() <= 255
            }
            DomainSeparation::ExternalMu(mu) => mu.len() == 64,
        };
        if ok {
            Ok(())
        } else {
            Err(FalconError::BadArgument)
        }
    }

    /// Run `f` on the `(context, hash identifier, input)` triple that the
    /// core expects for `message`.
    fn with_input<R>(&self, message: &[u8], f: impl FnOnce(&[u8], HashId<'_>, &[u8]) -> R) -> R {
        match *self {
            DomainSeparation::None => f(b"", HashId::Raw, message),
            DomainSeparation::Context(ctx) => f(ctx, HashId::Raw, message),
            DomainSeparation::Prehashed { alg, context } => {
                f(context, alg.id(), &alg.hash(message))
            }
            DomainSeparation::ExternalMu(mu) => f(b"", HashId::ExternalMu, mu),
        }
    }
}

// ======================================================================
// Error type
// ======================================================================

/// Errors returned by the FN-DSA API.
///
/// Marked `#[non_exhaustive]`: match on it with a `_` arm, so that a future
/// variant is not a breaking change for you.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FalconError {
    /// Random number generation failed (or no entropy source without `std`).
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
    /// A freshly produced signature failed its own verification.
    ///
    /// Signing re-runs verification with the public key before returning.
    /// A mismatch means the computation was corrupted between the two —
    /// fault injection, or failing hardware. The signature is discarded
    /// rather than returned: a signature computed from a corrupted
    /// intermediate state can expose the private basis. Treat this as a
    /// security event, not a retryable error.
    FaultDetected,
}

impl fmt::Display for FalconError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            FalconError::RandomError => "random number generation failed",
            FalconError::SizeError => "buffer size error",
            FalconError::FormatError => "invalid format",
            FalconError::BadSignature => "invalid signature",
            FalconError::BadArgument => "invalid argument",
            FalconError::InternalError => "internal error",
            FalconError::FaultDetected => "signature failed its own verification (fault detected)",
        };
        f.write_str(s)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FalconError {}

/// Minimum seed length accepted by [`FnDsaKeyPair::generate_deterministic`].
pub const MIN_KEYGEN_SEED_LEN: usize = 32;

/// The degrees FIPS 206 standardizes: 9 (FN-DSA-512) and 10 (FN-DSA-1024).
#[inline]
const fn is_fips_logn(logn: u32) -> bool {
    matches!(logn, 9 | 10)
}

/// Decode a signing key, distinguishing a non-standard degree
/// ([`FalconError::BadArgument`]) from a malformed encoding
/// ([`FalconError::FormatError`]). The verifying-key hash stored in the key
/// must match the key itself.
fn decode_sign_key(privkey: &[u8]) -> Result<DecodedSignKey, FalconError> {
    let head = *privkey.first().ok_or(FalconError::FormatError)?;
    if (head & 0xF0) != 0x50 {
        return Err(FalconError::FormatError);
    }
    if !is_fips_logn((head & 0x0F) as u32) {
        return Err(FalconError::BadArgument);
    }
    let key = DecodedSignKey::decode(privkey, 9, 10).ok_or(FalconError::FormatError)?;
    if fndsa::hashed_vrfykey_from_vrfykey(key.vrfy_key()) != *key.hashed_vrfy_key() {
        return Err(FalconError::FormatError);
    }
    Ok(key)
}

/// Sign with a decoded key and self-check the result.
fn sign_with(
    key: &DecodedSignKey,
    pubkey: &[u8],
    message: &[u8],
    rnd: &[u8],
    domain: &DomainSeparation<'_>,
) -> Result<FnDsaSignature, FalconError> {
    domain.validate()?;
    // `sign` fails only when mu cannot be formed (ruled out by validate())
    // or when 27 attempts are all rejected, which for a valid key has
    // probability below 2^-256 and so indicates a fault. The empty
    // placeholder then fails the self-check, which reports FaultDetected.
    let sig = domain
        .with_input(message, |ctx, id, hv| key.sign(ctx, id, hv, rnd))
        .unwrap_or_default();
    checked_signature(sig, pubkey, message, domain)
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
///
/// # Serialization
///
/// With the `serde` feature, serializing this type **writes the private key
/// out in the clear**. That is the point of the impl, but it means a keypair
/// must never be serialized into a log, a trace, an error report, or any
/// store you would not put a raw private key into. Deserialization goes
/// through [`FnDsaKeyPair::from_keys`], so a tampered blob is rejected rather
/// than producing an invalid key pair.
///
/// **Note:** `Clone` duplicates private key material in memory.
/// Only clone when you need multiple owners; prefer references otherwise.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "KeyPairRepr"))]
pub struct FnDsaKeyPair {
    /// Private key bytes — zeroized on drop.
    privkey: Zeroizing<Vec<u8>>,
    /// Public key bytes.
    pubkey: Vec<u8>,
    /// log2 of the lattice dimension (9 = FN-DSA-512, 10 = FN-DSA-1024).
    logn: u32,
}

/// The wire form of [`FnDsaKeyPair`], deserialized through
/// [`FnDsaKeyPair::from_keys`] so that a hostile or corrupted blob cannot
/// produce a key pair the constructors would have rejected.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct KeyPairRepr {
    privkey: Zeroizing<Vec<u8>>,
    pubkey: Vec<u8>,
    logn: u32,
}

#[cfg(feature = "serde")]
impl TryFrom<KeyPairRepr> for FnDsaKeyPair {
    type Error = FalconError;

    fn try_from(repr: KeyPairRepr) -> Result<Self, Self::Error> {
        let kp = FnDsaKeyPair::from_keys(&repr.privkey, &repr.pubkey)?;
        // The degree is derived from the key headers, so a `logn` field that
        // disagrees with them means the blob was tampered with.
        if kp.logn != repr.logn {
            return Err(FalconError::FormatError);
        }
        Ok(kp)
    }
}

impl fmt::Debug for FnDsaKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FnDsaKeyPair")
            .field("privkey", &"[REDACTED]")
            .field("pubkey_len", &self.pubkey.len())
            .field("logn", &self.logn)
            .finish()
    }
}

/// Type alias for backward compatibility.
pub type FalconKeyPair = FnDsaKeyPair;

impl FnDsaKeyPair {
    /// Generate a new FN-DSA key pair from 32 bytes of OS entropy.
    ///
    /// * `logn` — 9 for FN-DSA-512, 10 for FN-DSA-1024.
    pub fn generate(logn: u32) -> Result<Self, FalconError> {
        if !is_fips_logn(logn) {
            return Err(FalconError::BadArgument);
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        os_random(&mut seed[..])?;
        Self::generate_deterministic(&seed[..], logn)
    }

    /// Generate a key pair deterministically from `seed`. The same seed
    /// always gives the same key pair.
    ///
    /// # Security
    ///
    /// The key is exactly as secret as `seed`: it must hold at least 256
    /// bits of entropy and be kept as secret as the private key. Seeds
    /// shorter than [`MIN_KEYGEN_SEED_LEN`] (32 bytes) are rejected with
    /// [`FalconError::BadArgument`]; length is no proof of entropy, but a
    /// short seed is proof of its absence. (The low-level
    /// [`crate::fndsa::kgen::keygen_seeded`] accepts any length, for test
    /// vectors.)
    pub fn generate_deterministic(seed: &[u8], logn: u32) -> Result<Self, FalconError> {
        if !is_fips_logn(logn) || seed.len() < MIN_KEYGEN_SEED_LEN {
            return Err(FalconError::BadArgument);
        }
        let (privkey, pubkey) = kgen::keygen_seeded(logn, seed);
        Ok(FnDsaKeyPair {
            privkey,
            pubkey,
            logn,
        })
    }

    /// Import a key pair from its encoded private and public keys.
    ///
    /// Malformed encodings give [`FalconError::FormatError`], non-standard
    /// degrees [`FalconError::BadArgument`], and a public key that does not
    /// belong to the private key [`FalconError::BadArgument`].
    pub fn from_keys(privkey: &[u8], pubkey: &[u8]) -> Result<Self, FalconError> {
        let kp = Self::from_private_key(privkey)?;
        let head = *pubkey.first().ok_or(FalconError::FormatError)?;
        if (head & 0xF0) != 0x00 {
            return Err(FalconError::FormatError);
        }
        if !is_fips_logn(head as u32) {
            return Err(FalconError::BadArgument);
        }
        DecodedVrfyKey::decode(pubkey, 9, 10).ok_or(FalconError::FormatError)?;
        if kp.pubkey != pubkey {
            return Err(FalconError::BadArgument);
        }
        Ok(kp)
    }

    /// Import a key pair from the private key alone; the public key is
    /// recomputed from it.
    pub fn from_private_key(privkey: &[u8]) -> Result<Self, FalconError> {
        let key = decode_sign_key(privkey)?;
        Ok(FnDsaKeyPair {
            privkey: Zeroizing::new(privkey.to_vec()),
            pubkey: key.vrfy_key().to_vec(),
            logn: key.logn(),
        })
    }

    /// The public key belonging to `privkey`.
    pub fn public_key_from_private(privkey: &[u8]) -> Result<Vec<u8>, FalconError> {
        Ok(Self::from_private_key(privkey)?.pubkey)
    }

    /// Every constructor validates the private key, so decoding it again
    /// cannot fail.
    fn decoded(&self) -> DecodedSignKey {
        decode_sign_key(&self.privkey).expect("private key validated at construction")
    }

    /// Sign `message`, hedged with 40 bytes of OS entropy.
    ///
    /// The result is verified against the public key before it is returned;
    /// see [`FalconError::FaultDetected`].
    pub fn sign(
        &self,
        message: &[u8],
        domain: &DomainSeparation,
    ) -> Result<FnDsaSignature, FalconError> {
        let mut rnd = Zeroizing::new([0u8; 40]);
        os_random(&mut rnd[..])?;
        sign_with(&self.decoded(), &self.pubkey, message, &rnd[..], domain)
    }

    /// Sign `message` deterministically: the same key, message, domain and
    /// `seed` always give the same signature. `seed` replaces the OS
    /// randomness of [`sign`](Self::sign); it never needs to be secret for
    /// security, but distinct seeds give distinct signatures.
    pub fn sign_deterministic(
        &self,
        message: &[u8],
        seed: &[u8],
        domain: &DomainSeparation,
    ) -> Result<FnDsaSignature, FalconError> {
        sign_with(&self.decoded(), &self.pubkey, message, seed, domain)
    }

    /// The encoded public key.
    pub fn public_key(&self) -> &[u8] {
        &self.pubkey
    }

    /// The encoded private key.
    ///
    /// Handle with care: whoever holds these bytes can sign.
    pub fn private_key(&self) -> &[u8] {
        &self.privkey
    }

    /// log2 of the lattice dimension: 9 or 10.
    pub fn logn(&self) -> u32 {
        self.logn
    }

    /// `"FN-DSA-512"` or `"FN-DSA-1024"`.
    pub fn variant_name(&self) -> &'static str {
        if self.logn == 9 {
            "FN-DSA-512"
        } else {
            "FN-DSA-1024"
        }
    }

    /// Decode the private key once into an [`FnDsaExpandedKey`], which
    /// signs repeatedly without re-decoding it.
    pub fn expand(&self) -> Result<FnDsaExpandedKey, FalconError> {
        Ok(FnDsaExpandedKey {
            key: self.decoded(),
            pubkey: self.pubkey.clone(),
        })
    }
}

// ======================================================================
// Signature
// ======================================================================

/// An FN-DSA signature: header `0x30 + logn`, 40-byte nonce, compressed
/// `s2`, zero-padded to the fixed size (666 or 1280 bytes).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "SignatureRepr"))]
pub struct FnDsaSignature {
    data: Vec<u8>,
}

/// Type alias for backward compatibility.
pub type FalconSignature = FnDsaSignature;

/// The wire form of [`FnDsaSignature`], deserialized through
/// [`FnDsaSignature::from_bytes`] so that the header and size are checked.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct SignatureRepr {
    data: Vec<u8>,
}

#[cfg(feature = "serde")]
impl TryFrom<SignatureRepr> for FnDsaSignature {
    type Error = FalconError;

    fn try_from(repr: SignatureRepr) -> Result<Self, Self::Error> {
        FnDsaSignature::from_bytes(repr.data)
    }
}

impl FnDsaSignature {
    /// Wrap encoded signature bytes, checking the header and the size.
    ///
    /// This does not verify the signature; use [`FnDsaSignature::verify`].
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, FalconError> {
        let head = *data.first().ok_or(FalconError::FormatError)?;
        if (head & 0xF0) != 0x30 {
            return Err(FalconError::FormatError);
        }
        let logn = (head & 0x0F) as u32;
        if !is_fips_logn(logn) {
            return Err(FalconError::BadArgument);
        }
        if data.len() != fndsa::signature_size(logn) {
            return Err(FalconError::FormatError);
        }
        Ok(FnDsaSignature { data })
    }

    /// Verify `sig` over `message` under `pubkey`.
    ///
    /// Errors: [`FalconError::BadArgument`] for an invalid domain or a
    /// non-standard degree, [`FalconError::FormatError`] for a malformed
    /// key or signature, [`FalconError::BadSignature`] if verification fails.
    pub fn verify(
        sig: &[u8],
        pubkey: &[u8],
        message: &[u8],
        domain: &DomainSeparation,
    ) -> Result<(), FalconError> {
        domain.validate()?;
        let head = *pubkey.first().ok_or(FalconError::FormatError)?;
        if (head & 0xF0) != 0x00 {
            return Err(FalconError::FormatError);
        }
        let logn = head as u32;
        if !is_fips_logn(logn) {
            return Err(FalconError::BadArgument);
        }
        let key = DecodedVrfyKey::decode(pubkey, 9, 10).ok_or(FalconError::FormatError)?;
        if sig.len() != fndsa::signature_size(logn) || sig[0] != 0x30 + logn as u8 {
            return Err(FalconError::FormatError);
        }
        if domain.with_input(message, |ctx, id, hv| key.verify(sig, ctx, id, hv)) {
            Ok(())
        } else {
            Err(FalconError::BadSignature)
        }
    }

    /// The encoded signature.
    pub fn to_bytes(&self) -> &[u8] {
        &self.data
    }

    /// The encoded signature, by value.
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Always `false` for a constructed signature.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// ======================================================================
// Expanded key (amortized multi-signature)
// ======================================================================

/// A private key decoded once — `f`, `g`, `F`, the recomputed `G` and the
/// basis in FFT form — for repeated signing without re-decoding.
///
/// All secret material is **zeroized on drop**.
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
#[derive(Clone)]
pub struct FnDsaExpandedKey {
    key: DecodedSignKey,
    pubkey: Vec<u8>,
}

impl fmt::Debug for FnDsaExpandedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FnDsaExpandedKey")
            .field("expanded", &"[REDACTED]")
            .field("pubkey_len", &self.pubkey.len())
            .field("logn", &self.key.logn())
            .finish()
    }
}

impl FnDsaExpandedKey {
    /// Sign `message`, hedged with OS entropy; see [`FnDsaKeyPair::sign`].
    pub fn sign(
        &self,
        message: &[u8],
        domain: &DomainSeparation,
    ) -> Result<FnDsaSignature, FalconError> {
        let mut rnd = Zeroizing::new([0u8; 40]);
        os_random(&mut rnd[..])?;
        sign_with(&self.key, &self.pubkey, message, &rnd[..], domain)
    }

    /// Sign deterministically; see [`FnDsaKeyPair::sign_deterministic`].
    pub fn sign_deterministic(
        &self,
        message: &[u8],
        seed: &[u8],
        domain: &DomainSeparation,
    ) -> Result<FnDsaSignature, FalconError> {
        sign_with(&self.key, &self.pubkey, message, seed, domain)
    }

    /// The encoded public key.
    pub fn public_key(&self) -> &[u8] {
        &self.pubkey
    }

    /// log2 of the lattice dimension: 9 or 10.
    pub fn logn(&self) -> u32 {
        self.key.logn()
    }
}

/// Verify a freshly computed signature before handing it out.
///
/// Lattice signatures leak the private basis when they are produced from a
/// corrupted intermediate state, which makes fault injection a practical
/// attack on any target an adversary can touch. Recomputing the
/// verification from the public key turns a fault that yields an invalid
/// signature into a [`FalconError::FaultDetected`] error instead of a leak.
/// Faults that still yield a valid signature are not caught.
fn checked_signature(
    sig: Vec<u8>,
    pubkey: &[u8],
    message: &[u8],
    domain: &DomainSeparation<'_>,
) -> Result<FnDsaSignature, FalconError> {
    if FnDsaSignature::verify(&sig, pubkey, message, domain).is_ok() {
        Ok(FnDsaSignature { data: sig })
    } else {
        // A signature produced from a corrupted state is exactly the
        // artifact that can expose the private basis, so it is wiped
        // rather than merely dropped.
        let mut sig = sig;
        sig.zeroize();
        Err(FalconError::FaultDetected)
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;

    fn kp() -> FnDsaKeyPair {
        FnDsaKeyPair::generate_deterministic(b"safe_api unit tests: 32-byte seed", 9).unwrap()
    }

    #[test]
    fn self_check_rejects_corrupted_signature() {
        let kp = kp();
        let msg = b"fault injection target";
        let bytes = kp
            .sign_deterministic(msg, b"r", &DomainSeparation::None)
            .unwrap()
            .into_bytes();
        for pos in [41usize, bytes.len() / 2, bytes.len() - 1] {
            let mut bad = bytes.clone();
            bad[pos] ^= 0x01;
            assert_eq!(
                checked_signature(bad, kp.public_key(), msg, &DomainSeparation::None).unwrap_err(),
                FalconError::FaultDetected,
                "flipped bit at byte {pos} was not caught"
            );
        }
    }

    #[test]
    #[cfg(feature = "getrandom")]
    fn entropy_failure_is_reported() {
        use core::sync::atomic::Ordering;
        let kp = kp();
        let ek = kp.expand().unwrap();
        FORCE_RNG_FAILURE.store(true, Ordering::Relaxed);
        let a = FnDsaKeyPair::generate(9).unwrap_err();
        let b = kp.sign(b"m", &DomainSeparation::None).unwrap_err();
        let c = ek.sign(b"m", &DomainSeparation::None).unwrap_err();
        FORCE_RNG_FAILURE.store(false, Ordering::Relaxed);
        assert_eq!([a, b, c], [FalconError::RandomError; 3]);
    }

    #[test]
    fn every_error_renders() {
        for err in [
            FalconError::RandomError,
            FalconError::SizeError,
            FalconError::FormatError,
            FalconError::BadSignature,
            FalconError::BadArgument,
            FalconError::InternalError,
            FalconError::FaultDetected,
        ] {
            let text = format!("{err}");
            assert!(!text.is_empty(), "{err:?} has no message");
        }
    }

    #[test]
    fn signing_key_with_a_wrong_public_key_hash_is_rejected() {
        let kp = kp();
        let mut sk = kp.private_key().to_vec();
        let last = sk.len() - 1;
        sk[last] ^= 1;
        assert_eq!(
            FnDsaKeyPair::from_private_key(&sk).unwrap_err(),
            FalconError::FormatError
        );
    }
}
