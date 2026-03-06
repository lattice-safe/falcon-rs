//! High-level safe Rust SDK for FN-DSA (FIPS 206) post-quantum digital signatures.
//!
//! This module provides ergonomic types for key generation, signing,
//! verification, and key/signature serialization — hiding all `unsafe`
//! operations behind a safe Rust interface.
//!
//! FN-DSA (FFT over NTRU-Lattice-Based Digital Signature Algorithm) is the
//! NIST standardization of the Falcon signature scheme as FIPS 206.
//!
//! # Quick Start
//!
//! ```rust
//! use falcon::safe_api::{FnDsaKeyPair, FnDsaSignature, DomainSeparation};
//!
//! // Generate an FN-DSA-512 key pair
//! let kp = FnDsaKeyPair::generate(9).unwrap();
//!
//! // Sign a message (with no domain separation context)
//! let sig = kp.sign(b"Hello, post-quantum world!", &DomainSeparation::None).unwrap();
//!
//! // Verify the signature
//! FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), b"Hello, post-quantum world!", &DomainSeparation::None).unwrap();
//! ```
//!
//! # Domain Separation (FIPS 206)
//!
//! FIPS 206 introduces mandatory domain separation for signing and
//! verification. A context string (0–255 bytes) is injected into the
//! hash before the message:
//!
//! ```rust
//! # use falcon::safe_api::{FnDsaKeyPair, FnDsaSignature, DomainSeparation};
//! let kp = FnDsaKeyPair::generate(9).unwrap();
//!
//! // Sign with a custom domain context
//! let ctx = DomainSeparation::Context(b"my-protocol-v1");
//! let sig = kp.sign(b"msg", &ctx).unwrap();
//!
//! // Verify must use the same context
//! FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), b"msg", &ctx).unwrap();
//! ```
//!
//! # Serialization
//!
//! Keys and signatures can be serialized to bytes and restored:
//!
//! ```rust
//! # use falcon::safe_api::FnDsaKeyPair;
//! let kp = FnDsaKeyPair::generate(9).unwrap();
//!
//! // Export keys
//! let sk_bytes = kp.private_key().to_vec();
//! let pk_bytes = kp.public_key().to_vec();
//!
//! // Reconstruct key pair from exported bytes
//! let kp2 = FnDsaKeyPair::from_keys(&sk_bytes, &pk_bytes).unwrap();
//!
//! // Or reconstruct public key from private key alone
//! let pk_only = FnDsaKeyPair::public_key_from_private(&sk_bytes).unwrap();
//! assert_eq!(pk_bytes, pk_only);
//! ```
//!
//! # Security Levels
//!
//! | logn | Variant | NIST Level | Private Key | Public Key | Signature |
//! |------|---------|------------|-------------|------------|-----------|
//! | 9 | FN-DSA-512 | I | 1281 B | 897 B | 666 B |
//! | 10 | FN-DSA-1024 | V | 2305 B | 1793 B | 1280 B |

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use crate::falcon as falcon_api;
use crate::rng::get_seed;
use crate::shake::{i_shake256_flip, i_shake256_init, i_shake256_inject, InnerShake256Context};

// ======================================================================
// Domain Separation (FIPS 206)
// ======================================================================

/// Domain separation context for FN-DSA (FIPS 206).
///
/// FIPS 206 mandates that all signing and verification operations include
/// a domain separation prefix. This prevents cross-protocol signature
/// reuse attacks.
///
/// # Variants
///
/// * `None` — No context string (0x00 prefix byte, context length 0).
///   This is the default for backward-compatible usage.
/// * `Context(&[u8])` — A context string of up to 255 bytes.
pub enum DomainSeparation<'a> {
    /// No domain context (empty context).
    None,
    /// A context string (max 255 bytes).
    Context(&'a [u8]),
}

impl<'a> DomainSeparation<'a> {
    /// Inject the domain separation prefix into a SHAKE256 hash context.
    ///
    /// Format: `0x00 || len(context) || context`
    pub(crate) fn inject(&self, sc: &mut InnerShake256Context) {
        match self {
            DomainSeparation::None => {
                i_shake256_inject(sc, &[0x00, 0x00]);
            }
            DomainSeparation::Context(ctx) => {
                let len = ctx.len().min(255) as u8;
                i_shake256_inject(sc, &[0x00, len]);
                i_shake256_inject(sc, &ctx[..len as usize]);
            }
        }
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
    /// An argument was invalid (e.g., logn out of range).
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
/// The key pair stores encoded keys in the FN-DSA wire format.
/// Use `logn = 9` for FN-DSA-512 (NIST Level I) or `logn = 10`
/// for FN-DSA-1024 (NIST Level V).
///
/// # Serialization
///
/// ```rust
/// # use falcon::safe_api::FnDsaKeyPair;
/// let kp = FnDsaKeyPair::generate(9).unwrap();
///
/// // Export
/// let sk = kp.private_key().to_vec();
/// let pk = kp.public_key().to_vec();
///
/// // Import
/// let kp2 = FnDsaKeyPair::from_keys(&sk, &pk).unwrap();
/// assert_eq!(kp.public_key(), kp2.public_key());
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FnDsaKeyPair {
    privkey: Vec<u8>,
    pubkey: Vec<u8>,
    logn: u32,
}

/// Type alias for backward compatibility.
pub type FalconKeyPair = FnDsaKeyPair;

impl FnDsaKeyPair {
    /// Generate a new FN-DSA key pair using OS entropy.
    ///
    /// # Arguments
    ///
    /// * `logn` — Degree parameter: 9 for FN-DSA-512, 10 for FN-DSA-1024.
    ///   Values 1–8 are research-only reduced variants.
    ///
    /// # Errors
    ///
    /// * [`FalconError::BadArgument`] if `logn` is outside 1–10.
    /// * [`FalconError::RandomError`] if the OS RNG is unavailable.
    pub fn generate(logn: u32) -> Result<Self, FalconError> {
        if logn < 1 || logn > 10 {
            return Err(FalconError::BadArgument);
        }

        let mut seed = [0u8; 48];
        if !get_seed(&mut seed) {
            return Err(FalconError::RandomError);
        }

        let result = Self::generate_deterministic(&seed, logn);

        // Zeroize seed
        for b in seed.iter_mut() {
            unsafe {
                core::ptr::write_volatile(b, 0);
            }
        }

        result
    }

    /// Generate a new FN-DSA key pair from a deterministic seed.
    ///
    /// The seed is fed into a SHAKE256-based PRNG. The **same seed
    /// always produces the same key pair**, making this ideal for
    /// test vector reproducibility.
    ///
    /// # Arguments
    ///
    /// * `seed` — Entropy seed (≥ 32 bytes recommended).
    /// * `logn` — Degree parameter: 9 for FN-DSA-512, 10 for FN-DSA-1024.
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
            privkey,
            pubkey,
            logn,
        })
    }

    /// Reconstruct a key pair from previously exported private and public key bytes.
    ///
    /// Both keys must be valid FN-DSA-encoded keys with matching degree.
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
            privkey: privkey.to_vec(),
            pubkey: pubkey.to_vec(),
            logn,
        })
    }

    /// Reconstruct a key pair from a private key only.
    ///
    /// The public key is recomputed from the private key.
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
            privkey: privkey.to_vec(),
            pubkey,
            logn,
        })
    }

    /// Compute the public key bytes from a private key without creating a key pair.
    pub fn public_key_from_private(privkey: &[u8]) -> Result<Vec<u8>, FalconError> {
        let kp = Self::from_private_key(privkey)?;
        Ok(kp.pubkey)
    }

    /// Sign a message using this key pair with FIPS 206 domain separation.
    ///
    /// Uses the constant-time (CT) signature format and OS entropy.
    /// Each call produces a **different signature** due to random nonce
    /// generation.
    pub fn sign(&self, message: &[u8], domain: &DomainSeparation) -> Result<FnDsaSignature, FalconError> {
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
            unsafe { core::ptr::write_volatile(b, 0); }
        }

        let mut sig = vec![0u8; sig_max];
        let mut sig_len = sig_max;
        let mut tmp = vec![0u8; tmp_len];

        // Build hash context with domain separation
        let mut nonce = [0u8; 40];
        falcon_api::shake256_extract(&mut rng, &mut nonce);
        let mut hash_data = InnerShake256Context::new();
        falcon_api::shake256_init(&mut hash_data);
        falcon_api::shake256_inject(&mut hash_data, &nonce);
        domain.inject(&mut hash_data);
        falcon_api::shake256_inject(&mut hash_data, message);

        let rc = falcon_api::falcon_sign_dyn_finish(
            &mut rng,
            &mut sig,
            &mut sig_len,
            falcon_api::FALCON_SIG_CT,
            &self.privkey,
            &mut hash_data,
            &nonce,
            &mut tmp,
        );
        if rc != 0 {
            return Err(translate_error(rc));
        }

        sig.truncate(sig_len);
        Ok(FnDsaSignature { data: sig })
    }

    /// Sign a message with a deterministic seed (for testing / reproducibility).
    ///
    /// The same `(key, message, seed, domain)` tuple **always produces the same
    /// signature**.
    pub fn sign_deterministic(
        &self,
        message: &[u8],
        seed: &[u8],
        domain: &DomainSeparation,
    ) -> Result<FnDsaSignature, FalconError> {
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
        let mut hash_data = InnerShake256Context::new();
        falcon_api::shake256_init(&mut hash_data);
        falcon_api::shake256_inject(&mut hash_data, &nonce);
        domain.inject(&mut hash_data);
        falcon_api::shake256_inject(&mut hash_data, message);

        let rc = falcon_api::falcon_sign_dyn_finish(
            &mut rng,
            &mut sig,
            &mut sig_len,
            falcon_api::FALCON_SIG_CT,
            &self.privkey,
            &mut hash_data,
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

/// An FN-DSA digital signature.
///
/// Contains the encoded signature bytes in constant-time (CT) format.
/// The total size is fixed for CT format
/// (666 bytes for FN-DSA-512, 1280 bytes for FN-DSA-1024).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FnDsaSignature {
    data: Vec<u8>,
}

/// Type alias for backward compatibility.
pub type FalconSignature = FnDsaSignature;

impl FnDsaSignature {
    /// Create a signature from raw bytes (deserialization).
    pub fn from_bytes(data: Vec<u8>) -> Self {
        FnDsaSignature { data }
    }

    /// Verify a signature against a public key and message with FIPS 206 domain separation.
    ///
    /// Accepts signatures in any FN-DSA format (COMPRESSED, PADDED, CT) —
    /// the format is auto-detected from the header byte.
    ///
    /// # Arguments
    ///
    /// * `sig` — The encoded signature bytes.
    /// * `pubkey` — The encoded public key bytes.
    /// * `message` — The original message that was signed.
    /// * `domain` — Domain separation context (must match what was used for signing).
    pub fn verify(sig: &[u8], pubkey: &[u8], message: &[u8], domain: &DomainSeparation) -> Result<(), FalconError> {
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

        // Build hash context with domain separation
        let mut hd = InnerShake256Context::new();
        let r = falcon_api::falcon_verify_start(&mut hd, sig);
        if r < 0 {
            return Err(translate_error(r));
        }
        domain.inject(&mut hd);
        falcon_api::shake256_inject(&mut hd, message);
        let rc = falcon_api::falcon_verify_finish(sig, 0, pubkey, &mut hd, &mut tmp);
        if rc != 0 {
            return Err(translate_error(rc));
        }
        Ok(())
    }

    /// Get the raw signature bytes (serialization).
    pub fn to_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Consume the signature and return the owned byte vector.
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Get the length of the signature in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the signature is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}
