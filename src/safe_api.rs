//! High-level safe Rust SDK for Falcon post-quantum digital signatures.
//!
//! This module provides ergonomic types for key generation, signing,
//! verification, and key/signature serialization — hiding all `unsafe`
//! operations behind a safe Rust interface.
//!
//! # Quick Start
//!
//! ```rust
//! use falcon::safe_api::{FalconKeyPair, FalconSignature};
//!
//! // Generate a Falcon-512 key pair
//! let kp = FalconKeyPair::generate(9).unwrap();
//!
//! // Sign a message
//! let sig = kp.sign(b"Hello, post-quantum world!").unwrap();
//!
//! // Verify the signature
//! FalconSignature::verify(sig.to_bytes(), kp.public_key(), b"Hello, post-quantum world!").unwrap();
//! ```
//!
//! # Serialization
//!
//! Keys and signatures can be serialized to bytes and restored:
//!
//! ```rust
//! # use falcon::safe_api::FalconKeyPair;
//! let kp = FalconKeyPair::generate(9).unwrap();
//!
//! // Export keys
//! let sk_bytes = kp.private_key().to_vec();
//! let pk_bytes = kp.public_key().to_vec();
//!
//! // Reconstruct key pair from exported bytes
//! let kp2 = FalconKeyPair::from_keys(&sk_bytes, &pk_bytes).unwrap();
//!
//! // Or reconstruct public key from private key alone
//! let pk_only = FalconKeyPair::public_key_from_private(&sk_bytes).unwrap();
//! assert_eq!(pk_bytes, pk_only);
//! ```
//!
//! # Security Levels
//!
//! | logn | Variant | NIST Level | Private Key | Public Key | Signature |
//! |------|---------|------------|-------------|------------|-----------|
//! | 9 | Falcon-512 | I | 1281 B | 897 B | ~666 B |
//! | 10 | Falcon-1024 | V | 2305 B | 1793 B | ~1280 B |

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use crate::falcon as falcon_api;
use crate::shake::{InnerShake256Context, i_shake256_init, i_shake256_inject, i_shake256_flip};
use crate::rng::get_seed;

// ======================================================================
// Error type
// ======================================================================

/// Errors returned by the safe Falcon API.
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
    /// Internal error in the Falcon algorithm.
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

/// A Falcon key pair (private key + public key).
///
/// The key pair stores encoded keys in the Falcon wire format.
/// Use `logn = 9` for Falcon-512 (NIST Level I) or `logn = 10`
/// for Falcon-1024 (NIST Level V).
///
/// # Serialization
///
/// ```rust
/// # use falcon::safe_api::FalconKeyPair;
/// let kp = FalconKeyPair::generate(9).unwrap();
///
/// // Export
/// let sk = kp.private_key().to_vec();
/// let pk = kp.public_key().to_vec();
///
/// // Import
/// let kp2 = FalconKeyPair::from_keys(&sk, &pk).unwrap();
/// assert_eq!(kp.public_key(), kp2.public_key());
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FalconKeyPair {
    privkey: Vec<u8>,
    pubkey: Vec<u8>,
    logn: u32,
}

impl FalconKeyPair {
    /// Generate a new Falcon key pair using OS entropy.
    ///
    /// # Arguments
    ///
    /// * `logn` — Degree parameter: 9 for Falcon-512, 10 for Falcon-1024.
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
            unsafe { core::ptr::write_volatile(b, 0); }
        }

        result
    }

    /// Generate a new Falcon key pair from a deterministic seed.
    ///
    /// The seed is fed into a SHAKE256-based PRNG. The **same seed
    /// always produces the same key pair**, making this ideal for
    /// test vector reproducibility.
    ///
    /// # Arguments
    ///
    /// * `seed` — Entropy seed (≥ 32 bytes recommended).
    /// * `logn` — Degree parameter: 9 for Falcon-512, 10 for Falcon-1024.
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
            &mut rng, logn, &mut privkey, Some(&mut pubkey), &mut tmp,
        );
        if rc != 0 {
            return Err(translate_error(rc));
        }

        Ok(FalconKeyPair { privkey, pubkey, logn })
    }

    /// Reconstruct a key pair from previously exported private and public key bytes.
    ///
    /// Both keys must be valid Falcon-encoded keys with matching degree.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use falcon::safe_api::FalconKeyPair;
    /// let kp = FalconKeyPair::generate(9).unwrap();
    /// let sk = kp.private_key().to_vec();
    /// let pk = kp.public_key().to_vec();
    ///
    /// let restored = FalconKeyPair::from_keys(&sk, &pk).unwrap();
    /// assert_eq!(kp.logn(), restored.logn());
    /// ```
    pub fn from_keys(privkey: &[u8], pubkey: &[u8]) -> Result<Self, FalconError> {
        if privkey.is_empty() || pubkey.is_empty() {
            return Err(FalconError::FormatError);
        }

        let sk_logn = falcon_api::falcon_get_logn(privkey);
        let pk_logn = falcon_api::falcon_get_logn(pubkey);
        if sk_logn < 0 || pk_logn < 0 {
            return Err(FalconError::FormatError);
        }

        // Validate header types: privkey = 0x5X, pubkey = 0x0X
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

        // Validate sizes
        if privkey.len() != falcon_api::falcon_privkey_size(logn) {
            return Err(FalconError::FormatError);
        }
        if pubkey.len() != falcon_api::falcon_pubkey_size(logn) {
            return Err(FalconError::FormatError);
        }

        Ok(FalconKeyPair {
            privkey: privkey.to_vec(),
            pubkey: pubkey.to_vec(),
            logn,
        })
    }

    /// Reconstruct a key pair from a private key only.
    ///
    /// The public key is recomputed from the private key. This is slightly
    /// slower than [`from_keys`](Self::from_keys) but only requires the
    /// private key to be stored.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use falcon::safe_api::FalconKeyPair;
    /// let kp = FalconKeyPair::generate(9).unwrap();
    /// let sk = kp.private_key().to_vec();
    ///
    /// let restored = FalconKeyPair::from_private_key(&sk).unwrap();
    /// assert_eq!(kp.public_key(), restored.public_key());
    /// ```
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

        Ok(FalconKeyPair {
            privkey: privkey.to_vec(),
            pubkey,
            logn,
        })
    }

    /// Compute the public key bytes from a private key without creating a key pair.
    ///
    /// Useful when you only need the public key for distribution.
    pub fn public_key_from_private(privkey: &[u8]) -> Result<Vec<u8>, FalconError> {
        let kp = Self::from_private_key(privkey)?;
        Ok(kp.pubkey)
    }

    /// Sign a message using this key pair.
    ///
    /// Uses the constant-time (CT) signature format and OS entropy.
    /// Each call produces a **different signature** due to random nonce
    /// generation.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use falcon::safe_api::{FalconKeyPair, FalconSignature};
    /// let kp = FalconKeyPair::generate(9).unwrap();
    /// let sig = kp.sign(b"my message").unwrap();
    ///
    /// // Signature can be exported and sent over the wire
    /// let sig_bytes = sig.to_bytes().to_vec();
    /// ```
    pub fn sign(&self, message: &[u8]) -> Result<FalconSignature, FalconError> {
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

        // Zeroize seed
        for b in seed.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0); }
        }

        let mut sig = vec![0u8; sig_max];
        let mut sig_len = sig_max;
        let mut tmp = vec![0u8; tmp_len];

        let rc = falcon_api::falcon_sign_dyn(
            &mut rng,
            &mut sig,
            &mut sig_len,
            falcon_api::FALCON_SIG_CT,
            &self.privkey,
            message,
            &mut tmp,
        );
        if rc != 0 {
            return Err(translate_error(rc));
        }

        sig.truncate(sig_len);
        Ok(FalconSignature { data: sig })
    }

    /// Sign a message with a deterministic seed (for testing / reproducibility).
    ///
    /// The same `(key, message, seed)` triple **always produces the same
    /// signature**.
    pub fn sign_deterministic(
        &self,
        message: &[u8],
        seed: &[u8],
    ) -> Result<FalconSignature, FalconError> {
        let sig_max = falcon_api::falcon_sig_ct_size(self.logn);
        let tmp_len = falcon_api::falcon_tmpsize_signdyn(self.logn);

        let mut rng = InnerShake256Context::new();
        i_shake256_init(&mut rng);
        i_shake256_inject(&mut rng, seed);
        i_shake256_flip(&mut rng);

        let mut sig = vec![0u8; sig_max];
        let mut sig_len = sig_max;
        let mut tmp = vec![0u8; tmp_len];

        let rc = falcon_api::falcon_sign_dyn(
            &mut rng,
            &mut sig,
            &mut sig_len,
            falcon_api::FALCON_SIG_CT,
            &self.privkey,
            message,
            &mut tmp,
        );
        if rc != 0 {
            return Err(translate_error(rc));
        }

        sig.truncate(sig_len);
        Ok(FalconSignature { data: sig })
    }

    /// Get the encoded public key bytes.
    ///
    /// The returned bytes are in the standard Falcon wire format and can
    /// be safely distributed, stored, or passed to [`FalconSignature::verify`].
    pub fn public_key(&self) -> &[u8] {
        &self.pubkey
    }

    /// Get the encoded private key bytes.
    ///
    /// ⚠️ **Secret material** — handle with care. These bytes can be used
    /// to reconstruct the key pair via [`from_keys`](Self::from_keys) or
    /// [`from_private_key`](Self::from_private_key).
    pub fn private_key(&self) -> &[u8] {
        &self.privkey
    }

    /// Get the Falcon degree parameter.
    ///
    /// Returns 9 for Falcon-512, 10 for Falcon-1024.
    pub fn logn(&self) -> u32 {
        self.logn
    }

    /// Get the security variant name.
    pub fn variant_name(&self) -> &'static str {
        match self.logn {
            9 => "Falcon-512",
            10 => "Falcon-1024",
            n => {
                // Reduced variants (research only)
                match n {
                    1 => "Falcon-2",
                    2 => "Falcon-4",
                    3 => "Falcon-8",
                    4 => "Falcon-16",
                    5 => "Falcon-32",
                    6 => "Falcon-64",
                    7 => "Falcon-128",
                    8 => "Falcon-256",
                    _ => "Falcon-unknown",
                }
            }
        }
    }
}

// ======================================================================
// Signature
// ======================================================================

/// A Falcon digital signature.
///
/// Contains the encoded signature bytes in constant-time (CT) format.
/// Signatures can be exported with [`to_bytes`](Self::to_bytes) and
/// imported with [`from_bytes`](Self::from_bytes).
///
/// # Wire Format
///
/// The signature bytes include a 1-byte header, 40-byte nonce, and the
/// encoded signature coefficients. The total size is fixed for CT format
/// (809 bytes for Falcon-512, 1577 bytes for Falcon-1024).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FalconSignature {
    data: Vec<u8>,
}

impl FalconSignature {
    /// Create a signature from raw bytes (deserialization).
    ///
    /// The bytes must be a valid Falcon signature in any supported format.
    /// No verification is performed — use [`verify`](Self::verify) to
    /// check validity.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use falcon::safe_api::{FalconKeyPair, FalconSignature};
    /// let kp = FalconKeyPair::generate(9).unwrap();
    /// let sig = kp.sign(b"msg").unwrap();
    ///
    /// // Round-trip through bytes
    /// let bytes = sig.to_bytes().to_vec();
    /// let sig2 = FalconSignature::from_bytes(bytes);
    /// ```
    pub fn from_bytes(data: Vec<u8>) -> Self {
        FalconSignature { data }
    }

    /// Verify a signature against a public key and message.
    ///
    /// Accepts signatures in any Falcon format (COMPRESSED, PADDED, CT) —
    /// the format is auto-detected from the header byte.
    ///
    /// # Arguments
    ///
    /// * `sig` — The encoded signature bytes.
    /// * `pubkey` — The encoded public key bytes.
    /// * `message` — The original message that was signed.
    ///
    /// # Returns
    ///
    /// `Ok(())` if valid, `Err(FalconError::BadSignature)` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use falcon::safe_api::{FalconKeyPair, FalconSignature};
    /// let kp = FalconKeyPair::generate(9).unwrap();
    /// let sig = kp.sign(b"msg").unwrap();
    /// FalconSignature::verify(sig.to_bytes(), kp.public_key(), b"msg").unwrap();
    /// ```
    pub fn verify(sig: &[u8], pubkey: &[u8], message: &[u8]) -> Result<(), FalconError> {
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

        // Auto-detect signature format (sig_type = 0).
        let rc = falcon_api::falcon_verify(
            sig,
            0,
            pubkey,
            message,
            &mut tmp,
        );
        if rc != 0 {
            return Err(translate_error(rc));
        }
        Ok(())
    }

    /// Get the raw signature bytes (serialization).
    ///
    /// The returned bytes can be stored, transmitted, and later restored
    /// with [`from_bytes`](Self::from_bytes).
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
