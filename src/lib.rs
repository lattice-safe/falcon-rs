//! # falcon — FN-DSA (draft FIPS 206) Post-Quantum Digital Signatures
//!
//! Native Rust implementation of **FN-DSA** (FFT over NTRU-Lattice-Based
//! Digital Signature Algorithm), the NIST post-quantum signature scheme
//! formerly known as Falcon, per the draft FIPS 206. Ported from
//! [c-fn-dsa](https://github.com/pornin/c-fn-dsa) by Thomas Pornin, which
//! implements its author's best guess at the (unpublished) FIPS 206 draft.
//!
//! ## Quick start — Pure FN-DSA
//!
//! ```rust
//! use falcon::prelude::*;
//!
//! // Generate an FN-DSA-512 key pair
//! let kp = FnDsaKeyPair::generate(9).unwrap();
//!
//! // Sign with no context (ph_flag = 0x00)
//! let sig = kp.sign(b"Hello, post-quantum world!", &DomainSeparation::None).unwrap();
//!
//! // Verify
//! FnDsaSignature::verify(sig.to_bytes(), kp.public_key(),
//!     b"Hello, post-quantum world!", &DomainSeparation::None).unwrap();
//! ```
//!
//! ## HashFN-DSA — pre-hash large messages
//!
//! ```rust
//! use falcon::prelude::*;
//!
//! let kp = FnDsaKeyPair::generate(9).unwrap();
//!
//! // ph_flag = 0x01: message is SHA-256 hashed before signing
//! let domain = DomainSeparation::Prehashed {
//!     alg: PreHashAlgorithm::Sha256,
//!     context: b"my-protocol-v1",   // optional, max 255 bytes
//! };
//! let sig = kp.sign(b"large document ...", &domain).unwrap();
//! FnDsaSignature::verify(sig.to_bytes(), kp.public_key(),
//!     b"large document ...", &domain).unwrap();
//! ```
//!
//! ## Key serialization
//!
//! ```rust
//! # use falcon::prelude::*;
//! let kp = FnDsaKeyPair::generate(9).unwrap();
//!
//! let private_key = kp.private_key().to_vec();  // 1345 bytes (FN-DSA-512)
//! let public_key  = kp.public_key().to_vec();   // 897 bytes
//!
//! // Import from both keys or from private key only
//! let restored = FnDsaKeyPair::from_keys(&private_key, &public_key).unwrap();
//! let restored2 = FnDsaKeyPair::from_private_key(&private_key).unwrap();
//! assert_eq!(public_key, restored2.public_key());
//! ```
//!
//! ## Security levels
//!
//! | `logn` | Variant | NIST Level | Private Key | Public Key | Signature |
//! |--------|---------|------------|-------------|------------|-----------|
//! | 9 | FN-DSA-512  | I | 1345 B | 897 B  | 666 B  |
//! | 10 | FN-DSA-1024 | V | 2369 B | 1793 B | 1280 B |
//!
//! ## Modules
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`prelude`] | Re-exports all core public types — `use falcon::prelude::*` |
//! | [`safe_api`] | High-level SDK: keygen, sign, verify, serialization |
//! | [`fndsa`] | Low-level API mirroring `fndsa.h`: encoded keys, `mu`, hash identifiers, toy degrees |
//! | `sha3`, `shake` | Keccak-based hashes (internal) |
//!
//! ## Features
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `std` | ✅ | Cross-platform OS entropy via `getrandom` crate |
//! | *(no std)* | — | `no_std` / WASM — use `generate_deterministic` |
//! | `serde` | — | `Serialize`/`Deserialize` for all public types |

#![no_std]
#![forbid(unsafe_code)]
// The carried-over upstream code keeps the reference's naming (f, g, F, G,
// FFT, ...) and loop shapes so that it reads side by side with c-fn-dsa.
#![allow(
    clippy::needless_range_loop,
    clippy::manual_range_contains,
    clippy::identity_op,
    clippy::excessive_precision,
    clippy::too_many_arguments,
    clippy::unnecessary_cast,
    non_snake_case,
    non_upper_case_globals
)]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

pub mod fndsa;
#[cfg(feature = "round3")]
pub mod round3;
pub mod safe_api;
#[doc(hidden)]
pub mod sha3;
#[doc(hidden)]
pub mod shake;

/// Prelude — import the entire public API with `use falcon::prelude::*`.
///
/// ```rust
/// use falcon::prelude::*;
///
/// let kp = FnDsaKeyPair::generate(9).unwrap();
/// let sig = kp.sign(b"msg", &DomainSeparation::None).unwrap();
/// FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), b"msg",
///     &DomainSeparation::None).unwrap();
///
/// // Expanded key: decode once, sign repeatedly
/// let ek = kp.expand().unwrap();
/// let sig2 = ek.sign(b"msg", &DomainSeparation::None).unwrap();
/// FnDsaSignature::verify(sig2.to_bytes(), ek.public_key(), b"msg",
///     &DomainSeparation::None).unwrap();
/// ```
pub mod prelude {
    pub use crate::safe_api::{
        DomainSeparation,
        FalconError,
        FalconKeyPair,   // backward-compat alias
        FalconSignature, // backward-compat alias
        FnDsaExpandedKey,
        FnDsaKeyPair,
        FnDsaSignature,
        PreHashAlgorithm,
        MIN_KEYGEN_SEED_LEN,
    };
}

// Root-level convenience re-exports so `falcon::FnDsaKeyPair` works directly.
pub use safe_api::{
    DomainSeparation, FalconError, FalconKeyPair, FalconSignature, FnDsaExpandedKey, FnDsaKeyPair,
    FnDsaSignature, PreHashAlgorithm, MIN_KEYGEN_SEED_LEN,
};
