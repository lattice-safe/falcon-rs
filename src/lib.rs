//! # falcon — FN-DSA (FIPS 206) Post-Quantum Digital Signatures
//!
//! Native Rust implementation of **FN-DSA** (FFT over NTRU-Lattice-Based
//! Digital Signature Algorithm), the NIST FIPS 206 standard formerly known
//! as Falcon. Ported from the [C reference](https://falcon-sign.info/) by
//! Thomas Pornin.
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
//! let private_key = kp.private_key().to_vec();  // 1281 bytes (FN-DSA-512)
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
//! | 9 | FN-DSA-512  | I | 1281 B | 897 B  | 666 B  |
//! | 10 | FN-DSA-1024 | V | 2305 B | 1793 B | 1280 B |
//!
//! ## Modules
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`prelude`] | Re-exports all core public types — `use falcon::prelude::*` |
//! | [`safe_api`] | High-level SDK: keygen, sign, verify, serialization |
//! | [`falcon`] | Low-level C-equivalent API (streamed signing, expanded keys) |
//! | `codec`, `shake`, `rng`, … | Internal ports of the C reference |
//!
//! ## Features
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `std` | ✅ | Cross-platform OS entropy via `getrandom` crate |
//! | *(no std)* | — | `no_std` / WASM — use `generate_deterministic` |
//! | `serde` | — | `Serialize`/`Deserialize` for all public types |

#![no_std]
#![allow(
    clippy::needless_range_loop,
    clippy::manual_range_contains,
    clippy::identity_op,
    clippy::excessive_precision,
    clippy::too_many_arguments,
    clippy::unnecessary_cast,
    non_snake_case,
    non_upper_case_globals,
    dead_code
)]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

#[doc(hidden)]
pub mod codec;
#[doc(hidden)]
pub mod common;
pub mod falcon;
#[doc(hidden)]
pub mod fft;
#[doc(hidden)]
pub mod fpr;
#[doc(hidden)]
pub mod keygen;
#[doc(hidden)]
pub mod rng;
pub mod safe_api;
#[doc(hidden)]
pub mod shake;
#[doc(hidden)]
pub mod sign;
#[doc(hidden)]
pub mod vrfy;

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
/// // Expanded-key fast repeated signing
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
    };
}

// Root-level convenience re-exports so `falcon::FnDsaKeyPair` works directly.
pub use safe_api::{
    DomainSeparation, FalconError, FalconKeyPair, FalconSignature, FnDsaExpandedKey, FnDsaKeyPair,
    FnDsaSignature, PreHashAlgorithm,
};
