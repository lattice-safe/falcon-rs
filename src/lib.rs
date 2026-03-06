//! # falcon — FN-DSA (FIPS 206) Post-Quantum Digital Signatures
//!
//! Native Rust implementation of **FN-DSA** (FFT over NTRU-Lattice-Based
//! Digital Signature Algorithm), the NIST FIPS 206 standard formerly known
//! as Falcon. Ported from the [C reference](https://falcon-sign.info/) by
//! Thomas Pornin.
//!
//! ## Quick Start
//!
//! ```rust
//! use falcon::safe_api::{FnDsaKeyPair, FnDsaSignature, DomainSeparation};
//!
//! // Generate an FN-DSA-512 key pair (logn=9)
//! let kp = FnDsaKeyPair::generate(9).unwrap();
//!
//! // Sign a message
//! let sig = kp.sign(b"Hello, post-quantum world!", &DomainSeparation::None).unwrap();
//!
//! // Verify the signature
//! FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), b"Hello, post-quantum world!", &DomainSeparation::None).unwrap();
//! ```
//!
//! ## Key Serialization
//!
//! Keys can be exported to bytes for storage and reconstructed:
//!
//! ```rust
//! # use falcon::safe_api::FnDsaKeyPair;
//! let kp = FnDsaKeyPair::generate(9).unwrap();
//!
//! // Export
//! let private_key = kp.private_key().to_vec();  // 1281 bytes
//! let public_key = kp.public_key().to_vec();     // 897 bytes
//!
//! // Import from both keys
//! let restored = FnDsaKeyPair::from_keys(&private_key, &public_key).unwrap();
//!
//! // Or import from private key only (recomputes public key)
//! let restored2 = FnDsaKeyPair::from_private_key(&private_key).unwrap();
//! assert_eq!(public_key, restored2.public_key());
//! ```
//!
//! ## Signature Serialization
//!
//! ```rust
//! # use falcon::safe_api::{FnDsaKeyPair, FnDsaSignature, DomainSeparation};
//! let kp = FnDsaKeyPair::generate(9).unwrap();
//! let sig = kp.sign(b"msg", &DomainSeparation::None).unwrap();
//!
//! // Export signature bytes (for storage, transmission, etc.)
//! let sig_bytes: Vec<u8> = sig.into_bytes();
//!
//! // Import signature bytes
//! let sig2 = FnDsaSignature::from_bytes(sig_bytes);
//! ```
//!
//! ## Security Levels
//!
//! | `logn` | Variant | NIST Level | Private Key | Public Key | Signature |
//! |--------|---------|------------|-------------|------------|-----------|
//! | 9 | FN-DSA-512 | I | 1281 B | 897 B | 666 B |
//! | 10 | FN-DSA-1024 | V | 2305 B | 1793 B | 1280 B |
//!
//! ## Architecture
//!
//! - **[`safe_api`]** — High-level SDK: key generation, signing, verification,
//!   serialization. **Start here.**
//! - **[`falcon`]** — Low-level C-equivalent API for advanced use cases
//!   (streamed signing, expanded keys, custom signature formats).
//! - **Internal modules**: `shake`, `fpr`, `fft`, `codec`, `rng`, `keygen`,
//!   `sign`, `vrfy`, `common` — faithful ports of the C reference.
//!
//! ## Features
//!
//! - `std` *(default)* — Enables OS-level entropy via `/dev/urandom`.
//! - Without `std` — Compiles for `no_std` environments (embedded, WASM).
//!   Use [`FnDsaKeyPair::generate_deterministic`](safe_api::FnDsaKeyPair::generate_deterministic)
//!   with your own entropy source.

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

pub mod codec;
pub mod common;
pub mod falcon;
pub mod fft;
pub mod fpr;
pub mod keygen;
pub mod rng;
pub mod safe_api;
pub mod shake;
pub mod sign;
pub mod vrfy;
