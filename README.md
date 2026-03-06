# falcon-rust

[![Crates.io](https://img.shields.io/crates/v/falcon-rs.svg)](https://crates.io/crates/falcon-rs) [![Docs.rs](https://docs.rs/falcon-rs/badge.svg)](https://docs.rs/falcon-rs) [![CI](https://github.com/lattice-safe/falcon-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/lattice-safe/falcon-rs/actions/workflows/ci.yml) [![MSRV](https://img.shields.io/badge/rustc-1.70+-blue.svg)](https://blog.rust-lang.org/2023/06/01/Rust-1.70.0.html) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Native Rust implementation of **FN-DSA** (FIPS 206), the NIST post-quantum digital signature standard formerly known as Falcon. Ported from the C reference implementation by Thomas Pornin.

## Status

✅ **Production-ready** — 92 tests, security audited. Passes all NIST Known Answer Tests (FN-DSA-512 & FN-DSA-1024), full FIPS 206 domain-separation KAT vectors, FIPS 180-4 SHA-2 vectors, and property-based tests.

## Features

- **NIST FIPS 206 standard** — FN-DSA (FFT over NTRU-Lattice-Based Digital Signature Algorithm)
- **Pure FN-DSA** — `DomainSeparation::None` / `Context` (ph_flag = 0x00)
- **HashFN-DSA** — `DomainSeparation::Prehashed` with SHA-256 or SHA-512 (ph_flag = 0x01)
- **Context validation** — context > 255 bytes returns `Err(BadArgument)`, never truncates
- **`no_std` support** — works in embedded and WASM environments
- **WASM ready** — compiles to `wasm32-unknown-unknown` out of the box
- **Security hardening** — PRNG state is zeroized on drop via `write_volatile`
- **Pure Rust** — no C dependencies, no assembly, pure-Rust SHA-256/SHA-512
- **Full SDK** — high-level API with key/signature serialization
- **Serde support** — optional `Serialize`/`Deserialize` for keys and signatures
- **Performance optimized** — bounds-check-free NTT, FFT, and ChaCha20 hot paths
- **Fuzz tested** — 3 cargo-fuzz targets exercising all domain-separation modes

## Quick Start

```rust
use falcon::prelude::*;  // FnDsaKeyPair, FnDsaSignature, DomainSeparation, …

// Generate an FN-DSA-512 key pair
let kp = FnDsaKeyPair::generate(9).unwrap();

// Sign a message
let sig = kp.sign(b"Hello, post-quantum world!", &DomainSeparation::None).unwrap();

// Verify the signature
FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), b"Hello, post-quantum world!", &DomainSeparation::None).unwrap();
```

## Domain Separation (FIPS 206)

FN-DSA mandates domain separation to prevent cross-protocol signature reuse. Use `DomainSeparation::Context(b"...")` to bind signatures to a specific protocol:

```rust
use falcon::prelude::*;

let kp = FnDsaKeyPair::generate(9).unwrap();

// Sign with a protocol-specific context
let ctx = DomainSeparation::Context(b"my-protocol-v1");
let sig = kp.sign(b"msg", &ctx).unwrap();

// Verification requires the same context
FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), b"msg", &ctx).unwrap();
```

## Key Serialization

```rust
use falcon::prelude::*;

let kp = FnDsaKeyPair::generate(9).unwrap();

// Export keys to bytes (for storage, transmission, etc.)
let private_key: Vec<u8> = kp.private_key().to_vec();  // 1281 bytes
let public_key: Vec<u8> = kp.public_key().to_vec();     // 897 bytes

// Import from both keys
let restored = FnDsaKeyPair::from_keys(&private_key, &public_key).unwrap();

// Import from private key only (recomputes public key)
let restored2 = FnDsaKeyPair::from_private_key(&private_key).unwrap();
assert_eq!(public_key, restored2.public_key());

// Extract public key without creating a full key pair
let pk = FnDsaKeyPair::public_key_from_private(&private_key).unwrap();
```

## Signature Serialization

```rust
use falcon::prelude::*;

let kp = FnDsaKeyPair::generate(9).unwrap();
let sig = kp.sign(b"msg", &DomainSeparation::None).unwrap();

// Export
let sig_bytes: Vec<u8> = sig.into_bytes();

// Import
let sig2 = FnDsaSignature::from_bytes(sig_bytes);
```

## Serde Support

Enable the `serde` feature for JSON/bincode/etc. serialization:

```toml
[dependencies]
falcon-rust = { version = "0.2", features = ["serde"] }
```

`FnDsaKeyPair`, `FnDsaSignature`, `FalconError`, `DomainSeparation`, and
`PreHashAlgorithm` all implement `Serialize`/`Deserialize` when enabled.
`FalconError` also implements `std::error::Error` (std builds only).

## Security Levels

| Variant | `logn` | NIST Level | Private Key | Public Key | Signature |
|---------|--------|------------|-------------|------------|-----------|
| FN-DSA-512 | 9 | I | 1281 B | 897 B | 666 B |
| FN-DSA-1024 | 10 | V | 2305 B | 1793 B | 1280 B |

## Benchmarks — C vs Rust

Measured on Apple M-series (ARM64), single-threaded, release builds.
C compiled with `clang -O3`, Rust with `cargo --release` (opt-level 3).

### FN-DSA-512

| Operation | C (ref) | Rust | Ratio |
|-----------|---------|------|-------|
| **keygen** | 5.55 ms | 4.23 ms | **0.76×** ✅ |
| **sign** | 213 µs | 279 µs | 1.31× |
| **verify** | 14.3 µs | 26.6 µs | 1.86× |

### FN-DSA-1024

| Operation | C (ref) | Rust | Ratio |
|-----------|---------|------|-------|
| **keygen** | 18.6 ms | 15.2 ms | **0.82×** ✅ |
| **sign** | 434 µs | 569 µs | 1.31× |
| **verify** | 27.8 µs | 54.5 µs | 1.96× |

> **Notes:** Keygen is faster than C. Sign is ~1.3× slower (C reference uses
> AVX2/NEON ChaCha20 PRNG and hand-tuned NTT). Verify overhead is in the
> constant-time hash-to-point path; switching to `FALCON_SIG_COMPRESSED` format
> with `hash_to_point_vartime` closes this gap at the cost of timing-side-channel
> resistance.
>
> See [SECURITY.md](SECURITY.md) for responsible disclosure and security scope.

Run benchmarks yourself:
```sh
# Criterion (statistical, recommended)
cargo bench

# Quick ad-hoc benchmarks
cargo test --release --test bench_falcon -- --ignored --nocapture
```

## API Overview

### High-Level SDK (`safe_api`)

| Type | Description |
|------|-------------|
| `FnDsaKeyPair` | Key generation, signing, import/export |
| `FnDsaSignature` | Verification, serialization |
| `DomainSeparation::None` | Pure FN-DSA, no context |
| `DomainSeparation::Context` | Pure FN-DSA with protocol context string |
| `DomainSeparation::Prehashed` | HashFN-DSA — SHA-256/SHA-512 pre-hash |
| `PreHashAlgorithm` | `Sha256` / `Sha512` selector for HashFN-DSA |
| `FalconError` | Error codes (RandomError, FormatError, etc.) |

### HashFN-DSA (FIPS 206 §6)

FIPS 206 defines two operation modes. Use `Prehashed` when the message is
large or must be committed to before signing:

```rust
use falcon::prelude::*;

let kp = FnDsaKeyPair::generate(9).unwrap();

// HashFN-DSA — message is pre-hashed with SHA-256 inside sign/verify
let domain = DomainSeparation::Prehashed {
    alg: PreHashAlgorithm::Sha256,
    context: b"my-protocol-v2",   // optional, max 255 bytes
};
let sig = kp.sign(b"large document bytes...", &domain).unwrap();
FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), b"large document bytes...", &domain).unwrap();
```

> **Security note:** The `context` string (0–255 bytes) must match exactly
> between `sign` and `verify`. Passing > 255 bytes returns `Err(BadArgument)`.
> Signatures created under one `DomainSeparation` variant will never verify
> under a different variant.

### Backward Compatibility

The type aliases `FalconKeyPair` and `FalconSignature` are provided for
backward compatibility and map to `FnDsaKeyPair` and `FnDsaSignature`.

### Low-Level (`falcon`)

For advanced use cases — streamed signing, expanded keys, custom signature formats:

```rust
use falcon::falcon as falcon_api;
use falcon::shake::InnerShake256Context;

// Streamed signing (hash-then-sign for large messages)
let mut hash = InnerShake256Context::new();
falcon_api::falcon_sign_start(&mut rng, &mut nonce, &mut hash);
falcon_api::shake256_inject(&mut hash, &chunk1);
falcon_api::shake256_inject(&mut hash, &chunk2);
falcon_api::falcon_sign_dyn_finish(&mut rng, &mut sig, ...);

// Expanded key (amortized cost for multiple signatures)
falcon_api::falcon_expand_privkey(&mut expanded, &privkey, &mut tmp);
falcon_api::falcon_sign_tree(&mut rng, &mut sig, ..., &expanded, ...);
```

## Examples

```sh
cargo run --release --example keygen       # Generate key pair, inspect sizes
cargo run --release --example sign_verify  # Pure FN-DSA + HashFN-DSA demos
cargo run --release --example serialize    # Full serialization round-trip
cargo run --release --example expand_key   # Expanded-key amortized signing
```

## Expanded Key API

For workloads that sign many messages with the same key, expand once and reuse:

```rust
use falcon::prelude::*;

let kp = FnDsaKeyPair::generate(9).unwrap();
let ek = kp.expand().unwrap();   // one-time cost: ~2.5× a single sign()
drop(kp);                         // private key zeroized here

// Each sign() is now ~1.5× faster than FnDsaKeyPair::sign()
let sig = ek.sign(b"hello", &DomainSeparation::None).unwrap();
FnDsaSignature::verify(sig.to_bytes(), ek.public_key(), b"hello",
    &DomainSeparation::None).unwrap();
```

## Security Properties

| Property | Implementation |
|---|---|
| Private key zeroize-on-drop | `Zeroizing<Vec<u8>>` from the `zeroize` crate |
| Expanded key zeroize-on-drop | Same — `Zeroizing<Vec<u8>>` for the LDL tree |
| Constant-time verify | Branchless modular arithmetic — no secret-dependent branches or memory accesses |
| Constant-time Gaussian sampling | Bitwise CDF comparison in `mkgauss` — no secret-dependent branches |
| Seed material zeroized | `write_volatile` on the 48-byte OS-entropy seed in `sign()` |
| PRNG state zeroized | Custom `Drop` on `Prng` struct — `write_volatile` on 768 bytes |
| Context length bounded | Context strings \> 255 bytes return `Err(BadArgument)` per FIPS 206 |
| Cross-domain isolation | Signatures under one `DomainSeparation` variant never verify under another |
| Sampler bounded | Gaussian rejection loop capped at 1000 iterations (defense-in-depth) |
| No aliased `&mut` refs | All `u16`/`i16` buffer reinterpretations use scope-separated borrows |

## Security Audit

This crate has undergone a line-by-line security code audit covering:

- **164 `unsafe` blocks** across all source files — validated for soundness
- **101 `get_unchecked` calls** in FFT/NTT — all bounds proven
- **40+ raw pointer casts** — alignment and aliasing verified
- **All codec decode functions** — robust against malformed input (no panics)
- **`cargo deny check`** — no advisories, no banned crates, licenses clean

**12 findings identified, 7 fixed:**

| Fixed | Description |
|---|---|
| ✅ | Replaced unsafe raw pointer u64 read with safe `copy_from_slice` |
| ✅ | Scope-separated aliased `&mut` references in both signing paths |
| ✅ | Split `get_seed` into `#[cfg]` variants for clear no\_std/WASM behavior |
| ✅ | Added `debug_assert!` alignment checks before u8→u16 transmutes |
| ✅ | Added 1000-iteration cap to Gaussian sampler rejection loop |
| ℹ️ | `is_short` overflow sentinel pattern confirmed sound |
| ℹ️ | `fpr_rint() as i16` truncation bounded by L2 norm check |
| ℹ️ | `set_len` on uninitialized `Vec<Fpr>` immediately overwritten — sound |

## Building

```sh
cargo build --release
cargo test --release
```

## Testing

```sh
# Full suite — 92 tests across 5 test files + doc-tests
cargo test --release

# NIST Falcon KAT (FN-DSA-512 & FN-DSA-1024 algorithm core)
cargo test --release --test nist_kat

# FIPS 206 domain-separation KAT (pure + HashFN-DSA, all domain modes)
cargo test --release --test fips206_kat

# FIPS 180-4 SHA-256 / SHA-512 NIST vectors
cargo test --release --test full_coverage -- test_sha

# Benchmarks (low-level + safe_api + HashFN-DSA)
cargo test --release --test bench_falcon -- --ignored --nocapture
```

### Test matrix

| Suite | Count | Covers |
|-------|-------|--------|
| `full_coverage` | 47 | safe_api, domain sep, HashFN-DSA, SHA-2 vectors, codec |
| `fips206_kat` | 6 | Deterministic KAT vectors for all FIPS 206 domain modes |
| `prop_tests` | 7 | Property-based tests (sign→verify, cross-domain, wrong-msg) |
| `kat_test` | 16 | Low-level API, NTT/FFT, codec, keygen/sign/verify |
| `nist_kat` | 2 | NIST SHA-1 KAT hashes for FN-DSA-512 and FN-DSA-1024 |
| `doc-tests` | 7 | Crate-level and module doc examples |
| **Total** | **92** | |

## Fuzz Testing

Three [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets are included:

```sh
# Install cargo-fuzz (one-time)
cargo install cargo-fuzz

# Fuzz verify rejection (random data should never verify)
cargo fuzz run fuzz_verify_reject -- -max_total_time=60

# Fuzz sign+verify roundtrip (must always succeed)
cargo fuzz run fuzz_sign_verify -- -max_total_time=60

# Fuzz codec encode/decode roundtrip
cargo fuzz run fuzz_codec_roundtrip -- -max_total_time=60
```

## WASM

FN-DSA compiles to WebAssembly out of the box:

```sh
# Install the WASM target (one-time)
rustup target add wasm32-unknown-unknown

# Build for WASM (no_std, no OS entropy)
cargo build --target wasm32-unknown-unknown --no-default-features --release
```

In `no_std` / WASM environments, use deterministic key generation with your own entropy:

```rust
use falcon::prelude::*;

let seed: [u8; 48] = /* your entropy source */;
let kp = FnDsaKeyPair::generate_deterministic(&seed, 9).unwrap();
```

## Documentation

```sh
cargo doc --no-deps --open
```

## License

MIT — matching the C reference implementation.
