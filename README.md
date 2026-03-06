# falcon-rust

Native Rust implementation of the [Falcon](https://falcon-sign.info/) post-quantum digital signature scheme, ported from the C reference implementation by Thomas Pornin.

## Status

✅ **Bit-for-bit compatible** with the C reference — passes all NIST Known Answer Tests for both Falcon-512 and Falcon-1024.

## Features

- **NIST PQC standard** — Falcon is selected for standardization by NIST
- **`no_std` support** — works in embedded and WASM environments
- **WASM ready** — compiles to `wasm32-unknown-unknown` out of the box
- **Security hardening** — PRNG state is zeroized on drop via `write_volatile`
- **Pure Rust** — no C dependencies, no assembly
- **Full SDK** — high-level API with key/signature serialization
- **Serde support** — optional `Serialize`/`Deserialize` for keys and signatures
- **Performance optimized** — bounds-check-free NTT, FFT, and ChaCha20 hot paths
- **Fuzz tested** — 3 cargo-fuzz targets for verify, sign+verify, and codec

## Quick Start

```rust
use falcon::safe_api::{FalconKeyPair, FalconSignature};

// Generate a Falcon-512 key pair
let kp = FalconKeyPair::generate(9).unwrap();

// Sign a message
let sig = kp.sign(b"Hello, post-quantum world!").unwrap();

// Verify the signature
FalconSignature::verify(sig.to_bytes(), kp.public_key(), b"Hello, post-quantum world!").unwrap();
```

## Key Serialization

```rust
use falcon::safe_api::FalconKeyPair;

let kp = FalconKeyPair::generate(9).unwrap();

// Export keys to bytes (for storage, transmission, etc.)
let private_key: Vec<u8> = kp.private_key().to_vec();  // 1281 bytes
let public_key: Vec<u8> = kp.public_key().to_vec();     // 897 bytes

// Import from both keys
let restored = FalconKeyPair::from_keys(&private_key, &public_key).unwrap();

// Import from private key only (recomputes public key)
let restored2 = FalconKeyPair::from_private_key(&private_key).unwrap();
assert_eq!(public_key, restored2.public_key());

// Extract public key without creating a full key pair
let pk = FalconKeyPair::public_key_from_private(&private_key).unwrap();
```

## Signature Serialization

```rust
use falcon::safe_api::{FalconKeyPair, FalconSignature};

let kp = FalconKeyPair::generate(9).unwrap();
let sig = kp.sign(b"msg").unwrap();

// Export
let sig_bytes: Vec<u8> = sig.into_bytes();

// Import
let sig2 = FalconSignature::from_bytes(sig_bytes);
```

## Serde Support

Enable the `serde` feature for JSON/bincode/etc. serialization:

```toml
[dependencies]
falcon-rust = { version = "0.1.0", features = ["serde"] }
```

`FalconKeyPair`, `FalconSignature`, and `FalconError` all implement `Serialize`/`Deserialize` when enabled.

## Security Levels

| Variant | `logn` | NIST Level | Private Key | Public Key | Signature |
|---------|--------|------------|-------------|------------|-----------|
| Falcon-512 | 9 | I | 1281 B | 897 B | ~666 B |
| Falcon-1024 | 10 | V | 2305 B | 1793 B | ~1280 B |

## Benchmarks — C vs Rust

Measured on Apple M-series (ARM64), single-threaded, release builds.
C compiled with `clang -O3`, Rust with `cargo --release` (opt-level 3).

### Falcon-512

| Operation | C (ref) | Rust | Ratio |
|-----------|---------|------|-------|
| **keygen** | 5.55 ms | 4.60 ms | **0.83×** ✅ |
| **sign** | 213 µs | 272 µs | 1.28× |
| **verify** | 14.3 µs | 14.3 µs | **1.00×** ✅ |

### Falcon-1024

| Operation | C (ref) | Rust | Ratio |
|-----------|---------|------|-------|
| **keygen** | 18.6 ms | 15.9 ms | **0.86×** ✅ |
| **sign** | 434 µs | 542 µs | 1.25× |
| **verify** | 27.8 µs | 27.2 µs | **0.98×** ✅ |

> **Notes:** Keygen and verify are at or below C performance. Sign is ~1.25× slower,
> primarily because the C reference uses AVX2/NEON-optimized ChaCha20 PRNG and hand-tuned
> NTT. All measurements via [Criterion](https://github.com/bheisler/criterion.rs).

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
| `FalconKeyPair` | Key generation, signing, import/export |
| `FalconSignature` | Verification, serialization |
| `FalconError` | Error codes (RandomError, FormatError, etc.) |

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
cargo run --release --example keygen       # Generate key pair
cargo run --release --example sign_verify  # Sign + verify + tamper detection
cargo run --release --example serialize    # Full serialization round-trip
```

## Building

```sh
cargo build --release
cargo test --release
```

## Testing

```sh
# Full test suite (58 tests)
cargo test --release

# NIST KAT validation
cargo test --release --test nist_kat

# Benchmarks
cargo test --release --test bench_falcon -- --ignored --nocapture
```

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

Falcon-RS compiles to WebAssembly out of the box:

```sh
# Install the WASM target (one-time)
rustup target add wasm32-unknown-unknown

# Build for WASM (no_std, no OS entropy)
cargo build --target wasm32-unknown-unknown --no-default-features --release
```

In `no_std` / WASM environments, use deterministic key generation with your own entropy:

```rust
use falcon::safe_api::FalconKeyPair;

let seed: [u8; 48] = /* your entropy source */;
let kp = FalconKeyPair::generate_deterministic(9, &seed).unwrap();
```

## Documentation

```sh
cargo doc --no-deps --open
```

## License

MIT — matching the C reference implementation.
