# falcon-rs

[![Crates.io](https://img.shields.io/crates/v/falcon-rs.svg)](https://crates.io/crates/falcon-rs) [![Docs.rs](https://docs.rs/falcon-rs/badge.svg)](https://docs.rs/falcon-rs) [![CI](https://github.com/lattice-safe/falcon-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/lattice-safe/falcon-rs/actions/workflows/ci.yml) [![MSRV](https://img.shields.io/badge/rustc-1.84+-blue.svg)](https://blog.rust-lang.org/2025/01/09/Rust-1.84.0.html) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Native Rust implementation of **FN-DSA**, the NIST post-quantum digital signature scheme formerly known as Falcon, per the **draft FIPS 206**. Ported from the C reference implementation by Thomas Pornin.

## Status

176 tests (173 without `serde` or `fpemu`), 98.2% line coverage, reviewed line-by-line twice **in-house** — there has been no independent third-party audit, and no CMVP validation. **On test vectors, precisely.** NIST has published no test vectors for
FN-DSA: FIPS 206 is still a draft and there is no ACVP suite for it. What
this crate verifies instead:

- **Bit-for-bit parity with the C reference**, under the NIST PQC
  competition KAT procedure (AES-256-CTR DRBG, 100 keygen/sign/verify
  iterations, SHA-1 over the whole output stream) for Falcon-512 and
  Falcon-1024. The two expected digests are not ours: they are published in
  the reference's own `test_falcon.c` as the expected results of its
  `test_nist_KAT` self-test, and `./scripts/verify_c_parity.sh` verifies the
  whole chain — those digests, the reference compiled from source
  reproducing them, and this port matching. So the parity is verified rather
  than asserted. It is still parity with *Falcon*, the round-3 submission,
  not evidence about FN-DSA's domain-separation layer.
- **FIPS 180-4 SHA-2 vectors** — genuinely external, from NIST.
- **FIPS 206 domain separation**: self-generated deterministic regression
  anchors, because no published vectors exist for that layer.

So: no NIST conformance is demonstrated or claimed. Treat FIPS 206
conformance as best-effort against a draft.

## Features

- **Draft NIST FIPS 206** — FN-DSA (FFT over NTRU-Lattice-Based Digital Signature Algorithm)
- **Pure FN-DSA** — `DomainSeparation::None` / `Context` (ph_flag = 0x00)
- **HashFN-DSA** — `DomainSeparation::Prehashed` with SHA-256 or SHA-512 (ph_flag = 0x01)
- **Context validation** — context > 255 bytes returns `Err(BadArgument)`, never truncates
- **`no_std` support** — works in embedded and WASM environments
- **WASM ready** — compiles to `wasm32-unknown-unknown` out of the box
- **Security hardening** — PRNG state is zeroized on drop via `write_volatile`
- **Constant-time FP backend** — optional `fpemu` feature removes the floating-point timing side channel, with bit-identical output
- **Fault detection** — every signature is verified against the public key before it is returned; a corrupted computation returns `FaultDetected` instead of a key-leaking signature
- **Pure Rust** — no C dependencies, no assembly, pure-Rust SHA-256/SHA-512
- **Full SDK** — high-level API with key/signature serialization
- **Serde support** — optional `Serialize`/`Deserialize` for keys and signatures
- **Performance optimized** — bounds-check-free NTT, FFT, and ChaCha20 hot paths
- **Fuzz tested** — 3 cargo-fuzz targets exercising all domain-separation modes; CI runs a 60-second smoke campaign per target on every push

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
falcon-rs = { version = "0.3", features = ["serde"] }
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

> The Rust columns are reproducible from this repository
> (`cargo test --release --test bench_falcon -- --ignored`). The C columns
> are not: no C harness is vendored here, so the ratios rest on a separate
> run of the reference implementation and should be treated as indicative.
> These figures also predate the always-on hardening — see the `fpemu`
> section for current numbers.

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
let ek = kp.expand().unwrap();   // one-time cost: ~0.25× a single sign()
drop(kp);                         // private key zeroized here

// Each sign() is now ~1.6× faster than FnDsaKeyPair::sign()
let sig = ek.sign(b"hello", &DomainSeparation::None).unwrap();
FnDsaSignature::verify(sig.to_bytes(), ek.public_key(), b"hello",
    &DomainSeparation::None).unwrap();
```

## Constant-Time Floating Point (`fpemu`)

Falcon's signing path — the FFT and the ff-Sampling that walk the private
key — is written in floating point. On the default backend those are
hardware `f64` instructions, and floating-point instruction timing is
data-dependent on some architectures. The `fpemu` feature swaps in a second
backend where `Fpr` holds the IEEE-754 bit pattern in a `u64` and every
operation is branchless integer code:

```toml
falcon-rs = { version = "0.3", features = ["fpemu"] }
```

Nothing else changes — same API, same key and signature bytes:

| Property | How it is verified |
|---|---|
| Identical results | The reference-parity KAT suite and the FIPS 206 domain-separation vectors pass unchanged with `--features fpemu`; signatures are bit-for-bit the same |
| IEEE-754 exactness | `tests/fpr_diff.rs` compares every operation against native `f64` over ~4M random draws (~7M bit-exact comparisons) plus edge cases: signed zeros, exact ties, total cancellation, sticky-bit and alignment paths |
| No FP instructions | `scripts/check_no_fp.sh` disassembles the compiled crate and fails if any FP arithmetic, compare or convert instruction is present — and is itself checked by running it against the native build, where it must fail |
| No undefined behaviour | `cargo miri test` runs the unit tests and a full keygen/sign/verify cycle under `-Zmiri-strict-provenance`, in CI. It found four classes of UB when first applied — including unaligned references built into a caller-supplied byte buffer — all fixed |
| Measured timing | `tests/dudect.rs` runs Welch's t-test over fixed-vs-random inputs, three measurements judged by the median, with a self-test requiring the harness to detect a deliberate 2% difference. **Gated:** the Gaussian sampler's centre (which comes from the private basis), full signing, and normal-versus-subnormal operands — all stable on both architectures. **Reported but not gated:** the per-operation rows, because on x86_64 they also measure high for operands that cannot differ in control flow (see the test's documentation) |

Cost through the high-level API on Apple M-series, self-check included
(`cargo test --release --test bench_falcon -- --ignored --test-threads=1`):

| Operation | native | `fpemu` | Ratio |
|-----------|--------|---------|-------|
| 512 keygen | 4.69 ms | 8.18 ms | 1.7× |
| 512 sign | 0.415 ms | 2.71 ms | 6.5× |
| 512 verify | 0.032 ms | 0.031 ms | 1.0× |
| 1024 keygen | 16.3 ms | 24.0 ms | 1.5× |

Both columns include the always-on hardening described below: the signing
self-check, and wiping every secret-derived scratch buffer. Against the
unhardened 0.2.x baseline of 0.32 ms, FN-DSA-512 signing costs about +10%
for the self-check and a further ~16% for zeroizing the ff-Sampling
intermediates, which are allocated per recursion level.

Verification is unaffected because it is integer-only — the cost lands on
signing and key generation, which are the operations that touch the private
key. Two deviations from IEEE-754 are inherited from the C reference's
`FPEMU` mode, both outside the range Falcon reaches: subnormals are flushed
to zero, and infinities/NaN are unsupported.

What `fpemu` does **not** make constant-time, in either backend:

- **Key generation** — the Gaussian rejection loops and the NTRU solver run
  in data-dependent time, as in the C reference.
- **Rejection sampling** — the discrete Gaussian sampler and the
  signature-norm retry loop iterate a data-dependent number of times and
  consume a variable number of PRNG bytes. This is the specified algorithm:
  making it fixed-count would change the output and break KAT compliance.
- **Power and EM analysis** — no masking is implemented. The published
  practical attacks on Falcon are in this class and need physical access;
  `fpemu` does not address them.
- **Fault attacks** — partially: signing verifies its own output (below),
  which catches a fault that corrupts the result. There is no protection
  against faults that skip the check itself.

See [SECURITY.md](SECURITY.md) for the full security scope.

## Fault Detection (sign-then-verify)

A Falcon signature computed from a corrupted intermediate state can expose
the private basis, which makes fault injection a practical attack wherever
an adversary can touch the hardware. Every signing path in the high-level
API therefore verifies its own output against the public key before
returning it:

```rust
match kp.sign(msg, &DomainSeparation::None) {
    Ok(sig) => { /* verified before it reached you */ }
    Err(FalconError::FaultDetected) => {
        // The signature did not verify under our own public key.
        // The computation was corrupted — treat as a security event,
        // not as a retryable error.
    }
    Err(e) => { /* ordinary failure */ }
}
```

This costs one verification per signature: **+10%** on the default backend
(0.32 ms → 0.357 ms for FN-DSA-512) and about +1% with `fpemu`, where
signing dominates. Ratios vary by machine; these were measured on Apple
M-series. It is always on — there is no flag to turn it off,
because the failure it prevents is key recovery.

It is not complete fault protection: an attacker who can glitch the check
itself, or the branch that acts on it, is not stopped by it. It closes the
case that matters most, cheaply.

## Security Properties

| Property | Implementation |
|---|---|
| Private key zeroize-on-drop | `Zeroizing<Vec<u8>>` from the `zeroize` crate |
| Expanded key zeroize-on-drop | Same — `Zeroizing<Vec<u8>>` for the LDL tree |
| Constant-time verify | Branchless modular arithmetic — no secret-dependent branches or memory accesses |
| Branchless Gaussian CDT scan | Bitwise CDF comparison inside `mkgauss` (keygen) — no secret-dependent branches. The enclosing rejection loops, and the signing sampler, remain variable-time by design |
| Constant-time floating point | Optional: `fpemu` feature, branchless integer IEEE-754 (see above). Off by default |
| Fault detection on signing | Every signature is verified against the public key before being returned; failure yields `FalconError::FaultDetected` |
| Seed material zeroized | `write_volatile` on the 48-byte OS-entropy seed in `sign()` |
| Sampler and keygen scratch zeroized | The ff-Sampling scratch buffers, signature coefficients and all 85 key-generation working buffers are `Zeroizing`, so secret-derived intermediates are wiped rather than left in freed heap |
| PRNG state zeroized | Custom `Drop` on `Prng` struct — `write_volatile` on 768 bytes |
| Context length bounded | Context strings \> 255 bytes return `Err(BadArgument)` per FIPS 206 |
| Cross-domain isolation | Signatures under one `DomainSeparation` variant never verify under another |
| Sampler bounded | Gaussian rejection loop capped at 1000 iterations (defense-in-depth) |
| No aliased `&mut` refs | All `u16`/`i16` buffer reinterpretations use scope-separated borrows |

## Security Review

Two line-by-line reviews have been done **in-house**; neither is an
independent third-party audit, and the crate has no CMVP validation. The
second is written up in
[`docs/CODE_REVIEW_2026-07-20.md`](docs/CODE_REVIEW_2026-07-20.md); the
first predates that document and its findings are summarised below from
memory of the change set, without a report to point to.

A third pass — four adversarial reviews of the constant-time work, run by
separate agents against the fpemu backend, the signing-path side channels,
the refactor's integrity and the documentation's claims — is recorded in
the changelog for 0.3.0. It refuted two of this file's own claims, which
have been corrected.

The reviews covered:

- **130 `unsafe` blocks** across all source files, and no `unsafe` at all in
  the high-level API, which carries `#![deny(unsafe_code)]`. The count fell
  from ~140 when the undefined-behaviour fixes replaced raw views into the
  scratch buffer with owned buffers. Distribution: `sign.rs` 58,
  `falcon.rs` 39, `fft.rs` 20, `vrfy.rs` 9, `keygen.rs` 3, `rng.rs` 1
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

### Deep algebraic review (2026-07-20)

A second review re-derived **every constant table from first principles** with
exact arithmetic and hardened the remaining unchecked memory reinterpretations.
See [`docs/CODE_REVIEW_2026-07-20.md`](docs/CODE_REVIEW_2026-07-20.md) for the
full write-up.

- **33/33 algebraic checks pass** — FFT/NTT roots, Montgomery constants, the
  Gaussian CDTs, the 521-entry prime table, and Keccak/SHA constants were all
  recomputed and matched exactly. Rerun with `python3 scripts/verify_algebra.py`.
- **7 soundness/hardening fixes (F1–F7)** — removed unaligned `u8→u16` casts and
  aliased `&mut` views in `hash_to_point_ct` and `verify_raw`, eliminated
  release-mode UB in `is_short`, and dropped unnecessary `unsafe` from the
  Gaussian sampler. **No computed value changed — all KATs still pass.**
- **+29 deep-coverage tests** raising line coverage to ~94%
  (`./scripts/coverage.sh` enforces ≥90%).

## Building

```sh
cargo build --release
cargo test --release
```

## Testing

```sh
# Full suite — 176 tests across 13 test files + doc-tests
cargo test --release

# NIST Falcon KAT (FN-DSA-512 & FN-DSA-1024 algorithm core)
cargo test --release --test nist_kat

# FIPS 206 domain-separation KAT (pure + HashFN-DSA, all domain modes)
cargo test --release --test fips206_kat

# FIPS 180-4 SHA-256 / SHA-512 NIST vectors
cargo test --release --test full_coverage -- test_sha

# Deep-coverage internal + algebraic property tests
cargo test --release --test deep_coverage

# Benchmarks (low-level + safe_api + HashFN-DSA)
cargo test --release --test bench_falcon -- --ignored --nocapture
```

### Line coverage

```sh
# Requires: cargo install cargo-llvm-cov
./scripts/coverage.sh          # summary, enforces >= 90% line coverage
./scripts/coverage.sh --html   # detailed HTML report
```

### Reproducible test run in a container

A minimalist Alpine/musl [`Dockerfile`](Dockerfile) runs the entire suite
(format check, clippy, all tests, and the `no_std` build) in a clean Linux
environment. Building the image *is* the test run:

```sh
docker build -t falcon-rs-test .   # builds + runs the whole suite
docker run --rm falcon-rs-test     # re-run the suite inside the image
```

### Test matrix

| Suite | Count | Covers |
|-------|-------|--------|
| `full_coverage` | 48 | safe_api, domain separation, HashFN-DSA, SHA-2 vectors, codec |
| `deep_coverage` | 29 | Internal modules + algebraic identities (FFT/NTT/LDL, codec error paths) |
| lib unit-tests | 29 | Private helpers: branchless modular arithmetic (exhaustive over the residue range), bignum primitives up to the 209-limb lengths the solver uses, the two ffSampling recursions cross-checked against each other, entropy-failure paths, alignment helpers, SHAKE state, error mapping, fault detection |
| `kat_test` | 16 | Low-level API, NTT/FFT, codec, keygen/sign/verify |
| `lowlevel_api` | 15 | C-style API: every signature format on both signing paths, every size and range guard, the padded format's pad and retry paths, header validation, degree sweep, corrupted bodies |
| `error_paths` | 12 | Codec rejection paths, `serde` validation, every high-level validation branch, the empty-context equivalence |
| `fips206_kat` | 6 | FIPS 206 domain modes (self-generated anchors) |
| `prop_tests` | 6 | Property-based (sign→verify, cross-domain, wrong message) |
| `fpr_diff` | 6 | `Fpr` backend vs native `f64`, bit for bit, plus the pinned `fpemu` deviations |
| `doc-tests` | 7 | Crate-level and module doc examples |
| `nist_kat` | 2 | Parity with the C reference, verified (see above) |
| `miri_cycle` | 1 | Keygen/sign/verify cycle at a small degree, for running under Miri |
| **Total** | **176** | 173 with default features; 175 with `fpemu` |

Eleven more are `#[ignore]`d because they measure rather than assert, and are
run explicitly: `dudect` (7 — the timing t-tests, the harness self-test and
the diagnosis), `bench_falcon` (3) and `gen_fips206_vectors` (1, which
regenerates the fixtures and is deliberately locked away so that a "test"
cannot rewrite its own expectations).

### Coverage

`./scripts/coverage.sh` reports **98.2% of lines** (99.0% of regions, 99.3%
of functions) with `--all-features`. The residue is 113 lines, and it is not
reachable from a test:

| Uncovered | Why |
|---|---|
| 56 lines | Error returns whose condition cannot be induced from outside — a codec failing mid-keygen, a size check a correct caller cannot trip |
| 41 lines | Fragments of those same branches (arguments spread over several lines, the closing brace of an untaken block) |
| 7 lines | Internal invariants returning `FALCON_ERR_INTERNAL` |
| 1 line | A `match` arm for a degree every constructor rejects |

The OS-entropy failure paths used to be in this list; they are covered now
through a `#[cfg(test)]`-only injection point in `get_seed`, which is not
compiled into the published library. Going further would mean adding the same
kind of switch to the sampler and to the internal error paths, in code that
runs on every signature.

That is a trade we did not make for a coverage number, so those lines stay
uncovered and are enumerated here instead.

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
