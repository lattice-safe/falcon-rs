# falcon-rs

[![Crates.io](https://img.shields.io/crates/v/falcon-rs.svg)](https://crates.io/crates/falcon-rs) [![Docs.rs](https://docs.rs/falcon-rs/badge.svg)](https://docs.rs/falcon-rs) [![CI](https://github.com/lattice-safe/falcon-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/lattice-safe/falcon-rs/actions/workflows/ci.yml) [![MSRV](https://img.shields.io/badge/rustc-1.84+-blue.svg)](https://blog.rust-lang.org/2025/01/09/Rust-1.84.0.html) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Native Rust implementation of **FN-DSA**, the NIST post-quantum signature
scheme formerly known as Falcon. Ported from
[**c-fn-dsa**](https://github.com/pornin/c-fn-dsa) by Thomas Pornin.

> **Read this first — what "FIPS 206" means here.** NIST has not published
> the FIPS 206 draft. c-fn-dsa implements its author's *best guess* at it
> (little-endian encodings, public keys in NTT form, a 64-byte message
> representative `mu` that binds the public key, an infinity-norm bound of
> 840), and states that formats may still change before its own 1.0. This
> crate tracks c-fn-dsa at a pinned revision
> ([`scripts/c-fn-dsa/UPSTREAM`](scripts/c-fn-dsa/UPSTREAM)). Keys and
> signatures are **not** compatible with falcon-rs 0.3.x (round-3 Falcon),
> and may not be compatible with the final standard.
>
> **0.4.0-rc.1 is a pre-release.** Cargo never selects it on its own: a
> `"0.3"` or `"0.4"` requirement keeps resolving to 0.3.x until 0.4.0 is
> released. Opt in with an exact requirement,
> `falcon-rs = "=0.4.0-rc.1"`. Do not commit keys or signatures from it to
> anything permanent (a ledger, long-lived certificates) until the formats
> are final.

## Status

**Bit-for-bit parity with the C reference**, checked against vectors the
reference itself produces — none are self-generated:

| Vectors | From | What must match |
|---|---|---|
| End-to-end KAT, n = 4 … 1024 (90) | c-fn-dsa `test_fndsa.c` | SHA3-256(sk ‖ vk ‖ sig), raw and SHA3-pre-hashed |
| Key generation (300) | c-fn-dsa `test_fndsa.c` | SHA-256(f ‖ g ‖ F ‖ G), n = 256, 512, 1024 |
| Gaussian sampler (1024 draws) | c-fn-dsa `test_fndsa.c` | every sampled integer |
| Verification, n = 512 and 1024 | c-fn-dsa `test_fndsa.c` | accept; reject every single-bit flip |
| SHA3 and SHAKE256 | c-fn-dsa `test_fndsa.c` | every digest |
| High-level API, every domain mode (26) | c-fn-dsa public API (`fndsa.h`) | every key and signature byte |
| Randomized differential (200) | c-fn-dsa public API | every key and signature byte |
| SHA-256 / SHA-512 | NIST FIPS 180-4 | every digest |

Every vector passes on **both floating-point backends** (native and `fpemu`).
The fixtures are regenerated from the pinned reference by
[`scripts/c-fn-dsa/extract_vectors.sh`](scripts/c-fn-dsa/extract_vectors.sh),
and [`scripts/verify_c_parity.sh`](scripts/verify_c_parity.sh) closes the
loop: it builds the reference, runs its own test suite, regenerates every
fixture, requires them to be unchanged, and runs this crate against them.

**100% line, region and function coverage** of every file under `src/`,
merged over both backends, enforced by
[`scripts/c-fn-dsa/gate.sh`](scripts/c-fn-dsa/gate.sh) — see
[Coverage](#coverage) for how, and what it does and does not mean.

**Pure Rust:** no C, no FFI, no assembly, no architecture intrinsics, and
`#![forbid(unsafe_code)]` crate-wide. The same gate fails on a build
script, FFI or a native-code dependency.

**MSRV:** Rust 1.84 for the library. Building the tests and benchmarks
needs a newer toolchain (some dev-dependencies require 1.85+).

No independent audit, no CMVP validation, no NIST test vectors (there are
none for FN-DSA yet). See [Security review](#security-review) for the in-house review of the 0.4
code.

## Quick Start

```rust
use falcon::prelude::*;

// FN-DSA-512 key pair from OS entropy
let kp = FnDsaKeyPair::generate(9).unwrap();

// Sign (hedged with OS entropy) and verify
let sig = kp.sign(b"Hello, post-quantum world!", &DomainSeparation::None).unwrap();
FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), b"Hello, post-quantum world!",
    &DomainSeparation::None).unwrap();
```

## Message representative and domain separation

Every mode signs `mu`, a 64-byte SHAKE256 output that binds the hash of the
public key, as in ML-DSA:

| `DomainSeparation` | `mu` |
|---|---|
| `None` / `Context(ctx)` | `SHAKE256(H(pk) ‖ 0x00 ‖ len(ctx) ‖ ctx ‖ msg)` |
| `Prehashed { alg, context }` | `SHAKE256(H(pk) ‖ 0x01 ‖ len(ctx) ‖ ctx ‖ OID(alg) ‖ alg(msg))` |
| `ExternalMu(mu)` | the caller's 64 bytes (see `falcon::fndsa::compute_mu`) |

`PreHashAlgorithm` offers SHA-256, SHA-512, SHA3-256 and SHA3-512. Contexts
are at most 255 bytes; longer ones are rejected (`BadArgument`), never
truncated. A signature made in one mode never verifies in another.

```rust
use falcon::prelude::*;

let kp = FnDsaKeyPair::generate(9).unwrap();
let ctx = DomainSeparation::Context(b"my-protocol-v1");
let sig = kp.sign(b"msg", &ctx).unwrap();
FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), b"msg", &ctx).unwrap();

let ph = DomainSeparation::Prehashed { alg: PreHashAlgorithm::Sha3_256, context: b"" };
let sig = kp.sign(b"a large document", &ph).unwrap();
FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), b"a large document", &ph).unwrap();
```

## Sizes

| `logn` | Variant | NIST level | Private key | Public key | Signature |
|---|---|---|---|---|---|
| 9 | FN-DSA-512 | I | 1345 B | 897 B | 666 B |
| 10 | FN-DSA-1024 | V | 2369 B | 1793 B | 1280 B |

The private key is `header ‖ f ‖ g ‖ F ‖ SHAKE256(pk)[64]`; importing one
checks that the stored hash matches the key. Signatures have a fixed size.

## API overview

```rust
use falcon::prelude::*;

let kp = FnDsaKeyPair::generate_deterministic(b"at least 32 bytes of seed material", 9).unwrap();

// Deterministic signing: same inputs, same signature.
let sig = kp.sign_deterministic(b"msg", b"rnd", &DomainSeparation::None).unwrap();

// Import / export
let restored = FnDsaKeyPair::from_keys(kp.private_key(), kp.public_key()).unwrap();
let from_sk = FnDsaKeyPair::from_private_key(kp.private_key()).unwrap();
assert_eq!(from_sk.public_key(), kp.public_key());
let sig = FnDsaSignature::from_bytes(sig.into_bytes()).unwrap();

// Decode the private key once, sign many times.
let ek = kp.expand().unwrap();
let sig2 = ek.sign(b"msg", &DomainSeparation::None).unwrap();
```

The low-level module [`falcon::fndsa`](src/fndsa/mod.rs) mirrors `fndsa.h`:
encoded keys, `compute_mu` / `compute_mu_start`, every registered hash
identifier (SHA-384, SHA-512/256, SHAKE128/256 included, with a digest you
compute), and the non-standard degrees 2 … 8 for testing.

`serde` (feature) serializes keys and signatures; deserializing goes through
`from_keys` / `from_bytes`, so a tampered blob is rejected. Serializing a key
pair writes the private key in the clear, and the serializer's own buffers
(and those the deserializer grows while reading) are not zeroized by this
crate.

## Performance

High-level API, self-check included, on an Apple M-series laptop
(`cargo bench`, criterion medians; ratios vary by machine):

| Operation | native | `fpemu` |
|---|---|---|
| FN-DSA-512 keygen | 3.66 ms | 3.72 ms |
| FN-DSA-512 sign | 474 µs | 2.44 ms |
| FN-DSA-512 sign (expanded key) | 394 µs | — |
| FN-DSA-512 verify | 23.6 µs | 24.6 µs |
| FN-DSA-1024 keygen | 20.2 ms | — |
| FN-DSA-1024 sign | 915 µs | 5.50 ms |
| FN-DSA-1024 verify | 46.2 µs | 46.4 µs |

Key generation and verification are integer-only, so `fpemu` costs nothing
there. For comparison, 0.3.x on the same machine: 4.69 ms keygen, 415 µs
sign, 32 µs verify (FN-DSA-512, native). Signing is a little slower in 0.4
because it builds the Gram matrix and the per-attempt sampler state fresh
for every signature, as the reference does, and uses only portable code
(no NEON/SSE2 intrinsics).

## Constant-time floating point (`fpemu`)

Signing uses floating point (FFT, fast Fourier sampling). The default backend
uses native binary64 — strictly rounded, no FMA, with portable integer code
for rounding and square root. The `fpemu` feature replaces every
floating-point operation with branchless integer code, which removes the
floating-point timing side channel:

```toml
falcon-rs = { version = "=0.4.0-rc.1", features = ["fpemu"] }
```

Same API, same bytes: every vector above passes on both backends.
`scripts/check_no_fp.sh` disassembles the `fpemu` build and fails on any
floating-point arithmetic, compare or convert instruction (and is itself
checked against the native build, where it must fail). `tests/dudect.rs`
measures sampler and signing time with Welch's t-test, with a self-test that
requires the harness to detect a deliberate 2% difference.

Not made constant-time, in either backend: key generation (rejection loops
and the NTRU solver), the number of sampler and signing iterations (the
specified algorithm), and power/EM leakage (no masking).

## Fault detection

A signature computed from a corrupted intermediate state can expose the
private basis. Every high-level signing path verifies its own output against
the public key before returning it, and reports `FalconError::FaultDetected`
otherwise — treat that as a security event, not a retryable error. It is
always on.

Scope: it catches faults that produce an **invalid** signature. It does
not catch faults that still yield a valid one — the published Falcon fault
attacks of that kind skip or zero parts of the sampling, or make the
sampler's randomness repeat — nor an attacker who can skip the check
itself. The low-level `falcon::fndsa::sign` functions do not run the check.

## Security properties

| Property | How |
|---|---|
| No `unsafe` | `#![forbid(unsafe_code)]` |
| Secrets wiped | private keys, decoded `f, g, F, G`, the FFT basis, seeds and signing scratch are `Zeroizing`; SHAKE and PRNG states zeroize on drop |
| Hedged signing | per-signature seed `SHAKE256(SHAKE256(f‖g)[40] ‖ mu ‖ rnd)[40]`, a fresh 40-byte seed per attempt |
| Bounded retries | at most 27 signing attempts (failure probability < 2⁻²⁵⁶ for a valid key), and at most 1000 iterations per Gaussian draw, so even a degenerate key cannot make signing loop forever |
| Key validation | importing a private key checks its encoding, that `f` is invertible, that `G` is in range, the NTRU equation `fG − gF = q` (not checked by the C reference), and the embedded `H(pk)` |
| Strict decoding | malformed keys and signatures are rejected, never panic (fuzzed) |
| Key/public-key binding | `mu` includes `H(pk)`; imported private keys must carry the hash of their own public key |

See [SECURITY.md](SECURITY.md).

## Security review

**0.4 review (2026-11-17).** Three independent passes on the v0.4 code — an
algebraic audit (every constant table re-derived with exact arithmetic: NTT
and FFT roots, the 308 RNS primes, Gaussian tables, norm bounds, sampler
constants, Keccak/SHA-2; all match, and the port's five deliberate
deviations from upstream were confirmed behaviour-preserving), an
adversarial code and cryptography review, and a cyber-security /
supply-chain review. Findings and their fixes are listed in
[CHANGELOG.md](CHANGELOG.md). The most serious: a crafted private key with
`F = 0` passed import and made signing loop forever; import now checks the
NTRU equation and draws are bounded. These were in-house reviews, not an
independent audit.

Two in-house line-by-line reviews were done for 0.3.x
([`docs/CODE_REVIEW_2026-07-20.md`](docs/CODE_REVIEW_2026-07-20.md)). They do
not carry over to 0.4, which replaces the whole core.

## Testing

```sh
cargo test --release                      # native backend
cargo test --release --features fpemu     # integer backend
./scripts/verify_c_parity.sh              # rebuild the C reference and re-derive every fixture
./scripts/c-fn-dsa/gate.sh                # pure Rust + 100% coverage
cargo test --release --test dudect -- --ignored --nocapture --test-threads=1
```

| Suite | Covers |
|---|---|
| `c_fn_dsa_vectors` | the reference's own test vectors (SHAKE256, SHA3, verify, keygen, sampler, end-to-end KAT) |
| `api_vectors` | the high-level API against the C public API, every domain mode, plus 200 randomized cases |
| `api` | every accessor and every error path of the high-level API, `serde` |
| `sha2_vectors` | FIPS 180-4 SHA-256 / SHA-512 |
| `prop_tests` | property-based round-trips and cross-domain rejection |
| `round3` (feature) | `falcon::round3` reproduces falcon-rs 0.3.1's bytes; private and public key conversion keep the basis and validate |
| `round3_nist_kat` (feature) | the NIST PQC competition KAT procedure against `falcon::round3`, digests published in the round-3 C reference |
| `miri_cycle` | keygen/sign/verify at a toy degree, for `cargo miri` |
| `dudect` (ignored) | timing t-tests |
| unit tests | the arithmetic, codecs, NTRU solver, FFT and sampler internals, with the unit tests carried over from rust-fn-dsa |

### Coverage

`./scripts/c-fn-dsa/gate.sh` requires **100% of lines, regions and
functions** of every file under `src/`, merged over a native run and an
`fpemu` run (each backend is compiled only in its own build). Items are
counted per *source* location: a region is covered if any compiled copy of
it ran. (The library is compiled twice under test — with `cfg(test)` for its
unit tests and as a dependency of the integration tests — and llvm-cov's
per-file summary counts the copies separately, so a path that only a unit
test can reach, such as a forced RNG failure, would otherwise show as
uncovered in the copy that cannot reach it.) How the last percent was
reached, so the number can be judged:

- **Dead upstream code was removed, not tested** — fixed-point and
  floating-point helpers and operator impls only the architecture-specific
  paths used.
- **Unreachable branches were made explicit**: a length-table case that
  cannot occur is a `debug_assert!`; two rare rejections are folded into the
  function's return value with identical behaviour; a lazy byte comparison
  keeps its exact PRNG consumption without an unreachable tail.
- **Rare paths are driven directly** by unit tests with crafted input: a
  non-invertible `f` at depth 0 of the NTRU solver, a basis for the wrong
  lattice that makes all 27 signing attempts fail, degenerate lengths in the
  big-integer code.
- **One test-only switch**: `#[cfg(test)]` can force the OS RNG to fail, to
  cover the `RandomError` paths. It is not compiled into the library.

There is no fault-injection switch in the signing path. Coverage shows that
every line runs under test; the evidence that the lines are *right* is the
vectors above.

## Fuzzing

```sh
cargo install cargo-fuzz
cargo fuzz run fuzz_verify_reject     # random bytes must never verify
cargo fuzz run fuzz_sign_verify       # sign→verify must always succeed
cargo fuzz run fuzz_codec_roundtrip   # key/signature codecs: no panics, canonical round-trips
```

## WASM / `no_std`

```sh
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --no-default-features --release
```

Without `std` there is no OS entropy: `generate` and `sign` return
`RandomError`; use `generate_deterministic` and `sign_deterministic` with
your own randomness.

## Two formats: FN-DSA (default) and round-3 Falcon (`round3`)

0.4 is a format break. For code and data that must keep the 0.3 formats,
the `round3` feature adds `falcon::round3`, which **is** the published
falcon-rs 0.3.1 crate re-exported unchanged — same API, same bytes (checked
against 0.3.1's own regression vectors and the NIST PQC competition KAT
digests of the round-3 C reference):

```toml
falcon-rs = { version = "=0.4.0-rc.1", features = ["round3"] }
```

```rust
// 0.3 code: change `falcon::` to `falcon::round3::`
use falcon::round3::prelude::*;
```

**The formats cannot be told apart from the bytes**: public keys have the
same header and size in both (897 / 1793 bytes), and so do signature
headers. Decide which API a key or signature belongs to from context, never
by trying one and falling back to the other.

**Key conversion.** A round-3 private key holds the same secret basis
`(f, g, F)` as an FN-DSA one, so it converts:

```rust
let old = falcon::round3::FnDsaKeyPair::generate_deterministic(b"legacy key", 9).unwrap();
let new = falcon::round3::to_fndsa_keypair(old.private_key()).unwrap();
// `new` signs with the same trapdoor in the FN-DSA formats; distribute
// new.public_key() to verifiers (its encoding differs from the old one).

// Verifiers holding only the old public key derive the same new key,
// no secret needed:
let vk = falcon::round3::to_fndsa_public_key(old.public_key()).unwrap();
assert_eq!(vk, new.public_key());
```

The converted key passes the full FN-DSA import validation (including the
NTRU equation). Signatures do not convert: round-3 signatures verify only
with `falcon::round3`. Anything derived from the public-key *bytes* (an
address, a key fingerprint) changes with the conversion; systems that key
accounts by such a value need their own mapping from the old value to the
new one. The 0.3 code has `unsafe` blocks; they stay in that
crate, and `#![forbid(unsafe_code)]` and the 100% coverage gate apply to
this crate's own code.

0.3.x maintenance (security fixes only) continues on the `release/0.3`
branch. See [CHANGELOG.md](CHANGELOG.md) and
[`docs/MIGRATION_C_FN_DSA.md`](docs/MIGRATION_C_FN_DSA.md); the low-level
round-3 C-style API is available as `falcon::round3::falcon`.

## License

MIT. c-fn-dsa and rust-fn-dsa, from which the core is ported, are public
domain (Unlicense).
