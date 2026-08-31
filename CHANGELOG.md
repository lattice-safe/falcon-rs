# Changelog

All notable changes to `falcon-rs` are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.3.0] — 2026-08-31

**Breaking:** `FalconError` gained the `FaultDetected` variant, so exhaustive
`match` arms on it must be updated (the enum is now `#[non_exhaustive]`, so
this is the last time a new variant breaks callers). `FnDsaKeyPair::from_keys`
now rejects a mismatched key pair with `BadArgument` where it previously
accepted it.

### Added — Constant-Time Floating-Point Backend (`fpemu`)

Falcon's signing path runs the private key through a floating-point FFT, and
floating-point instruction timing is data-dependent on some architectures.
The new opt-in `fpemu` feature removes that side channel without changing a
single output byte.

- `src/fpr/emu.rs` — branchless integer IEEE-754 binary64 backend: `Fpr`
  holds the bit pattern in a `u64`; add, sub, mul, div, sqrt, rounding,
  comparison and `expm_p63` are implemented with masks and fixed-count
  loops, round-to-nearest-ties-to-even, no data-dependent branch or memory
  access
- `src/fpr/` — `fpr.rs` split into `mod.rs` (shared constants and tables),
  `native.rs` (the existing `f64` backend, still the default) and `emu.rs`;
  the constant tables are shared and converted at compile time, so no
  literal was retyped
- `Fpr::to_f64()` on both backends, for backend-agnostic callers and tests
- `tests/fpr_diff.rs` — differential tests: every operation against native
  `f64`, bit for bit, over ~2M random values plus IEEE edge cases (signed
  zeros, exact ties, total cancellation, sticky-bit and alignment paths)
- `scripts/check_no_fp.sh` — disassembles the built crate and fails if any
  floating-point arithmetic, compare or convert instruction is present; CI
  also runs it against the native build, where it must fail
- CI job `fpemu` — KAT vectors, `no_std` build and both machine-code checks

**FIPS 206 compliance is unchanged:** the NIST KAT (FN-DSA-512/1024) and the
FIPS 206 domain-separation KAT vectors produce byte-identical signatures
under both backends.

Cost (Apple M-series): signing ~10x, key generation ~1.6x, verification
unaffected (it is integer-only). Off by default.

### Added — Fault Detection on Signing

- Every signing path in `safe_api` (`FnDsaKeyPair::sign`,
  `sign_deterministic`, and both `FnDsaExpandedKey` equivalents) now
  verifies its own output against the public key before returning it. A
  Falcon signature produced from a corrupted intermediate state can expose
  the private basis, so a fault now yields an error rather than a leak
- `FalconError::FaultDetected` — new variant, returned when that check
  fails. **Adding it is a breaking change for exhaustive `match` arms on
  `FalconError`**
- Cost: one verification per signature — measured +10% on the default
  backend (0.32 ms -> 0.357 ms for FN-DSA-512), ~1% with `fpemu`. Always on;
  there is no flag to disable it
- Unit tests in `safe_api` cover a mismatched message, single flipped bits
  at three positions in the signature, and that honest signatures in every
  domain-separation mode still pass

### Added — Timing Measurements (`tests/dudect.rs`)

- Welch t-test harness following the `dudect` method: two input classes
  (fixed and random) interleaved randomly, percentile-cropped, threshold
  `|t| > 4.5`, three attempts before failing so that a loaded CI machine
  does not produce a false positive
- Covers every `Fpr` operation, normal-versus-subnormal operands, the
  Gaussian sampler's centre (which comes from the private basis) and full
  signing; verification is reported but not gated, since it processes only
  public data
- `harness_detects_known_leak` — the harness must flag a deliberate 2%
  timing difference, so a clean result cannot be an artefact of an
  insensitive measurement (it reports `|t| ~ 60` against the threshold 4.5)
- CI job `dudect` runs the suite on the `fpemu` backend as a gate, and on
  the native backend for comparison without gating
- Removed `tests/timing_test.rs`, superseded: it compared wall-clock ratios
  with a 20% tolerance, and its verification test asserted nothing

### Fixed — Findings From The Adversarial Review

Four independent audits were run over the changes above (fpemu internals,
signing-path side channels, refactor integrity, and documentation claims).
What they found:

- `scripts/verify_algebra.py` was broken by the module split — it still
  opened the removed `src/fpr.rs` and died before checking anything, while
  README told users to run it. Fixed, and now gated in CI (job `algebra`),
  which is what should have caught the breakage: 33/33 checks pass
- Secret-derived intermediates are now wiped: the nine ff-Sampling scratch
  buffers and the two signature-coefficient vectors in `src/sign.rs` are
  `Zeroizing`, and `Fpr` implements `Zeroize` on both backends. A rejected
  signature is wiped in `checked_signature` before the `FaultDetected`
  error is returned — it is discarded precisely because it may encode
  private-basis information
- `FnDsaKeyPair::from_keys` now recomputes the public key from the private
  key and rejects a mismatched pair with `BadArgument`. Previously such a
  pair imported cleanly and then failed the signing self-check, reporting a
  hardware-fault alarm for a configuration mistake
- `FalconError` is `#[non_exhaustive]`, so the next variant is not another
  breaking change
- `tests/dudect.rs` gated tests judge by the **median** of three
  measurements. The previous rule passed if *any* attempt was under the
  threshold, and the audit caught it passing a run of |t| = 6.35, 7.71, 2.26
- `src/fpr/emu.rs` module docs: the flush threshold is `2^-1022` (the
  smallest normal), not `2^-1076` as written, and the clamp happens before
  rounding, so a result IEEE would round *up* to the smallest normal becomes
  zero. `tests/fpr_diff.rs` now pins this and the other documented
  deviations with a verified counterexample
  (`fpr_mul(0x1E00000000000000, 0x21FFFFFFFFFFFFFF)`)

### Added — Test Coverage

Line coverage went from 94.4% to **97.8%** (98.8% of regions, 99.3% of
functions), and the test count from 116 to 165.

- `tests/lowlevel_api.rs` — the ported C-style API had been exercised only
  incidentally: all three signature formats end to end on both the dynamic
  and expanded-key paths, header and degree validation on every entry
  point, short-output-buffer handling per format, corrupted key and
  signature bodies, and key generation across every supported degree
- `tests/error_paths.rs` — the codec decoders are the crate's untrusted-input
  surface: trailing padding bits, the forbidden `-2^(bits-1)` encoding,
  unterminated unary runs, `-0`, truncated input and short output buffers,
  for each of the four codecs, plus argument validation on the high-level API
- Unit tests inside the modules for what integration tests cannot reach:
  the branchless modular helpers (`mq_add`/`mq_sub`/`mq_rshift1`, checked
  exhaustively against plain modular arithmetic), the bignum primitives the
  NTRU solver is built on, the alignment helpers, SHAKE state accessors,
  PRNG defaults, `fpr_mulconst`, and the error-code mapping
- `src/main.rs` removed: a "Hello, world!" stub was being published as a
  binary target
- `variant_name` no longer carries match arms for degrees that every
  constructor rejects

The remaining ~127 uncovered lines are enumerated in the README: error
returns whose condition cannot be induced from outside, internal
invariants, OS-entropy failure, and the sampler's defensive panic. Covering
the last two would require a fault-injection switch in the RNG and the
sampler, which is not a thing to ship for a coverage number.

### Changed — Documentation Claims Corrected

The claims audit found the README overselling in ways worth listing:

- **The install snippets named a different crate.** README said
  `falcon-rust = ...`, which is an unrelated crate on crates.io; this
  package is `falcon-rs`. A reader following the README would have
  installed someone else's implementation
- FIPS 206 is a **draft**, not a finalized standard — corrected in README,
  SECURITY.md, `Cargo.toml`, `src/lib.rs` and the article, which claimed
  NIST "finalized FIPS 206"
- The FIPS 206 domain-separation vectors are **self-generated** regression
  anchors (NIST has published no ACVP vectors for that layer). README
  implied they were external
- "Security audited (twice)" now says in-house review, with no independent
  third-party audit; "Production-ready" removed
- The article's "SIMD NTT" claim was false — there is no SIMD in the crate
- Stale numbers: MSRV badge (1.70 → 1.84), test counts (116 → 124), unsafe
  blocks (164 → ~140), article counters (92 tests, 164 unsafe, v0.2.3)
- "No C bindings" — `getrandom` reaches OS entropy through `libc`; the
  dependency table now says so and lists `getrandom`
- `fpemu` cost figures reconciled between README and SECURITY.md (~7x on
  signing, ~1.5x on keygen, measured)
- The differential-test figure was *understated*: ~4M random draws and ~7M
  bit-exact comparisons, not "~2M values"
- The article's "harvest now, decrypt later" paragraph conflated encryption
  with signatures; rewritten around long-lived signing keys

### Changed

- `SECURITY.md`, `README.md`, `docs/MATH.md`, `docs/article/index.html` —
  constant-time claims restated to match what the code does: the scope of
  the branchless paths, the `fpemu` option and its verification, and the
  parts that remain data-dependent in both backends (key generation, the
  specified rejection-sampling loops, and the absence of masking or
  fault-attack countermeasures)
- **Two claims were refuted by the audits and are now corrected.**
  SECURITY.md said `fpemu` means "no timing in the signing path depends on
  the private key's values" — false: the sampler's acceptance rate scales
  with `sigma_min / sigma`, and the per-node sigma comes from the private
  basis, so mean signing time is a weak function of the key. It also said
  the rejection loops' iteration counts are "statistically independent of
  the secret"; what `sampler_timing_vs_centre` actually establishes is
  independence from the sampler's *centre*. Both now say what the code and
  the measurements support

---

## [0.2.5] — 2026-07-20

### Security — Deep Algebraic & Code Review (2026-07-20)

See [`docs/CODE_REVIEW_2026-07-20.md`](docs/CODE_REVIEW_2026-07-20.md). Every
constant table was re-derived from first principles (`scripts/verify_algebra.py`,
33/33 checks). **No computed value changed — all KATs still pass.**

- **F1:** Removed unaligned `u8→u16` cast in `hash_to_point_ct`; now byte-wise, no `unsafe` (`common.rs`)
- **F2:** Removed aliased `&mut [u16]`/`&mut [i16]` views in `verify_raw`; normalization uses a dedicated buffer (`vrfy.rs`)
- **F3:** Centralized unchecked `u8→u16` casts into `tmp_as_u16()` with length+alignment asserts (`vrfy.rs`)
- **F4:** Eliminated release-mode UB in `is_short`/`is_short_half` (`get_unchecked` guarded only by `debug_assert!`) via safe slicing (`common.rs`)
- **F5:** Removed redundant idempotent sign-extension line in `trim_i16_decode` (`codec.rs`)
- **F6:** Removed dead binding in `ifft` (`fft.rs`)
- **F7:** Replaced `unsafe` table walk with safe `chunks_exact(3)` in the Gaussian sampler (`sign.rs`)

### Added

- `tests/deep_coverage.rs` — +29 internal + algebraic property tests (line coverage ~94%)
- `scripts/verify_algebra.py` — 33-check algebraic verification harness
- `scripts/coverage.sh` — `cargo llvm-cov` line-coverage gate (≥90%)
- `Dockerfile` + `.dockerignore` — reproducible Alpine/musl run of the full suite

### Fixed

- `tests/deep_coverage.rs`: corrected an invalid exact-float assertion in `fft_add_sub_neg_adj_const` (tested `poly_neg` on an FP-rounded value)

### Changed

- Test count: 94 → 116

---

## [0.2.1] — 2026-03-06

### Security — Deep Code Audit

- **F1:** Replaced unsafe raw pointer u64 read with safe `copy_from_slice` (`rng.rs`)
- **F2/F9:** Scope-separated aliased `&mut` references in both signing paths (`falcon.rs`)
- **F3:** Split `get_seed` into `#[cfg]` variants with clear no\_std/WASM documentation (`rng.rs`)
- **F4:** Added `debug_assert!` alignment checks before u8→u16 transmutes (`vrfy.rs`)
- **F7:** Added 1000-iteration cap to Gaussian sampler rejection loop (`sign.rs`)

### Added

- `tests/timing_test.rs` — constant-time validation tests (sign ratio=1.15, verify ratio=1.00)
- CI: `audit` job — RUSTSEC advisory checks via `rustsec/audit-check`
- CI: `miri` job — UB detection with symbolic alignment and retag checks
- README: Security Audit section with 12-finding summary
- README: Expanded Security Properties table (10 properties)

### Changed

- Version: `0.2.0 → 0.2.1`
- Test count: 92 → 94 (added 2 timing tests)

---

## [0.2.0] — 2026-03-06

### Added — FIPS 206 Full Compliance

#### HashFN-DSA (ph_flag = 0x01)
- New `DomainSeparation::Prehashed { alg: PreHashAlgorithm, context: &[u8] }` variant
- New `PreHashAlgorithm` enum (`Sha256`, `Sha512`) with correct NIST OIDs injected into the hash context
- Pure-Rust SHA-256 and SHA-512 (FIPS 180-4 compliant, no external deps, `no_std` safe)
- `sha256_public` / `sha512_public` doc-hidden exports for integration-test NIST vector validation

#### Pure FN-DSA (ph_flag = 0x00)
- `DomainSeparation::Context(&[u8])` — bind signatures to a protocol context string
- Strict context length validation: `> 255 bytes → Err(FalconError::BadArgument)` in `sign`, `sign_deterministic`, and `verify`

#### SDK ergonomics
- `pub mod prelude` — `use falcon::prelude::*` imports all core types
- Root-level re-exports: `use falcon::FnDsaKeyPair` now works without `safe_api`
- `DomainSeparation` and `PreHashAlgorithm` derive `Clone, Copy, PartialEq, Eq`
- `--features serde`: `DomainSeparation` and `PreHashAlgorithm` now implement `Serialize`/`Deserialize`
- `FalconError` implements `std::error::Error` (gated on `std` feature) — integrates with `?` / `anyhow`

#### Tests (81 total, up from 16)
- `tests/fips206_kat.rs` — 6 deterministic FIPS 206 KAT vectors (all domain modes, FN-DSA-512 + 1024)
- `tests/full_coverage.rs` — 47 tests: context cross-rejection, length validation, HashFN-DSA round-trips, FIPS 180-4 SHA-256/SHA-512 NIST vectors
- `tests/fixtures/fips206/` — 12 hex fixture files (pk + sig) for each KAT vector

#### Benchmarks
- Criterion suite expanded: `safe_api` sign/verify groups for `None`, `Context`, `Prehashed SHA-256/SHA-512`
- Ad-hoc bench (`bench_falcon.rs`) updated with safe_api sections alongside existing low-level baselines

#### Fuzz targets
- `fuzz_sign_verify`: now uses `FnDsaSignature::verify` with domain-separation fuzzing (all 4 modes, cross-domain rejection)
- `fuzz_verify_reject`: now uses `FnDsaSignature::verify` across all 4 domain modes

#### Documentation
- `lib.rs` — added HashFN-DSA code example, module reference table, feature flag table
- `README.md` — full benchmark table (fresh numbers), HashFN-DSA API section, test matrix table, WASM arg-order fix

### Changed
- Version: `0.1.0 → 0.2.0`
- `DomainSeparation` doc-comment updated with FIPS 206 wire-format reference table
- Criterion benchmarks renamed (`falcon512_*` → `fn_dsa_512_*`) for clarity

---

## [0.2.0] — 2026-03-06

### Added — SDK Polish
- `serde` feature flag: `FnDsaKeyPair`, `FnDsaSignature`, `FalconError` implement `Serialize`/`Deserialize`
- Example programs: `keygen`, `sign_verify`, `serialize`
- Fuzz targets: `fuzz_verify_reject`, `fuzz_sign_verify`, `fuzz_codec_roundtrip`
- Benchmark suite via Criterion

### Changed
- Renamed `FalconKeyPair` → `FnDsaKeyPair`, `FalconSignature` → `FnDsaSignature` (aliases kept for backward compat)
- `DomainSeparation::None` is now the default for all signing/verification calls

---

## [0.1.0] — 2026-03-05

### Added — Initial Rust Port
- Faithful port of the Falcon C reference implementation (Thomas Pornin)
- Modules: `shake`, `fpr`, `fft`, `codec`, `rng`, `keygen`, `sign`, `vrfy`, `common`, `falcon` (API)
- Passes all NIST Known Answer Tests for FN-DSA-512 (logn=9) and FN-DSA-1024 (logn=10)
- Bit-for-bit parity with C reference: Gaussian sampling, NTRU solver, `zint_bezout`
- `no_std` support, WASM-compatible (`wasm32-unknown-unknown`)
- NTT/FFT performance optimizations, heap-allocation elimination in recursive sampling
