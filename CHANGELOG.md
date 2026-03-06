# Changelog

All notable changes to `falcon-rs` are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
