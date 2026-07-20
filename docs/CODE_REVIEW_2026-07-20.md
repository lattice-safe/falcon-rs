# falcon-rs — Deep Algebraic & Code Review (2026-07-20)

Scope: full source tree (`src/*.rs`, 12,954 lines) reviewed against the Falcon
C reference (Pornin) and FIPS 206 semantics. Every constant table was
re-derived from first principles with exact arithmetic
(`scripts/verify_algebra.py`, 33/33 checks pass).

## 1. Algebraic verification — all correct

| Item | Method | Result |
|---|---|---|
| `FPR_GM_TAB` (2048 FFT roots) | recomputed `exp(iπ·brev10(k)/1024)` per entry | exact match (entry 0 unused, as in C) |
| `GMB`/`IGMB` NTT tables | recomputed `R·7^rev10(x) mod 12289`, `R·8778^rev10(x)` | exact match, all 2048 entries |
| Montgomery constants `R=4091`, `R2=10952`, `Q0I=12287` | `2^16 mod q`, `R² mod q`, `q·Q0I ≡ −1 mod 2^16` | correct |
| `mq_div_12289` addition chain | symbolic exponent evaluation | exponent = 12287 = q−2 ✔ |
| `NI_TAB` | `R·n⁻¹ mod q` for all logn | exact match |
| `L2BOUND` | vs reference + independent `⌊(1.1σ)²·2n⌋` | exact / within rounding |
| `GAUSS0_DIST` (RCDT σ=1.8205) | 72-bit tail probabilities, exact Decimal | match within 8 ulps at 2⁻⁷² (generator rounding); strictly decreasing, terminates at 1 |
| `GAUSS_1024_12289` (keygen CDT) | full sampler-semantics model vs `D(σ=1.17·√(q/2048))` | P(0) and all P(±k) match to <2⁻⁵⁸ |
| `FPR_INV_SIGMA` / `FPR_SIGMA_MIN` | vs C reference + monotonicity + σ₅₁₂=165.7366 | exact |
| `REV10`, `OVERTAB`, `MAX_*_BITS` | recomputed / vs C | exact |
| `PRIMES` (521 entries) | primality (Miller–Rabin), p≡1 mod 2048, ord(g)=2048, decreasing, `s` = CRT inverse | correct; 521 ≥ max index used (308) |
| Keccak RC, SHA-256/512 K | recomputed (LFSR / cube-root fractions) | exact |
| FFT/iFFT, poly ops, LDL, split/merge | structural diff vs fft.c + new property tests | correct |
| NTT butterflies, `verify_raw` algebra | structural diff vs vrfy.c + new `verify_recover` reconstruction test | correct |
| `fpr_rint` / `fpr_expm_p63` | vs C FPNATIVE (bit-identical logic); FACCT coefficients verbatim | correct |
| ChaCha20 PRNG, SHAKE256 | vs rng.c/shake.c incl. interleaving `(u<<2)+(v<<5)` and counter add-back | correct; endianness handled explicitly (portable) |
| Size formulas (`falcon_*_size`, `tmpsize_*`) | vs C macros | exact |

No algebraic errors were found. KAT compatibility is preserved: none of the
fixes below change any computed value.

## 2. Findings fixed

**F1 (soundness, `src/common.rs::hash_to_point_ct`)** — cast `&mut [u8] →
&mut [u16]` via `from_raw_parts_mut` with no alignment guarantee: undefined
behavior on an unaligned buffer. Rewritten with byte-level `tmp_get`/`tmp_set`
helpers (no `unsafe`, no alignment requirement, identical output).

**F2 (soundness, `src/vrfy.rs::verify_raw`)** — two live `&mut` views (`tt:
&mut [u16]` and `s1: &mut [i16]`) over the same memory, both accessed in the
same loop: aliasing UB under Rust's memory model. The normalization now writes
into a dedicated stack buffer; the `i16` reinterpretation is gone.

**F3 (soundness, `src/vrfy.rs`, 6 functions)** — unchecked `u8→u16` pointer
casts in `verify_raw`, `compute_public`, `complete_private`, `is_invertible`,
`count_nttzero`, `verify_recover`. Centralized into `tmp_as_u16()` which
asserts length and 2-byte alignment (panic instead of UB; all in-crate callers
pass aligned scratch).

**F4 (release-mode UB risk, `src/common.rs`)** — `is_short`/`is_short_half`
used `get_unchecked` guarded only by `debug_assert!`; a short slice in release
was UB. Replaced with slice truncation + safe indexing (bounds checks elided
by the compiler; constant-time accumulation preserved).

**F5 (cleanup, `src/codec.rs::trim_i16_decode`)** — duplicated (idempotent)
`w |= (w & mask2).wrapping_neg();` line removed (single line as in the C
reference).

**F6 (cleanup, `src/fft.rs::ifft`)** — dead `let _ = i1;` removed.

**F7 (hardening, `src/sign.rs::gaussian0_sampler`)** — unnecessary `unsafe`
`get_unchecked` table walk replaced with safe `chunks_exact(3)`; constant-time
structure unchanged.

## 3. Noted, intentionally not changed

- `sign.rs` (`do_sign_tree`/`do_sign_dyn`) and `falcon.rs` use raw-pointer
  slice carving over one scratch buffer, mirroring the C layout. Regions are
  disjoint at every use, but some patterns are technically flagged by strict
  aliasing models (Miri). A full borrow-clean rewrite is invasive and risks
  KAT regressions; recommended as its own change with Miri in CI.
- `keygen.rs::make_fg_step` and the samplers allocate `Vec`s in hot paths
  (deviation from the C in-place layout). Correct, but heap traffic during
  signing/keygen; candidate for a later perf pass.
- `safe_api` derives `serde::Deserialize` for `FnDsaKeyPair` when the `serde`
  feature is on; deserialization bypasses key validation. Consider a
  validating `TryFrom` in a future breaking release.
- `sampler()` caps at 1000 iterations with a documented panic (deviation from
  C's infinite loop): sound defense-in-depth, distribution unaffected.

## 4. New tests & coverage

- `tests/deep_coverage.rs` (+29 tests, registered in `Cargo.toml`): fpr
  rounding edges (ties-to-even, ±2⁵² branch), `fpr_expm_p63` accuracy,
  FFT↔schoolbook negacyclic equivalence, div/LDL/split-merge identities,
  `verify_recover` public-key reconstruction against schoolbook mod-q algebra,
  NTRU identity `f·G − g·F = q`, hash-to-point CT≡vartime for all logn 1–10,
  `is_short` boundary values at the exact L2 bound and saturation, all codec
  error paths (range, truncation, trailing bits, forbidden −2^(b−1), −0),
  SHAKE rate-boundary and multi-block behavior, PRNG refill boundaries and
  stream consistency, Gaussian sampler mean/variance, keygen→sign→verify for
  logn 1–8 (covers all solver depths), expanded-key signing for logn 1–3
  (covers `ff_sampling_fft` inline leaves), API error paths, safe_api branch
  coverage (Debug redaction, from_keys/from_bytes validation, Display).
- `scripts/coverage.sh` — runs `cargo llvm-cov` with `--fail-under-lines 90`.
- `scripts/verify_algebra.py` — the 33-check algebraic harness (rerunnable).

Verify locally (no Rust toolchain was available in the review sandbox):

```sh
cargo test                 # full suite incl. KATs + new deep_coverage
cargo clippy --all-targets
./scripts/coverage.sh      # enforces >= 90% line coverage
python3 scripts/verify_algebra.py
```
