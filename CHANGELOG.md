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

Cost (Apple M-series, measured through the high-level API with the hardening
below included): signing ~6.5x, key generation ~1.7x, verification unaffected
because it is integer-only. Off by default.

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

### Added — Verified Parity With The C Reference

The crate's one external trust anchor was the pair of SHA-1 digests in
`tests/nist_kat.rs`, described as coming from running the C reference — which
nobody downstream could check, and which two audits flagged as the one claim
they could not verify.

They are checkable. The digests are not ours: they are published in the
reference's own `test_falcon.c` (lines 5024-5025) as the expected results of
its `test_nist_KAT` self-test. The official round-3 package was fetched, the
local reference source confirmed byte-identical to it for every core
algorithm file, compiled with `clang -O2`, and run — it prints exactly those
two digests, and our test reproduces them.

`scripts/verify_c_parity.sh` performs the whole chain in one command, so
"bit-exact with the C reference" is now a verified statement rather than a
number to trust.

A version difference surfaced while comparing: the round-3 package's
`falcon.c` omits `shake256_flip` in `shake256_init_prng_from_seed` and
`shake256_init_prng_from_system`; the 2021-11-01 reference release added it,
and this port follows the later release. The test added for those two
constructors earlier in this cycle would have caught the older behaviour.

Also closed, the last isolated-testing gap the solver review named:
`zint_bezout` is now checked directly at every limb length the solver uses —
up to 209 limbs, about 6500 bits — verifying `x*u - y*v == 1` modulo three
61-bit primes plus the exact range bounds. It had been covered only
end-to-end above `len = 10`.

### Changed — Third Review Round: The Solver And The Sampling Numerics

Two areas no earlier audit had entered: the NTRU solver, and the ffSampling /
LDL-tree numerics. Both came back without a correctness defect, and the
evidence is worth recording because these are the parts that fail silently.

**The solver.** Across ~60,600 generated key pairs at every supported degree,
every `(f, g, F, G)` satisfies `f*G - g*F = q` exactly as integer polynomials
mod `x^n+1`; every basis is inside the `1.17*sqrt(q)` Gram-Schmidt bound; and
every `(F, G)` is fully Babai-reduced (the residual reduction coefficient
`|k| <= 0.5` in all cases, with its mean tracking the order statistic of n
samples on `[0, 1/2]` — an unreduced-but-valid basis would show `|k| > 1/2`).
Both floating-point backends produce byte-identical `(f, g, F, G, h)` for
5,220 keys. Under fault injection — forcing `solve_ntru` to fail after
`big_f`/`big_g` were already written — 1,500 returned keys were all valid,
with no poisoned prefill surviving a retry.

**The long-standing question about three dead bignum helpers is settled.**
`zint_norm_zero`, `zint_sub` and `zint_add_mul_small` have no callers because
their bodies were transcribed *inline* into `zint_rebuild_crt`, which is
where the reference calls them from. Checked by differentially testing the
shipped inlined form against a transcription that calls the standalone
functions: 1,200 cases spanning `xlen` 1..521 and both normalization modes,
zero differences. So no reduction step is missing. Their `#[allow(dead_code)]`
notes now say this, and warn that a fix applied to the copies will not reach
the solver.

**The sampling numerics.** `poly_LDL_fft` produces the true L and D of the
Gram matrix (verified against exact rational arithmetic, 2e-16); split and
merge are exact inverses at every level; the LDL tree layout is the one the
sampler walks (checked against an independent implementation of the
specification's algorithm); and the expanded tree is bit-identical to what the
dynamic path recomputes. The produced signatures' distribution matches theory
to 0.2-0.4%.

The priority item was `ffldl_binary_normalize`'s leaf sigma, because an error
there weakens the output distribution while leaving every fixed-seed KAT
passing. Over 18,864 leaves it is bit-for-bit
`fpr_mul(fpr_sqrt(d), FPR_INV_SIGMA[orig_logn])`, the ratio `leaf / sqrt(d)`
is a single constant across all depths, and the nearest wrong sigma index
would shift it by 5e13 times the observed spread. The constant matches the
specification's `sigma(n) = 1.17 * sqrt(q) * sigma_min(n)`.

Acted on:

- `do_sign_tree`'s scratch assertion said `5 * n`; the real requirement is
  `4 * n` plus `ff_sampling_fft`'s recursion scratch, `2^(logn+1) - 8`.
  Corrected. In-crate callers were never at risk, but the entry point is
  `pub` (doc-hidden) and the assertion is compiled out in release.
- `keygen`'s retry loop was unbounded and could not report failure: forcing
  `solve_ntru` to fail on every call made it spin forever. It now returns
  `bool` with a 1000-attempt cap, and `falcon_keygen_make` maps exhaustion to
  `FALCON_ERR_RANDOM` — the same defence-in-depth as the sampler's existing
  cap. **This changes the signature of the doc-hidden `keygen::keygen`.**
- `keygen`'s undocumented 8-byte alignment precondition on `tmp` is now
  documented and asserted in debug builds.
- `zint_bezout` deviates from its documented postcondition when `y == 1`
  (returning `u = 0, v = x - 1`). Reachable only at `logn == 1` with `Res(g)
  == 1`, and `solve_ntru`'s final `f*G - g*F == q` check rejects the result
  anyway — that check never fired across ~250,000 solver attempts. Documented
  rather than changed, since the behaviour is inherited from the reference.
- `poly_invnorm2_fft` writes only the first half of its output, a convention
  every current consumer respects; documented so a new one does not assume
  otherwise.
- `ffldl_binary_normalize` now records that the leaf-sigma lower bound is
  saturated by design, with a margin as small as 1e-5 relative, so the two
  `1.17^2` constants must never drift apart.

One thing not to document as a guarantee: the dynamic and expanded-key
signing paths produce byte-identical signatures in practice (1,340 pairs
across logn 2-10, zero differences) but are not *guaranteed* to. The inlined
`logn == 2` base case and the generic recursion compute the same value through
different rounding sequences, differing by ~1 ulp on 48% of random inputs;
that faithfully mirrors the C reference, and a 1-ulp shift in a sampler centre
changes the sampled integer with probability around 2^-50.

### Fixed — `serde` Deserialization Bypassed Every Constructor

`FnDsaKeyPair` derived `Deserialize`, which builds the struct field by field
and therefore skipped all validation. Demonstrated with a harness against
tampered JSON:

| tampered blob | before | after |
|---|---|---|
| one pair's private key with another's public key | deserialized, then signing returned `FaultDetected` | rejected as `BadArgument` |
| `logn = 3`, outside FIPS 206 | deserialized, signing returned `SizeError` | rejected as `FormatError` |
| truncated private key | deserialized, signing returned `FormatError` | rejected as `FormatError` |

The first row is the worst: `from_keys` was changed earlier in this release
precisely so a mismatched pair reports a configuration mistake instead of
`FaultDetected`, which the docs tell callers to treat as a security event —
and `Deserialize` reintroduced exactly that confusion.

Deserialization now goes through `from_keys` (`#[serde(try_from = ...)]`),
including a check that the `logn` field agrees with the key headers, and the
private key stays inside a zeroizing container on the way in.
`tests/error_paths.rs` covers all four tampering cases.

Also documented, because it is a footgun rather than a bug: **serializing a
key pair writes the private key out in the clear.** That is what the impl is
for, but it means a keypair must never be serialized into a log, a trace or
an error report.

Two checks that were looking the other way, found while fixing the above:
`cargo doc` only ever ran with default features, so broken intra-doc links in
the `fpemu` backend went unnoticed; and the Miri job I had just added would
have inherited a unit test that generates real FN-DSA-512 keys under the
interpreter. Both fixed — the docs job now also runs `--all-features`, and the
keygen-heavy tests are `#[cfg_attr(miri, ignore)]`.

### Fixed — Undefined Behaviour Found By Miri

No UB checker had ever been run against this crate. Miri finds four distinct
classes of undefined behaviour on the keygen -> expand -> sign -> verify path.
All are fixed, output is byte-identical (the KAT vectors pass unchanged), and
`cargo miri test` now runs in CI over the unit tests and a small-degree cycle
test so they cannot come back.

- **Reborrowing the scratch buffer after carving it.** Deriving slices from
  `tmp.as_mut_ptr()` and then evaluating `tmp.len()` reborrows the whole
  buffer and invalidates the tags of those slices; using them afterwards is
  UB. Nine sites across `falcon.rs` and `sign.rs`; the length is read before
  the pointer everywhere now.
- **A raw-derived slice held across further uses of its buffer.** Both
  signing cores kept `s1tmp` alive while reading `tmp` again, then wrote
  through it. Owned buffer now, as `s2_vals` already was.
- **`&mut` aliasing `&` over the same bytes.** The signature vector and the
  hashed point were two views of one region — deliberate in the C reference,
  where the signature overwrites the hashed point, and forbidden in Rust.
- **Unaligned references.** `falcon_sign_dyn_finish` built `&mut [u16]` and
  `&mut [i16]` at a fixed offset into the caller's `&mut [u8]` with no
  alignment adjustment — the expanded-key path had one, the dynamic path did
  not — so it was UB whenever the caller's buffer landed on an odd address.
  The `78 * n + 7` size contract had no slack to bump the offset, so the
  hashed point and signature vector are owned buffers in both paths now,
  which removes the alignment requirement and the aliasing together and
  leaves the scratch region larger than before. Cost: 4 KB per signature at
  logn = 10, against the 78n bytes the caller already supplies.

### Fixed — Second Adversarial Review Round

Four more reviews (the new shift ladder's arithmetic, an independent algebraic
re-derivation, a code review of the whole release diff, and a fresh security
analysis) ran against the release candidate. The arithmetic and security
reviews came back clean on the parts that mattered most — the ladder is
exactly equivalent to the semantics the rounding depends on (proof plus ~8e8
adversarial evaluations, and 3e8 old-versus-new comparisons with zero
differences), and its emitted code is branch-free on both aarch64 and x86_64.
What they did find:

- **Two install snippets pinned `version = "0.2"` while asking for `fpemu`**,
  a feature that does not exist there — following the README produced a
  build failure, and the `serde` snippet silently installed the previous
  release. The same class of defect this release already fixed once; fixed
  again, and the lesson is that version strings in docs need to move with the
  version
- **`cargo test --no-default-features` failed on three new tests** that need
  an entropy source; CI only *built* `no_std`, so it never showed. Gated on
  `std`, and the MSRV job now checks `fpemu` and `no-default-features` too
- **Secret copies escaped the zeroization sweep**: `fx_n`/`gx_n` and
  `rt2_half` in the NTRU solver are `.to_vec()` copies off `Zeroizing`
  sources, which hands back a plain `Vec`. Both auditors found this
  independently. Wrapped
- **`int_parts` still used the clamp-plus-variable-shift shape** that
  `fpr_add` was rewritten to drop — and `fpr_rint` sends secret signature
  coefficients through it. It now uses the same ladder, so no variable-count
  shift remains anywhere in the emulated backend
- The `# Errors` docs on all four signing methods omitted `FaultDetected`,
  the release's own headline error
- Clippy only ever ran with `--all-features`, which compiles the native
  backend out; both configurations are linted now
- `verify_algebra.py` had three blind spots the algebraic review exposed: the
  "order of 7 mod 12289" check accepted 2048, 4096 *or* 12288 and so
  asserted nothing (the order is exactly 2048); the Gaussian CDT check used a
  tolerance that hid the table's exact construction (it is integer-exact as
  suffix sums of the floored pmf); and only 60 of 521 solver primes were
  deep-checked. All three tightened — 35 checks now, and the array extractor
  no longer matches names inside doc comments
- `dead_code` is no longer allowed crate-wide. The eleven items that are
  genuinely dead in the library — ported-but-unused reference helpers, and
  paths live only on other targets — carry targeted allows with reasons;
  `ursh` had no callers left and was removed
- `FPR_INV_SIGMA`'s literals are one ulp above the correctly-rounded value,
  inherited from the C reference and required for KAT parity; now documented
  where they are defined rather than left as a puzzle
- The `[[test]]` blocks in `Cargo.toml` restated what auto-discovery already
  finds, and listed only the older suites; removed
- The `mulconst` tests asserted the function's own definition; they compare
  against the hardware product now

### Fixed — What CI Found On Its First Run

The new jobs earned their place immediately: two of them failed on the first
push, and neither failure reproduced on the development machine (aarch64).

- **The fuzzer found a real bug in a fuzz target** within 60 seconds, from a
  one-byte input. `fuzz_sign_verify` asserted that a signature must not
  verify under a *different* `DomainSeparation` variant — but FIPS 206
  encodes the context as `(ph_flag, len, ctx)`, so `Context(b"")` and `None`
  produce byte-identical headers and are the same domain. The library was
  right; the assertion was wrong. Fixed, and the equivalence is now pinned
  by a test of its own rather than left implicit.
- **The timing job failed on x86_64 with `fpr_add`/`fpr_sub` at |t| ~ 2200**,
  while `fpr_mul` and `fpr_sqrt` sat at ~1.3 — far too structured to be
  runner noise. Two causes, both addressed:
  - The harness refreshed only the random-class buffer before timing, so one
    class read a just-written (hot) buffer and the other a possibly-evicted
    one. On a machine with a small L1 that asymmetry dominates a cheap
    operation like addition. Both buffers are now rewritten before every
    measurement, so the only difference between classes is which one the
    timed loop reads.
  - `normalize_top` used `leading_zeros()` on all of x86_64. Baseline x86-64
    has no `lzcnt`, so that lowers to `bsr`, whose latency is data-dependent
    on some implementations — and `fpr_add`/`fpr_sub` are the only operations
    that call it. The count-leading-zeros path is now taken only where the
    target guarantees fixed latency (aarch64's `clz`, or x86_64 with `lzcnt`
    enabled); everywhere else the branchless fallback runs. The guarantee is
    now a property of the code rather than of the CPU.

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

### Changed — Test-Vector Claims Corrected

Reported from outside the project, and correct: the README claimed the crate
"passes all NIST Known Answer Tests (FN-DSA-512 & FN-DSA-1024)". NIST has
published no test vectors for FN-DSA — FIPS 206 is a draft and has no ACVP
suite — so that claim borrowed an authority that does not exist yet. Three
separate errors in one sentence:

- The vectors are not NIST's. `tests/nist_kat.rs` reproduces the NIST PQC
  *competition* KAT procedure (AES-256-CTR DRBG, 100 iterations, SHA-1 over
  the output stream) and compares against digests obtained by running
  Thomas Pornin's C reference. It is a parity check against that
  implementation.
- They are Falcon vectors, not FN-DSA ones. Falcon-512/1024 as submitted in
  round 3 is not FN-DSA as specified in draft FIPS 206, which adds the
  domain-separation layer — so passing them demonstrates nothing about
  FIPS 206 conformance.
- "All" overstated two digest comparisons.

README, the article, and the test's own documentation now state what the
vectors are, where the expected digests come from, and what they do not
show. The "production-ready" claim the same report objected to had already
been removed earlier in this release.

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
- `fpemu` cost figures reconciled across README, SECURITY.md and these notes
  (~6.5x on signing, ~1.7x on key generation, measured)
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
