# Migration to c-fn-dsa (v0.4 branch)

This branch moves the port from the round-3 Falcon C reference to
[pornin/c-fn-dsa](https://github.com/pornin/c-fn-dsa), pinned in
[`scripts/c-fn-dsa/UPSTREAM`](../scripts/c-fn-dsa/UPSTREAM).

**Status of upstream:** c-fn-dsa implements its author's *best guess* at the
FIPS 206 draft, which NIST has not published. Upstream promises no format
stability before its own 1.0. This branch therefore stays off `main` and
unreleased until the draft appears and upstream settles.

**Compatibility:** keys and signatures are *not* compatible with 0.3.x
(private keys grow by a 64-byte public-key hash, public keys are in NTT
form, the norm bound drops to 840, and the message goes through a
64-byte `mu` as in ML-DSA).

## Non-negotiable rules

1. **Pure Rust.** No C, no `build.rs`, no FFI, no assembly, no `-sys`/`cc`/
   `bindgen` dependency. The C reference is compiled only by the dev scripts
   below, never by `cargo build`.
2. **100% coverage.** Every ported file reaches 100% line, region and
   function coverage under the full suite. Files join
   `scripts/c-fn-dsa/PORTED` in the commit that ports them, and
   `scripts/c-fn-dsa/gate.sh` must pass before a phase is marked done.
   (The 0.3.x "98%, by choice" policy does not carry over to this branch.)

## Tooling

| Script | What it does |
|---|---|
| `scripts/c-fn-dsa/fetch.sh [dir]` | Clones upstream at the pinned commit (default `target/c-fn-dsa`), builds `test_fndsa` and runs it |
| `scripts/c-fn-dsa/gate.sh` | Enforces both rules above |
| `scripts/c-fn-dsa/extract_vectors.sh [dir]` | Regenerates `tests/fixtures/c-fn-dsa/` from upstream's `test_fndsa.c`, by compiling `dump_vectors.c` against it, so the C compiler evaluates every table |

Fixtures are checked in and must be reproducible: re-running the extractor
must leave `git status` clean. `tests/c_fn_dsa_vectors.rs` checks their
completeness and that every file names the pinned commit.

## Phases

Each phase is gated on upstream vectors before the next starts.

| # | Phase | Upstream source | Gate | Status |
|---|---|---|---|---|
| 0 | Scaffolding: pin, fetch, fixture extraction | — | Upstream suite passes; fixtures reproducible | ✅ done |
| 1 | Hashing: SHA3 on the existing Keccak core | `sha3.c` | `sha3.txt`, `shake256.txt` | ✅ done |
| 2 | mod q, NTT-format keys, codec, `mu`, verify | `mq.c`, `codec.c`, `vrfy.c` | `verify_{512,1024}_*.hex` verify; bit flips rejected | ✅ done |
| 3 | Key generation (full rewrite) | `kgen*.c` | `keygen_{256,512,1024}.txt` | ✅ done |
| 4 | Signing: SHAKE sampler, 79-bit base sampler, per-attempt seeds | `sign_*.c` | `sampler_512.txt`, then `kat_{4..1024}.txt` | ⏳ |
| 5 | Public API: `mu`-based `DomainSeparation`, new hash IDs, external mu, sizes | `fndsa.h`, `sign.c` | API tests; fault detection re-wired | ⏳ |
| 6 | Retire round-3 tests; port suites, fuzzers, examples, docs; differential test vs `rust-fn-dsa` | — | Full suite, Miri, dudect | ⏳ |
| 7 | Release 0.4.0 | — | Only once the FIPS 206 draft is out | ⏳ |

Only upstream's portable scalar paths are ported; its AVX2, SSE2, NEON,
RISC-V and Cortex-M4 paths are out of scope.
