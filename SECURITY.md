# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| 0.2.x   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in `falcon-rs`, please report it
responsibly:

1. **Do NOT open a public GitHub issue.**
2. Email **latticesafe@gmail.com** with:
   - A description of the vulnerability
   - Steps to reproduce
   - Impact assessment
   - Suggested fix (if any)
3. You will receive an acknowledgment within **48 hours**.
4. We will work with you to understand and address the issue before any public
   disclosure.

## Security Considerations

### What this crate provides

- **FN-DSA signing and verification** per the draft FIPS 206. The standard
  is not final, and NIST has published no ACVP vectors for the
  domain-separation layer, so conformance there is checked against
  self-generated deterministic vectors rather than official ones
- **Automatic zeroization** of PRNG state on drop via `write_volatile`, and
  of secret-derived intermediates: the ff-Sampling scratch buffers and
  signature coefficients in signing, and all 85 working buffers in key
  generation, are wiped on drop rather than left in freed heap. This costs
  about 16% of a signature and 2% of a key generation. Note that `Drop` does
  not run under `panic = "abort"` — see below
- **Fault detection on signing** — every signing path in the high-level API
  verifies its own output against the public key before returning it, and
  returns `FalconError::FaultDetected` instead of a signature if the check
  fails. A Falcon signature produced from a corrupted intermediate state can
  expose the private basis, so this turns a fault into an error rather than
  a key leak. Cost: one verification per signature (~10% on the default
  backend). Always on
- **Optional constant-time floating point** — the `fpemu` feature replaces
  the hardware `f64` backend with branchless integer IEEE-754 arithmetic, so
  the timing of the arithmetic in the signing path no longer depends on the
  values it processes. This is not a blanket constant-time claim — the
  rejection-sampling loops still iterate a data-dependent number of times,
  see below. Output
  is bit-identical (the NIST and FIPS 206 KAT suites pass under both
  backends), verified by `tests/fpr_diff.rs` and by
  `scripts/check_no_fp.sh`, which fails if the compiled crate contains any
  floating-point instruction
- **No C code** — pure Rust implementation; nothing is compiled or vendored
  from C. (With the default `std` feature, `getrandom` reaches the OS entropy
  source through `libc`, which is FFI to the system C library.)
- **`no_std` compatible** — works in embedded and WASM environments

### What this crate does NOT provide

- **Certified FIPS 206 module** — This implementation has not been submitted
  for CMVP validation. Do not use it where a certified module is required.
- **Constant-time FFT by default** — On the default backend the FFT and
  ff-Sampling use hardware floating-point operations, whose timing is
  data-dependent on some architectures. The C reference has the same
  property in `FPNATIVE` mode. Build with `--features fpemu` to remove
  this; see "Constant-time backend" below.
- **Constant-time key generation** — The Gaussian rejection loops and the
  NTRU solver in `keygen` run in data-dependent time, in both backends, as
  in the C reference. Generate keys where an attacker cannot observe the
  timing.
- **Constant-time rejection sampling** — The discrete Gaussian sampler and
  the signature-norm retry loop iterate a data-dependent number of times and
  consume a variable number of PRNG bytes. This is the algorithm as
  specified: a fixed-count variant would produce different signatures and
  fail the KAT vectors. (The byte-comparison loop inside `ber_exp` stops at
  the first mismatch against a *fresh uniform* byte, so its iteration count
  is independent of the value being tested.)
- **Masking against power/EM analysis** — No DPA countermeasures are
  implemented: no masking, no shuffling, no randomised execution order. The
  published practical attacks on Falcon are single-trace power/EM attacks on
  ff-Sampling, and they require physical access to the device. `fpemu` does
  not address them, and may present a different (not smaller) leakage
  surface, since it performs the same computation with more integer
  operations.
- **Complete fault-attack protection** — Signing verifies its own output,
  which catches a fault that corrupts the result (see above). It does not
  stop an attacker who can glitch the verification itself or the branch that
  acts on its result, and key generation has no equivalent check.
- **Formal verification** — The implementation is a faithful port of the
  C reference but has not been formally verified.
- **Hardware-backed key storage** — Key material lives in process memory.
  Use HSMs or secure enclaves for high-value keys.

### A note on `panic = "abort"`

Zeroization runs in `Drop`, so it depends on unwinding. A profile with
`panic = "abort"` (this crate sets none) skips destructors, and key
material, PRNG state and scratch buffers would not be wiped if a panic ever
occurred. The crate's own panics are unreachable by construction — the
sampler's 1000-iteration cap fires with probability below 2^-1000 — but if
you build with `panic = "abort"`, that is the trade you are making.

### Constant-time backend

```toml
falcon-rs = { version = "0.2", features = ["fpemu"] }
```

`fpemu` costs roughly 6.5x on signing and 1.7x on key generation, and
nothing on verification, which is integer-only (measured on Apple M-series;
the ratio varies by machine). It is off by default so that the
common case stays fast; enable it when private-key operations run somewhere
an attacker can measure them — shared hosts, smart cards, WASM in a browser,
or any target whose floating-point unit has data-dependent timing.

What is verified, in CI, on every commit:

1. `cargo test --release --features fpemu` — the full NIST and FIPS 206 KAT
   vectors produce byte-identical signatures under the emulated backend.
2. `tests/fpr_diff.rs` — every `Fpr` operation matches native `f64` bit for
   bit over ~2M random values and the IEEE edge cases.
3. `scripts/check_no_fp.sh` — the disassembled crate contains no
   floating-point arithmetic, compare or convert instruction. The same
   script is run against the default backend, where it must fail; that is
   how we know the check is not vacuous.
4. `tests/dudect.rs` — Welch's t-test (the `dudect` method) over
   fixed-versus-random inputs, interleaved randomly, with percentile
   cropping, three measurements judged by the median, and a `|t| > 4.5`
   threshold. The same file contains a self-test that requires the harness
   to detect a deliberate 2% timing difference, so a clean result is
   evidence rather than an artefact of a blind measurement.

   Gated: the Gaussian sampler's centre (which comes from the private
   basis), full signing, and normal-versus-subnormal operands. These are
   stable on both aarch64 and x86_64.

   Reported but **not** gated: the per-operation rows. On the x86_64 runner
   `fpr_add` and `fpr_sub` measure well above the control, and the
   investigation recorded in that file's documentation could not attribute
   it to the code — operands that share an exponent and differ only in
   mantissa bits measure high too, and for those the masks, shift amounts
   and branch decisions inside the operation are bit-for-bit identical, so
   no control-flow difference exists to measure. Reshaping the alignment
   into a provably uniform ladder made the numbers worse rather than
   better, which a structural leak cannot do. What remains is
   value-dependence that a 512-iteration microbenchmark timed with
   `Instant` on a shared cloud vCPU cannot separate from the machine. We
   report it rather than either gating on it or claiming it away.

What the measurements say about the parts that remain data-dependent:

* `ber_exp`'s byte loop compares against a *fresh uniform* random byte, so
  the probability of continuing is 1/256 per step whatever the value being
  tested — its iteration count is genuinely independent of that value.
* The sampler's rejection loop shows no measurable dependence on the
  sampler's centre, which is what `sampler_timing_vs_centre` tests (a Welch
  t-test on mean timing; it cannot rule out higher-order correlation). It is
  **not** independent of the key in general: the acceptance rate scales with
  `sigma_min / sigma`, and the per-node sigma is derived from the private
  basis, so mean signing time is a weak function of the key. Averaged over
  very many signatures under one key that is a real, if narrow, channel —
  the standard Falcon rejection-count behaviour, which no backend choice
  removes.
* Key generation is not covered by any of this and remains variable-time.

### Dependencies

No dependency compiles or vendors C code. `getrandom` binds to the system C library through `libc` for OS entropy:

| Crate | Purpose |
|-------|---------|
| `getrandom` | OS entropy (default `std` feature only; pulls in `libc`) |
| `libm` | Math functions for the native FFT backend |
| `zeroize` | Secure memory zeroing |
