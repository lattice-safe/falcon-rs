# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: (unreleased: `v0.4` branch only; tracks c-fn-dsa, formats may change) |
| 0.3.x   | :white_check_mark: (round-3 Falcon; security fixes only) |
| 0.2.x   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in `falcon-rs`, please report it
responsibly:

1. **Do NOT open a public GitHub issue.**
2. Use GitHub's private vulnerability reporting (Security → Report a
   vulnerability) where enabled, or email **latticesafe@gmail.com** with:
   - A description of the vulnerability
   - Steps to reproduce
   - Impact assessment
   - Suggested fix (if any)
3. We aim to acknowledge reports within 48 hours (best effort; this is a
   small project).
4. We will work with you to understand and address the issue before any public
   disclosure.

## Security Considerations

### What this crate provides

- **FN-DSA signing and verification** following c-fn-dsa's best guess at the
  unpublished FIPS 206 draft. Every output is checked bit for bit against
  vectors produced by the C reference itself (see below); there are no NIST
  vectors for FN-DSA yet, and formats may change when the draft appears.
- **Automatic zeroization** of secret material on drop: encoded private keys,
  the decoded `f, g, F, G`, the FFT-form basis, per-signature seeds, signing
  scratch, key-generation scratch, and SHAKE/PRNG states. Note that `Drop`
  does not run under `panic = "abort"` — see below.
- **Private-key validation** — import checks the encoding, invertibility of
  `f`, the range of `G`, the NTRU equation `fG − gF = q` and the embedded
  public-key hash. Without the NTRU check (which the C reference omits) a
  crafted key could make signing loop forever; draws are also capped at
  1000 iterations as a second line of defence.
- **Fault detection on signing** — every high-level signing path verifies
  its own output against the public key before returning it, and returns
  `FalconError::FaultDetected` instead of a signature if the check fails
  (including when all 27 signing attempts are rejected, which for a valid key
  has probability below 2^-256). Always on.
- **Hedged signing** — the per-signature seed is
  `SHAKE256(SHAKE256(f‖g)[40] ‖ mu ‖ rnd)[40]`, so a broken RNG degrades to
  deterministic signing rather than to nonce reuse across messages.
- **Optional constant-time floating point** — the `fpemu` feature replaces
  native binary64 with branchless integer arithmetic. Output is identical
  (every vector passes on both backends) and `scripts/check_no_fp.sh` proves
  the compiled `fpemu` crate contains no floating-point instruction.
- **Pure Rust, no `unsafe`** — `#![forbid(unsafe_code)]`; no C, FFI,
  assembly or architecture intrinsics. (With the default `std` feature,
  `getrandom` reaches the OS entropy source through `libc`.)
- **`no_std` compatible** — works in embedded and WASM environments.

### What this crate does NOT provide

- **A certified or final FIPS 206 module** — no CMVP validation, and the
  standard is not published. Do not use it where a certified module is
  required.
- **Constant-time floating point by default** — the default backend uses
  hardware binary64, whose timing is data-dependent on some CPUs. Build with
  `--features fpemu` to remove this.
- **Constant-time key generation** — the Gaussian rejection loops and the
  NTRU solver run in data-dependent time, in both backends, as in the C
  reference. Generate keys where an attacker cannot observe the timing.
- **Constant-time rejection sampling** — the sampler and the signature
  retry loop iterate a data-dependent number of times, as specified. (The
  byte comparison in the sampler stops at the first mismatch against a
  *fresh uniform* byte, so its iteration count is independent of the value
  being tested.) The acceptance rate depends weakly on the private basis —
  the standard Falcon rejection-count behaviour, which no backend removes.
- **Masking against power/EM analysis** — none. The published practical
  attacks on Falcon are physical-access power/EM attacks on the sampler;
  `fpemu` does not address them.
- **Complete fault-attack protection** — the self-check only catches faults
  that yield an *invalid* signature. Faults that still produce a valid one
  (skipping or zeroing parts of the sampling, repeating the sampler's
  randomness — the published Falcon fault attacks) pass it, as does an
  attacker who can skip the check itself. Key generation has no equivalent
  check, and the low-level `fndsa::sign` functions skip it.
- **Guaranteed wiping of every copy** — Rust may leave copies of a value
  behind when it is moved. The PRNG and sampler states and the decoded key
  are kept on the heap and seeded in place to avoid that, but stack
  temporaries in the arithmetic, and buffers inside a `serde` serializer or
  deserializer, are outside the crate's control.
- **Formal verification** — none.
- **Hardware-backed key storage** — key material lives in process memory.

### A note on `panic = "abort"`

Zeroization runs in `Drop`, so it depends on unwinding. With
`panic = "abort"` (this crate sets none) destructors are skipped if a panic
occurs. The high-level API validates its inputs and does not panic on any
input, valid or malformed. The low-level `fndsa` functions assert on
programming errors — a degree outside 2..10 passed to key generation, a SHAKE
engine used out of order.

### Verifying parity with the C reference yourself

```sh
./scripts/verify_c_parity.sh                 # clones c-fn-dsa at the pinned commit
./scripts/verify_c_parity.sh /path/to/clone  # or uses a local checkout
```

It builds the reference, runs the reference's own test suite, regenerates
every fixture under `tests/fixtures/c-fn-dsa/` from it (the reference's test
vectors, and vectors from its public API including 200 randomized cases),
fails if any fixture changed, and runs this crate against them on both
backends.

### Constant-time backend

```toml
falcon-rs = { version = "0.4", features = ["fpemu"] }
```

What is verified for `fpemu`:

1. Every vector — the reference's KATs, sampler vectors and the API
   vectors — produces identical bytes under the emulated backend.
2. `scripts/check_no_fp.sh` — the disassembled crate contains no
   floating-point arithmetic, compare or convert instruction; the same
   script must fail on the native build, which shows the check is not
   vacuous.
3. `tests/dudect.rs` — Welch's t-test over fixed-versus-random inputs, three
   measurements judged by the median, `|t| > 4.5` threshold, with a
   self-test that requires the harness to detect a deliberate 2% timing
   difference. Gated: the sampler's centre and full signing versus the
   message. Reported: verification of valid versus invalid signatures
   (public data). The 0.3.x per-operation floating-point rows are retired:
   the floating-point type is private in 0.4.

### Dependencies

No dependency compiles or vendors C code.

| Crate | Purpose |
|-------|---------|
| `getrandom` | OS entropy (default `std` feature only; pulls in `libc`) |
| `zeroize` | Secure memory zeroing |
| `serde` | Optional serialization |
