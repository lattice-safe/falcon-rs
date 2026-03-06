# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |

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

- **FIPS 206 (FN-DSA)** compliant signing and verification
- **Automatic zeroization** of PRNG state on drop via `write_volatile`
- **No external C dependencies** — pure Rust implementation
- **`no_std` compatible** — works in embedded and WASM environments

### What this crate does NOT provide

- **Certified FIPS 206 module** — This implementation has not been submitted
  for CMVP validation. Do not use it where a certified module is required.
- **Constant-time FFT** — The FFT uses floating-point operations which may
  exhibit timing variations on some architectures. The C reference has the
  same property.
- **Formal verification** — The implementation is a faithful port of the
  C reference but has not been formally verified.
- **Hardware-backed key storage** — Key material lives in process memory.
  Use HSMs or secure enclaves for high-value keys.

### Dependencies

All dependencies are pure Rust with no C bindings:

| Crate | Purpose |
|-------|---------|
| `libm` | Math functions for `no_std` FFT |
| `zeroize` | Secure memory zeroing |
