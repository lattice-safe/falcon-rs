//! Fuzz target: sign → verify round-trip with domain separation.
//!
//! Uses fuzzer input as both the message and to select the domain separation
//! variant. Ensures FnDsaSignature::verify always accepts a just-produced
//! signature regardless of domain mode.

#![no_main]
use libfuzzer_sys::fuzz_target;
use falcon::safe_api::{DomainSeparation, FnDsaKeyPair, FnDsaSignature, PreHashAlgorithm};

// Pre-generate a key pair once (shared across all fuzz iterations).
// libfuzzer does not share state between calls, so we regenerate cheaply.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() { return; }

    // First byte selects the domain mode.
    let domain_byte = data[0];
    let msg = if data.len() > 1 { &data[1..] } else { b"" };

    // Limit context string from fuzzer data to keep iterations fast.
    let ctx_bytes: &[u8] = if msg.len() > 4 { &msg[..4] } else { msg };

    let domain = match domain_byte % 5 {
        0 => DomainSeparation::None,
        1 => DomainSeparation::Context(b"fuzz-proto-a"),
        2 => DomainSeparation::Context(ctx_bytes),
        3 => DomainSeparation::Prehashed { alg: PreHashAlgorithm::Sha256, context: b"" },
        _ => DomainSeparation::Prehashed { alg: PreHashAlgorithm::Sha512, context: b"fuzz-ctx" },
    };

    // Context > 255 bytes is valid input that must return BadArgument, not panic.
    if let DomainSeparation::Context(c) = domain {
        if c.len() > 255 { return; }
    }
    if let DomainSeparation::Prehashed { context: c, .. } = domain {
        if c.len() > 255 { return; }
    }

    let kp = FnDsaKeyPair::generate_deterministic(b"fuzz-seed-sign-verify-512", 9).unwrap();

    let sig = match kp.sign_deterministic(msg, b"fuzz-rng", &domain) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Valid signature must always verify with the same domain.
    FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), msg, &domain)
        .expect("Valid signature must verify!");

    // Must NOT verify with a different domain.
    let other = match domain_byte % 5 {
        0 => DomainSeparation::Context(b"other"),
        _ => DomainSeparation::None,
    };
    let cross = FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), msg, &other);
    assert!(
        cross.is_err() || domain == other,
        "Cross-domain verification must fail!"
    );
});
