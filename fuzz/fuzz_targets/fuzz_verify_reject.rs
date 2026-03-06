//! Fuzz target: verify with arbitrary (likely invalid) data.
//!
//! Ensures FnDsaSignature::verify never panics on arbitrary input and that
//! random byte strings are rejected across all domain separation modes.

#![no_main]
use libfuzzer_sys::fuzz_target;
use falcon::safe_api::{DomainSeparation, FnDsaSignature, PreHashAlgorithm};

fuzz_target!(|data: &[u8]| {
    if data.len() < 50 { return; }

    // Use first byte to select domain mode; rest is split into sig/pubkey/message.
    let domain_byte = data[0];
    let rest = &data[1..];
    let split1 = rest.len() / 3;
    let split2 = 2 * rest.len() / 3;
    let sig_data = &rest[..split1];
    let pk_data  = &rest[split1..split2];
    let msg_data = &rest[split2..];

    let domain = match domain_byte % 4 {
        0 => DomainSeparation::None,
        1 => DomainSeparation::Context(b"fuzz-ctx"),
        2 => DomainSeparation::Prehashed { alg: PreHashAlgorithm::Sha256, context: b"" },
        _ => DomainSeparation::Prehashed { alg: PreHashAlgorithm::Sha512, context: b"fuzz-ctx" },
    };

    // Must never panic; must return an error for random data.
    let r = FnDsaSignature::verify(sig_data, pk_data, msg_data, &domain);
    // Accepting random garbage as a valid sig would be catastrophic.
    assert!(r.is_err(), "Random data accepted as valid signature under domain {:?}!", domain);
});
