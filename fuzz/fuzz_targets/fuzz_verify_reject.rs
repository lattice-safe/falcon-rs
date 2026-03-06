//! Fuzz target: verify with arbitrary (likely invalid) signatures.
//!
//! Ensures that falcon_verify never panics on arbitrary input,
//! and that invalid signatures are rejected (not accepted).

#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need at least enough bytes for a minimal sig + pubkey.
    if data.len() < 50 { return; }

    // Split fuzzer data into "signature" and "pubkey" and "message".
    let split1 = data.len() / 3;
    let split2 = 2 * data.len() / 3;
    let sig_data = &data[..split1];
    let pk_data = &data[split1..split2];
    let msg_data = &data[split2..];

    let mut tmp = vec![0u8; 16384];

    // This should never panic, but should return an error code.
    let r = falcon::falcon::falcon_verify(sig_data, 0, pk_data, msg_data, &mut tmp);
    // A valid signature from random data is astronomically unlikely.
    // If it somehow "verifies", that would be a critical bug.
    assert!(r != 0, "Random data accepted as valid signature!");
});
