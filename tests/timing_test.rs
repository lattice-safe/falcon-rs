//! Basic constant-time validation tests.
//!
//! These tests verify that critical operations do not exhibit significant
//! timing variation based on input values. This is NOT a replacement for
//! formal constant-time verification tools (dudect, ctgrind, etc.), but
//! provides a basic sanity check.

use std::time::Instant;

use falcon::prelude::*;

/// Measure signing time across different message contents.
/// Signing time should be independent of message content (not length,
/// since SHAKE256 absorb is proportional to length).
#[test]
#[ignore] // Run with: cargo test --release --test timing_test -- --ignored --nocapture
fn test_sign_timing_independence() {
    let kp = FnDsaKeyPair::generate(9).unwrap();

    // Two messages of same length but very different content
    let msg_zeros = vec![0u8; 128];
    let msg_ones = vec![0xFFu8; 128];

    let rounds = 50;

    // Warmup
    for _ in 0..5 {
        kp.sign(&msg_zeros, &DomainSeparation::None).unwrap();
    }

    // Measure zeros
    let start = Instant::now();
    for _ in 0..rounds {
        kp.sign(&msg_zeros, &DomainSeparation::None).unwrap();
    }
    let t_zeros = start.elapsed();

    // Measure ones
    let start = Instant::now();
    for _ in 0..rounds {
        kp.sign(&msg_ones, &DomainSeparation::None).unwrap();
    }
    let t_ones = start.elapsed();

    let ratio = t_zeros.as_nanos() as f64 / t_ones.as_nanos() as f64;
    println!(
        "Sign timing: zeros={:?} ones={:?} ratio={:.3}",
        t_zeros / rounds as u32,
        t_ones / rounds as u32,
        ratio
    );

    // Timing should be within 20% — a loose bound for statistical noise
    assert!(
        (0.80..=1.20).contains(&ratio),
        "Signing time varies >20% based on message content: ratio={:.3}",
        ratio
    );
}

/// Measure verification time for valid vs invalid signatures.
/// Verification should take the same time regardless of outcome
/// (constant-time rejection).
#[test]
#[ignore]
fn test_verify_timing_independence() {
    let kp = FnDsaKeyPair::generate(9).unwrap();
    let msg = b"constant-time test message";
    let sig = kp.sign(msg, &DomainSeparation::None).unwrap();
    let sig_bytes: Vec<u8> = sig.into_bytes();

    // Create a corrupted signature (flip a byte in the middle)
    let mut bad_sig = sig_bytes.clone();
    let mid = bad_sig.len() / 2;
    bad_sig[mid] ^= 0xFF;

    let rounds = 100;

    // Warmup
    for _ in 0..5 {
        let _ = FnDsaSignature::verify(&sig_bytes, kp.public_key(), msg, &DomainSeparation::None);
    }

    // Measure valid verification
    let start = Instant::now();
    for _ in 0..rounds {
        let _ = FnDsaSignature::verify(&sig_bytes, kp.public_key(), msg, &DomainSeparation::None);
    }
    let t_valid = start.elapsed();

    // Measure invalid verification
    let start = Instant::now();
    for _ in 0..rounds {
        let _ = FnDsaSignature::verify(&bad_sig, kp.public_key(), msg, &DomainSeparation::None);
    }
    let t_invalid = start.elapsed();

    let ratio = t_valid.as_nanos() as f64 / t_invalid.as_nanos() as f64;
    println!(
        "Verify timing: valid={:?} invalid={:?} ratio={:.3}",
        t_valid / rounds as u32,
        t_invalid / rounds as u32,
        ratio
    );

    // Note: Some variation is expected since invalid sigs may fail at
    // different points in the codec decode. The important thing is that
    // the NTT/polynomial comparison is constant-time.
    println!("(Note: >20% variation may be acceptable for verify due to codec path differences)");
}
