//! Deterministic FIPS 206 FN-DSA Known Answer Tests.
//!
//! These vectors are self-generated using fixed seeds with our pure-Rust
//! `FnDsaKeyPair::generate_deterministic` + `sign_deterministic` API and
//! serve as **regression anchors** for all domain separation modes.
//!
//! **Why self-generated?**  NIST has not yet published ACVP test vectors for
//! the FIPS 206 domain-separation layer (ph_flag / HashFN-DSA).  These
//! deterministic vectors provide the same regression guarantees.
//!
//! To regenerate after an intentional algorithm change:
//!   cargo test --release --test gen_fips206_vectors -- gen_vectors --ignored --nocapture
//!   # Then re-run the Python extraction script to update tests/fixtures/fips206/

use falcon::safe_api::{DomainSeparation, FnDsaKeyPair, FnDsaSignature, PreHashAlgorithm};

// ─── fixture macros ──────────────────────────────────────────────────────────

macro_rules! pk {
    ($file:expr) => {
        hex(include_str!(concat!("fixtures/fips206/", $file, "_pk.hex")).trim())
    };
}
macro_rules! sig_file {
    ($file:expr) => {
        hex(include_str!(concat!("fixtures/fips206/", $file, "_sig.hex")).trim())
    };
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ─── core assertion ──────────────────────────────────────────────────────────

fn check_kat(
    key_seed: &[u8],
    logn: u32,
    msg: &[u8],
    sign_seed: &[u8],
    domain: &DomainSeparation,
    expected_pk: &[u8],
    expected_sig: &[u8],
) {
    let kp = FnDsaKeyPair::generate_deterministic(key_seed, logn).unwrap();

    assert_eq!(
        kp.public_key(),
        expected_pk,
        "Public-key KAT mismatch (logn={logn} domain={domain:?})"
    );

    let sig = kp.sign_deterministic(msg, sign_seed, domain).unwrap();
    assert_eq!(
        sig.to_bytes(),
        expected_sig,
        "Signature KAT mismatch (logn={logn} domain={domain:?})"
    );

    // Cryptographic consistency
    FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), msg, domain)
        .expect("KAT signature must verify");

    // Wrong message must be rejected
    assert!(
        FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), b"WRONG_MSG", domain).is_err(),
        "KAT sig must not verify wrong message"
    );

    // Cross-domain must be rejected (sanity — use a different domain)
    let other = match domain {
        DomainSeparation::None => DomainSeparation::Context(b"other"),
        _ => DomainSeparation::None,
    };
    assert!(
        FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), msg, &other).is_err(),
        "KAT sig must not verify under different domain"
    );
}

const MSG: &[u8] = b"FIPS 206 FN-DSA Known Answer Test";
const KEY_SEED_512: &[u8] = b"fips206-kat-key-seed-512";
const KEY_SEED_1024: &[u8] = b"fips206-kat-key-seed-1024";
const SIGN_SEED: &[u8] = b"fips206-kat-sign-seed";

// ─── FN-DSA-512 KATs ─────────────────────────────────────────────────────────

/// FN-DSA-512 — pure FN-DSA, no context (ph_flag = 0x00, ctx = "")
#[test]
fn kat_fn_dsa_512_none() {
    check_kat(
        KEY_SEED_512,
        9,
        MSG,
        SIGN_SEED,
        &DomainSeparation::None,
        &pk!("FN-DSA-512__DomainSeparation::None"),
        &sig_file!("FN-DSA-512__DomainSeparation::None"),
    );
}

/// FN-DSA-512 — pure FN-DSA with context "fips206-ctx-v1" (ph_flag = 0x00)
#[test]
fn kat_fn_dsa_512_context() {
    check_kat(
        KEY_SEED_512,
        9,
        MSG,
        SIGN_SEED,
        &DomainSeparation::Context(b"fips206-ctx-v1"),
        &pk!("FN-DSA-512__DomainSeparation::Context_b_fips206-ctx-v1"),
        &sig_file!("FN-DSA-512__DomainSeparation::Context_b_fips206-ctx-v1"),
    );
}

/// FN-DSA-512 — HashFN-DSA SHA-256, no context (ph_flag = 0x01)
#[test]
fn kat_fn_dsa_512_prehashed_sha256() {
    check_kat(
        KEY_SEED_512,
        9,
        MSG,
        SIGN_SEED,
        &DomainSeparation::Prehashed {
            alg: PreHashAlgorithm::Sha256,
            context: b"",
        },
        &pk!("FN-DSA-512__Prehashed_SHA-256_no_ctx"),
        &sig_file!("FN-DSA-512__Prehashed_SHA-256_no_ctx"),
    );
}

/// FN-DSA-512 — HashFN-DSA SHA-512 with context "fips206-ctx-v1" (ph_flag = 0x01)
#[test]
fn kat_fn_dsa_512_prehashed_sha512_ctx() {
    check_kat(
        KEY_SEED_512,
        9,
        MSG,
        SIGN_SEED,
        &DomainSeparation::Prehashed {
            alg: PreHashAlgorithm::Sha512,
            context: b"fips206-ctx-v1",
        },
        &pk!("FN-DSA-512__Prehashed_SHA-512_ctx_b_fips206-ctx-v1"),
        &sig_file!("FN-DSA-512__Prehashed_SHA-512_ctx_b_fips206-ctx-v1"),
    );
}

// ─── FN-DSA-1024 KATs ────────────────────────────────────────────────────────

/// FN-DSA-1024 — pure FN-DSA, no context (ph_flag = 0x00, ctx = "")
#[test]
fn kat_fn_dsa_1024_none() {
    check_kat(
        KEY_SEED_1024,
        10,
        MSG,
        SIGN_SEED,
        &DomainSeparation::None,
        &pk!("FN-DSA-1024__DomainSeparation::None"),
        &sig_file!("FN-DSA-1024__DomainSeparation::None"),
    );
}

/// FN-DSA-1024 — HashFN-DSA SHA-512 with context "fips206-ctx-v1" (ph_flag = 0x01)
#[test]
fn kat_fn_dsa_1024_prehashed_sha512_ctx() {
    check_kat(
        KEY_SEED_1024,
        10,
        MSG,
        SIGN_SEED,
        &DomainSeparation::Prehashed {
            alg: PreHashAlgorithm::Sha512,
            context: b"fips206-ctx-v1",
        },
        &pk!("FN-DSA-1024__Prehashed_SHA-512_ctx_b_fips206-ctx-v1"),
        &sig_file!("FN-DSA-1024__Prehashed_SHA-512_ctx_b_fips206-ctx-v1"),
    );
}
