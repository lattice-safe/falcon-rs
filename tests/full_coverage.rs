/// Full API coverage tests for the Falcon Rust port.
///
/// Covers all public API paths not already tested in kat_test.rs and nist_kat.rs:
/// - shake256_init_prng_from_system
/// - falcon_make_public (reconstruct pubkey from privkey)
/// - falcon_get_logn (extract logn from encoded objects)
/// - Streamed sign API (sign_start → sign_dyn_finish)
/// - Streamed verify API (verify_start → verify_finish)
/// - Expanded key API (expand_privkey → sign_tree)
/// - All signature formats (COMPRESSED, PADDED, CT)
/// - Safe API (FalconKeyPair, FalconSignature)
/// - Error paths (bad sizes, bad formats, bad signatures, bad logn)
/// - hash_to_point_ct consistency with vartime

use falcon::shake::{InnerShake256Context, i_shake256_init, i_shake256_inject, i_shake256_flip};
use falcon::falcon as falcon_api;
use falcon::safe_api::{FalconKeyPair, FalconSignature, FalconError};
use falcon::common;
use falcon::codec;

// ======================================================================
// Helper: generate a deterministic key pair for testing
// ======================================================================

fn test_keypair(logn: u32) -> (Vec<u8>, Vec<u8>, InnerShake256Context) {
    let mut rng = InnerShake256Context::new();
    i_shake256_init(&mut rng);
    i_shake256_inject(&mut rng, b"full-coverage-test-seed-2026!!");
    i_shake256_flip(&mut rng);

    let sk_len = falcon_api::falcon_privkey_size(logn);
    let pk_len = falcon_api::falcon_pubkey_size(logn);
    let tmp_len = falcon_api::falcon_tmpsize_keygen(logn);

    let mut sk = vec![0u8; sk_len];
    let mut pk = vec![0u8; pk_len];
    let mut tmp = vec![0u8; tmp_len];

    let rc = falcon_api::falcon_keygen_make(&mut rng, logn, &mut sk, Some(&mut pk), &mut tmp);
    assert_eq!(rc, 0, "keygen failed");
    (sk, pk, rng)
}

// ======================================================================
// Test: shake256_init_prng_from_system
// ======================================================================

#[test]
fn test_prng_from_system() {
    let mut sc = InnerShake256Context::new();
    let rc = falcon_api::shake256_init_prng_from_system(&mut sc);
    assert_eq!(rc, 0, "shake256_init_prng_from_system failed");

    // Should produce non-zero output.
    let mut out = [0u8; 32];
    falcon_api::shake256_extract(&mut sc, &mut out);
    assert_ne!(out, [0u8; 32], "System PRNG produced all-zero output");

    // Two calls should produce different output (with overwhelming probability).
    let mut sc2 = InnerShake256Context::new();
    let rc2 = falcon_api::shake256_init_prng_from_system(&mut sc2);
    assert_eq!(rc2, 0);
    let mut out2 = [0u8; 32];
    falcon_api::shake256_extract(&mut sc2, &mut out2);
    assert_ne!(out, out2, "Two system PRNG calls produced identical output");
}

// ======================================================================
// Test: falcon_make_public
// ======================================================================

#[test]
fn test_make_public() {
    let logn = 9u32;
    let (sk, pk, _) = test_keypair(logn);

    let pk_len = falcon_api::falcon_pubkey_size(logn);
    let tmp_len = falcon_api::falcon_tmpsize_makepub(logn);
    let mut pk_recomputed = vec![0u8; pk_len];
    let mut tmp = vec![0u8; tmp_len];

    let rc = falcon_api::falcon_make_public(&mut pk_recomputed, &sk, &mut tmp);
    assert_eq!(rc, 0, "falcon_make_public failed");
    assert_eq!(pk, pk_recomputed, "Recomputed public key doesn't match");
}

// ======================================================================
// Test: falcon_get_logn
// ======================================================================

#[test]
fn test_get_logn() {
    // From a private key (header 0x59 = 0x50 + 9)
    let logn = 9u32;
    let (sk, pk, _) = test_keypair(logn);

    let logn_from_sk = falcon_api::falcon_get_logn(&sk);
    assert_eq!(logn_from_sk, 9, "get_logn from privkey returned wrong value");

    let logn_from_pk = falcon_api::falcon_get_logn(&pk);
    assert_eq!(logn_from_pk, 9, "get_logn from pubkey returned wrong value");

    // Empty buffer should error.
    let empty: &[u8] = &[];
    let rc = falcon_api::falcon_get_logn(empty);
    assert!(rc < 0, "get_logn on empty should fail");

    // Invalid logn (0).
    let bad = [0x00u8];
    let rc = falcon_api::falcon_get_logn(&bad);
    assert!(rc < 0, "get_logn with logn=0 should fail");
}

// ======================================================================
// Test: Streamed sign API (sign_start → inject → sign_dyn_finish)
// ======================================================================

#[test]
fn test_streamed_sign_dyn() {
    let logn = 9u32;
    let (sk, pk, mut rng) = test_keypair(logn);
    let message = b"Streamed sign test message";

    // sign_start: generates nonce, inits hash_data
    let mut nonce = [0u8; 40];
    let mut hash_data = InnerShake256Context::new();
    let rc = falcon_api::falcon_sign_start(&mut rng, &mut nonce, &mut hash_data);
    assert_eq!(rc, 0);

    // Inject message data
    falcon_api::shake256_inject(&mut hash_data, message);

    // sign_dyn_finish
    let sig_max = falcon_api::falcon_sig_ct_size(logn);
    let tmp_len = falcon_api::falcon_tmpsize_signdyn(logn);
    let mut sig = vec![0u8; sig_max];
    let mut sig_len = sig_max;
    let mut tmp = vec![0u8; tmp_len];

    let rc = falcon_api::falcon_sign_dyn_finish(
        &mut rng, &mut sig, &mut sig_len,
        falcon_api::FALCON_SIG_CT,
        &sk, &mut hash_data, &nonce, &mut tmp,
    );
    assert_eq!(rc, 0, "sign_dyn_finish failed");
    assert!(sig_len > 0 && sig_len <= sig_max);

    // Verify with standard API
    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    let rc = falcon_api::falcon_verify(
        &sig[..sig_len], falcon_api::FALCON_SIG_CT, &pk, message, &mut vtmp,
    );
    assert_eq!(rc, 0, "Streamed signature did not verify");
}

// ======================================================================
// Test: Streamed verify API (verify_start → inject → verify_finish)
// ======================================================================

#[test]
fn test_streamed_verify() {
    let logn = 9u32;
    let (sk, pk, mut rng) = test_keypair(logn);
    let message = b"Streamed verify test message";

    // Sign normally first
    let sig_max = falcon_api::falcon_sig_ct_size(logn);
    let tmp_len = falcon_api::falcon_tmpsize_signdyn(logn);
    let mut sig = vec![0u8; sig_max];
    let mut sig_len = sig_max;
    let mut tmp = vec![0u8; tmp_len];

    let rc = falcon_api::falcon_sign_dyn(
        &mut rng, &mut sig, &mut sig_len,
        falcon_api::FALCON_SIG_CT, &sk, message, &mut tmp,
    );
    assert_eq!(rc, 0);
    let sig_bytes = sig[..sig_len].to_vec();

    // Streamed verify: start → inject message → finish
    let mut hash_data = InnerShake256Context::new();
    let rc = falcon_api::falcon_verify_start(&mut hash_data, &sig_bytes);
    assert_eq!(rc, 0, "verify_start failed");

    falcon_api::shake256_inject(&mut hash_data, message);

    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    let rc = falcon_api::falcon_verify_finish(
        &sig_bytes, falcon_api::FALCON_SIG_CT, &pk, &mut hash_data, &mut vtmp,
    );
    assert_eq!(rc, 0, "Streamed verify failed");
}

// ======================================================================
// Test: Expanded key API (expand_privkey → sign_tree)
// ======================================================================

#[test]
fn test_expand_privkey_and_sign_tree() {
    let logn = 9u32;
    let (sk, pk, mut rng) = test_keypair(logn);
    let message = b"Expanded key sign_tree test";

    // Expand the private key
    let expkey_len = falcon_api::falcon_expandedkey_size(logn);
    let tmp_exp_len = falcon_api::falcon_tmpsize_expandpriv(logn);
    let mut expanded_key = vec![0u8; expkey_len];
    let mut tmp_exp = vec![0u8; tmp_exp_len];

    let rc = falcon_api::falcon_expand_privkey(&mut expanded_key, &sk, &mut tmp_exp);
    assert_eq!(rc, 0, "expand_privkey failed");

    // Sign with expanded key (tree mode)
    let sig_max = falcon_api::falcon_sig_ct_size(logn);
    let tmp_sign_len = falcon_api::falcon_tmpsize_signtree(logn);
    let mut sig = vec![0u8; sig_max];
    let mut sig_len = sig_max;
    let mut tmp_sign = vec![0u8; tmp_sign_len];

    let rc = falcon_api::falcon_sign_tree(
        &mut rng, &mut sig, &mut sig_len,
        falcon_api::FALCON_SIG_CT,
        &expanded_key, message, &mut tmp_sign,
    );
    assert_eq!(rc, 0, "sign_tree failed");

    // Verify
    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    let rc = falcon_api::falcon_verify(
        &sig[..sig_len], falcon_api::FALCON_SIG_CT, &pk, message, &mut vtmp,
    );
    assert_eq!(rc, 0, "sign_tree signature did not verify");
}

// ======================================================================
// Test: All signature formats (COMPRESSED, PADDED, CT)
// ======================================================================

#[test]
fn test_signature_format_compressed() {
    let logn = 9u32;
    let (sk, pk, mut rng) = test_keypair(logn);
    let message = b"Compressed format test";

    let sig_max = falcon_api::falcon_sig_compressed_maxsize(logn);
    let tmp_len = falcon_api::falcon_tmpsize_signdyn(logn);
    let mut sig = vec![0u8; sig_max];
    let mut sig_len = sig_max;
    let mut tmp = vec![0u8; tmp_len];

    let rc = falcon_api::falcon_sign_dyn(
        &mut rng, &mut sig, &mut sig_len,
        falcon_api::FALCON_SIG_COMPRESSED, &sk, message, &mut tmp,
    );
    assert_eq!(rc, 0, "COMPRESSED sign failed");
    assert!(sig_len < sig_max, "COMPRESSED sig should be shorter than max");

    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    let rc = falcon_api::falcon_verify(
        &sig[..sig_len], falcon_api::FALCON_SIG_COMPRESSED, &pk, message, &mut vtmp,
    );
    assert_eq!(rc, 0, "COMPRESSED verify failed");
}

#[test]
fn test_signature_format_padded() {
    let logn = 9u32;
    let (sk, pk, mut rng) = test_keypair(logn);
    let message = b"Padded format test";

    let sig_size = falcon_api::falcon_sig_padded_size(logn);
    let tmp_len = falcon_api::falcon_tmpsize_signdyn(logn);
    let mut sig = vec![0u8; sig_size];
    let mut sig_len = sig_size;
    let mut tmp = vec![0u8; tmp_len];

    let rc = falcon_api::falcon_sign_dyn(
        &mut rng, &mut sig, &mut sig_len,
        falcon_api::FALCON_SIG_PADDED, &sk, message, &mut tmp,
    );
    assert_eq!(rc, 0, "PADDED sign failed");
    assert_eq!(sig_len, sig_size, "PADDED sig should be exactly the padded size");

    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    let rc = falcon_api::falcon_verify(
        &sig[..sig_len], falcon_api::FALCON_SIG_PADDED, &pk, message, &mut vtmp,
    );
    assert_eq!(rc, 0, "PADDED verify failed");
}

#[test]
fn test_signature_format_ct() {
    let logn = 9u32;
    let (sk, pk, mut rng) = test_keypair(logn);
    let message = b"CT format test";

    let sig_size = falcon_api::falcon_sig_ct_size(logn);
    let tmp_len = falcon_api::falcon_tmpsize_signdyn(logn);
    let mut sig = vec![0u8; sig_size];
    let mut sig_len = sig_size;
    let mut tmp = vec![0u8; tmp_len];

    let rc = falcon_api::falcon_sign_dyn(
        &mut rng, &mut sig, &mut sig_len,
        falcon_api::FALCON_SIG_CT, &sk, message, &mut tmp,
    );
    assert_eq!(rc, 0, "CT sign failed");
    assert_eq!(sig_len, sig_size, "CT sig should be exactly the CT size");

    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    let rc = falcon_api::falcon_verify(
        &sig[..sig_len], falcon_api::FALCON_SIG_CT, &pk, message, &mut vtmp,
    );
    assert_eq!(rc, 0, "CT verify failed");
}

// ======================================================================
// Test: Verify with sig_type=0 (auto-detect format)
// ======================================================================

#[test]
fn test_verify_auto_detect_format() {
    let logn = 9u32;
    let (sk, pk, mut rng) = test_keypair(logn);
    let message = b"Auto-detect format test";

    // Sign with COMPRESSED
    let sig_max = falcon_api::falcon_sig_compressed_maxsize(logn);
    let tmp_len = falcon_api::falcon_tmpsize_signdyn(logn);
    let mut sig = vec![0u8; sig_max];
    let mut sig_len = sig_max;
    let mut tmp = vec![0u8; tmp_len];

    let rc = falcon_api::falcon_sign_dyn(
        &mut rng, &mut sig, &mut sig_len,
        falcon_api::FALCON_SIG_COMPRESSED, &sk, message, &mut tmp,
    );
    assert_eq!(rc, 0);

    // Verify with sig_type=0 (auto-detect)
    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    let rc = falcon_api::falcon_verify(
        &sig[..sig_len], 0, &pk, message, &mut vtmp,
    );
    assert_eq!(rc, 0, "Auto-detect verify failed");
}

// ======================================================================
// Test: Safe API — FalconKeyPair and FalconSignature
// ======================================================================

#[test]
fn test_safe_api_generate_sign_verify() {
    let kp = FalconKeyPair::generate(9).unwrap();
    assert_eq!(kp.logn(), 9);
    assert!(!kp.public_key().is_empty());
    assert!(!kp.private_key().is_empty());

    let sig = kp.sign(b"safe api test").unwrap();
    assert!(!sig.is_empty());
    assert!(sig.len() > 0);

    FalconSignature::verify(sig.to_bytes(), kp.public_key(), b"safe api test").unwrap();
}

#[test]
fn test_safe_api_deterministic() {
    let seed = b"deterministic-safe-api-seed-1234";
    let kp1 = FalconKeyPair::generate_deterministic(seed, 9).unwrap();
    let kp2 = FalconKeyPair::generate_deterministic(seed, 9).unwrap();
    assert_eq!(kp1.public_key(), kp2.public_key(), "Deterministic keygen should match");
    assert_eq!(kp1.private_key(), kp2.private_key());

    let sig_seed = b"sign-seed";
    let sig1 = kp1.sign_deterministic(b"hello", sig_seed).unwrap();
    let sig2 = kp2.sign_deterministic(b"hello", sig_seed).unwrap();
    assert_eq!(sig1.to_bytes(), sig2.to_bytes(), "Deterministic sign should match");
}

#[test]
fn test_safe_api_bad_logn() {
    assert_eq!(FalconKeyPair::generate(0).unwrap_err(), FalconError::BadArgument);
    assert_eq!(FalconKeyPair::generate(11).unwrap_err(), FalconError::BadArgument);
}

#[test]
fn test_safe_api_bad_signature() {
    let kp = FalconKeyPair::generate(9).unwrap();
    let sig = kp.sign(b"original message").unwrap();

    // Verify with wrong message should fail.
    let result = FalconSignature::verify(sig.to_bytes(), kp.public_key(), b"wrong message");
    assert!(result.is_err(), "Verification with wrong message should fail");
}

#[test]
fn test_safe_api_falcon1024() {
    let kp = FalconKeyPair::generate(10).unwrap();
    assert_eq!(kp.logn(), 10);

    let sig = kp.sign(b"falcon-1024 test").unwrap();
    FalconSignature::verify(sig.to_bytes(), kp.public_key(), b"falcon-1024 test").unwrap();
}

// ======================================================================
// Test: Error paths
// ======================================================================

#[test]
fn test_verify_bad_signature() {
    let logn = 9u32;
    let (_, pk, _) = test_keypair(logn);

    // Garbage signature should fail.
    let garbage = vec![0xFFu8; 100];
    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    let rc = falcon_api::falcon_verify(&garbage, 0, &pk, b"msg", &mut vtmp);
    assert!(rc < 0, "Garbage signature should not verify");
}

#[test]
fn test_verify_wrong_pubkey() {
    let logn = 9u32;
    let (sk, _, mut rng) = test_keypair(logn);

    // Sign with key 1
    let sig_max = falcon_api::falcon_sig_compressed_maxsize(logn);
    let tmp_len = falcon_api::falcon_tmpsize_signdyn(logn);
    let mut sig = vec![0u8; sig_max];
    let mut sig_len = sig_max;
    let mut tmp = vec![0u8; tmp_len];
    let rc = falcon_api::falcon_sign_dyn(
        &mut rng, &mut sig, &mut sig_len,
        falcon_api::FALCON_SIG_COMPRESSED, &sk, b"msg", &mut tmp,
    );
    assert_eq!(rc, 0);

    // Generate a different key pair
    let mut rng2 = InnerShake256Context::new();
    i_shake256_init(&mut rng2);
    i_shake256_inject(&mut rng2, b"different-seed-for-wrong-key!!");
    i_shake256_flip(&mut rng2);
    let mut sk2 = vec![0u8; falcon_api::falcon_privkey_size(logn)];
    let mut pk2 = vec![0u8; falcon_api::falcon_pubkey_size(logn)];
    let mut tmp2 = vec![0u8; falcon_api::falcon_tmpsize_keygen(logn)];
    falcon_api::falcon_keygen_make(&mut rng2, logn, &mut sk2, Some(&mut pk2), &mut tmp2);

    // Verify with wrong pubkey should fail.
    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    let rc = falcon_api::falcon_verify(
        &sig[..sig_len], falcon_api::FALCON_SIG_COMPRESSED, &pk2, b"msg", &mut vtmp,
    );
    assert!(rc < 0, "Verify with wrong pubkey should fail");
}

#[test]
fn test_sign_bad_sig_type() {
    let logn = 9u32;
    let (sk, _, mut rng) = test_keypair(logn);

    let sig_max = falcon_api::falcon_sig_ct_size(logn);
    let tmp_len = falcon_api::falcon_tmpsize_signdyn(logn);
    let mut sig = vec![0u8; sig_max];
    let mut sig_len = sig_max;
    let mut tmp = vec![0u8; tmp_len];

    let rc = falcon_api::falcon_sign_dyn(
        &mut rng, &mut sig, &mut sig_len,
        99, // invalid sig_type
        &sk, b"msg", &mut tmp,
    );
    assert!(rc < 0, "Sign with invalid sig_type should fail");
}

#[test]
fn test_make_public_bad_privkey() {
    let logn = 9u32;
    let pk_len = falcon_api::falcon_pubkey_size(logn);
    let tmp_len = falcon_api::falcon_tmpsize_makepub(logn);
    let mut pk = vec![0u8; pk_len];
    let mut tmp = vec![0u8; tmp_len];

    // Empty privkey
    let rc = falcon_api::falcon_make_public(&mut pk, &[], &mut tmp);
    assert!(rc < 0, "make_public with empty privkey should fail");

    // Wrong header byte
    let bad_sk = vec![0x00u8; 100];
    let rc = falcon_api::falcon_make_public(&mut pk, &bad_sk, &mut tmp);
    assert!(rc < 0, "make_public with bad header should fail");
}

// ======================================================================
// Test: hash_to_point_ct produces same result as vartime
// ======================================================================

#[test]
fn test_hash_to_point_ct_vs_vartime() {
    let logn = 9u32;
    let n: usize = 1 << logn;

    // Set up identical SHAKE256 contexts.
    let mut sc1 = InnerShake256Context::new();
    i_shake256_init(&mut sc1);
    i_shake256_inject(&mut sc1, b"hash-to-point-test-data-seed!!!");
    i_shake256_flip(&mut sc1);
    let mut sc2 = sc1.clone();

    // hash_to_point_vartime
    let mut hm_vt = vec![0u16; n];
    common::hash_to_point_vartime(&mut sc1, &mut hm_vt, logn);

    // hash_to_point_ct
    let mut hm_ct = vec![0u16; n];
    let mut tmp = vec![0u8; n * 2];
    common::hash_to_point_ct(&mut sc2, &mut hm_ct, logn, &mut tmp);

    // Both should produce results in [0, 12289).
    for u in 0..n {
        assert!(hm_vt[u] < 12289, "vartime value out of range at {}: {}", u, hm_vt[u]);
        assert!(hm_ct[u] < 12289, "ct value out of range at {}: {}", u, hm_ct[u]);
    }

    // They should produce the same distribution (same outputs for same SHAKE input).
    assert_eq!(hm_vt, hm_ct, "hash_to_point_ct and vartime should produce same output");
}

// ======================================================================
// Test: Codec — comp_encode/comp_decode roundtrip
// ======================================================================

#[test]
fn test_comp_codec_roundtrip() {
    let logn = 9u32;
    let n: usize = 1 << logn;

    // Create a signature-like vector with small values.
    let mut coeffs = vec![0i16; n];
    for i in 0..n {
        coeffs[i] = ((i as i16) % 201) - 100; // range [-100, 100]
    }

    // Encode
    let enc_len = codec::comp_encode(None, &coeffs, logn);
    assert!(enc_len > 0, "comp_encode length should be positive");

    let mut encoded = vec![0u8; enc_len];
    let enc_len2 = codec::comp_encode(Some(&mut encoded), &coeffs, logn);
    assert_eq!(enc_len, enc_len2);

    // Decode
    let mut decoded = vec![0i16; n];
    let dec_len = codec::comp_decode(&mut decoded, logn, &encoded);
    assert!(dec_len > 0, "comp_decode should succeed");
    assert_eq!(coeffs, decoded, "comp codec roundtrip mismatch");
}

// ======================================================================
// Test: trim_i16 codec roundtrip
// ======================================================================

#[test]
fn test_trim_i16_codec_roundtrip() {
    let logn = 9u32;
    let n: usize = 1 << logn;
    let bits = codec::MAX_SIG_BITS[logn as usize] as u32;

    let max_val = (1i16 << (bits - 1)) - 1;
    let mut coeffs = vec![0i16; n];
    for i in 0..n {
        coeffs[i] = ((i as i16) % (2 * max_val + 1)) - max_val;
    }

    let enc_len = codec::trim_i16_encode(None, &coeffs, logn, bits);
    assert!(enc_len > 0);
    let mut encoded = vec![0u8; enc_len];
    let enc_len2 = codec::trim_i16_encode(Some(&mut encoded), &coeffs, logn, bits);
    assert_eq!(enc_len, enc_len2);

    let mut decoded = vec![0i16; n];
    let dec_len = codec::trim_i16_decode(&mut decoded, logn, bits, &encoded);
    assert!(dec_len > 0);
    assert_eq!(coeffs, decoded, "trim_i16 codec roundtrip mismatch");
}

// ======================================================================
// Test: Size function consistency
// ======================================================================

#[test]
fn test_size_functions_all_logn() {
    for logn in 1..=10u32 {
        let sk_size = falcon_api::falcon_privkey_size(logn);
        let pk_size = falcon_api::falcon_pubkey_size(logn);
        let sig_comp_max = falcon_api::falcon_sig_compressed_maxsize(logn);
        let sig_padded = falcon_api::falcon_sig_padded_size(logn);
        let sig_ct = falcon_api::falcon_sig_ct_size(logn);
        let tmp_keygen = falcon_api::falcon_tmpsize_keygen(logn);
        let tmp_makepub = falcon_api::falcon_tmpsize_makepub(logn);
        let tmp_signdyn = falcon_api::falcon_tmpsize_signdyn(logn);
        let tmp_signtree = falcon_api::falcon_tmpsize_signtree(logn);
        let tmp_expandpriv = falcon_api::falcon_tmpsize_expandpriv(logn);
        let expkey_size = falcon_api::falcon_expandedkey_size(logn);
        let tmp_verify = falcon_api::falcon_tmpsize_verify(logn);

        // All sizes should be > 0.
        assert!(sk_size > 0, "logn={logn}: privkey size");
        assert!(pk_size > 0, "logn={logn}: pubkey size");
        assert!(sig_comp_max > 0, "logn={logn}: sig_comp_max");
        assert!(sig_padded > 0, "logn={logn}: sig_padded");
        assert!(sig_ct > 0, "logn={logn}: sig_ct");
        assert!(tmp_keygen > 0, "logn={logn}: tmp_keygen");
        assert!(tmp_makepub > 0, "logn={logn}: tmp_makepub");
        assert!(tmp_signdyn > 0, "logn={logn}: tmp_signdyn");
        assert!(tmp_signtree > 0, "logn={logn}: tmp_signtree");
        assert!(tmp_expandpriv > 0, "logn={logn}: tmp_expandpriv");
        assert!(expkey_size > 0, "logn={logn}: expkey_size");
        assert!(tmp_verify > 0, "logn={logn}: tmp_verify");

        // CT >= PADDED >= average COMPRESSED
        assert!(sig_ct >= sig_padded, "logn={logn}: CT should be >= PADDED");
    }

    // Known values for Falcon-512 (logn=9)
    assert_eq!(falcon_api::falcon_privkey_size(9), 1281);
    assert_eq!(falcon_api::falcon_pubkey_size(9), 897);
    assert_eq!(falcon_api::falcon_sig_ct_size(9), 809);
    assert_eq!(falcon_api::falcon_sig_padded_size(9), 666);
}

// ======================================================================
// Test: Multiple signatures from same key are different
// ======================================================================

#[test]
fn test_different_signatures_same_key() {
    let logn = 9u32;
    let (sk, pk, mut rng) = test_keypair(logn);
    let message = b"Same message, different signatures";

    let sig_max = falcon_api::falcon_sig_compressed_maxsize(logn);
    let tmp_len = falcon_api::falcon_tmpsize_signdyn(logn);

    let mut sig1 = vec![0u8; sig_max];
    let mut sig1_len = sig_max;
    let mut tmp = vec![0u8; tmp_len];
    let rc = falcon_api::falcon_sign_dyn(
        &mut rng, &mut sig1, &mut sig1_len,
        falcon_api::FALCON_SIG_COMPRESSED, &sk, message, &mut tmp,
    );
    assert_eq!(rc, 0);

    let mut sig2 = vec![0u8; sig_max];
    let mut sig2_len = sig_max;
    let rc = falcon_api::falcon_sign_dyn(
        &mut rng, &mut sig2, &mut sig2_len,
        falcon_api::FALCON_SIG_COMPRESSED, &sk, message, &mut tmp,
    );
    assert_eq!(rc, 0);

    // Both should verify.
    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    assert_eq!(falcon_api::falcon_verify(&sig1[..sig1_len], falcon_api::FALCON_SIG_COMPRESSED, &pk, message, &mut vtmp), 0);
    assert_eq!(falcon_api::falcon_verify(&sig2[..sig2_len], falcon_api::FALCON_SIG_COMPRESSED, &pk, message, &mut vtmp), 0);

    // Signatures should be different (different nonces).
    assert_ne!(sig1[..sig1_len], sig2[..sig2_len], "Two signatures should differ");
}

// ======================================================================
// Test: Streamed sign_tree_finish with expanded key
// ======================================================================

#[test]
fn test_streamed_sign_tree_finish() {
    let logn = 9u32;
    let (sk, pk, mut rng) = test_keypair(logn);
    let message = b"Streamed sign_tree_finish test";

    // Expand key
    let expkey_len = falcon_api::falcon_expandedkey_size(logn);
    let tmp_exp_len = falcon_api::falcon_tmpsize_expandpriv(logn);
    let mut expanded_key = vec![0u8; expkey_len];
    let mut tmp_exp = vec![0u8; tmp_exp_len];
    let rc = falcon_api::falcon_expand_privkey(&mut expanded_key, &sk, &mut tmp_exp);
    assert_eq!(rc, 0);

    // Streamed sign_tree: start → inject → finish
    let mut nonce = [0u8; 40];
    let mut hash_data = InnerShake256Context::new();
    falcon_api::falcon_sign_start(&mut rng, &mut nonce, &mut hash_data);
    falcon_api::shake256_inject(&mut hash_data, message);

    let sig_max = falcon_api::falcon_sig_ct_size(logn);
    let tmp_sign_len = falcon_api::falcon_tmpsize_signtree(logn);
    let mut sig = vec![0u8; sig_max];
    let mut sig_len = sig_max;
    let mut tmp_sign = vec![0u8; tmp_sign_len];

    let rc = falcon_api::falcon_sign_tree_finish(
        &mut rng, &mut sig, &mut sig_len,
        falcon_api::FALCON_SIG_CT,
        &expanded_key, &mut hash_data, &nonce, &mut tmp_sign,
    );
    assert_eq!(rc, 0, "sign_tree_finish failed");

    // Verify
    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    let rc = falcon_api::falcon_verify(
        &sig[..sig_len], falcon_api::FALCON_SIG_CT, &pk, message, &mut vtmp,
    );
    assert_eq!(rc, 0, "sign_tree_finish signature did not verify");
}

// ======================================================================
// Test: Signature mutability detection
// ======================================================================

#[test]
fn test_signature_bit_flip_detected() {
    let logn = 9u32;
    let (sk, pk, mut rng) = test_keypair(logn);
    let message = b"Bit flip detection test";

    let sig_max = falcon_api::falcon_sig_ct_size(logn);
    let tmp_len = falcon_api::falcon_tmpsize_signdyn(logn);
    let mut sig = vec![0u8; sig_max];
    let mut sig_len = sig_max;
    let mut tmp = vec![0u8; tmp_len];

    let rc = falcon_api::falcon_sign_dyn(
        &mut rng, &mut sig, &mut sig_len,
        falcon_api::FALCON_SIG_CT, &sk, message, &mut tmp,
    );
    assert_eq!(rc, 0);

    // Flip one bit in the signature payload (after nonce).
    let mut tampered = sig[..sig_len].to_vec();
    tampered[42] ^= 0x01;

    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    let rc = falcon_api::falcon_verify(
        &tampered, falcon_api::FALCON_SIG_CT, &pk, message, &mut vtmp,
    );
    assert!(rc < 0, "Tampered signature should not verify");
}

// ======================================================================
// Test: Empty message sign/verify
// ======================================================================

#[test]
fn test_sign_verify_empty_message() {
    let logn = 9u32;
    let (sk, pk, mut rng) = test_keypair(logn);
    let message = b"";

    let sig_max = falcon_api::falcon_sig_compressed_maxsize(logn);
    let tmp_len = falcon_api::falcon_tmpsize_signdyn(logn);
    let mut sig = vec![0u8; sig_max];
    let mut sig_len = sig_max;
    let mut tmp = vec![0u8; tmp_len];

    let rc = falcon_api::falcon_sign_dyn(
        &mut rng, &mut sig, &mut sig_len,
        falcon_api::FALCON_SIG_COMPRESSED, &sk, message, &mut tmp,
    );
    assert_eq!(rc, 0, "Sign empty message failed");

    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    let rc = falcon_api::falcon_verify(
        &sig[..sig_len], falcon_api::FALCON_SIG_COMPRESSED, &pk, message, &mut vtmp,
    );
    assert_eq!(rc, 0, "Verify empty message failed");
}
