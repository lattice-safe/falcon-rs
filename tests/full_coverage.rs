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
use falcon::shake::{i_shake256_flip, i_shake256_init, i_shake256_inject, InnerShake256Context};
use falcon::{
    codec, common, falcon as falcon_api,
    safe_api::{DomainSeparation, FalconError, FalconKeyPair, FalconSignature, PreHashAlgorithm},
};

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
    assert_eq!(
        logn_from_sk, 9,
        "get_logn from privkey returned wrong value"
    );

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
        &mut rng,
        &mut sig,
        &mut sig_len,
        falcon_api::FALCON_SIG_CT,
        &sk,
        &mut hash_data,
        &nonce,
        &mut tmp,
    );
    assert_eq!(rc, 0, "sign_dyn_finish failed");
    assert!(sig_len > 0 && sig_len <= sig_max);

    // Verify with standard API
    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    let rc = falcon_api::falcon_verify(
        &sig[..sig_len],
        falcon_api::FALCON_SIG_CT,
        &pk,
        message,
        &mut vtmp,
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
        &mut rng,
        &mut sig,
        &mut sig_len,
        falcon_api::FALCON_SIG_CT,
        &sk,
        message,
        &mut tmp,
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
        &sig_bytes,
        falcon_api::FALCON_SIG_CT,
        &pk,
        &mut hash_data,
        &mut vtmp,
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
        &mut rng,
        &mut sig,
        &mut sig_len,
        falcon_api::FALCON_SIG_CT,
        &expanded_key,
        message,
        &mut tmp_sign,
    );
    assert_eq!(rc, 0, "sign_tree failed");

    // Verify
    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    let rc = falcon_api::falcon_verify(
        &sig[..sig_len],
        falcon_api::FALCON_SIG_CT,
        &pk,
        message,
        &mut vtmp,
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
        &mut rng,
        &mut sig,
        &mut sig_len,
        falcon_api::FALCON_SIG_COMPRESSED,
        &sk,
        message,
        &mut tmp,
    );
    assert_eq!(rc, 0, "COMPRESSED sign failed");
    assert!(
        sig_len < sig_max,
        "COMPRESSED sig should be shorter than max"
    );

    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    let rc = falcon_api::falcon_verify(
        &sig[..sig_len],
        falcon_api::FALCON_SIG_COMPRESSED,
        &pk,
        message,
        &mut vtmp,
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
        &mut rng,
        &mut sig,
        &mut sig_len,
        falcon_api::FALCON_SIG_PADDED,
        &sk,
        message,
        &mut tmp,
    );
    assert_eq!(rc, 0, "PADDED sign failed");
    assert_eq!(
        sig_len, sig_size,
        "PADDED sig should be exactly the padded size"
    );

    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    let rc = falcon_api::falcon_verify(
        &sig[..sig_len],
        falcon_api::FALCON_SIG_PADDED,
        &pk,
        message,
        &mut vtmp,
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
        &mut rng,
        &mut sig,
        &mut sig_len,
        falcon_api::FALCON_SIG_CT,
        &sk,
        message,
        &mut tmp,
    );
    assert_eq!(rc, 0, "CT sign failed");
    assert_eq!(sig_len, sig_size, "CT sig should be exactly the CT size");

    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    let rc = falcon_api::falcon_verify(
        &sig[..sig_len],
        falcon_api::FALCON_SIG_CT,
        &pk,
        message,
        &mut vtmp,
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
        &mut rng,
        &mut sig,
        &mut sig_len,
        falcon_api::FALCON_SIG_COMPRESSED,
        &sk,
        message,
        &mut tmp,
    );
    assert_eq!(rc, 0);

    // Verify with sig_type=0 (auto-detect)
    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    let rc = falcon_api::falcon_verify(&sig[..sig_len], 0, &pk, message, &mut vtmp);
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

    let sig = kp.sign(b"safe api test", &DomainSeparation::None).unwrap();
    assert!(!sig.is_empty());
    assert!(!sig.is_empty());

    FalconSignature::verify(
        sig.to_bytes(),
        kp.public_key(),
        b"safe api test",
        &DomainSeparation::None,
    )
    .unwrap();
}

#[test]
fn test_safe_api_deterministic() {
    let seed = b"deterministic-safe-api-seed-1234";
    let kp1 = FalconKeyPair::generate_deterministic(seed, 9).unwrap();
    let kp2 = FalconKeyPair::generate_deterministic(seed, 9).unwrap();
    assert_eq!(
        kp1.public_key(),
        kp2.public_key(),
        "Deterministic keygen should match"
    );
    assert_eq!(kp1.private_key(), kp2.private_key());

    let sig_seed = b"sign-seed";
    let sig1 = kp1
        .sign_deterministic(b"hello", sig_seed, &DomainSeparation::None)
        .unwrap();
    let sig2 = kp2
        .sign_deterministic(b"hello", sig_seed, &DomainSeparation::None)
        .unwrap();
    assert_eq!(
        sig1.to_bytes(),
        sig2.to_bytes(),
        "Deterministic sign should match"
    );
}

#[test]
fn test_safe_api_bad_logn() {
    assert_eq!(
        FalconKeyPair::generate(0).unwrap_err(),
        FalconError::BadArgument
    );
    assert_eq!(
        FalconKeyPair::generate(11).unwrap_err(),
        FalconError::BadArgument
    );
}

#[test]
fn test_safe_api_bad_signature() {
    let kp = FalconKeyPair::generate(9).unwrap();
    let sig = kp
        .sign(b"original message", &DomainSeparation::None)
        .unwrap();

    // Verify with wrong message should fail.
    let result = FalconSignature::verify(
        sig.to_bytes(),
        kp.public_key(),
        b"wrong message",
        &DomainSeparation::None,
    );
    assert!(
        result.is_err(),
        "Verification with wrong message should fail"
    );
}

#[test]
fn test_safe_api_falcon1024() {
    let kp = FalconKeyPair::generate(10).unwrap();
    assert_eq!(kp.logn(), 10);

    let sig = kp
        .sign(b"fn-dsa-1024 test", &DomainSeparation::None)
        .unwrap();
    FalconSignature::verify(
        sig.to_bytes(),
        kp.public_key(),
        b"fn-dsa-1024 test",
        &DomainSeparation::None,
    )
    .unwrap();
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
        &mut rng,
        &mut sig,
        &mut sig_len,
        falcon_api::FALCON_SIG_COMPRESSED,
        &sk,
        b"msg",
        &mut tmp,
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
        &sig[..sig_len],
        falcon_api::FALCON_SIG_COMPRESSED,
        &pk2,
        b"msg",
        &mut vtmp,
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
        &mut rng,
        &mut sig,
        &mut sig_len,
        99, // invalid sig_type
        &sk,
        b"msg",
        &mut tmp,
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
        assert!(
            hm_vt[u] < 12289,
            "vartime value out of range at {}: {}",
            u,
            hm_vt[u]
        );
        assert!(
            hm_ct[u] < 12289,
            "ct value out of range at {}: {}",
            u,
            hm_ct[u]
        );
    }

    // They should produce the same distribution (same outputs for same SHAKE input).
    assert_eq!(
        hm_vt, hm_ct,
        "hash_to_point_ct and vartime should produce same output"
    );
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
    for (i, coeff) in coeffs.iter_mut().enumerate().take(n) {
        *coeff = ((i as i16) % 201) - 100; // range [-100, 100]
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
    for (i, coeff) in coeffs.iter_mut().enumerate().take(n) {
        *coeff = ((i as i16) % (2 * max_val + 1)) - max_val;
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
        &mut rng,
        &mut sig1,
        &mut sig1_len,
        falcon_api::FALCON_SIG_COMPRESSED,
        &sk,
        message,
        &mut tmp,
    );
    assert_eq!(rc, 0);

    let mut sig2 = vec![0u8; sig_max];
    let mut sig2_len = sig_max;
    let rc = falcon_api::falcon_sign_dyn(
        &mut rng,
        &mut sig2,
        &mut sig2_len,
        falcon_api::FALCON_SIG_COMPRESSED,
        &sk,
        message,
        &mut tmp,
    );
    assert_eq!(rc, 0);

    // Both should verify.
    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    assert_eq!(
        falcon_api::falcon_verify(
            &sig1[..sig1_len],
            falcon_api::FALCON_SIG_COMPRESSED,
            &pk,
            message,
            &mut vtmp
        ),
        0
    );
    assert_eq!(
        falcon_api::falcon_verify(
            &sig2[..sig2_len],
            falcon_api::FALCON_SIG_COMPRESSED,
            &pk,
            message,
            &mut vtmp
        ),
        0
    );

    // Signatures should be different (different nonces).
    assert_ne!(
        sig1[..sig1_len],
        sig2[..sig2_len],
        "Two signatures should differ"
    );
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
        &mut rng,
        &mut sig,
        &mut sig_len,
        falcon_api::FALCON_SIG_CT,
        &expanded_key,
        &mut hash_data,
        &nonce,
        &mut tmp_sign,
    );
    assert_eq!(rc, 0, "sign_tree_finish failed");

    // Verify
    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    let rc = falcon_api::falcon_verify(
        &sig[..sig_len],
        falcon_api::FALCON_SIG_CT,
        &pk,
        message,
        &mut vtmp,
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
        &mut rng,
        &mut sig,
        &mut sig_len,
        falcon_api::FALCON_SIG_CT,
        &sk,
        message,
        &mut tmp,
    );
    assert_eq!(rc, 0);

    // Flip one bit in the signature payload (after nonce).
    let mut tampered = sig[..sig_len].to_vec();
    tampered[42] ^= 0x01;

    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    let rc = falcon_api::falcon_verify(
        &tampered,
        falcon_api::FALCON_SIG_CT,
        &pk,
        message,
        &mut vtmp,
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
        &mut rng,
        &mut sig,
        &mut sig_len,
        falcon_api::FALCON_SIG_COMPRESSED,
        &sk,
        message,
        &mut tmp,
    );
    assert_eq!(rc, 0, "Sign empty message failed");

    let mut vtmp = vec![0u8; falcon_api::falcon_tmpsize_verify(logn)];
    let rc = falcon_api::falcon_verify(
        &sig[..sig_len],
        falcon_api::FALCON_SIG_COMPRESSED,
        &pk,
        message,
        &mut vtmp,
    );
    assert_eq!(rc, 0, "Verify empty message failed");
}

// ======================================================================
// FIPS 206 §6 — Pure FN-DSA Domain Separation Tests
// ======================================================================

/// Sign and verify succeed when both use the same Context string.
#[test]
fn test_domain_context_sign_verify() {
    let kp = FalconKeyPair::generate(9).unwrap();
    let msg = b"protocol message";
    let ctx = DomainSeparation::Context(b"my-protocol-v1");

    let sig = kp.sign(msg, &ctx).expect("sign with Context failed");
    FalconSignature::verify(sig.to_bytes(), kp.public_key(), msg, &ctx)
        .expect("verify with matching Context should succeed");
}

/// Verify MUST fail when context strings differ between sign and verify.
#[test]
fn test_domain_context_cross_rejection() {
    let kp = FalconKeyPair::generate(9).unwrap();
    let msg = b"cross-context rejection test";
    let ctx_a = DomainSeparation::Context(b"protocol-A");
    let ctx_b = DomainSeparation::Context(b"protocol-B");

    let sig = kp.sign(msg, &ctx_a).expect("sign with ctx_a failed");
    let result = FalconSignature::verify(sig.to_bytes(), kp.public_key(), msg, &ctx_b);
    assert!(
        result.is_err(),
        "Verify with different context must fail (cross-context rejection)"
    );
}

/// None vs Context(non-empty) mismatch must be rejected in both directions.
#[test]
fn test_domain_none_vs_context_mismatch() {
    let kp = FalconKeyPair::generate(9).unwrap();
    let msg = b"none vs context mismatch test";

    let sig_none = kp
        .sign(msg, &DomainSeparation::None)
        .expect("sign None failed");
    let result = FalconSignature::verify(
        sig_none.to_bytes(),
        kp.public_key(),
        msg,
        &DomainSeparation::Context(b"some-context"),
    );
    assert!(
        result.is_err(),
        "None-signed: verify with Context must fail"
    );

    let ctx = DomainSeparation::Context(b"some-context");
    let sig_ctx = kp.sign(msg, &ctx).expect("sign Context failed");
    let result2 = FalconSignature::verify(
        sig_ctx.to_bytes(),
        kp.public_key(),
        msg,
        &DomainSeparation::None,
    );
    assert!(
        result2.is_err(),
        "Context-signed: verify with None must fail"
    );
}

/// Context string > 255 bytes must return Err(BadArgument) — not silently truncate.
#[test]
fn test_domain_context_too_long_rejected() {
    let kp = FalconKeyPair::generate(9).unwrap();
    let long_ctx = vec![b'x'; 256];
    let domain = DomainSeparation::Context(&long_ctx);

    assert_eq!(
        kp.sign(b"msg", &domain).unwrap_err(),
        FalconError::BadArgument,
        "sign(): context > 255 must be BadArgument"
    );
    assert_eq!(
        kp.sign_deterministic(b"msg", b"seed", &domain).unwrap_err(),
        FalconError::BadArgument,
        "sign_deterministic(): context > 255 must be BadArgument"
    );

    let good_sig = kp.sign(b"msg", &DomainSeparation::None).unwrap();
    assert_eq!(
        FalconSignature::verify(good_sig.to_bytes(), kp.public_key(), b"msg", &domain).unwrap_err(),
        FalconError::BadArgument,
        "verify(): context > 255 must be BadArgument"
    );
}

/// Boundary: exactly 255-byte context must be accepted.
#[test]
fn test_domain_context_exactly_255_bytes_ok() {
    let kp = FalconKeyPair::generate(9).unwrap();
    let ctx_255 = vec![b'a'; 255];
    let domain = DomainSeparation::Context(&ctx_255);

    let sig = kp
        .sign(b"boundary test", &domain)
        .expect("255-byte context must be accepted");
    FalconSignature::verify(sig.to_bytes(), kp.public_key(), b"boundary test", &domain)
        .expect("verify with 255-byte context must succeed");
}

// ======================================================================
// FIPS 206 §6 — HashFN-DSA Tests (ph_flag = 0x01)
// ======================================================================

/// HashFN-DSA round-trip with SHA-256, no context.
#[test]
fn test_hash_fn_dsa_sha256_roundtrip() {
    let kp = FalconKeyPair::generate(9).unwrap();
    let msg = b"HashFN-DSA SHA-256 test message";
    let domain = DomainSeparation::Prehashed {
        alg: PreHashAlgorithm::Sha256,
        context: b"",
    };

    let sig = kp
        .sign(msg, &domain)
        .expect("HashFN-DSA SHA-256 sign failed");
    FalconSignature::verify(sig.to_bytes(), kp.public_key(), msg, &domain)
        .expect("HashFN-DSA SHA-256 verify failed");
}

/// HashFN-DSA round-trip with SHA-512, no context.
#[test]
fn test_hash_fn_dsa_sha512_roundtrip() {
    let kp = FalconKeyPair::generate(9).unwrap();
    let msg = b"HashFN-DSA SHA-512 test message, somewhat longer to exercise multiple blocks";
    let domain = DomainSeparation::Prehashed {
        alg: PreHashAlgorithm::Sha512,
        context: b"",
    };

    let sig = kp
        .sign(msg, &domain)
        .expect("HashFN-DSA SHA-512 sign failed");
    FalconSignature::verify(sig.to_bytes(), kp.public_key(), msg, &domain)
        .expect("HashFN-DSA SHA-512 verify failed");
}

/// HashFN-DSA with a context string round-trip.
#[test]
fn test_hash_fn_dsa_with_context_roundtrip() {
    let kp = FalconKeyPair::generate(9).unwrap();
    let msg = b"prehashed message with context";
    let domain = DomainSeparation::Prehashed {
        alg: PreHashAlgorithm::Sha256,
        context: b"my-protocol-v2",
    };

    let sig = kp.sign(msg, &domain).expect("HashFN-DSA+ctx sign failed");
    FalconSignature::verify(sig.to_bytes(), kp.public_key(), msg, &domain)
        .expect("HashFN-DSA+ctx verify failed");
}

/// SHA-256 signature must NOT verify under SHA-512 domain.
#[test]
fn test_hash_fn_dsa_cross_alg_rejection() {
    let kp = FalconKeyPair::generate(9).unwrap();
    let msg = b"cross prehash algorithm test";
    let d256 = DomainSeparation::Prehashed {
        alg: PreHashAlgorithm::Sha256,
        context: b"",
    };
    let d512 = DomainSeparation::Prehashed {
        alg: PreHashAlgorithm::Sha512,
        context: b"",
    };

    let sig = kp.sign(msg, &d256).expect("SHA-256 sign failed");
    let result = FalconSignature::verify(sig.to_bytes(), kp.public_key(), msg, &d512);
    assert!(
        result.is_err(),
        "SHA-256 sig must NOT verify under SHA-512 domain"
    );
}

/// HashFN-DSA signature must NOT verify under pure FN-DSA domain (and vice versa).
#[test]
fn test_hash_fn_dsa_vs_pure_mismatch() {
    let kp = FalconKeyPair::generate(9).unwrap();
    let msg = b"prehash vs pure mismatch";
    let ph = DomainSeparation::Prehashed {
        alg: PreHashAlgorithm::Sha256,
        context: b"",
    };

    let sig_ph = kp.sign(msg, &ph).expect("prehash sign failed");
    assert!(
        FalconSignature::verify(
            sig_ph.to_bytes(),
            kp.public_key(),
            msg,
            &DomainSeparation::None
        )
        .is_err(),
        "Prehash sig must not verify as pure FN-DSA"
    );

    let sig_pure = kp
        .sign(msg, &DomainSeparation::None)
        .expect("pure sign failed");
    assert!(
        FalconSignature::verify(sig_pure.to_bytes(), kp.public_key(), msg, &ph).is_err(),
        "Pure sig must not verify as HashFN-DSA"
    );
}

/// HashFN-DSA: wrong message must not verify.
#[test]
fn test_hash_fn_dsa_wrong_message_rejected() {
    let kp = FalconKeyPair::generate(9).unwrap();
    let msg = b"correct message";
    let domain = DomainSeparation::Prehashed {
        alg: PreHashAlgorithm::Sha256,
        context: b"",
    };

    let sig = kp.sign(msg, &domain).expect("sign failed");
    let result =
        FalconSignature::verify(sig.to_bytes(), kp.public_key(), b"wrong message", &domain);
    assert!(result.is_err(), "HashFN-DSA must reject wrong message");
}

/// HashFN-DSA with context > 255 bytes returns BadArgument.
#[test]
fn test_hash_fn_dsa_context_too_long_rejected() {
    let kp = FalconKeyPair::generate(9).unwrap();
    let long_ctx = vec![b'z'; 256];
    let domain = DomainSeparation::Prehashed {
        alg: PreHashAlgorithm::Sha256,
        context: &long_ctx,
    };
    assert_eq!(
        kp.sign(b"msg", &domain).unwrap_err(),
        FalconError::BadArgument,
        "HashFN-DSA context > 255 must return BadArgument"
    );
}

/// Deterministic HashFN-DSA: same inputs always produce the same signature.
#[test]
fn test_hash_fn_dsa_deterministic_reproducible() {
    let seed = b"hash-fn-dsa-deterministic-seed!!";
    let kp = FalconKeyPair::generate_deterministic(seed, 9).unwrap();
    let msg = b"deterministic prehash test";
    let domain = DomainSeparation::Prehashed {
        alg: PreHashAlgorithm::Sha256,
        context: b"",
    };
    let sign_seed = b"signing-entropy-seed";

    let sig1 = kp
        .sign_deterministic(msg, sign_seed, &domain)
        .expect("det sign 1 failed");
    let sig2 = kp
        .sign_deterministic(msg, sign_seed, &domain)
        .expect("det sign 2 failed");
    assert_eq!(
        sig1.to_bytes(),
        sig2.to_bytes(),
        "Deterministic HashFN-DSA must reproduce"
    );

    FalconSignature::verify(sig1.to_bytes(), kp.public_key(), msg, &domain)
        .expect("det HashFN-DSA verify failed");
}

/// FN-DSA-1024 with HashFN-DSA SHA-512.
#[test]
fn test_hash_fn_dsa_1024_sha512() {
    let kp = FalconKeyPair::generate(10).unwrap();
    let msg = b"FN-DSA-1024 HashFN-DSA SHA-512 test";
    let domain = DomainSeparation::Prehashed {
        alg: PreHashAlgorithm::Sha512,
        context: b"level-v",
    };
    let sig = kp
        .sign(msg, &domain)
        .expect("FN-DSA-1024 HashFN-DSA sign failed");
    FalconSignature::verify(sig.to_bytes(), kp.public_key(), msg, &domain)
        .expect("FN-DSA-1024 HashFN-DSA verify failed");
}

// ======================================================================
// FIPS 180-4 SHA-2 NIST Vector Tests
// ======================================================================
//
// NIST vectors from https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines
// These validate our pure-Rust SHA-256 and SHA-512 implementations used
// inside DomainSeparation::Prehashed.

use falcon::safe_api::{sha256_public, sha512_public};

/// SHA-256("") — FIPS 180-4 Example A.1
#[test]
fn test_sha256_empty() {
    assert_eq!(
        sha256_public(b""),
        [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ],
        "SHA-256('') NIST vector mismatch"
    );
}

/// SHA-256("abc") — FIPS 180-4 Example A.1
#[test]
fn test_sha256_abc() {
    assert_eq!(
        sha256_public(b"abc"),
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ],
        "SHA-256('abc') NIST vector mismatch"
    );
}

/// SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
/// — FIPS 180-4 Example A.2 (448-bit boundary, exercises two blocks)
#[test]
fn test_sha256_2block() {
    assert_eq!(
        sha256_public(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        [
            0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
            0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
            0x19, 0xdb, 0x06, 0xc1,
        ],
        "SHA-256(2-block) NIST vector mismatch"
    );
}

/// SHA-512("") — FIPS 180-4 Example B.1
#[test]
fn test_sha512_empty() {
    assert_eq!(
        sha512_public(b""),
        [
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d,
            0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
            0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83,
            0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
        ],
        "SHA-512('') NIST vector mismatch"
    );
}

/// SHA-512("abc") — FIPS 180-4 Example B.1
#[test]
fn test_sha512_abc() {
    assert_eq!(
        sha512_public(b"abc"),
        [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
            0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
            0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
            0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ],
        "SHA-512('abc') NIST vector mismatch"
    );
}

/// SHA-512("abcdefgh...") 2-block boundary — FIPS 180-4 Example B.2
#[test]
fn test_sha512_2block() {
    assert_eq!(
        sha512_public(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
        [
            0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda,
            0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f,
            0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1,
            0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18,
            0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4,
            0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
            0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54,
            0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09,
        ],
        "SHA-512(2-block) NIST vector mismatch"
    );
}
