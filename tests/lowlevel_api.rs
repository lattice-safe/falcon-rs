//! Coverage of the low-level C-style API and the expanded-key path.
//!
//! `safe_api` is what most callers use, so the ported `falcon.rs` entry
//! points — and their error returns — go largely unexercised by the other
//! suites. They are public API: a caller can reach every one of these
//! branches, so each needs to behave, not just compile.

use falcon::{
    falcon::{self as api, *},
    prelude::*,
    shake::InnerShake256Context,
};

fn seeded(seed: &[u8]) -> InnerShake256Context {
    let mut sc = InnerShake256Context::new();
    api::shake256_init_prng_from_seed(&mut sc, seed);
    sc
}

// ======================================================================
// Sizes, headers and argument validation
// ======================================================================

#[test]
fn size_helpers_and_logn_extraction() {
    for logn in 1..=10u32 {
        assert!(falcon_privkey_size(logn) > 0);
        assert!(falcon_pubkey_size(logn) > 0);
        assert!(falcon_sig_ct_size(logn) > 0);
        assert!(falcon_sig_padded_size(logn) > 0);
        assert!(falcon_sig_compressed_maxsize(logn) > 0);
        assert!(falcon_tmpsize_keygen(logn) > 0);
        assert!(falcon_tmpsize_signdyn(logn) > 0);
        assert!(falcon_tmpsize_signtree(logn) > 0);
        assert!(falcon_tmpsize_expandpriv(logn) > 0);
        assert!(falcon_tmpsize_verify(logn) > 0);
        assert!(falcon_tmpsize_makepub(logn) > 0);
    }

    // The degree lives in the low nibble of the header byte; the high
    // nibble marks the object kind and must be ignored here.
    assert_eq!(falcon_get_logn(&[0x59]), 9, "private-key header");
    assert_eq!(falcon_get_logn(&[0x0A]), 10, "public-key header");
    assert_eq!(falcon_get_logn(&[]), FALCON_ERR_FORMAT, "empty input");
    assert_eq!(falcon_get_logn(&[0x50]), FALCON_ERR_FORMAT, "degree 0");
    assert_eq!(falcon_get_logn(&[0x5B]), FALCON_ERR_FORMAT, "degree 11");
}

#[test]
fn low_level_calls_reject_empty_and_short_buffers() {
    let mut tmp = vec![0u8; falcon_tmpsize_makepub(9)];
    let mut out = vec![0u8; falcon_pubkey_size(9)];

    // Empty private key.
    assert_eq!(
        falcon_make_public(&mut out, &[], &mut tmp),
        FALCON_ERR_FORMAT
    );
    assert_eq!(
        falcon_expand_privkey(&mut out, &[], &mut tmp),
        FALCON_ERR_FORMAT
    );

    // Empty or too-short signature / public key on the verify path.
    let mut vtmp = vec![0u8; falcon_tmpsize_verify(9)];
    assert_eq!(
        falcon_verify(&[], FALCON_SIG_CT, &out, b"m", &mut vtmp),
        FALCON_ERR_FORMAT
    );
    assert_eq!(
        falcon_verify(&[0u8; 41], FALCON_SIG_CT, &[], b"m", &mut vtmp),
        FALCON_ERR_FORMAT
    );
    let short_sig = [0u8; 40];
    assert_eq!(
        falcon_verify(&short_sig, FALCON_SIG_CT, &out, b"m", &mut vtmp),
        FALCON_ERR_FORMAT
    );
}

// ======================================================================
// Every signature format, end to end, through the low-level API
// ======================================================================

fn keypair(logn: u32) -> (Vec<u8>, Vec<u8>) {
    let mut rng = seeded(b"lowlevel-keygen");
    let mut sk = vec![0u8; falcon_privkey_size(logn)];
    let mut pk = vec![0u8; falcon_pubkey_size(logn)];
    let mut tmp = vec![0u8; falcon_tmpsize_keygen(logn)];
    let rc = falcon_keygen_make(&mut rng, logn, &mut sk, Some(&mut pk), &mut tmp);
    assert_eq!(rc, 0, "keygen failed");
    (sk, pk)
}

#[test]
fn all_three_signature_formats_roundtrip() {
    let logn = 9u32;
    let (sk, pk) = keypair(logn);
    let msg = b"low-level signature format coverage";

    for &(sig_type, cap) in &[
        (FALCON_SIG_COMPRESSED, falcon_sig_compressed_maxsize(logn)),
        (FALCON_SIG_PADDED, falcon_sig_padded_size(logn)),
        (FALCON_SIG_CT, falcon_sig_ct_size(logn)),
    ] {
        let mut rng = seeded(b"lowlevel-sign");
        let mut sig = vec![0u8; cap];
        let mut sig_len = cap;
        let mut tmp = vec![0u8; falcon_tmpsize_signdyn(logn)];

        let rc = falcon_sign_dyn(
            &mut rng,
            &mut sig,
            &mut sig_len,
            sig_type,
            &sk,
            msg,
            &mut tmp,
        );
        assert_eq!(rc, 0, "sign_dyn failed for format {sig_type}");
        sig.truncate(sig_len);

        let mut vtmp = vec![0u8; falcon_tmpsize_verify(logn)];
        assert_eq!(
            falcon_verify(&sig, sig_type, &pk, msg, &mut vtmp),
            0,
            "verify failed for format {sig_type}"
        );

        // A different message must not verify.
        assert_eq!(
            falcon_verify(&sig, sig_type, &pk, b"other", &mut vtmp),
            FALCON_ERR_BADSIG
        );

        // A flipped bit in the body must not verify.
        let mut bad = sig.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0x40;
        assert_ne!(falcon_verify(&bad, sig_type, &pk, msg, &mut vtmp), 0);
    }
}

#[test]
fn expanded_key_signing_matches_dynamic() {
    let logn = 9u32;
    let (sk, pk) = keypair(logn);
    let msg = b"expanded key low-level path";

    let mut ek = vec![0u8; falcon_expandedkey_size(logn)];
    let mut tmp = vec![0u8; falcon_tmpsize_expandpriv(logn)];
    assert_eq!(falcon_expand_privkey(&mut ek, &sk, &mut tmp), 0);

    for &(sig_type, cap) in &[
        (FALCON_SIG_COMPRESSED, falcon_sig_compressed_maxsize(logn)),
        (FALCON_SIG_PADDED, falcon_sig_padded_size(logn)),
        (FALCON_SIG_CT, falcon_sig_ct_size(logn)),
    ] {
        let mut rng = seeded(b"lowlevel-tree-sign");
        let mut sig = vec![0u8; cap];
        let mut sig_len = cap;
        let mut stmp = vec![0u8; falcon_tmpsize_signtree(logn)];

        let rc = falcon_sign_tree(
            &mut rng,
            &mut sig,
            &mut sig_len,
            sig_type,
            &ek,
            msg,
            &mut stmp,
        );
        assert_eq!(rc, 0, "sign_tree failed for format {sig_type}");
        sig.truncate(sig_len);

        let mut vtmp = vec![0u8; falcon_tmpsize_verify(logn)];
        assert_eq!(falcon_verify(&sig, sig_type, &pk, msg, &mut vtmp), 0);
    }
}

#[test]
fn signing_into_a_short_buffer_reports_size_error() {
    let logn = 9u32;
    let (sk, _) = keypair(logn);
    let mut rng = seeded(b"short-buffer");
    let mut sig = vec![0u8; 42];
    let mut sig_len = sig.len();
    let mut tmp = vec![0u8; falcon_tmpsize_signdyn(logn)];

    let rc = falcon_sign_dyn(
        &mut rng,
        &mut sig,
        &mut sig_len,
        FALCON_SIG_CT,
        &sk,
        b"m",
        &mut tmp,
    );
    assert_eq!(rc, FALCON_ERR_SIZE);
}

#[test]
fn make_public_recomputes_the_key() {
    let (sk, pk) = keypair(9);
    let mut derived = vec![0u8; falcon_pubkey_size(9)];
    let mut tmp = vec![0u8; falcon_tmpsize_makepub(9)];
    assert_eq!(falcon_make_public(&mut derived, &sk, &mut tmp), 0);
    assert_eq!(
        derived, pk,
        "public key must be a function of the private key"
    );
}

// ======================================================================
// Expanded keys through the safe API
// ======================================================================

#[test]
fn expanded_key_safe_api_roundtrip() {
    let kp = FnDsaKeyPair::generate(9).unwrap();
    let ek = kp.expand().expect("expand");

    assert_eq!(ek.logn(), 9);
    assert_eq!(ek.public_key(), kp.public_key());

    let msg = b"expanded key safe api";
    for domain in [
        DomainSeparation::None,
        DomainSeparation::Context(b"ctx"),
        DomainSeparation::Prehashed {
            alg: PreHashAlgorithm::Sha512,
            context: b"",
        },
    ] {
        let sig = ek.sign(msg, &domain).expect("expanded sign");
        FnDsaSignature::verify(sig.to_bytes(), ek.public_key(), msg, &domain)
            .expect("expanded signature must verify");

        // Deterministic signing must reproduce byte for byte.
        let a = ek.sign_deterministic(msg, b"fixed seed", &domain).unwrap();
        let b = ek.sign_deterministic(msg, b"fixed seed", &domain).unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes());
        FnDsaSignature::verify(a.to_bytes(), ek.public_key(), msg, &domain).unwrap();
    }

    // Context length is validated on the expanded path too.
    let long = vec![0u8; 256];
    assert_eq!(
        ek.sign(msg, &DomainSeparation::Context(&long)).unwrap_err(),
        FalconError::BadArgument
    );
    assert_eq!(
        ek.sign_deterministic(msg, b"s", &DomainSeparation::Context(&long))
            .unwrap_err(),
        FalconError::BadArgument
    );
}

#[test]
fn variant_names_cover_every_supported_degree() {
    for (logn, want) in [(9u32, "FN-DSA-512"), (10, "FN-DSA-1024")] {
        let kp = FnDsaKeyPair::generate(logn).unwrap();
        assert_eq!(kp.variant_name(), want);
        assert_eq!(kp.logn(), logn);
    }
}

// ======================================================================
// Header and format validation on every low-level entry point
// ======================================================================

/// Each entry point checks the object header before touching the payload.
/// A wrong kind nibble, a degree outside 1..=10, or a truncated object must
/// all be refused with `FALCON_ERR_FORMAT` rather than misparsed.
#[test]
fn header_validation_on_every_entry_point() {
    let logn = 9u32;
    let (sk, pk) = keypair(logn);
    let msg = b"header validation";

    let mut sig = vec![0u8; falcon_sig_ct_size(logn)];
    let mut sig_len = sig.len();
    let mut stmp = vec![0u8; falcon_tmpsize_signdyn(logn)];
    let mut vtmp = vec![0u8; falcon_tmpsize_verify(logn)];
    let mut etmp = vec![0u8; falcon_tmpsize_expandpriv(logn)];
    let mut ptmp = vec![0u8; falcon_tmpsize_makepub(logn)];
    let mut ek = vec![0u8; falcon_expandedkey_size(logn)];
    let mut derived = vec![0u8; falcon_pubkey_size(logn)];

    // A private key whose header says "public key".
    let mut wrong_kind = sk.clone();
    wrong_kind[0] = 0x09;
    let mut rng = seeded(b"hdr");
    assert_eq!(
        falcon_sign_dyn(
            &mut rng,
            &mut sig,
            &mut sig_len,
            FALCON_SIG_CT,
            &wrong_kind,
            msg,
            &mut stmp
        ),
        FALCON_ERR_FORMAT
    );
    assert_eq!(
        falcon_expand_privkey(&mut ek, &wrong_kind, &mut etmp),
        FALCON_ERR_FORMAT
    );
    assert_eq!(
        falcon_make_public(&mut derived, &wrong_kind, &mut ptmp),
        FALCON_ERR_FORMAT
    );

    // A degree the format does not allow.
    let mut bad_degree = sk.clone();
    bad_degree[0] = 0x5F;
    assert_eq!(
        falcon_make_public(&mut derived, &bad_degree, &mut ptmp),
        FALCON_ERR_FORMAT
    );
    assert_eq!(
        falcon_expand_privkey(&mut ek, &bad_degree, &mut etmp),
        FALCON_ERR_FORMAT
    );

    // Truncated private key.
    assert_eq!(
        falcon_make_public(&mut derived, &sk[..sk.len() - 1], &mut ptmp),
        FALCON_ERR_FORMAT
    );

    // Produce a real signature, then attack the verify path's headers.
    let mut rng = seeded(b"hdr-sign");
    let mut sig_len = sig.len();
    assert_eq!(
        falcon_sign_dyn(
            &mut rng,
            &mut sig,
            &mut sig_len,
            FALCON_SIG_CT,
            &sk,
            msg,
            &mut stmp
        ),
        0
    );
    sig.truncate(sig_len);

    // Public key with the wrong kind nibble and with a bad degree.
    let mut wrong_pk = pk.clone();
    wrong_pk[0] = 0x59;
    assert_eq!(
        falcon_verify(&sig, FALCON_SIG_CT, &wrong_pk, msg, &mut vtmp),
        FALCON_ERR_FORMAT
    );
    let mut bad_pk_degree = pk.clone();
    bad_pk_degree[0] = 0x0F;
    assert_eq!(
        falcon_verify(&sig, FALCON_SIG_CT, &bad_pk_degree, msg, &mut vtmp),
        FALCON_ERR_FORMAT
    );

    // Truncated public key.
    assert_eq!(
        falcon_verify(&sig, FALCON_SIG_CT, &pk[..pk.len() - 1], msg, &mut vtmp),
        FALCON_ERR_FORMAT
    );

    // Signature header that disagrees with the requested format or degree.
    let mut wrong_fmt = sig.clone();
    wrong_fmt[0] = 0x30 + logn as u8; // padded header, CT requested
    assert_ne!(
        falcon_verify(&wrong_fmt, FALCON_SIG_CT, &pk, msg, &mut vtmp),
        0
    );
    let mut wrong_sig_degree = sig.clone();
    wrong_sig_degree[0] = 0x50 + 10;
    assert_ne!(
        falcon_verify(&wrong_sig_degree, FALCON_SIG_CT, &pk, msg, &mut vtmp),
        0
    );

    // A signature whose length does not match the CT size for this degree.
    assert_ne!(
        falcon_verify(&sig[..sig.len() - 1], FALCON_SIG_CT, &pk, msg, &mut vtmp),
        0
    );
}

/// Key generation across every degree the low-level API accepts. The NTRU
/// solver takes different depths and word-length paths at each one, so this
/// is the cheapest way to exercise the solver's branches.
#[test]
fn keygen_across_all_supported_degrees() {
    for logn in 1..=8u32 {
        let mut rng = seeded(b"degree sweep");
        let mut sk = vec![0u8; falcon_privkey_size(logn)];
        let mut pk = vec![0u8; falcon_pubkey_size(logn)];
        let mut tmp = vec![0u8; falcon_tmpsize_keygen(logn)];
        assert_eq!(
            falcon_keygen_make(&mut rng, logn, &mut sk, Some(&mut pk), &mut tmp),
            0,
            "keygen failed at logn = {logn}"
        );

        // The generated pair must round-trip a signature.
        let mut sig = vec![0u8; falcon_sig_ct_size(logn)];
        let mut sig_len = sig.len();
        let mut stmp = vec![0u8; falcon_tmpsize_signdyn(logn)];
        let msg = b"degree sweep message";
        assert_eq!(
            falcon_sign_dyn(
                &mut rng,
                &mut sig,
                &mut sig_len,
                FALCON_SIG_CT,
                &sk,
                msg,
                &mut stmp
            ),
            0,
            "sign failed at logn = {logn}"
        );
        sig.truncate(sig_len);

        let mut vtmp = vec![0u8; falcon_tmpsize_verify(logn)];
        assert_eq!(
            falcon_verify(&sig, FALCON_SIG_CT, &pk, msg, &mut vtmp),
            0,
            "verify failed at logn = {logn}"
        );
    }
}

/// Key generation must refuse degrees outside the supported range, and must
/// report a size error rather than overrunning a short output buffer.
#[test]
fn keygen_rejects_bad_arguments() {
    let mut rng = seeded(b"bad args");
    let mut sk = vec![0u8; falcon_privkey_size(9)];
    let mut tmp = vec![0u8; falcon_tmpsize_keygen(9)];

    assert_eq!(
        falcon_keygen_make(&mut rng, 0, &mut sk, None, &mut tmp),
        FALCON_ERR_BADARG
    );
    assert_eq!(
        falcon_keygen_make(&mut rng, 11, &mut sk, None, &mut tmp),
        FALCON_ERR_BADARG
    );

    let mut short = vec![0u8; 4];
    assert_eq!(
        falcon_keygen_make(&mut rng, 9, &mut short, None, &mut tmp),
        FALCON_ERR_SIZE
    );
}

/// Every signature format must report a size error rather than overrun a
/// short output buffer, on both the dynamic and the expanded-key path.
#[test]
fn short_output_buffers_are_refused_for_every_format() {
    let logn = 9u32;
    let (sk, _) = keypair(logn);
    let msg = b"short buffer per format";

    let mut ek = vec![0u8; falcon_expandedkey_size(logn)];
    let mut etmp = vec![0u8; falcon_tmpsize_expandpriv(logn)];
    assert_eq!(falcon_expand_privkey(&mut ek, &sk, &mut etmp), 0);

    for &sig_type in &[FALCON_SIG_COMPRESSED, FALCON_SIG_PADDED, FALCON_SIG_CT] {
        // 41 bytes is the header plus nonce: enough to start, never enough
        // to hold the body.
        let mut sig = vec![0u8; 42];
        let mut sig_len = sig.len();
        let mut stmp = vec![0u8; falcon_tmpsize_signdyn(logn)];
        let mut rng = seeded(b"short-per-format");
        assert_eq!(
            falcon_sign_dyn(
                &mut rng,
                &mut sig,
                &mut sig_len,
                sig_type,
                &sk,
                msg,
                &mut stmp
            ),
            FALCON_ERR_SIZE,
            "sign_dyn format {sig_type} accepted a short buffer"
        );

        let mut sig = vec![0u8; 42];
        let mut sig_len = sig.len();
        let mut ttmp = vec![0u8; falcon_tmpsize_signtree(logn)];
        let mut rng = seeded(b"short-per-format-tree");
        assert_eq!(
            falcon_sign_tree(
                &mut rng,
                &mut sig,
                &mut sig_len,
                sig_type,
                &ek,
                msg,
                &mut ttmp
            ),
            FALCON_ERR_SIZE,
            "sign_tree format {sig_type} accepted a short buffer"
        );
    }

    // An unknown format value must be rejected outright.
    let mut sig = vec![0u8; falcon_sig_ct_size(logn)];
    let mut sig_len = sig.len();
    let mut stmp = vec![0u8; falcon_tmpsize_signdyn(logn)];
    let mut rng = seeded(b"bad-format");
    assert_ne!(
        falcon_sign_dyn(&mut rng, &mut sig, &mut sig_len, 99, &sk, msg, &mut stmp),
        0
    );
}

/// Corrupted key and signature *bodies* — as opposed to headers — must fail
/// in the decoders rather than producing a wrong result.
#[test]
fn corrupted_bodies_fail_to_decode() {
    let logn = 9u32;
    let (sk, pk) = keypair(logn);
    let msg = b"corrupt bodies";

    let mut sig = vec![0u8; falcon_sig_ct_size(logn)];
    let mut sig_len = sig.len();
    let mut stmp = vec![0u8; falcon_tmpsize_signdyn(logn)];
    let mut rng = seeded(b"corrupt");
    assert_eq!(
        falcon_sign_dyn(
            &mut rng,
            &mut sig,
            &mut sig_len,
            FALCON_SIG_CT,
            &sk,
            msg,
            &mut stmp
        ),
        0
    );
    sig.truncate(sig_len);

    // A public key whose coefficients are not valid residues mod q: the
    // modq decoder must refuse it.
    let mut bad_pk = pk.clone();
    for byte in bad_pk[1..].iter_mut() {
        *byte = 0xFF;
    }
    let mut vtmp = vec![0u8; falcon_tmpsize_verify(logn)];
    assert_eq!(
        falcon_verify(&sig, FALCON_SIG_CT, &bad_pk, msg, &mut vtmp),
        FALCON_ERR_FORMAT
    );

    // A private key whose body cannot be decoded at the declared widths.
    // An all-ones body would decode fine (every coefficient becomes -1), so
    // the corruption has to be the one pattern the encoder never emits:
    // -2^(bits-1). At logn = 9 the small polynomials use six bits, so that
    // is the repeating group 100000, which tiles as 0x82 0x08 0x20.
    let mut bad_sk = sk.clone();
    for (i, byte) in bad_sk[1..].iter_mut().enumerate() {
        *byte = [0x82u8, 0x08, 0x20][i % 3];
    }
    let mut derived = vec![0u8; falcon_pubkey_size(logn)];
    let mut ptmp = vec![0u8; falcon_tmpsize_makepub(logn)];
    assert_ne!(falcon_make_public(&mut derived, &bad_sk, &mut ptmp), 0);

    let mut ek = vec![0u8; falcon_expandedkey_size(logn)];
    let mut etmp = vec![0u8; falcon_tmpsize_expandpriv(logn)];
    assert_ne!(falcon_expand_privkey(&mut ek, &bad_sk, &mut etmp), 0);

    let mut sig2 = vec![0u8; falcon_sig_ct_size(logn)];
    let mut sig2_len = sig2.len();
    let mut rng = seeded(b"corrupt-sign");
    assert_ne!(
        falcon_sign_dyn(
            &mut rng,
            &mut sig2,
            &mut sig2_len,
            FALCON_SIG_CT,
            &bad_sk,
            msg,
            &mut stmp
        ),
        0
    );

    // A signature body that decodes but is not short enough.
    let mut long_sig = sig.clone();
    for byte in long_sig[41..].iter_mut() {
        *byte = 0x7F;
    }
    assert_ne!(
        falcon_verify(&long_sig, FALCON_SIG_CT, &pk, msg, &mut vtmp),
        0
    );
}
