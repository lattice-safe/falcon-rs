//! Feature `round3`: backward compatibility with falcon-rs 0.3, and key
//! conversion to FN-DSA.
//!
//! The fixtures under `tests/fixtures/round3/` are the 0.3.1 regression
//! anchors, copied unchanged from the 0.3.1 tree (`tests/fixtures/fips206`
//! at c0cef65): `falcon::round3` must reproduce them byte for byte.

#![cfg(feature = "round3")]

use falcon::round3;

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

macro_rules! fixture {
    ($name:expr, $kind:expr) => {
        unhex(include_str!(concat!(
            "fixtures/round3/",
            $name,
            "_",
            $kind,
            ".hex"
        )))
    };
}

const MSG: &[u8] = b"FIPS 206 FN-DSA Known Answer Test";
const SIGN_SEED: &[u8] = b"fips206-kat-sign-seed";

/// (key seed, logn, domain, expected public key, expected signature)
type Case<'a> = (
    &'a [u8],
    u32,
    falcon::round3::DomainSeparation<'a>,
    Vec<u8>,
    Vec<u8>,
);

#[test]
fn reproduces_falcon_rs_0_3_1_bytes() {
    use round3::prelude::*;
    let ctx = b"fips206-ctx-v1";
    let cases: [Case; 6] = [
        (
            b"fips206-kat-key-seed-512",
            9,
            DomainSeparation::None,
            fixture!("FN-DSA-512__DomainSeparation_None", "pk"),
            fixture!("FN-DSA-512__DomainSeparation_None", "sig"),
        ),
        (
            b"fips206-kat-key-seed-512",
            9,
            DomainSeparation::Context(ctx),
            fixture!(
                "FN-DSA-512__DomainSeparation_Context_b_fips206-ctx-v1",
                "pk"
            ),
            fixture!(
                "FN-DSA-512__DomainSeparation_Context_b_fips206-ctx-v1",
                "sig"
            ),
        ),
        (
            b"fips206-kat-key-seed-512",
            9,
            DomainSeparation::Prehashed {
                alg: PreHashAlgorithm::Sha256,
                context: b"",
            },
            fixture!("FN-DSA-512__Prehashed_SHA-256_no_ctx", "pk"),
            fixture!("FN-DSA-512__Prehashed_SHA-256_no_ctx", "sig"),
        ),
        (
            b"fips206-kat-key-seed-512",
            9,
            DomainSeparation::Prehashed {
                alg: PreHashAlgorithm::Sha512,
                context: ctx,
            },
            fixture!("FN-DSA-512__Prehashed_SHA-512_ctx_b_fips206-ctx-v1", "pk"),
            fixture!("FN-DSA-512__Prehashed_SHA-512_ctx_b_fips206-ctx-v1", "sig"),
        ),
        (
            b"fips206-kat-key-seed-1024",
            10,
            DomainSeparation::None,
            fixture!("FN-DSA-1024__DomainSeparation_None", "pk"),
            fixture!("FN-DSA-1024__DomainSeparation_None", "sig"),
        ),
        (
            b"fips206-kat-key-seed-1024",
            10,
            DomainSeparation::Prehashed {
                alg: PreHashAlgorithm::Sha512,
                context: ctx,
            },
            fixture!("FN-DSA-1024__Prehashed_SHA-512_ctx_b_fips206-ctx-v1", "pk"),
            fixture!("FN-DSA-1024__Prehashed_SHA-512_ctx_b_fips206-ctx-v1", "sig"),
        ),
    ];
    for (i, (seed, logn, domain, pk, sig)) in cases.iter().enumerate() {
        let kp = FnDsaKeyPair::generate_deterministic(seed, *logn).unwrap();
        assert_eq!(kp.public_key(), &pk[..], "case {i}: 0.3.1 public key");
        let s = kp.sign_deterministic(MSG, SIGN_SEED, domain).unwrap();
        assert_eq!(s.to_bytes(), &sig[..], "case {i}: 0.3.1 signature");
        FnDsaSignature::verify(sig, pk, MSG, domain).unwrap();
    }
}

/// Coefficients of h from a round-3 public key (plain form).
fn round3_h(pk: &[u8], logn: u32) -> Vec<u16> {
    let mut h = vec![0u16; 1 << logn];
    assert!(round3::codec::modq_decode(&mut h, logn, &pk[1..]) > 0);
    h
}

/// Coefficients of h from an FN-DSA public key (stored in NTT form).
fn fndsa_h(vk: &[u8], logn: u32) -> Vec<u16> {
    use falcon::fndsa::{codec, mq};
    let mut h = vec![0u16; 1 << logn];
    codec::modq_decode(&vk[1..], &mut h).unwrap();
    mq::mqpoly_ext_to_int(logn, &mut h);
    mq::mqpoly_NTT_to_int(logn, &mut h);
    mq::mqpoly_int_to_ext(logn, &mut h);
    h
}

#[test]
fn conversion_keeps_the_basis_and_signs() {
    use falcon::prelude::*;
    for logn in [9u32, 10] {
        let old =
            round3::FnDsaKeyPair::generate_deterministic(b"round-3 key to convert", logn).unwrap();
        let new = round3::to_fndsa_keypair(old.private_key()).unwrap();
        assert_eq!(new.logn(), logn);

        // Same public polynomial h = g/f, only encoded differently.
        assert_eq!(
            round3_h(old.public_key(), logn),
            fndsa_h(new.public_key(), logn)
        );
        assert_ne!(old.public_key(), new.public_key());
        // A verifier gets the same new key from the old public key alone.
        assert_eq!(
            round3::to_fndsa_public_key(old.public_key()).unwrap(),
            new.public_key()
        );

        let sig = new.sign(b"msg", &DomainSeparation::None).unwrap();
        FnDsaSignature::verify(
            sig.to_bytes(),
            new.public_key(),
            b"msg",
            &DomainSeparation::None,
        )
        .unwrap();

        // The formats are not interchangeable: each API rejects the other's
        // signature even under the matching key.
        let old_sig = old
            .sign_deterministic(b"msg", b"r", &round3::DomainSeparation::None)
            .unwrap();
        assert!(FnDsaSignature::verify(
            old_sig.to_bytes(),
            new.public_key(),
            b"msg",
            &DomainSeparation::None
        )
        .is_err());
        assert!(round3::FnDsaSignature::verify(
            sig.to_bytes(),
            old.public_key(),
            b"msg",
            &round3::DomainSeparation::None
        )
        .is_err());
    }
}

#[test]
fn conversion_rejects_bad_keys() {
    use falcon::FalconError::{BadArgument, FormatError};
    let old = round3::FnDsaKeyPair::generate_deterministic(b"round-3 key to convert", 9).unwrap();
    let sk = old.private_key();

    assert_eq!(round3::to_fndsa_keypair(&[]).unwrap_err(), FormatError);
    let mut bad = sk.to_vec();
    bad[0] = 0x09;
    assert_eq!(round3::to_fndsa_keypair(&bad).unwrap_err(), FormatError);
    bad[0] = 0x58;
    assert_eq!(round3::to_fndsa_keypair(&bad).unwrap_err(), BadArgument);
    assert_eq!(
        round3::to_fndsa_keypair(&sk[..sk.len() - 1]).unwrap_err(),
        FormatError
    );
    // An FN-DSA private key is not a round-3 one (different size).
    let fn_dsa = round3::to_fndsa_keypair(sk).unwrap();
    assert_eq!(
        round3::to_fndsa_keypair(fn_dsa.private_key()).unwrap_err(),
        FormatError
    );

    // The forbidden 6-bit pattern 0b100000 as the first f coefficient
    // (round-3 packs bits most-significant first).
    let mut bad = sk.to_vec();
    bad[1] = 0x80 | (bad[1] & 0x03);
    assert_eq!(round3::to_fndsa_keypair(&bad).unwrap_err(), FormatError);

    // F = 0: decodes, but is not an NTRU basis; the FN-DSA import refuses it.
    let mut bad = sk.to_vec();
    let fg = 512 * 6 / 8;
    bad[1 + 2 * fg..].fill(0);
    assert_eq!(round3::to_fndsa_keypair(&bad).unwrap_err(), FormatError);
}

#[test]
fn public_key_conversion_rejects_bad_keys() {
    use falcon::FalconError::{BadArgument, FormatError};
    let old = round3::FnDsaKeyPair::generate_deterministic(b"round-3 key to convert", 9).unwrap();
    let pk = old.public_key();
    let conv = round3::to_fndsa_public_key;

    assert_eq!(conv(&[]).unwrap_err(), FormatError);
    let mut bad = pk.to_vec();
    bad[0] = 0x19;
    assert_eq!(conv(&bad).unwrap_err(), FormatError);
    bad[0] = 0x08;
    assert_eq!(conv(&bad).unwrap_err(), BadArgument);
    assert_eq!(conv(&pk[..pk.len() - 1]).unwrap_err(), FormatError);
    // A private key is not a public key.
    assert_eq!(conv(old.private_key()).unwrap_err(), FormatError);
    // First coefficient 0x3FFF >= q.
    let mut bad = pk.to_vec();
    bad[1] = 0xFF;
    bad[2] |= 0xFC;
    assert_eq!(conv(&bad).unwrap_err(), FormatError);
}
