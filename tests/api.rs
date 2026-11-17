//! The high-level API: every accessor, and every rejection path with the
//! error kind it must report. Byte-exactness against the C reference is
//! checked separately in `api_vectors.rs`.

use falcon::prelude::*;

fn kp(logn: u32) -> FnDsaKeyPair {
    FnDsaKeyPair::generate_deterministic(b"tests/api.rs: a 32-byte key seed", logn).unwrap()
}

const D: DomainSeparation<'static> = DomainSeparation::None;

#[test]
fn accessors_and_round_trips() {
    for (logn, name, sk, pk, sig) in [
        (9, "FN-DSA-512", 1345, 897, 666),
        (10, "FN-DSA-1024", 2369, 1793, 1280),
    ] {
        let kp = kp(logn);
        assert_eq!(kp.logn(), logn);
        assert_eq!(kp.variant_name(), name);
        assert_eq!(kp.private_key().len(), sk);
        assert_eq!(kp.public_key().len(), pk);

        let s = kp.sign(b"msg", &D).unwrap();
        assert_eq!(s.len(), sig);
        assert!(!s.is_empty());
        FnDsaSignature::verify(s.to_bytes(), kp.public_key(), b"msg", &D).unwrap();
        let s2 = FnDsaSignature::from_bytes(s.clone().into_bytes()).unwrap();
        assert_eq!(s2.to_bytes(), s.to_bytes());

        let ek = kp.expand().unwrap();
        assert_eq!(ek.logn(), logn);
        assert_eq!(ek.public_key(), kp.public_key());
        let s3 = ek.sign(b"msg", &D).unwrap();
        FnDsaSignature::verify(s3.to_bytes(), ek.public_key(), b"msg", &D).unwrap();

        // Hedged signing: two signatures of the same message differ.
        assert_ne!(s.to_bytes(), s3.to_bytes());

        // Import paths.
        let a = FnDsaKeyPair::from_keys(kp.private_key(), kp.public_key()).unwrap();
        let b = FnDsaKeyPair::from_private_key(kp.private_key()).unwrap();
        assert_eq!(a.public_key(), kp.public_key());
        assert_eq!(b.public_key(), kp.public_key());
        assert_eq!(
            FnDsaKeyPair::public_key_from_private(kp.private_key()).unwrap(),
            kp.public_key()
        );

        // Debug output never shows the private key.
        let dbg = format!("{kp:?} {ek:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains(&format!("{:?}", &kp.private_key()[..8])));
    }
}

#[test]
fn os_entropy_keygen() {
    let a = FnDsaKeyPair::generate(9).unwrap();
    let b = FnDsaKeyPair::generate(9).unwrap();
    assert_ne!(a.private_key(), b.private_key());
    assert_eq!(falcon::safe_api::sha512_public(b"").len(), 64);
}

#[test]
fn deterministic_keygen_and_signing() {
    let seed = [7u8; 32];
    let a = FnDsaKeyPair::generate_deterministic(&seed, 9).unwrap();
    let b = FnDsaKeyPair::generate_deterministic(&seed, 9).unwrap();
    // Shorter seeds are refused.
    assert_eq!(
        FnDsaKeyPair::generate_deterministic(&seed[..31], 9).unwrap_err(),
        FalconError::BadArgument
    );
    assert_eq!(a.private_key(), b.private_key());
    let s1 = a.sign_deterministic(b"m", b"r", &D).unwrap();
    let s2 = a.sign_deterministic(b"m", b"r", &D).unwrap();
    let s3 = a.sign_deterministic(b"m", b"r2", &D).unwrap();
    assert_eq!(s1.to_bytes(), s2.to_bytes());
    assert_ne!(s1.to_bytes(), s3.to_bytes());
}

#[test]
fn non_standard_degrees_are_rejected() {
    for logn in [0, 2, 8, 11] {
        assert_eq!(
            FnDsaKeyPair::generate(logn).unwrap_err(),
            FalconError::BadArgument
        );
        assert_eq!(
            FnDsaKeyPair::generate_deterministic(&[0u8; 32], logn).unwrap_err(),
            FalconError::BadArgument
        );
    }
}

#[test]
fn domain_validation() {
    let kp = kp(9);
    let long = [0u8; 256];
    let max = [0u8; 255];
    let sig = kp.sign_deterministic(b"m", b"r", &D).unwrap();
    for bad in [
        DomainSeparation::Context(&long),
        DomainSeparation::Prehashed {
            alg: PreHashAlgorithm::Sha256,
            context: &long,
        },
        DomainSeparation::ExternalMu(&long[..63]),
    ] {
        assert_eq!(kp.sign(b"m", &bad).unwrap_err(), FalconError::BadArgument);
        assert_eq!(
            FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), b"m", &bad).unwrap_err(),
            FalconError::BadArgument
        );
    }
    // 255 bytes is the maximum, and it is accepted.
    let ok = DomainSeparation::Context(&max);
    let s = kp.sign(b"m", &ok).unwrap();
    FnDsaSignature::verify(s.to_bytes(), kp.public_key(), b"m", &ok).unwrap();

    // Every mode separates from every other.
    let mu = [7u8; 64];
    let modes = [
        DomainSeparation::None,
        DomainSeparation::Context(b"c"),
        DomainSeparation::Prehashed {
            alg: PreHashAlgorithm::Sha256,
            context: b"",
        },
        DomainSeparation::Prehashed {
            alg: PreHashAlgorithm::Sha512,
            context: b"",
        },
        DomainSeparation::Prehashed {
            alg: PreHashAlgorithm::Sha3_256,
            context: b"",
        },
        DomainSeparation::Prehashed {
            alg: PreHashAlgorithm::Sha3_512,
            context: b"",
        },
        DomainSeparation::ExternalMu(&mu),
    ];
    for (i, a) in modes.iter().enumerate() {
        let s = kp.sign_deterministic(b"m", b"r", a).unwrap();
        for (j, b) in modes.iter().enumerate() {
            let r = FnDsaSignature::verify(s.to_bytes(), kp.public_key(), b"m", b);
            assert_eq!(r.is_ok(), i == j, "signed as {a:?}, verified as {b:?}");
        }
    }
}

#[test]
fn private_key_rejections() {
    let kp = kp(9);
    let sk = kp.private_key();
    let fmt = FalconError::FormatError;
    assert_eq!(FnDsaKeyPair::from_private_key(&[]).unwrap_err(), fmt);
    let mut bad = sk.to_vec();
    bad[0] = 0x09; // a public-key header
    assert_eq!(FnDsaKeyPair::from_private_key(&bad).unwrap_err(), fmt);
    bad[0] = 0x58; // degree 8 is not standard
    assert_eq!(
        FnDsaKeyPair::from_private_key(&bad).unwrap_err(),
        FalconError::BadArgument
    );
    assert_eq!(
        FnDsaKeyPair::from_private_key(&sk[..sk.len() - 1]).unwrap_err(),
        fmt
    );
    assert_eq!(FnDsaKeyPair::public_key_from_private(&[]).unwrap_err(), fmt);
}

#[test]
fn public_key_rejections_on_import() {
    let a = kp(9);
    let other =
        FnDsaKeyPair::generate_deterministic(b"another key, also 32 bytes long!", 9).unwrap();
    let sk = a.private_key();
    let pk = a.public_key();
    let fmt = FalconError::FormatError;
    assert_eq!(FnDsaKeyPair::from_keys(sk, &[]).unwrap_err(), fmt);
    let mut bad = pk.to_vec();
    bad[0] = 0x59;
    assert_eq!(FnDsaKeyPair::from_keys(sk, &bad).unwrap_err(), fmt);
    bad[0] = 0x08;
    assert_eq!(
        FnDsaKeyPair::from_keys(sk, &bad).unwrap_err(),
        FalconError::BadArgument
    );
    assert_eq!(
        FnDsaKeyPair::from_keys(sk, &pk[..pk.len() - 1]).unwrap_err(),
        fmt
    );
    // A well-formed public key of another pair.
    assert_eq!(
        FnDsaKeyPair::from_keys(sk, other.public_key()).unwrap_err(),
        FalconError::BadArgument
    );
    // The private key is checked first.
    assert_eq!(FnDsaKeyPair::from_keys(&[], pk).unwrap_err(), fmt);
}

#[test]
fn verify_rejections() {
    let kp = kp(9);
    let pk = kp.public_key();
    let sig = kp.sign_deterministic(b"m", b"r", &D).unwrap().into_bytes();
    let v = |s: &[u8], p: &[u8]| FnDsaSignature::verify(s, p, b"m", &D).unwrap_err();
    let fmt = FalconError::FormatError;

    assert_eq!(v(&sig, &[]), fmt);
    let mut bad = pk.to_vec();
    bad[0] = 0x19;
    assert_eq!(v(&sig, &bad), fmt);
    bad[0] = 0x08;
    assert_eq!(v(&sig, &bad), FalconError::BadArgument);
    assert_eq!(v(&sig, &pk[..pk.len() - 1]), fmt);

    assert_eq!(v(&sig[..sig.len() - 1], pk), fmt);
    let mut bad = sig.clone();
    bad[0] = 0x3A;
    assert_eq!(v(&bad, pk), fmt);
    let mut bad = sig.clone();
    bad[20] ^= 1; // nonce
    assert_eq!(v(&bad, pk), FalconError::BadSignature);
    assert_eq!(
        FnDsaSignature::verify(&sig, pk, b"other", &D).unwrap_err(),
        FalconError::BadSignature
    );
}

#[test]
fn signature_from_bytes() {
    let kp = kp(9);
    let sig = kp.sign_deterministic(b"m", b"r", &D).unwrap().into_bytes();
    let fmt = FalconError::FormatError;
    assert_eq!(FnDsaSignature::from_bytes(vec![]).unwrap_err(), fmt);
    let mut bad = sig.clone();
    bad[0] = 0x59;
    assert_eq!(FnDsaSignature::from_bytes(bad).unwrap_err(), fmt);
    let mut bad = sig.clone();
    bad[0] = 0x38;
    assert_eq!(
        FnDsaSignature::from_bytes(bad).unwrap_err(),
        FalconError::BadArgument
    );
    assert_eq!(
        FnDsaSignature::from_bytes(sig[..sig.len() - 1].to_vec()).unwrap_err(),
        fmt
    );
}

#[test]
fn errors_implement_std_error() {
    let e: Box<dyn std::error::Error> = Box::new(FalconError::BadSignature);
    assert_eq!(e.to_string(), "invalid signature");
}

#[cfg(feature = "serde")]
#[test]
fn serde_round_trip_and_tamper_detection() {
    let kp = kp(9);
    let json = serde_json::to_string(&kp).unwrap();
    let back: FnDsaKeyPair = serde_json::from_str(&json).unwrap();
    assert_eq!(back.private_key(), kp.private_key());

    // A private key that does not decode.
    let broken = json.replacen("\"privkey\":[89,", "\"privkey\":[88,", 1);
    assert_ne!(broken, json);
    assert!(serde_json::from_str::<FnDsaKeyPair>(&broken).is_err());

    // A logn field that disagrees with the key headers.
    let tampered = json.replace("\"logn\":9", "\"logn\":10");
    assert_ne!(tampered, json);
    assert!(serde_json::from_str::<FnDsaKeyPair>(&tampered).is_err());

    let sig = kp.sign_deterministic(b"m", b"r", &D).unwrap();
    let js = serde_json::to_string(&sig).unwrap();
    let sig2: FnDsaSignature = serde_json::from_str(&js).unwrap();
    assert_eq!(sig2.to_bytes(), sig.to_bytes());
    // Deserialization goes through from_bytes: a wrong size is refused.
    assert!(serde_json::from_str::<FnDsaSignature>(r#"{"data":[57]}"#).is_err());

    let d = DomainSeparation::Prehashed {
        alg: PreHashAlgorithm::Sha3_512,
        context: b"ctx",
    };
    // Borrowed byte slices serialize; deserializing them needs a format
    // with native byte strings (JSON has none), so only serialize here.
    let jd = serde_json::to_string(&d).unwrap();
    assert!(jd.contains("Sha3_512"));
    let je = serde_json::to_string(&FalconError::FaultDetected).unwrap();
    assert_eq!(
        serde_json::from_str::<FalconError>(&je).unwrap(),
        FalconError::FaultDetected
    );
}

/// A private key whose F is zeroed still decodes mod q (G = 0) and carries
/// a matching public-key hash, but is not an NTRU basis. It must be refused
/// at import: signing with it would never terminate.
#[test]
fn degenerate_private_key_is_refused() {
    let kp = kp(9);
    let mut sk = kp.private_key().to_vec();
    let flen = 512 * 6 / 8;
    let off = 1 + 2 * flen;
    sk[off..off + 512].fill(0);
    assert_eq!(
        FnDsaKeyPair::from_private_key(&sk).unwrap_err(),
        FalconError::FormatError
    );
    assert_eq!(
        FnDsaKeyPair::from_keys(&sk, kp.public_key()).unwrap_err(),
        FalconError::FormatError
    );
}
