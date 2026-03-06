//! Property-based tests: for any (key_seed, message, domain) the sign→verify round-trip
//! must always succeed, and cross-domain verification must always fail.
//!
//! Run with: `cargo test --release --test prop_tests`

use falcon::prelude::*;
use proptest::prelude::*;

/// Generate an arbitrary domain separation value from a u8 seed.
fn arb_domain_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=255)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Property: sign then verify always succeeds (FN-DSA-512, None domain).
    #[test]
    fn prop_sign_verify_roundtrip_512(
        key_bytes  in prop::collection::vec(any::<u8>(), 32..=64),
        sign_bytes in prop::collection::vec(any::<u8>(), 16..=48),
        msg        in prop::collection::vec(any::<u8>(), 0..=512),
    ) {
        let kp = FnDsaKeyPair::generate_deterministic(&key_bytes, 9).unwrap();
        let sig = kp.sign_deterministic(&msg, &sign_bytes, &DomainSeparation::None).unwrap();
        prop_assert!(
            FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), &msg, &DomainSeparation::None).is_ok()
        );
    }

    /// Property: sign then verify always succeeds (FN-DSA-512, Context domain).
    #[test]
    fn prop_sign_verify_roundtrip_ctx(
        key_bytes   in prop::collection::vec(any::<u8>(), 32..=64),
        sign_bytes  in prop::collection::vec(any::<u8>(), 16..=48),
        msg         in prop::collection::vec(any::<u8>(), 0..=512),
        ctx_bytes   in arb_domain_bytes(),
    ) {
        // Context length must not exceed 255 bytes (FIPS 206 §6).
        prop_assume!(ctx_bytes.len() <= 255);
        let kp  = FnDsaKeyPair::generate_deterministic(&key_bytes, 9).unwrap();
        let dom = DomainSeparation::Context(ctx_bytes.as_slice());
        let sig = kp.sign_deterministic(&msg, &sign_bytes, &dom).unwrap();
        prop_assert!(
            FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), &msg, &dom).is_ok()
        );
    }

    /// Property: a signature under one domain never verifies under a different domain.
    #[test]
    fn prop_cross_domain_rejection(
        key_bytes  in prop::collection::vec(any::<u8>(), 32..=64),
        sign_bytes in prop::collection::vec(any::<u8>(), 16..=48),
        msg        in prop::collection::vec(any::<u8>(), 1..=256),
    ) {
        let kp   = FnDsaKeyPair::generate_deterministic(&key_bytes, 9).unwrap();
        let sig  = kp.sign_deterministic(&msg, &sign_bytes, &DomainSeparation::None).unwrap();
        let other = DomainSeparation::Context(b"other-protocol");
        prop_assert!(
            FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), &msg, &other).is_err()
        );
    }

    /// Property: a wrong message is always rejected.
    #[test]
    fn prop_wrong_message_rejected(
        key_bytes  in prop::collection::vec(any::<u8>(), 32..=64),
        sign_bytes in prop::collection::vec(any::<u8>(), 16..=48),
        msg        in prop::collection::vec(any::<u8>(), 1..=256),
        extra_byte in any::<u8>(),
    ) {
        let kp   = FnDsaKeyPair::generate_deterministic(&key_bytes, 9).unwrap();
        let sig  = kp.sign_deterministic(&msg, &sign_bytes, &DomainSeparation::None).unwrap();
        // Append one byte to the message — must not verify.
        let mut wrong = msg.clone();
        wrong.push(extra_byte);
        prop_assert!(
            FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), &wrong, &DomainSeparation::None).is_err()
        );
    }

    /// Property: expanded-key sign gives a verifiable signature.
    #[test]
    fn prop_expanded_key_sign_verify(
        key_bytes  in prop::collection::vec(any::<u8>(), 32..=64),
        sign_bytes in prop::collection::vec(any::<u8>(), 16..=48),
        msg        in prop::collection::vec(any::<u8>(), 0..=256),
    ) {
        let kp = FnDsaKeyPair::generate_deterministic(&key_bytes, 9).unwrap();
        let ek = kp.expand().unwrap();
        let sig = ek.sign_deterministic(&msg, &sign_bytes, &DomainSeparation::None).unwrap();
        prop_assert!(
            FnDsaSignature::verify(sig.to_bytes(), ek.public_key(), &msg, &DomainSeparation::None).is_ok()
        );
    }

    /// Property: context strings > 255 bytes always return BadArgument.
    #[test]
    fn prop_context_too_long_rejected(
        key_bytes  in prop::collection::vec(any::<u8>(), 32..=64),
        sign_bytes in prop::collection::vec(any::<u8>(), 16..=32),
        msg        in prop::collection::vec(any::<u8>(), 1..=64),
        ctx_len    in 256usize..=512,
    ) {
        let kp  = FnDsaKeyPair::generate_deterministic(&key_bytes, 9).unwrap();
        let ctx = vec![0u8; ctx_len];
        let dom = DomainSeparation::Context(ctx.as_slice());
        prop_assert_eq!(
            kp.sign_deterministic(&msg, &sign_bytes, &dom).unwrap_err(),
            FalconError::BadArgument
        );
    }
}
