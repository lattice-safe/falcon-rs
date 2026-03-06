//! Fuzz target: sign → verify roundtrip.
//!
//! Uses fuzzer input as the message, signs it with a pre-generated key,
//! then verifies the signature.

#![no_main]
use libfuzzer_sys::fuzz_target;


fuzz_target!(|data: &[u8]| {
    // Use a fixed seed for deterministic keygen (avoids regenerating keys per input).
    let mut seed_sc = falcon::shake::InnerShake256Context::new();
    falcon::shake::i_shake256_init(&mut seed_sc);
    falcon::shake::i_shake256_inject(&mut seed_sc, b"fuzz-seed-sign-verify-512");
    falcon::shake::i_shake256_flip(&mut seed_sc);

    let logn = 9; // Falcon-512
    let sk_len = falcon::falcon::falcon_privkey_size(logn);
    let pk_len = falcon::falcon::falcon_pubkey_size(logn);
    let tmp_len = falcon::falcon::falcon_tmpsize_keygen(logn);

    let mut sk = vec![0u8; sk_len];
    let mut pk = vec![0u8; pk_len];
    let mut tmp = vec![0u8; tmp_len];

    let r = falcon::falcon::falcon_keygen_make(&mut seed_sc, logn, &mut sk, Some(&mut pk), &mut tmp);
    if r != 0 { return; }

    // Sign the fuzzed data.
    let sig_max = falcon::falcon::falcon_sig_compressed_maxsize(logn);
    let mut sig = vec![0u8; sig_max];
    let mut sig_len = sig_max;
    let mut rng = seed_sc.clone();
    falcon::shake::i_shake256_init(&mut rng);
    falcon::shake::i_shake256_inject(&mut rng, b"fuzz-rng-sign");
    falcon::shake::i_shake256_inject(&mut rng, data);
    falcon::shake::i_shake256_flip(&mut rng);

    let mut tmp2 = vec![0u8; falcon::falcon::falcon_tmpsize_signdyn(logn)];
    let r = falcon::falcon::falcon_sign_dyn(
        &mut rng, &mut sig, &mut sig_len,
        falcon::falcon::FALCON_SIG_COMPRESSED,
        &sk, data, &mut tmp2,
    );
    if r != 0 { return; }

    // Verify must succeed.
    let mut tmp3 = vec![0u8; falcon::falcon::falcon_tmpsize_verify(logn)];
    let r = falcon::falcon::falcon_verify(
        &sig[..sig_len], 0, &pk, data, &mut tmp3,
    );
    assert_eq!(r, 0, "Valid signature did not verify!");
});
