/// Performance benchmarks for FN-DSA keygen/sign/verify.
///
/// Run with: cargo test --release --test bench_falcon -- --ignored --nocapture
use falcon::shake::{i_shake256_flip, i_shake256_init, i_shake256_inject, InnerShake256Context};
use falcon::{
    falcon as falcon_api,
    prelude::{DomainSeparation, FnDsaKeyPair, FnDsaSignature, PreHashAlgorithm},
};

/// Benchmark helper: measure wall-clock time for `iterations` of `f`.
fn bench<F: FnMut()>(name: &str, mut f: F, iterations: u32) {
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed = start.elapsed();
    let per_op = elapsed / iterations;
    let ops_sec = if per_op.as_nanos() > 0 {
        1_000_000_000.0 / per_op.as_nanos() as f64
    } else {
        f64::INFINITY
    };
    println!(
        "  {:<25} {:>8} iterations  {:>10.3} ms/op  {:>10.1} ops/sec",
        name,
        iterations,
        per_op.as_secs_f64() * 1000.0,
        ops_sec,
    );
}

#[test]
#[ignore]
fn bench_falcon512() {
    let logn: u32 = 9;
    let sk_len = falcon_api::falcon_privkey_size(logn);
    let pk_len = falcon_api::falcon_pubkey_size(logn);
    let sig_max = falcon_api::falcon_sig_ct_size(logn);
    let tmp_kg = falcon_api::falcon_tmpsize_keygen(logn);
    let tmp_sd = falcon_api::falcon_tmpsize_signdyn(logn);
    let tmp_vv = falcon_api::falcon_tmpsize_verify(logn);
    let tmp_len = std::cmp::max(tmp_kg, std::cmp::max(tmp_sd, tmp_vv));

    let seed = b"Falcon-512 benchmark seed 2026!!";
    let mut rng = InnerShake256Context::new();
    i_shake256_init(&mut rng);
    i_shake256_inject(&mut rng, seed);
    i_shake256_flip(&mut rng);

    let mut privkey = vec![0u8; sk_len];
    let mut pubkey = vec![0u8; pk_len];
    let mut tmp = vec![0u8; tmp_len];

    println!("\n=== Falcon-512 (logn=9) Benchmarks ===\n");

    // Warm up + keygen
    bench(
        "keygen",
        || {
            let mut rng2 = InnerShake256Context::new();
            i_shake256_init(&mut rng2);
            i_shake256_inject(&mut rng2, seed);
            i_shake256_flip(&mut rng2);
            let rc = falcon_api::falcon_keygen_make(
                &mut rng2,
                logn,
                &mut privkey,
                Some(&mut pubkey),
                &mut tmp,
            );
            assert_eq!(rc, 0);
        },
        5,
    );

    // Generate a key for sign/verify benchmarks
    let mut rng2 = InnerShake256Context::new();
    i_shake256_init(&mut rng2);
    i_shake256_inject(&mut rng2, seed);
    i_shake256_flip(&mut rng2);
    let rc =
        falcon_api::falcon_keygen_make(&mut rng2, logn, &mut privkey, Some(&mut pubkey), &mut tmp);
    assert_eq!(rc, 0);

    let message = b"Benchmark message for Falcon-512 sign/verify performance testing.";
    let mut sig = vec![0u8; sig_max];
    let mut sig_len = sig_max;

    // Sign benchmark
    bench(
        "sign_dyn",
        || {
            sig_len = sig_max;
            let rc = falcon_api::falcon_sign_dyn(
                &mut rng,
                &mut sig,
                &mut sig_len,
                falcon_api::FALCON_SIG_CT,
                &privkey,
                message,
                &mut tmp,
            );
            assert_eq!(rc, 0);
        },
        50,
    );

    // Generate one real signature
    sig_len = sig_max;
    let rc = falcon_api::falcon_sign_dyn(
        &mut rng,
        &mut sig,
        &mut sig_len,
        falcon_api::FALCON_SIG_CT,
        &privkey,
        message,
        &mut tmp,
    );
    assert_eq!(rc, 0);
    let sig_bytes = sig[..sig_len].to_vec();

    // Verify benchmark
    bench(
        "verify",
        || {
            let rc = falcon_api::falcon_verify(
                &sig_bytes,
                falcon_api::FALCON_SIG_CT,
                &pubkey,
                message,
                &mut tmp,
            );
            assert_eq!(rc, 0);
        },
        200,
    );
}

#[test]
#[ignore]
fn bench_falcon1024() {
    let logn: u32 = 10;
    let sk_len = falcon_api::falcon_privkey_size(logn);
    let pk_len = falcon_api::falcon_pubkey_size(logn);
    let sig_max = falcon_api::falcon_sig_ct_size(logn);
    let tmp_kg = falcon_api::falcon_tmpsize_keygen(logn);
    let tmp_sd = falcon_api::falcon_tmpsize_signdyn(logn);
    let tmp_vv = falcon_api::falcon_tmpsize_verify(logn);
    let tmp_len = std::cmp::max(tmp_kg, std::cmp::max(tmp_sd, tmp_vv));

    let seed = b"Falcon-1024 bench seed 2026!!!!!";
    let mut rng = InnerShake256Context::new();
    i_shake256_init(&mut rng);
    i_shake256_inject(&mut rng, seed);
    i_shake256_flip(&mut rng);

    let mut privkey = vec![0u8; sk_len];
    let mut pubkey = vec![0u8; pk_len];
    let mut tmp = vec![0u8; tmp_len];

    println!("\n=== Falcon-1024 (logn=10) Benchmarks ===\n");

    bench(
        "keygen",
        || {
            let mut rng2 = InnerShake256Context::new();
            i_shake256_init(&mut rng2);
            i_shake256_inject(&mut rng2, seed);
            i_shake256_flip(&mut rng2);
            let rc = falcon_api::falcon_keygen_make(
                &mut rng2,
                logn,
                &mut privkey,
                Some(&mut pubkey),
                &mut tmp,
            );
            assert_eq!(rc, 0);
        },
        3,
    );

    let mut rng2 = InnerShake256Context::new();
    i_shake256_init(&mut rng2);
    i_shake256_inject(&mut rng2, seed);
    i_shake256_flip(&mut rng2);
    let rc =
        falcon_api::falcon_keygen_make(&mut rng2, logn, &mut privkey, Some(&mut pubkey), &mut tmp);
    assert_eq!(rc, 0);

    let message = b"Benchmark message for Falcon-1024 performance testing.";
    let mut sig = vec![0u8; sig_max];
    let mut sig_len = sig_max;

    bench(
        "sign_dyn",
        || {
            sig_len = sig_max;
            let rc = falcon_api::falcon_sign_dyn(
                &mut rng,
                &mut sig,
                &mut sig_len,
                falcon_api::FALCON_SIG_CT,
                &privkey,
                message,
                &mut tmp,
            );
            assert_eq!(rc, 0);
        },
        20,
    );

    sig_len = sig_max;
    let rc = falcon_api::falcon_sign_dyn(
        &mut rng,
        &mut sig,
        &mut sig_len,
        falcon_api::FALCON_SIG_CT,
        &privkey,
        message,
        &mut tmp,
    );
    assert_eq!(rc, 0);
    let sig_bytes = sig[..sig_len].to_vec();

    bench(
        "verify",
        || {
            let rc = falcon_api::falcon_verify(
                &sig_bytes,
                falcon_api::FALCON_SIG_CT,
                &pubkey,
                message,
                &mut tmp,
            );
            assert_eq!(rc, 0);
        },
        100,
    );
}

// ======================================================================
// Safe API benchmarks (FN-DSA-512)
// ======================================================================

#[test]
#[ignore]
fn bench_safe_api_512() {
    let kp = FnDsaKeyPair::generate_deterministic(b"bench-safe-seed-512", 9).unwrap();
    let msg = b"Benchmark message for safe API";

    println!("\n=== FN-DSA-512 safe_api Benchmarks ===\n");

    bench(
        "sign/None",
        || {
            kp.sign_deterministic(msg, b"seed", &DomainSeparation::None)
                .unwrap();
        },
        50,
    );

    bench(
        "sign/Context",
        || {
            kp.sign_deterministic(msg, b"seed", &DomainSeparation::Context(b"proto-v1"))
                .unwrap();
        },
        50,
    );

    bench(
        "sign/SHA-256",
        || {
            let ph = DomainSeparation::Prehashed {
                alg: PreHashAlgorithm::Sha256,
                context: b"",
            };
            kp.sign_deterministic(msg, b"seed", &ph).unwrap();
        },
        50,
    );

    bench(
        "sign/SHA-512",
        || {
            let ph = DomainSeparation::Prehashed {
                alg: PreHashAlgorithm::Sha512,
                context: b"",
            };
            kp.sign_deterministic(msg, b"seed", &ph).unwrap();
        },
        50,
    );

    let sig = kp
        .sign_deterministic(msg, b"seed", &DomainSeparation::None)
        .unwrap();
    let pk = kp.public_key().to_vec();
    bench(
        "verify/None",
        || {
            FnDsaSignature::verify(sig.to_bytes(), &pk, msg, &DomainSeparation::None).unwrap();
        },
        200,
    );

    let ph = DomainSeparation::Prehashed {
        alg: PreHashAlgorithm::Sha256,
        context: b"",
    };
    let sig256 = kp.sign_deterministic(msg, b"seed", &ph).unwrap();
    bench(
        "verify/SHA-256",
        || {
            FnDsaSignature::verify(sig256.to_bytes(), &pk, msg, &ph).unwrap();
        },
        200,
    );
}
