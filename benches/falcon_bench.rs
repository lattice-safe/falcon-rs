use criterion::{criterion_group, criterion_main, Criterion};
use falcon::safe_api::{DomainSeparation, FnDsaKeyPair, FnDsaSignature, PreHashAlgorithm};

// ======================================================================
// FN-DSA-512 (logn = 9)
// ======================================================================

fn bench_fn_dsa_512(c: &mut Criterion) {
    let logn: u32 = 9;
    let msg = b"Benchmark message for FN-DSA-512";
    let kp = FnDsaKeyPair::generate_deterministic(b"bench-seed-512", logn).unwrap();

    // --- Low-level keygen (raw API) ---
    {
        let sk_len = falcon::falcon::falcon_privkey_size(logn);
        let tmp_len = falcon::falcon::falcon_tmpsize_keygen(logn);
        c.bench_function("fn_dsa_512_keygen_ll", |b| {
            b.iter(|| {
                let mut sc = falcon::shake::InnerShake256Context::new();
                falcon::shake::i_shake256_init(&mut sc);
                falcon::shake::i_shake256_inject(&mut sc, b"bench-keygen");
                falcon::shake::i_shake256_flip(&mut sc);
                let mut sk2 = vec![0u8; sk_len];
                let mut tmp2 = vec![0u8; tmp_len];
                falcon::falcon::falcon_keygen_make(&mut sc, logn, &mut sk2, None, &mut tmp2);
            });
        });
    }

    // --- Safe-API keygen ---
    c.bench_function("fn_dsa_512_keygen", |b| {
        b.iter(|| {
            FnDsaKeyPair::generate_deterministic(b"bench-keygen-safe", logn).unwrap();
        });
    });

    // --- Safe-API sign (DomainSeparation::None) ---
    c.bench_function("fn_dsa_512_sign_none", |b| {
        b.iter(|| {
            kp.sign_deterministic(msg, b"bench-sign-seed", &DomainSeparation::None)
                .unwrap();
        });
    });

    // --- Safe-API sign (DomainSeparation::Context) ---
    c.bench_function("fn_dsa_512_sign_ctx", |b| {
        let ctx = DomainSeparation::Context(b"bench-protocol-v1");
        b.iter(|| {
            kp.sign_deterministic(msg, b"bench-sign-seed", &ctx)
                .unwrap();
        });
    });

    // --- Safe-API sign (HashFN-DSA SHA-256) ---
    c.bench_function("fn_dsa_512_sign_sha256", |b| {
        let ph = DomainSeparation::Prehashed {
            alg: PreHashAlgorithm::Sha256,
            context: b"",
        };
        b.iter(|| {
            kp.sign_deterministic(msg, b"bench-sign-seed", &ph).unwrap();
        });
    });

    // --- Safe-API sign (HashFN-DSA SHA-512) ---
    c.bench_function("fn_dsa_512_sign_sha512", |b| {
        let ph = DomainSeparation::Prehashed {
            alg: PreHashAlgorithm::Sha512,
            context: b"",
        };
        b.iter(|| {
            kp.sign_deterministic(msg, b"bench-sign-seed", &ph).unwrap();
        });
    });

    // --- Safe-API verify (DomainSeparation::None) ---
    {
        let sig = kp
            .sign_deterministic(msg, b"bench-verify-seed", &DomainSeparation::None)
            .unwrap();
        let pk_bytes = kp.public_key().to_vec();
        c.bench_function("fn_dsa_512_verify_none", |b| {
            b.iter(|| {
                FnDsaSignature::verify(sig.to_bytes(), &pk_bytes, msg, &DomainSeparation::None)
                    .unwrap();
            });
        });
    }

    // --- Safe-API verify (HashFN-DSA SHA-256) ---
    {
        let ph = DomainSeparation::Prehashed {
            alg: PreHashAlgorithm::Sha256,
            context: b"",
        };
        let sig = kp
            .sign_deterministic(msg, b"bench-verify-seed-ph", &ph)
            .unwrap();
        let pk_bytes = kp.public_key().to_vec();
        c.bench_function("fn_dsa_512_verify_sha256", |b| {
            b.iter(|| {
                FnDsaSignature::verify(sig.to_bytes(), &pk_bytes, msg, &ph).unwrap();
            });
        });
    }

    // --- Low-level sign_dyn (baseline) ---
    {
        let sk = kp.private_key().to_vec();
        let sig_max = falcon::falcon::falcon_sig_compressed_maxsize(logn);
        let tmp_sign = falcon::falcon::falcon_tmpsize_signdyn(logn);
        c.bench_function("fn_dsa_512_sign_dyn_ll", |b| {
            let mut rng = falcon::shake::InnerShake256Context::new();
            falcon::shake::i_shake256_init(&mut rng);
            falcon::shake::i_shake256_inject(&mut rng, b"bench-sign-rng");
            falcon::shake::i_shake256_flip(&mut rng);
            b.iter(|| {
                let mut sig = vec![0u8; sig_max];
                let mut sig_len = sig_max;
                let mut tmp2 = vec![0u8; tmp_sign];
                falcon::falcon::falcon_sign_dyn(
                    &mut rng,
                    &mut sig,
                    &mut sig_len,
                    falcon::falcon::FALCON_SIG_COMPRESSED,
                    &sk,
                    msg,
                    &mut tmp2,
                );
            });
        });
    }
}

// ======================================================================
// FN-DSA-1024 (logn = 10)
// ======================================================================

fn bench_fn_dsa_1024(c: &mut Criterion) {
    let logn: u32 = 10;
    let msg = b"Benchmark message for FN-DSA-1024";
    let kp = FnDsaKeyPair::generate_deterministic(b"bench-seed-1024", logn).unwrap();

    // --- Safe-API keygen ---
    c.bench_function("fn_dsa_1024_keygen", |b| {
        b.iter(|| {
            FnDsaKeyPair::generate_deterministic(b"bench-keygen-1024-safe", logn).unwrap();
        });
    });

    // --- Safe-API sign (DomainSeparation::None) ---
    c.bench_function("fn_dsa_1024_sign_none", |b| {
        b.iter(|| {
            kp.sign_deterministic(msg, b"bench-sign-seed-1024", &DomainSeparation::None)
                .unwrap();
        });
    });

    // --- Safe-API sign (HashFN-DSA SHA-512) ---
    c.bench_function("fn_dsa_1024_sign_sha512", |b| {
        let ph = DomainSeparation::Prehashed {
            alg: PreHashAlgorithm::Sha512,
            context: b"",
        };
        b.iter(|| {
            kp.sign_deterministic(msg, b"bench-sign-seed-1024", &ph)
                .unwrap();
        });
    });

    // --- Safe-API verify (DomainSeparation::None) ---
    {
        let sig = kp
            .sign_deterministic(msg, b"bench-verify-seed-1024", &DomainSeparation::None)
            .unwrap();
        let pk_bytes = kp.public_key().to_vec();
        c.bench_function("fn_dsa_1024_verify_none", |b| {
            b.iter(|| {
                FnDsaSignature::verify(sig.to_bytes(), &pk_bytes, msg, &DomainSeparation::None)
                    .unwrap();
            });
        });
    }

    // --- Low-level sign_dyn (baseline) ---
    {
        let sk = kp.private_key().to_vec();
        let sig_max = falcon::falcon::falcon_sig_compressed_maxsize(logn);
        let tmp_sign = falcon::falcon::falcon_tmpsize_signdyn(logn);
        c.bench_function("fn_dsa_1024_sign_dyn_ll", |b| {
            let mut rng = falcon::shake::InnerShake256Context::new();
            falcon::shake::i_shake256_init(&mut rng);
            falcon::shake::i_shake256_inject(&mut rng, b"bench-sign-rng-1024");
            falcon::shake::i_shake256_flip(&mut rng);
            b.iter(|| {
                let mut sig = vec![0u8; sig_max];
                let mut sig_len = sig_max;
                let mut tmp2 = vec![0u8; tmp_sign];
                falcon::falcon::falcon_sign_dyn(
                    &mut rng,
                    &mut sig,
                    &mut sig_len,
                    falcon::falcon::FALCON_SIG_COMPRESSED,
                    &sk,
                    msg,
                    &mut tmp2,
                );
            });
        });
    }

    // --- Low-level verify (baseline) ---
    {
        let sk = kp.private_key().to_vec();
        let pk = kp.public_key().to_vec();
        let sig_max = falcon::falcon::falcon_sig_compressed_maxsize(logn);
        let mut sig = vec![0u8; sig_max];
        let mut sig_len = sig_max;
        let mut rng = falcon::shake::InnerShake256Context::new();
        falcon::shake::i_shake256_init(&mut rng);
        falcon::shake::i_shake256_inject(&mut rng, b"bench-sign-for-verify-1024");
        falcon::shake::i_shake256_flip(&mut rng);
        let mut tmp_sign = vec![0u8; falcon::falcon::falcon_tmpsize_signdyn(logn)];
        falcon::falcon::falcon_sign_dyn(
            &mut rng,
            &mut sig,
            &mut sig_len,
            falcon::falcon::FALCON_SIG_COMPRESSED,
            &sk,
            msg,
            &mut tmp_sign,
        );
        let sig_bytes = sig[..sig_len].to_vec();
        c.bench_function("fn_dsa_1024_verify_ll", |b| {
            let tmp_verify_len = falcon::falcon::falcon_tmpsize_verify(logn);
            b.iter(|| {
                let mut tmp2 = vec![0u8; tmp_verify_len];
                falcon::falcon::falcon_verify(&sig_bytes, 0, &pk, msg, &mut tmp2);
            });
        });
    }
}

criterion_group!(
    benches,
    bench_fn_dsa_512,
    bench_fn_dsa_1024,
    bench_expanded_key
);
criterion_main!(benches);

fn bench_expanded_key(c: &mut Criterion) {
    use falcon::safe_api::{DomainSeparation, FnDsaKeyPair, FnDsaSignature};
    let msg = b"Benchmark message for expanded key";
    let kp = FnDsaKeyPair::generate_deterministic(b"bench-seed-ek", 9).unwrap();

    c.bench_function("fn_dsa_512_expand", |b| {
        b.iter(|| {
            kp.expand().unwrap();
        });
    });

    let ek = kp.expand().unwrap();
    c.bench_function("fn_dsa_512_sign_expanded", |b| {
        b.iter(|| {
            ek.sign_deterministic(msg, b"seed", &DomainSeparation::None)
                .unwrap();
        });
    });

    let sig = ek
        .sign_deterministic(msg, b"seed", &DomainSeparation::None)
        .unwrap();
    let pk = ek.public_key().to_vec();
    c.bench_function("fn_dsa_512_verify_expanded", |b| {
        b.iter(|| {
            FnDsaSignature::verify(sig.to_bytes(), &pk, msg, &DomainSeparation::None).unwrap();
        });
    });
}
