use criterion::{criterion_group, criterion_main, Criterion};

fn bench_falcon512(c: &mut Criterion) {
    let logn: u32 = 9;

    // Pre-generate a key pair for sign/verify benchmarks.
    let mut seed_sc = falcon::shake::InnerShake256Context::new();
    falcon::shake::i_shake256_init(&mut seed_sc);
    falcon::shake::i_shake256_inject(&mut seed_sc, b"bench-seed-512");
    falcon::shake::i_shake256_flip(&mut seed_sc);

    let sk_len = falcon::falcon::falcon_privkey_size(logn);
    let pk_len = falcon::falcon::falcon_pubkey_size(logn);
    let tmp_len = falcon::falcon::falcon_tmpsize_keygen(logn);

    let mut sk = vec![0u8; sk_len];
    let mut pk = vec![0u8; pk_len];
    let mut tmp = vec![0u8; tmp_len];

    falcon::falcon::falcon_keygen_make(&mut seed_sc, logn, &mut sk, Some(&mut pk), &mut tmp);

    let msg = b"Benchmark message for Falcon-512";

    // --- keygen ---
    c.bench_function("falcon512_keygen", |b| {
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

    // --- sign_dyn ---
    c.bench_function("falcon512_sign_dyn", |b| {
        let mut rng = falcon::shake::InnerShake256Context::new();
        falcon::shake::i_shake256_init(&mut rng);
        falcon::shake::i_shake256_inject(&mut rng, b"bench-sign-rng");
        falcon::shake::i_shake256_flip(&mut rng);

        let sig_max = falcon::falcon::falcon_sig_compressed_maxsize(logn);
        let tmp_sign = falcon::falcon::falcon_tmpsize_signdyn(logn);

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

    // --- verify ---
    // Pre-sign for verify bench.
    let sig_max = falcon::falcon::falcon_sig_compressed_maxsize(logn);
    let mut sig = vec![0u8; sig_max];
    let mut sig_len = sig_max;
    let mut rng = falcon::shake::InnerShake256Context::new();
    falcon::shake::i_shake256_init(&mut rng);
    falcon::shake::i_shake256_inject(&mut rng, b"bench-sign-for-verify");
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

    c.bench_function("falcon512_verify", |b| {
        let tmp_verify_len = falcon::falcon::falcon_tmpsize_verify(logn);
        b.iter(|| {
            let mut tmp2 = vec![0u8; tmp_verify_len];
            falcon::falcon::falcon_verify(&sig_bytes, 0, &pk, msg, &mut tmp2);
        });
    });
}

fn bench_falcon1024(c: &mut Criterion) {
    let logn: u32 = 10;

    let mut seed_sc = falcon::shake::InnerShake256Context::new();
    falcon::shake::i_shake256_init(&mut seed_sc);
    falcon::shake::i_shake256_inject(&mut seed_sc, b"bench-seed-1024");
    falcon::shake::i_shake256_flip(&mut seed_sc);

    let sk_len = falcon::falcon::falcon_privkey_size(logn);
    let pk_len = falcon::falcon::falcon_pubkey_size(logn);
    let tmp_len = falcon::falcon::falcon_tmpsize_keygen(logn);

    let mut sk = vec![0u8; sk_len];
    let mut pk = vec![0u8; pk_len];
    let mut tmp = vec![0u8; tmp_len];

    falcon::falcon::falcon_keygen_make(&mut seed_sc, logn, &mut sk, Some(&mut pk), &mut tmp);

    let msg = b"Benchmark message for Falcon-1024";

    // --- sign_dyn ---
    c.bench_function("falcon1024_sign_dyn", |b| {
        let mut rng = falcon::shake::InnerShake256Context::new();
        falcon::shake::i_shake256_init(&mut rng);
        falcon::shake::i_shake256_inject(&mut rng, b"bench-sign-rng-1024");
        falcon::shake::i_shake256_flip(&mut rng);

        let sig_max = falcon::falcon::falcon_sig_compressed_maxsize(logn);
        let tmp_sign = falcon::falcon::falcon_tmpsize_signdyn(logn);

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

    // --- verify ---
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

    c.bench_function("falcon1024_verify", |b| {
        let tmp_verify_len = falcon::falcon::falcon_tmpsize_verify(logn);
        b.iter(|| {
            let mut tmp2 = vec![0u8; tmp_verify_len];
            falcon::falcon::falcon_verify(&sig_bytes, 0, &pk, msg, &mut tmp2);
        });
    });
}

criterion_group!(benches, bench_falcon512, bench_falcon1024);
criterion_main!(benches);
