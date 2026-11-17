//! Criterion benchmarks for the high-level API.
//!
//! `cargo bench` (native floating point) or `cargo bench --features fpemu`
//! (integer-only backend).

use criterion::{criterion_group, criterion_main, Criterion};
use falcon::safe_api::{DomainSeparation, FnDsaKeyPair, FnDsaSignature, PreHashAlgorithm};

fn bench_degree(c: &mut Criterion, logn: u32) {
    let name = if logn == 9 {
        "fn_dsa_512"
    } else {
        "fn_dsa_1024"
    };
    let msg = b"Benchmark message for FN-DSA";
    let kp = FnDsaKeyPair::generate_deterministic(b"bench-seed", logn).unwrap();
    let ek = kp.expand().unwrap();
    let ph = DomainSeparation::Prehashed {
        alg: PreHashAlgorithm::Sha256,
        context: b"bench",
    };

    c.bench_function(&format!("{name}_keygen"), |b| {
        b.iter(|| FnDsaKeyPair::generate_deterministic(b"bench-keygen", logn).unwrap())
    });
    c.bench_function(&format!("{name}_sign"), |b| {
        b.iter(|| kp.sign(msg, &DomainSeparation::None).unwrap())
    });
    c.bench_function(&format!("{name}_sign_prehashed"), |b| {
        b.iter(|| kp.sign(msg, &ph).unwrap())
    });
    c.bench_function(&format!("{name}_sign_expanded"), |b| {
        b.iter(|| ek.sign(msg, &DomainSeparation::None).unwrap())
    });
    let sig = kp.sign(msg, &DomainSeparation::None).unwrap();
    c.bench_function(&format!("{name}_verify"), |b| {
        b.iter(|| {
            FnDsaSignature::verify(
                sig.to_bytes(),
                kp.public_key(),
                msg,
                &DomainSeparation::None,
            )
            .unwrap()
        })
    });
}

fn bench_512(c: &mut Criterion) {
    bench_degree(c, 9);
}

fn bench_1024(c: &mut Criterion) {
    bench_degree(c, 10);
}

criterion_group!(benches, bench_512, bench_1024);
criterion_main!(benches);
