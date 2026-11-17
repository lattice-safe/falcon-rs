//! Test vectors from c-fn-dsa (github.com/pornin/c-fn-dsa), the reference
//! this port is migrating to.
//!
//! The fixtures under `tests/fixtures/c-fn-dsa/` are generated from the
//! pinned upstream `test_fndsa.c` by `scripts/c-fn-dsa/extract_vectors.sh`;
//! the pin is in `scripts/c-fn-dsa/UPSTREAM`. Each group of tests mirrors
//! the corresponding `test_*` function in the reference.
//!
//! The fixture-integrity test below also guards the vectors for phases not
//! yet ported, so they cannot drift or be truncated before the code that
//! consumes them lands.

use falcon::{
    sha3::Sha3Context,
    shake::{
        i_shake256_extract, i_shake256_flip, i_shake256_init, i_shake256_inject,
        InnerShake256Context,
    },
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/c-fn-dsa");

fn read_fixture(name: &str) -> String {
    let path = format!("{FIXTURES}/{name}");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"))
}

/// Non-comment, non-empty lines.
fn data_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
        .collect()
}

/// `<hex>:<hex>` pairs.
fn hex_pairs(name: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    data_lines(&read_fixture(name))
        .map(|l| {
            let (a, b) = l.split_once(':').expect("expected <in>:<out>");
            (unhex(a), unhex(b))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// SHAKE256 — mirrors test_SHAKE256: one-shot, byte-at-a-time, and 17-byte
// chunks, for both absorbing and squeezing.
// ---------------------------------------------------------------------------

fn shake256_chunked(input: &[u8], out_len: usize, chunk: usize) -> Vec<u8> {
    let mut sc = InnerShake256Context::new();
    i_shake256_init(&mut sc);
    for c in input.chunks(chunk) {
        i_shake256_inject(&mut sc, c);
    }
    i_shake256_flip(&mut sc);
    let mut out = vec![0u8; out_len];
    for c in out.chunks_mut(chunk) {
        i_shake256_extract(&mut sc, c);
    }
    out
}

#[test]
fn shake256_vectors() {
    let vectors = hex_pairs("shake256.txt");
    assert_eq!(vectors.len(), 3);
    for (i, (input, expected)) in vectors.iter().enumerate() {
        // usize::MAX chunk = one call; 1 = byte at a time; 17 = odd chunks.
        for chunk in [usize::MAX, 1, 17] {
            let chunk = chunk.min(input.len().max(expected.len()).max(1));
            assert_eq!(
                &shake256_chunked(input, expected.len(), chunk),
                expected,
                "SHAKE256 vector {i}, chunk size {chunk}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// SHA3 — mirrors test_SHA3: the digest length selects the variant; each
// vector is checked one-shot, byte-at-a-time and in odd-size chunks.
// ---------------------------------------------------------------------------

fn sha3_chunked(bits: usize, input: &[u8], chunk: usize) -> Vec<u8> {
    let mut sc = Sha3Context::new(bits);
    for c in input.chunks(chunk) {
        sc.update(c);
    }
    let mut out = vec![0u8; sc.output_len()];
    sc.finalize_into(&mut out);
    out
}

#[test]
fn sha3_vectors() {
    let vectors = hex_pairs("sha3.txt");
    let mut per_size = [0usize; 4];
    for (i, (input, expected)) in vectors.iter().enumerate() {
        let bits = expected.len() * 8;
        per_size[match bits {
            224 => 0,
            256 => 1,
            384 => 2,
            512 => 3,
            _ => panic!("vector {i}: unexpected digest size {bits}"),
        }] += 1;
        for chunk in [usize::MAX, 1, 17, 136] {
            let chunk = chunk.min(input.len().max(1));
            assert_eq!(
                &sha3_chunked(bits, input, chunk),
                expected,
                "SHA3-{bits} vector {i} (input {} bytes), chunk size {chunk}",
                input.len()
            );
        }
    }
    // Every variant must actually be exercised.
    assert!(
        per_size.iter().all(|&n| n > 0),
        "per-size counts: {per_size:?}"
    );
}

// ---------------------------------------------------------------------------
// Fixture integrity for the phases not yet ported.
// ---------------------------------------------------------------------------

/// FN-DSA verifying-key and signature sizes from fndsa.h.
fn vrfy_key_size(logn: u32) -> usize {
    1 + (7 << (logn - 2))
}
fn signature_size(logn: u32) -> usize {
    let l = 10 - logn;
    44 + 3 * (256 >> l) + 2 * (128 >> l) + 3 * (64 >> l) + 2 * (16 >> l)
        - 2 * (2 >> l)
        - 8 * (1 >> l)
}

#[test]
fn fixtures_are_complete() {
    // Every fixture names the same pinned upstream commit.
    let upstream = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/c-fn-dsa/UPSTREAM"
    ))
    .unwrap();
    let commit = upstream
        .lines()
        .find_map(|l| l.strip_prefix("commit="))
        .expect("no commit= line in UPSTREAM");
    let mut files = 0;
    for entry in std::fs::read_dir(FIXTURES).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains(commit),
            "{} was not generated from the pinned commit {commit}",
            path.display()
        );
        files += 1;
    }
    assert_eq!(files, 20, "unexpected number of fixture files");

    // End-to-end KAT: 10 SHA3-256 digests per degree, n = 4 .. 1024.
    for logn in 2..=10u32 {
        let lines: Vec<_> = data_lines(&read_fixture(&format!("kat_{}.txt", 1u32 << logn)))
            .map(unhex)
            .collect();
        assert_eq!(lines.len(), 10, "kat_{}", 1u32 << logn);
        assert!(lines.iter().all(|h| h.len() == 32));
    }

    // Keygen: 100 SHA-256 digests each for n = 256, 512, 1024.
    for n in [256, 512, 1024] {
        let lines: Vec<_> = data_lines(&read_fixture(&format!("keygen_{n}.txt")))
            .map(unhex)
            .collect();
        assert_eq!(lines.len(), 100, "keygen_{n}");
        assert!(lines.iter().all(|h| h.len() == 32));
    }

    // Verify vectors: sizes must match fndsa.h, and headers must encode logn.
    for logn in [9u32, 10] {
        let n = 1u32 << logn;
        let vk = unhex(
            data_lines(&read_fixture(&format!("verify_{n}_vk.hex")))
                .next()
                .unwrap(),
        );
        let sig = unhex(
            data_lines(&read_fixture(&format!("verify_{n}_sig.hex")))
                .next()
                .unwrap(),
        );
        assert_eq!(vk.len(), vrfy_key_size(logn), "verify_{n}_vk");
        assert_eq!(sig.len(), signature_size(logn), "verify_{n}_sig");
        assert_eq!(vk[0], logn as u8, "vk header");
        assert_eq!(sig[0], 0x30 + logn as u8, "sig header");
    }
    assert_eq!(signature_size(9), 666);
    assert_eq!(signature_size(10), 1280);

    // Sampler: 40-byte nonce, then (mu, 1/sigma, output) triples.
    let text = read_fixture("sampler_512.txt");
    let mut lines = data_lines(&text);
    assert!(lines.next().unwrap().starts_with("seed="));
    let nonce = lines.next().unwrap().strip_prefix("nonce=").unwrap();
    assert_eq!(unhex(nonce).len(), 40);
    let triples: Vec<_> = lines.collect();
    assert_eq!(triples.len(), 1024);
    for t in triples {
        let f: Vec<_> = t.split_whitespace().collect();
        assert_eq!(f.len(), 3, "bad sampler line: {t}");
        u64::from_str_radix(f[0], 16).unwrap();
        u64::from_str_radix(f[1], 16).unwrap();
        f[2].parse::<i32>().unwrap();
    }
}

// ---------------------------------------------------------------------------
// Verify — mirrors test_verify: the reference signatures verify (directly
// and through external mu), and flipping any single bit makes them fail.
// ---------------------------------------------------------------------------

use falcon::fndsa::{self, vrfy, HashId};

fn hex_fixture(name: &str) -> Vec<u8> {
    unhex(data_lines(&read_fixture(name)).next().unwrap())
}

#[test]
fn verify_vectors() {
    for n in [512, 1024] {
        let vk = hex_fixture(&format!("verify_{n}_vk.hex"));
        let mut sig = hex_fixture(&format!("verify_{n}_sig.hex"));

        assert!(
            vrfy::verify(&sig, &vk, b"context", HashId::Raw, b"message"),
            "n={n}"
        );

        let hvk = fndsa::hashed_vrfykey_from_vrfykey(&vk);
        let mu = fndsa::compute_mu(&hvk, b"context", HashId::Raw, b"message").unwrap();
        assert!(vrfy::verify(&sig, &vk, b"", HashId::ExternalMu, &mu));

        // Wrong message, context or mode.
        assert!(!vrfy::verify(
            &sig,
            &vk,
            b"context",
            HashId::Raw,
            b"messagf"
        ));
        assert!(!vrfy::verify(
            &sig,
            &vk,
            b"contexu",
            HashId::Raw,
            b"message"
        ));
        assert!(!vrfy::verify(
            &sig,
            &vk,
            b"context",
            fndsa::HASH_ID_SHA3_256,
            b"message"
        ));
        // Standard keys are refused by the weak-degree entry point.
        assert!(!vrfy::verify_weak(
            &sig,
            &vk,
            b"context",
            HashId::Raw,
            b"message"
        ));

        let key = vrfy::DecodedVrfyKey::decode(&vk, 9, 10).unwrap();
        for i in 0..sig.len() * 8 {
            sig[i >> 3] ^= 1 << (i & 7);
            assert!(!key.verify_mu(&sig, &mu), "n={n}: bit {i} flip accepted");
            sig[i >> 3] ^= 1 << (i & 7);
        }
        assert!(key.verify_mu(&sig, &mu));
    }
}

// ---------------------------------------------------------------------------
// Keygen — mirrors test_keygen_ref: seed "test<i>", digest
// SHA-256(f || g || F || G) over the int8 coefficients.
// ---------------------------------------------------------------------------

use falcon::fndsa::kgen;

fn keygen_digest(logn: u32, i: usize) -> Vec<u8> {
    let kp = kgen::keygen_polys(logn, format!("test{i}").as_bytes());
    let mut buf = Vec::new();
    for p in [&kp.f, &kp.g, &kp.F, &kp.G] {
        buf.extend(p.iter().map(|&x| x as u8));
    }
    falcon::safe_api::sha256_public(&buf).to_vec()
}

fn check_keygen(logn: u32, count: usize) {
    let n = 1usize << logn;
    let expected: Vec<_> = data_lines(&read_fixture(&format!("keygen_{n}.txt")))
        .map(unhex)
        .collect();
    for (i, want) in expected.iter().enumerate().take(count) {
        assert_eq!(&keygen_digest(logn, i), want, "keygen n={n} i={i}");
    }
}

#[test]
fn keygen_vectors_256() {
    check_keygen(8, 100);
}

#[test]
fn keygen_vectors_512() {
    check_keygen(9, 100);
}

#[test]
fn keygen_vectors_1024() {
    check_keygen(10, 100);
}

// ---------------------------------------------------------------------------
// Sampler — mirrors test_sampler.
// ---------------------------------------------------------------------------

use falcon::fndsa::sign;

#[test]
fn sampler_vectors() {
    let text = read_fixture("sampler_512.txt");
    let mut lines = data_lines(&text);
    let seed = unhex(lines.next().unwrap().strip_prefix("seed=").unwrap());
    let nonce = unhex(lines.next().unwrap().strip_prefix("nonce=").unwrap());
    let mut inputs = Vec::new();
    let mut want = Vec::new();
    for l in lines {
        let f: Vec<_> = l.split_whitespace().collect();
        inputs.push((
            u64::from_str_radix(f[0], 16).unwrap(),
            u64::from_str_radix(f[1], 16).unwrap(),
        ));
        want.push(f[2].parse::<i32>().unwrap());
    }
    let (got_nonce, got) = sign::sampler_test_vector(&seed, &inputs);
    assert_eq!(&got_nonce[..], &nonce[..]);
    assert_eq!(got, want);
}

// ---------------------------------------------------------------------------
// End-to-end KAT — mirrors test_kat (see the header of kat_*.txt).
// ---------------------------------------------------------------------------

use falcon::sha3::sha3_256;

fn kat_digest(logn: u32, j: u32) -> Vec<u8> {
    let mut seed = vec![logn as u8];
    seed.extend_from_slice(&j.to_le_bytes());
    let mut sh = falcon::shake::Shake256::new();
    sh.inject(&seed);
    sh.flip();
    let mut seed_kgen = [0u8; 32];
    let mut seed_sign = [0u8; 40];
    sh.extract(&mut seed_kgen);
    sh.extract(&mut seed_sign);

    let (sk, vk) = kgen::keygen_seeded(logn, &seed_kgen);
    let prehashed = sha3_256(b"message");
    let (id, msg): (HashId, &[u8]) = if j & 1 == 0 {
        (HashId::Raw, b"message")
    } else {
        (fndsa::HASH_ID_SHA3_256, &prehashed)
    };
    let (sig, ok) = if logn <= 8 {
        let sig = sign::sign_weak(&sk, b"domain", id, msg, &seed_sign).unwrap();
        let ok = vrfy::verify_weak(&sig, &vk, b"domain", id, msg);
        (sig, ok)
    } else {
        let sig = sign::sign(&sk, b"domain", id, msg, &seed_sign).unwrap();
        let ok = vrfy::verify(&sig, &vk, b"domain", id, msg);
        (sig, ok)
    };
    assert!(ok, "logn={logn} j={j}: own signature does not verify");
    assert_eq!(sig.len(), fndsa::signature_size(logn));

    let mut all = sk.to_vec();
    all.extend_from_slice(&vk);
    all.extend_from_slice(&sig);
    sha3_256(&all).to_vec()
}

#[test]
fn end_to_end_kat() {
    for logn in 2..=10u32 {
        let n = 1u32 << logn;
        let expected: Vec<_> = data_lines(&read_fixture(&format!("kat_{n}.txt")))
            .map(unhex)
            .collect();
        for (j, want) in expected.iter().enumerate() {
            assert_eq!(&kat_digest(logn, j as u32), want, "KAT n={n} j={j}");
        }
    }
}
