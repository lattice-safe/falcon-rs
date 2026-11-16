//! Test vectors from c-fn-dsa (github.com/pornin/c-fn-dsa), the reference
//! this port is migrating to.
//!
//! The fixtures under `tests/fixtures/c-fn-dsa/` are generated from the
//! pinned upstream `test_fndsa.c` by `scripts/c-fn-dsa/extract_vectors.sh`;
//! the pin is in `scripts/c-fn-dsa/UPSTREAM`. Each group of tests mirrors
//! the corresponding `test_*` function in the reference.
//!
//! Migration status: hashing (SHAKE256, SHA3) is ported and checked here.
//! The fixture-integrity test below also guards the vectors for the phases
//! not yet ported (verify, keygen, sampler, end-to-end KAT), so they cannot
//! drift or be truncated before the code that consumes them lands.

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
    assert_eq!(files, 19, "unexpected number of fixture files");

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
