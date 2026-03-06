/// Known-Answer Tests for the Falcon Rust port.
///
/// Tests SHAKE256 KAT, codec round-trips, public key computation with known vectors,
/// and a full sign-verify round trip at degree 16 (logn=4).
use falcon::shake::{
    i_shake256_extract, i_shake256_flip, i_shake256_init, i_shake256_inject, InnerShake256Context,
};
use falcon::{codec, common, falcon as falcon_api, fft, fpr::*, sign, vrfy};

// ======================================================================
// Helper: hex string → bytes
// ======================================================================

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let s = s.replace(' ', "");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ======================================================================
// Test 1: SHAKE256 KAT
// ======================================================================

#[test]
fn test_shake256_kat_empty() {
    let expected = hex_to_bytes("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");
    let mut sc = InnerShake256Context::new();
    i_shake256_init(&mut sc);
    i_shake256_flip(&mut sc);
    let mut out = vec![0u8; expected.len()];
    i_shake256_extract(&mut sc, &mut out);
    assert_eq!(out, expected, "SHAKE256 KAT (empty input)");
}

#[test]
fn test_shake256_kat_short() {
    let input = hex_to_bytes("8d8001e2c096f1b88e7c9224a086efd4797fbf74a8033a2d422a2b6b8f6747e4");
    let expected = hex_to_bytes(
        "2e975f6a8a14f0704d51b13667d8195c219f71e6345696c49fa4b9d08e9225d3\
         d39393425152c97e71dd24601c11abcfa0f12f53c680bd3ae757b8134a9c10d42\
         9615869217fdd5885c4db174985703a6d6de94a667eac3023443a8337ae1bc601\
         b76d7d38ec3c34463105f0d3949d78e562a039e4469548b609395de5a4fd43c46\
         ca9fd6ee29ada5efc07d84d553249450dab4a49c483ded250c9338f85cd937ae6\
         6bb436f3b4026e859fda1ca571432f3bfc09e7c03ca4d183b741111ca0483d0ed\
         abc03feb23b17ee48e844ba2408d9dcfd0139d2e8c7310125aee801c61ab7900d\
         1efc47c078281766f361c5e6111346235e1dc38325666c",
    );
    let mut sc = InnerShake256Context::new();
    i_shake256_init(&mut sc);
    i_shake256_inject(&mut sc, &input);
    i_shake256_flip(&mut sc);
    let mut out = vec![0u8; expected.len()];
    i_shake256_extract(&mut sc, &mut out);
    assert_eq!(out, expected, "SHAKE256 KAT (32-byte input)");
}

#[test]
fn test_shake256_incremental() {
    // Same test but inject byte-by-byte.
    let expected = hex_to_bytes("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");
    let mut sc = InnerShake256Context::new();
    i_shake256_init(&mut sc);
    // Empty input, no injection needed
    i_shake256_flip(&mut sc);
    // Extract byte by byte
    let mut out = vec![0u8; expected.len()];
    for i in 0..out.len() {
        i_shake256_extract(&mut sc, &mut out[i..i + 1]);
    }
    assert_eq!(out, expected, "SHAKE256 KAT (incremental extract)");
}

// ======================================================================
// Test 2: Codec round-trips
// ======================================================================

#[test]
fn test_modq_codec_roundtrip() {
    let logn: u32 = 4;
    let n: usize = 1 << logn;
    // Use known h values for degree-16
    let h: [u16; 16] = [
        7768, 1837, 4498, 1226, 9594, 8992, 2227, 6132, 2850, 7612, 4314, 3834, 2585, 3954, 6198,
        589,
    ];

    // Encode
    let enc_len = codec::modq_encode(None, &h, logn);
    assert!(enc_len > 0);
    let mut encoded = vec![0u8; enc_len];
    let written = codec::modq_encode(Some(&mut encoded), &h, logn);
    assert_eq!(written, enc_len);

    // Decode
    let mut decoded = [0u16; 16];
    let read = codec::modq_decode(&mut decoded, logn, &encoded);
    assert_eq!(read, enc_len);
    assert_eq!(&decoded[..n], &h[..n]);
}

#[test]
fn test_trim_i8_codec_roundtrip() {
    let logn: u32 = 4;
    let n: usize = 1 << logn;
    let f: [i8; 16] = [
        7, -7, 12, 18, 19, 6, 18, -18, 18, -17, -14, 51, 24, -17, 2, 31,
    ];
    let bits = codec::MAX_FG_BITS[logn as usize] as u32;

    let enc_len = codec::trim_i8_encode(None, &f, logn, bits);
    assert!(enc_len > 0);
    let mut encoded = vec![0u8; enc_len];
    codec::trim_i8_encode(Some(&mut encoded), &f, logn, bits);

    let mut decoded = [0i8; 16];
    let read = codec::trim_i8_decode(&mut decoded, logn, bits, &encoded);
    assert!(read > 0);
    assert_eq!(&decoded[..n], &f[..n]);
}

// ======================================================================
// Test 3: Public key computation from known f, g (degree 16)
// ======================================================================

#[test]
fn test_compute_public_degree16() {
    let logn: u32 = 4;
    let n: usize = 1 << logn;
    let f: [i8; 16] = [
        7, -7, 12, 18, 19, 6, 18, -18, 18, -17, -14, 51, 24, -17, 2, 31,
    ];
    let g: [i8; 16] = [
        -2, -35, 3, 28, -21, 10, 4, 20, 15, -28, 31, -26, 5, 33, 0, 5,
    ];
    let expected_h: [u16; 16] = [
        7768, 1837, 4498, 1226, 9594, 8992, 2227, 6132, 2850, 7612, 4314, 3834, 2585, 3954, 6198,
        589,
    ];

    let mut h = [0u16; 16];
    let mut tmp = vec![0u8; 4096];
    let ok = vrfy::compute_public(&mut h, &f, &g, logn, &mut tmp);
    assert!(ok, "compute_public should succeed");
    assert_eq!(&h[..n], &expected_h[..n], "Public key h mismatch");
}

// ======================================================================
// Test 4: Public key encoding matches known encoded key (degree 16)
// ======================================================================

#[test]
fn test_pubkey_encoding_degree16() {
    let logn: u32 = 4;
    let expected_hex = "04796072d46484ca95ea32022cd7f42c89dbc4368efa2864f7260d824d";
    let expected_bytes = hex_to_bytes(expected_hex);

    let h: [u16; 16] = [
        7768, 1837, 4498, 1226, 9594, 8992, 2227, 6132, 2850, 7612, 4314, 3834, 2585, 3954, 6198,
        589,
    ];

    // The encoded public key from C is: header byte (logn) + modq_encode(h)
    let mut encoded = vec![0u8; 256];
    encoded[0] = logn as u8;
    let v = codec::modq_encode(Some(&mut encoded[1..]), &h, logn);
    assert!(v > 0);
    let total_len = 1 + v;
    assert_eq!(
        &encoded[..total_len],
        &expected_bytes[..],
        "Encoded public key mismatch"
    );
}

// ======================================================================
// Test 5: complete_private recovers G from f, g, F (degree 16)
// ======================================================================

#[test]
fn test_complete_private_degree16() {
    let logn: u32 = 4;
    let n: usize = 1 << logn;
    let f: [i8; 16] = [
        7, -7, 12, 18, 19, 6, 18, -18, 18, -17, -14, 51, 24, -17, 2, 31,
    ];
    let g: [i8; 16] = [
        -2, -35, 3, 28, -21, 10, 4, 20, 15, -28, 31, -26, 5, 33, 0, 5,
    ];
    let big_f: [i8; 16] = [
        16, 65, -6, 15, 26, -10, 14, -9, 22, 48, 26, -14, 15, 21, -23, 4,
    ];
    let expected_g: [i8; 16] = [
        37, -57, 27, 31, -45, -49, -11, 46, -14, 26, 0, 3, -33, -33, -3, 54,
    ];

    let mut big_g = [0i8; 16];
    let mut tmp = vec![0u8; 8192];
    let ok = vrfy::complete_private(&mut big_g, &f, &g, &big_f, logn, &mut tmp);
    assert!(ok, "complete_private should succeed");
    assert_eq!(&big_g[..n], &expected_g[..n], "Recovered G mismatch");
}

// ======================================================================
// Test 6: Hash-to-point produces consistent output
// ======================================================================

#[test]
fn test_hash_to_point_vartime() {
    let logn: u32 = 4;
    let n: usize = 1 << logn;
    let msg = b"test message for Falcon";
    let nonce = [0x42u8; 40];

    let mut sc = InnerShake256Context::new();
    i_shake256_init(&mut sc);
    i_shake256_inject(&mut sc, &nonce);
    i_shake256_inject(&mut sc, msg);
    i_shake256_flip(&mut sc);

    let mut hm = vec![0u16; n];
    common::hash_to_point_vartime(&mut sc, &mut hm, logn);

    // Verify all values are < 12289
    for (u, &val) in hm.iter().enumerate().take(n) {
        assert!(
            val < 12289,
            "hash_to_point produced value {} >= q at index {}",
            val,
            u
        );
    }

    // Verify it's reproducible with same input
    let mut sc2 = InnerShake256Context::new();
    i_shake256_init(&mut sc2);
    i_shake256_inject(&mut sc2, &nonce);
    i_shake256_inject(&mut sc2, msg);
    i_shake256_flip(&mut sc2);

    let mut hm2 = vec![0u16; n];
    common::hash_to_point_vartime(&mut sc2, &mut hm2, logn);
    assert_eq!(hm, hm2, "hash_to_point should be deterministic");
}

// ======================================================================
// Test 7: Verify known signature (degree 16, using known key vectors)
// ======================================================================

#[test]
fn test_verify_with_known_key_degree16() {
    let logn: u32 = 4;
    let n: usize = 1 << logn;

    let f: [i8; 16] = [
        7, -7, 12, 18, 19, 6, 18, -18, 18, -17, -14, 51, 24, -17, 2, 31,
    ];
    let g: [i8; 16] = [
        -2, -35, 3, 28, -21, 10, 4, 20, 15, -28, 31, -26, 5, 33, 0, 5,
    ];
    let big_f: [i8; 16] = [
        16, 65, -6, 15, 26, -10, 14, -9, 22, 48, 26, -14, 15, 21, -23, 4,
    ];
    let big_g: [i8; 16] = [
        37, -57, 27, 31, -45, -49, -11, 46, -14, 26, 0, 3, -33, -33, -3, 54,
    ];

    let mut h: [u16; 16] = [
        7768, 1837, 4498, 1226, 9594, 8992, 2227, 6132, 2850, 7612, 4314, 3834, 2585, 3954, 6198,
        589,
    ];

    // Create a deterministic hash for signing
    let nonce = [0xABu8; 40];
    let msg = b"Falcon degree-16 test message";

    let mut sc = InnerShake256Context::new();
    i_shake256_init(&mut sc);
    i_shake256_inject(&mut sc, &nonce);
    i_shake256_inject(&mut sc, msg);
    i_shake256_flip(&mut sc);

    let mut hm = vec![0u16; n];
    common::hash_to_point_vartime(&mut sc, &mut hm, logn);

    // Create a deterministic RNG for signing
    let seed = [0x01u8; 48];
    let mut rng = InnerShake256Context::new();
    i_shake256_init(&mut rng);
    i_shake256_inject(&mut rng, &seed);
    i_shake256_flip(&mut rng);

    // Sign using sign_dyn
    let mut sv = vec![0i16; n];
    let mut tmp = vec![0u8; 78 * n + 64];
    sign::sign_dyn(
        &mut sv, &mut rng, &f, &g, &big_f, &big_g, &hm, logn, &mut tmp,
    );

    // Verify using verify_raw
    vrfy::to_ntt_monty(&mut h, logn);
    let mut verify_tmp = vec![0u8; 8 * n + 8];
    let ok = vrfy::verify_raw(&hm, &sv, &h, logn, &mut verify_tmp);
    assert!(
        ok,
        "Signature verification should succeed for degree-16 known key"
    );
}

// ======================================================================
// Test 8: High-level API sign-verify round trip (degree 4, logn=2)
// ======================================================================

#[test]
fn test_falcon_api_size_functions() {
    // Verify size macros match expected values from the C table.
    assert_eq!(falcon_api::falcon_privkey_size(9), 1281); // Falcon-512
    assert_eq!(falcon_api::falcon_privkey_size(10), 2305); // Falcon-1024
    assert_eq!(falcon_api::falcon_pubkey_size(9), 897); // Falcon-512
    assert_eq!(falcon_api::falcon_pubkey_size(10), 1793); // Falcon-1024

    assert_eq!(falcon_api::falcon_tmpsize_keygen(9), 15879);
    assert_eq!(falcon_api::falcon_tmpsize_signdyn(9), 39943);
    assert_eq!(falcon_api::falcon_tmpsize_signtree(9), 25607);
    assert_eq!(falcon_api::falcon_tmpsize_verify(9), 4097);
}

// ======================================================================
// Test 9: FPR correctness
// ======================================================================

#[test]
fn test_fpr_basic_operations() {
    let a = fpr_of(42);
    let b = fpr_of(13);

    let sum = fpr_add(a, b);
    assert_eq!(fpr_rint(sum), 55);

    let diff = fpr_sub(a, b);
    assert_eq!(fpr_rint(diff), 29);

    let prod = fpr_mul(a, b);
    assert_eq!(fpr_rint(prod), 546);

    let half = fpr_half(a);
    assert_eq!(fpr_rint(half), 21);

    let dbl = fpr_double(a);
    assert_eq!(fpr_rint(dbl), 84);

    let neg = fpr_neg(a);
    assert_eq!(fpr_rint(neg), -42);

    assert_eq!(fpr_lt(a, b), 0);
    assert_eq!(fpr_lt(b, a), 1);
}

// ======================================================================
// Test 10: FFT round-trip
// ======================================================================

#[test]
fn test_fft_roundtrip() {
    let logn: u32 = 4;
    let n: usize = 1 << logn;

    // Create a polynomial with known coefficients
    let mut f = vec![FPR_ZERO; n];
    for (i, fi) in f.iter_mut().enumerate().take(n) {
        *fi = fpr_of(((i as i64 * 7 + 3) % 31) - 15);
    }
    let original = f.clone();

    // FFT then iFFT should give back the original
    fft::fft(&mut f, logn);
    fft::ifft(&mut f, logn);

    for i in 0..n {
        let diff = fpr_sub(f[i], original[i]);
        let diff_val = fpr_rint(diff);
        assert!(
            diff_val.abs() <= 1,
            "FFT round-trip mismatch at index {}: expected {}, got diff {}",
            i,
            fpr_rint(original[i]),
            diff_val
        );
    }
}

// ======================================================================
// Test 11: Poly operations consistency
// ======================================================================

#[test]
fn test_poly_add_sub() {
    let logn: u32 = 4;
    let n: usize = 1 << logn;

    let mut a = vec![FPR_ZERO; n];
    let mut b = vec![FPR_ZERO; n];
    for i in 0..n {
        a[i] = fpr_of(i as i64 + 1);
        b[i] = fpr_of(100 - i as i64);
    }

    let orig_a = a.clone();
    fft::poly_add(&mut a, &b, logn);
    fft::poly_sub(&mut a, &b, logn);

    // a + b - b should equal original a
    for i in 0..n {
        let diff = fpr_sub(a[i], orig_a[i]);
        assert!(
            fpr_rint(diff).abs() <= 1,
            "poly_add/sub round-trip error at {}",
            i
        );
    }
}

// ======================================================================
// Test 12: Full Falcon-512 key generation → sign → verify round trip
// ======================================================================

#[test]
fn test_falcon512_keygen_sign_verify() {
    let logn: u32 = 9; // Falcon-512

    // Buffer sizes from the API
    let sk_len = falcon_api::falcon_privkey_size(logn);
    let pk_len = falcon_api::falcon_pubkey_size(logn);
    let sig_max = falcon_api::falcon_sig_ct_size(logn);
    let tmp_kg = falcon_api::falcon_tmpsize_keygen(logn);
    let tmp_sd = falcon_api::falcon_tmpsize_signdyn(logn);
    let tmp_vv = falcon_api::falcon_tmpsize_verify(logn);

    // Create a deterministic RNG
    let seed = b"Falcon-512 keygen test seed 2026";
    let mut rng = InnerShake256Context::new();
    i_shake256_init(&mut rng);
    i_shake256_inject(&mut rng, seed);
    i_shake256_flip(&mut rng);

    // Key generation
    let mut privkey = vec![0u8; sk_len];
    let mut pubkey = vec![0u8; pk_len];
    let mut tmp = vec![0u8; std::cmp::max(tmp_kg, std::cmp::max(tmp_sd, tmp_vv))];

    let rc =
        falcon_api::falcon_keygen_make(&mut rng, logn, &mut privkey, Some(&mut pubkey), &mut tmp);
    assert_eq!(rc, 0, "falcon_keygen_make failed with error {}", rc);

    // Verify private key header
    assert_eq!(privkey[0], 0x50 + logn as u8, "Private key header mismatch");
    // Verify public key header
    assert_eq!(pubkey[0], logn as u8, "Public key header mismatch");

    // Sign a message
    let message = b"Hello, Falcon-512! Post-quantum signatures work!";
    let mut sig = vec![0u8; sig_max];
    let mut sig_len = sig_max;

    let rc = falcon_api::falcon_sign_dyn(
        &mut rng,
        &mut sig,
        &mut sig_len,
        falcon_api::FALCON_SIG_CT,
        &privkey,
        message,
        &mut tmp,
    );
    assert_eq!(rc, 0, "falcon_sign_dyn failed with error {}", rc);
    assert!(
        sig_len > 0 && sig_len <= sig_max,
        "Invalid signature length: {}",
        sig_len
    );

    // Verify the signature
    let rc = falcon_api::falcon_verify(
        &sig[..sig_len],
        falcon_api::FALCON_SIG_CT,
        &pubkey,
        message,
        &mut tmp,
    );
    assert_eq!(rc, 0, "falcon_verify failed with error {}", rc);

    // Verify that a corrupted signature fails
    let mut bad_sig = sig[..sig_len].to_vec();
    if sig_len > 2 {
        bad_sig[sig_len / 2] ^= 0xFF;
    }
    let rc = falcon_api::falcon_verify(
        &bad_sig,
        falcon_api::FALCON_SIG_CT,
        &pubkey,
        message,
        &mut tmp,
    );
    assert_ne!(rc, 0, "Corrupted signature should fail verification");

    // Verify that wrong message fails
    let wrong_message = b"This is a different message";
    let rc = falcon_api::falcon_verify(
        &sig[..sig_len],
        falcon_api::FALCON_SIG_CT,
        &pubkey,
        wrong_message,
        &mut tmp,
    );
    assert_ne!(rc, 0, "Wrong message should fail verification");
}

// ======================================================================
// Test 13: Full Falcon-1024 key generation → sign → verify round trip
// ======================================================================

#[test]
fn test_falcon1024_keygen_sign_verify() {
    let logn: u32 = 10; // Falcon-1024

    // Buffer sizes from the API
    let sk_len = falcon_api::falcon_privkey_size(logn);
    let pk_len = falcon_api::falcon_pubkey_size(logn);
    let sig_max = falcon_api::falcon_sig_ct_size(logn);
    let tmp_kg = falcon_api::falcon_tmpsize_keygen(logn);
    let tmp_sd = falcon_api::falcon_tmpsize_signdyn(logn);
    let tmp_vv = falcon_api::falcon_tmpsize_verify(logn);

    // Verify expected sizes for Falcon-1024
    assert_eq!(sk_len, 2305, "Falcon-1024 private key size");
    assert_eq!(pk_len, 1793, "Falcon-1024 public key size");

    // Create a deterministic RNG
    let seed = b"Falcon-1024 keygen test seed 026";
    let mut rng = InnerShake256Context::new();
    i_shake256_init(&mut rng);
    i_shake256_inject(&mut rng, seed);
    i_shake256_flip(&mut rng);

    // Key generation
    let mut privkey = vec![0u8; sk_len];
    let mut pubkey = vec![0u8; pk_len];
    let mut tmp = vec![0u8; std::cmp::max(tmp_kg, std::cmp::max(tmp_sd, tmp_vv))];

    let rc =
        falcon_api::falcon_keygen_make(&mut rng, logn, &mut privkey, Some(&mut pubkey), &mut tmp);
    assert_eq!(rc, 0, "falcon_keygen_make (1024) failed with error {}", rc);

    // Verify private key header
    assert_eq!(
        privkey[0],
        0x50 + logn as u8,
        "Private key header mismatch (1024)"
    );
    // Verify public key header
    assert_eq!(pubkey[0], logn as u8, "Public key header mismatch (1024)");

    // Sign a message
    let message = b"Hello, Falcon-1024! Post-quantum signatures at max degree!";
    let mut sig = vec![0u8; sig_max];
    let mut sig_len = sig_max;

    let rc = falcon_api::falcon_sign_dyn(
        &mut rng,
        &mut sig,
        &mut sig_len,
        falcon_api::FALCON_SIG_CT,
        &privkey,
        message,
        &mut tmp,
    );
    assert_eq!(rc, 0, "falcon_sign_dyn (1024) failed with error {}", rc);
    assert!(
        sig_len > 0 && sig_len <= sig_max,
        "Invalid signature length (1024): {}",
        sig_len
    );

    // Verify the signature
    let rc = falcon_api::falcon_verify(
        &sig[..sig_len],
        falcon_api::FALCON_SIG_CT,
        &pubkey,
        message,
        &mut tmp,
    );
    assert_eq!(rc, 0, "falcon_verify (1024) failed with error {}", rc);

    // Verify that a corrupted signature fails
    let mut bad_sig = sig[..sig_len].to_vec();
    if sig_len > 2 {
        bad_sig[sig_len / 2] ^= 0xFF;
    }
    let rc = falcon_api::falcon_verify(
        &bad_sig,
        falcon_api::FALCON_SIG_CT,
        &pubkey,
        message,
        &mut tmp,
    );
    assert_ne!(rc, 0, "Corrupted signature should fail verification (1024)");

    // Verify that wrong message fails
    let wrong_message = b"This is a different message";
    let rc = falcon_api::falcon_verify(
        &sig[..sig_len],
        falcon_api::FALCON_SIG_CT,
        &pubkey,
        wrong_message,
        &mut tmp,
    );
    assert_ne!(rc, 0, "Wrong message should fail verification (1024)");
}
