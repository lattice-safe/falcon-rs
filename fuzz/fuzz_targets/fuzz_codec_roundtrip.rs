//! Fuzz target: the codecs that parse untrusted bytes.
//!
//! - trim_i8 (private-key f, g, F): encode -> decode round-trips, and
//!   decoding arbitrary bytes never panics.
//! - compressed (signature s2): decoding arbitrary bytes never panics,
//!   and whatever decodes re-encodes to the same canonical bytes.
//! - mod q (public key h): decoding arbitrary bytes never panics, and
//!   whatever decodes re-encodes to the same bytes.

#![no_main]
use falcon::fndsa::codec;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let n = 512usize;
    if data.len() < n {
        return;
    }

    // trim_i8 at 6 bits (FN-DSA-512 f, g): clamp into [-31, +31].
    let coeffs: Vec<i8> = data[..n].iter().map(|&b| (b as i8) % 32).collect();
    let mut enc = vec![0u8; n * 6 / 8];
    assert_eq!(codec::trim_i8_encode(&coeffs, 6, &mut enc), enc.len());
    let mut dec = vec![0i8; n];
    assert_eq!(codec::trim_i8_decode(&enc, &mut dec, 6), Some(enc.len()));
    assert_eq!(coeffs, dec);
    let _ = codec::trim_i8_decode(data, &mut dec, 6);

    // Compressed s2, as in a 666-byte signature (625 bytes after the
    // header and nonce).
    let body = &data[..data.len().min(625)];
    let mut s2 = vec![0i16; n];
    if codec::comp_decode(body, &mut s2) {
        let mut again = vec![0u8; body.len()];
        assert!(codec::comp_encode(&s2, &mut again));
        assert_eq!(&again[..], body);
    }

    // mod q public key body (896 bytes for n = 512).
    if data.len() >= 896 {
        let mut h = vec![0u16; n];
        if codec::modq_decode(&data[..896], &mut h).is_some() {
            let mut again = vec![0u8; 896];
            assert_eq!(codec::modq_encode(&h, &mut again), 896);
            assert_eq!(&again[..], &data[..896]);
        }
    }
});
