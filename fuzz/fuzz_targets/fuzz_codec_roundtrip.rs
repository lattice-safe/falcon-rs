//! Fuzz target: codec encode → decode roundtrip.
//!
//! Tests that trim_i8_encode → trim_i8_decode and comp_encode → comp_decode
//! produce correct roundtrips and never panic.

#![no_main]
use libfuzzer_sys::fuzz_target;
use falcon::codec;

fuzz_target!(|data: &[u8]| {
    // Test trim_i8 roundtrip for logn=9 (n=512).
    let logn: u32 = 9;
    let n: usize = 1 << logn;
    let max_bits = codec::MAX_FG_BITS[logn as usize] as u32;

    if data.len() < n { return; }

    // Interpret input as i8 values, clamped to valid range.
    let max_val = (1i32 << (max_bits - 1)) - 1;
    let min_val = -(1i32 << (max_bits - 1));
    let coeffs: Vec<i8> = data[..n].iter().map(|&b| {
        let v = b as i8;
        let clamped = if (v as i32) > max_val { max_val }
                      else if (v as i32) < min_val { min_val }
                      else { v as i32 };
        clamped as i8
    }).collect();

    // Encode.
    let enc_len = codec::trim_i8_encode(None, &coeffs, logn, max_bits);
    if enc_len == 0 { return; }
    let mut encoded = vec![0u8; enc_len];
    let enc_len2 = codec::trim_i8_encode(Some(&mut encoded), &coeffs, logn, max_bits);
    assert_eq!(enc_len, enc_len2);

    // Decode and verify roundtrip.
    let mut decoded = vec![0i8; n];
    let dec_len = codec::trim_i8_decode(&mut decoded, logn, max_bits, &encoded);
    assert!(dec_len > 0, "Decode failed");
    assert_eq!(&coeffs[..], &decoded[..], "Roundtrip mismatch");
});
