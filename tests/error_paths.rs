//! Rejection and error-path tests.
//!
//! The codec decoders are the crate's attack surface for untrusted bytes:
//! every one of them must reject malformed input by returning zero rather
//! than panicking, over-reading, or accepting a value the encoder could
//! never have produced. The encoders must likewise refuse to write past a
//! short buffer or to encode an out-of-range coefficient.
//!
//! These paths are unreachable through the high-level API — which is why
//! they need direct tests.

use falcon::{codec::*, prelude::*};

const LOGN: u32 = 9;
const N: usize = 1 << LOGN;

// ======================================================================
// modq (public key) codec
// ======================================================================

#[test]
fn modq_decode_rejects_trailing_garbage_bits() {
    let x: Vec<u16> = (0..N).map(|i| (i % 12289) as u16).collect();
    let mut buf = vec![0u8; modq_encode(None, &x, LOGN)];
    assert_ne!(modq_encode(Some(&mut buf), &x, LOGN), 0);

    let mut out = vec![0u16; N];
    assert_ne!(
        modq_decode(&mut out, LOGN, &buf),
        0,
        "clean input must decode"
    );
    assert_eq!(out, x);

    // Padding bits only exist when n * 14 is not a multiple of 8, which for
    // n = 512 it is. At logn = 1 the encoding ends mid-byte, and a decoder
    // that ignored the leftover bits would accept two encodings of one
    // value.
    let small: Vec<u16> = vec![1234, 5678];
    let mut sbuf = vec![0u8; modq_encode(None, &small, 1)];
    assert_ne!(modq_encode(Some(&mut sbuf), &small, 1), 0);
    let mut sout = vec![0u16; 2];
    assert_ne!(modq_decode(&mut sout, 1, &sbuf), 0);
    assert_eq!(sout, small);

    *sbuf.last_mut().unwrap() |= 1;
    assert_eq!(
        modq_decode(&mut sout, 1, &sbuf),
        0,
        "non-zero padding bits must be rejected"
    );

    // A destination buffer shorter than the encoding must be refused.
    let mut tiny = vec![0u8; 2];
    assert_eq!(modq_encode(Some(&mut tiny), &small, 1), 0);
}

#[test]
fn modq_decode_rejects_out_of_range_coefficient() {
    // 12289 and above are not valid residues mod q.
    let mut x = vec![0u16; N];
    x[0] = 12289;
    let mut buf = vec![0u8; 1024];
    // Encoding an out-of-range value must fail rather than wrap.
    assert_eq!(modq_encode(Some(&mut buf), &x, LOGN), 0);
}

#[test]
fn modq_decode_rejects_short_input() {
    let x = vec![1u16; N];
    let full = modq_encode(None, &x, LOGN);
    let mut buf = vec![0u8; full];
    modq_encode(Some(&mut buf), &x, LOGN);

    let mut out = vec![0u16; N];
    assert_eq!(modq_decode(&mut out, LOGN, &buf[..full - 1]), 0);
}

// ======================================================================
// trim_i16 (signature) codec
// ======================================================================

#[test]
fn trim_i16_encode_rejects_out_of_range_and_short_buffers() {
    let bits = 11u32;
    let mut x = vec![0i16; N];
    let len = trim_i16_encode(None, &x, LOGN, bits);
    assert_ne!(len, 0);

    // A coefficient outside +/-(2^(bits-1) - 1) has no encoding.
    x[3] = 1 << (bits - 1);
    assert_eq!(
        trim_i16_encode(None, &x, LOGN, bits),
        0,
        "positive overflow"
    );
    x[3] = -(1 << (bits - 1));
    assert_eq!(
        trim_i16_encode(None, &x, LOGN, bits),
        0,
        "negative overflow"
    );

    // A buffer one byte short must be refused, not overrun.
    x[3] = 0;
    let mut small = vec![0u8; len - 1];
    assert_eq!(trim_i16_encode(Some(&mut small), &x, LOGN, bits), 0);
}

#[test]
fn trim_i16_decode_rejects_forbidden_value_and_padding() {
    let bits = 11u32;
    let x: Vec<i16> = (0..N).map(|i| ((i % 512) as i16) - 256).collect();
    let mut buf = vec![0u8; trim_i16_encode(None, &x, LOGN, bits)];
    assert_ne!(trim_i16_encode(Some(&mut buf), &x, LOGN, bits), 0);

    let mut out = vec![0i16; N];
    assert_ne!(trim_i16_decode(&mut out, LOGN, bits, &buf), 0);
    assert_eq!(out, x);

    // Short input.
    assert_eq!(
        trim_i16_decode(&mut out, LOGN, bits, &buf[..buf.len() - 1]),
        0
    );

    // -2^(bits-1) is the one bit pattern the encoder never emits (it has no
    // positive counterpart), so the decoder must reject it. With bits = 11
    // that is the 11-bit pattern 100_0000_0000, i.e. 0x80 0x00.
    let mut forbidden = vec![0u8; buf.len()];
    forbidden[0] = 0x80;
    forbidden[1] = 0x00;
    assert_eq!(
        trim_i16_decode(&mut out, LOGN, bits, &forbidden),
        0,
        "the forbidden minimum must be rejected"
    );

    // Padding bits exist only at degrees where n * bits is not a multiple
    // of 8; at logn = 1 it is 22 bits, leaving two.
    let pair = [100i16, -100];
    let mut pbuf = vec![0u8; trim_i16_encode(None, &pair, 1, bits)];
    assert_ne!(trim_i16_encode(Some(&mut pbuf), &pair, 1, bits), 0);
    let mut pout = [0i16; 2];
    assert_ne!(trim_i16_decode(&mut pout, 1, bits, &pbuf), 0);
    assert_eq!(pout, pair);

    *pbuf.last_mut().unwrap() |= 1;
    assert_eq!(trim_i16_decode(&mut pout, 1, bits, &pbuf), 0);
}

// ======================================================================
// trim_i8 (private key) codec
// ======================================================================

#[test]
fn trim_i8_roundtrip_and_rejections() {
    let bits = 6u32;
    let x: Vec<i8> = (0..N).map(|i| ((i % 31) as i8) - 15).collect();
    let len = trim_i8_encode(None, &x, LOGN, bits);
    let mut buf = vec![0u8; len];
    assert_ne!(trim_i8_encode(Some(&mut buf), &x, LOGN, bits), 0);

    let mut out = vec![0i8; N];
    assert_ne!(trim_i8_decode(&mut out, LOGN, bits, &buf), 0);
    assert_eq!(out, x);

    let mut small = vec![0u8; len - 1];
    assert_eq!(trim_i8_encode(Some(&mut small), &x, LOGN, bits), 0);
    assert_eq!(trim_i8_decode(&mut out, LOGN, bits, &buf[..len - 1]), 0);

    // Padding bits: at logn = 1 the 6-bit packing leaves four spare bits in
    // the final byte, which must be zero.
    let pair = [5i8, -5];
    let mut pbuf = vec![0u8; trim_i8_encode(None, &pair, 1, bits)];
    assert_ne!(trim_i8_encode(Some(&mut pbuf), &pair, 1, bits), 0);
    let mut pout = [0i8; 2];
    assert_ne!(trim_i8_decode(&mut pout, 1, bits, &pbuf), 0);
    assert_eq!(pout, pair);

    *pbuf.last_mut().unwrap() |= 1;
    assert_eq!(trim_i8_decode(&mut pout, 1, bits, &pbuf), 0);

    // The forbidden -2^(bits-1) value, here -32 in six bits.
    let forbidden = [0b1000_0000u8, 0x00];
    assert_eq!(trim_i8_decode(&mut pout, 1, bits, &forbidden), 0);

    // Out-of-range coefficient for the given width.
    let mut bad = x.clone();
    bad[0] = 1 << (bits - 1);
    assert_eq!(trim_i8_encode(None, &bad, LOGN, bits), 0);
}

// ======================================================================
// Compressed signature codec
// ======================================================================

#[test]
fn comp_codec_roundtrip_and_rejections() {
    let x: Vec<i16> = (0..N).map(|i| ((i % 200) as i16) - 100).collect();
    let len = comp_encode(None, &x, LOGN);
    assert_ne!(len, 0);
    let mut buf = vec![0u8; len];
    assert_ne!(comp_encode(Some(&mut buf), &x, LOGN), 0);

    let mut out = vec![0i16; N];
    assert_ne!(comp_decode(&mut out, LOGN, &buf), 0);
    assert_eq!(out, x);

    // Too small an output buffer for the variable-length encoding.
    let mut small = vec![0u8; len / 2];
    assert_eq!(comp_encode(Some(&mut small), &x, LOGN), 0);

    // Truncated input: the decoder runs out of bits mid-coefficient.
    assert_eq!(comp_decode(&mut out, LOGN, &buf[..len / 2]), 0);

    // The unary high part terminates on a one bit, so an all-zero input is
    // an unterminated run: the magnitude must saturate and be rejected
    // rather than growing without bound.
    let zeros = vec![0u8; len];
    assert_eq!(
        comp_decode(&mut out, LOGN, &zeros),
        0,
        "an unterminated unary run must be rejected"
    );

    // Running out of input in the middle of that run is a separate path.
    assert_eq!(comp_decode(&mut out, LOGN, &[0u8, 0u8]), 0);

    // Not even one coefficient's worth of input.
    assert_eq!(comp_decode(&mut out, LOGN, &[]), 0);

    // "-0" has no encoding: sign set with a zero magnitude.
    assert_eq!(comp_decode(&mut out, LOGN, &[0x80, 0x80]), 0);

    // Non-zero bits after the last coefficient must be rejected.
    let mut tampered = buf.clone();
    *tampered.last_mut().unwrap() ^= 0x01;
    let rc = comp_decode(&mut out, LOGN, &tampered);
    assert!(
        rc == 0 || out != x,
        "tampered padding must not decode cleanly"
    );
}

// ======================================================================
// High-level API rejections
// ======================================================================

#[test]
fn safe_api_rejects_malformed_inputs() {
    let kp = FnDsaKeyPair::generate(LOGN).unwrap();
    let msg = b"error path message";
    let sig = kp.sign(msg, &DomainSeparation::None).unwrap();

    // Empty and truncated inputs.
    assert!(FnDsaSignature::verify(&[], kp.public_key(), msg, &DomainSeparation::None).is_err());
    assert!(FnDsaSignature::verify(sig.to_bytes(), &[], msg, &DomainSeparation::None).is_err());
    assert!(
        FnDsaSignature::verify(
            &sig.to_bytes()[..40],
            kp.public_key(),
            msg,
            &DomainSeparation::None
        )
        .is_err(),
        "a signature shorter than the 41-byte header must be refused"
    );

    // A signature longer than any valid format for this degree.
    let mut oversized = sig.to_bytes().to_vec();
    oversized.extend_from_slice(&[0u8; 4096]);
    assert!(
        FnDsaSignature::verify(&oversized, kp.public_key(), msg, &DomainSeparation::None).is_err()
    );

    // A public key whose header byte does not describe a public key.
    let mut bad_pk = kp.public_key().to_vec();
    bad_pk[0] = 0x50;
    assert!(FnDsaSignature::verify(sig.to_bytes(), &bad_pk, msg, &DomainSeparation::None).is_err());

    // Context strings are capped at 255 bytes by FIPS 206.
    let long = vec![0u8; 256];
    assert_eq!(
        kp.sign(msg, &DomainSeparation::Context(&long)).unwrap_err(),
        FalconError::BadArgument
    );
    assert_eq!(
        FnDsaSignature::verify(
            sig.to_bytes(),
            kp.public_key(),
            msg,
            &DomainSeparation::Context(&long)
        )
        .unwrap_err(),
        FalconError::BadArgument
    );
}

#[test]
fn key_import_rejects_malformed_bytes() {
    let kp = FnDsaKeyPair::generate(LOGN).unwrap();

    assert!(FnDsaKeyPair::from_keys(&[], kp.public_key()).is_err());
    assert!(FnDsaKeyPair::from_keys(kp.private_key(), &[]).is_err());
    assert!(FnDsaKeyPair::from_private_key(&[]).is_err());

    // Header nibble must mark the key kind.
    let mut bad_sk = kp.private_key().to_vec();
    bad_sk[0] = 0x00;
    assert!(FnDsaKeyPair::from_keys(&bad_sk, kp.public_key()).is_err());

    let mut bad_pk = kp.public_key().to_vec();
    bad_pk[0] = 0x50;
    assert!(FnDsaKeyPair::from_keys(kp.private_key(), &bad_pk).is_err());

    // Degree mismatch between the two halves.
    let other = FnDsaKeyPair::generate(10).unwrap();
    assert!(FnDsaKeyPair::from_keys(kp.private_key(), other.public_key()).is_err());

    // Truncated key bytes.
    assert!(FnDsaKeyPair::from_keys(&kp.private_key()[..10], kp.public_key()).is_err());
    assert!(FnDsaKeyPair::from_keys(kp.private_key(), &kp.public_key()[..10]).is_err());

    // Degrees outside FIPS 206 (only 9 and 10 are standardised).
    assert_eq!(
        FnDsaKeyPair::generate(8).unwrap_err(),
        FalconError::BadArgument
    );
    assert_eq!(
        FnDsaKeyPair::generate(11).unwrap_err(),
        FalconError::BadArgument
    );
}
