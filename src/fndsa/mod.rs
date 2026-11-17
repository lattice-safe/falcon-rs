//! FN-DSA core, ported from c-fn-dsa (github.com/pornin/c-fn-dsa).
//!
//! This is the v0.4 core that replaces the round-3 Falcon port. It follows
//! c-fn-dsa's best guess at the FIPS 206 draft: little-endian encodings,
//! public keys in NTT form, a 64-byte message representative `mu` that
//! binds the hashed public key, and an infinity-norm bound of 840. The Rust
//! structure follows Pornin's public-domain `rust-fn-dsa`, which reproduces
//! the same test vectors; only the portable scalar code paths are ported.
//!
//! Functions here mirror `fndsa.h` and work on encoded keys and signatures.
//! The high-level API lives in [`crate::safe_api`].

use crate::shake::Shake256;

pub mod codec;
pub mod mq;
pub mod vrfy;

/// `logn` for FN-DSA-512.
pub const LOGN_512: u32 = 9;
/// `logn` for FN-DSA-1024.
pub const LOGN_1024: u32 = 10;

/// Bits per coefficient of `f` and `g` in the signing-key encoding.
pub(crate) const fn nbits_fg(logn: u32) -> u32 {
    match logn {
        2..=5 => 8,
        6..=7 => 7,
        8..=9 => 6,
        _ => 5,
    }
}

/// Signing (private) key size in bytes, `2 <= logn <= 10`.
///
/// Layout: header byte, `f` and `g` (trimmed), `F` (8 bits each), then the
/// 64-byte SHAKE256 hash of the verifying key.
pub const fn sign_key_size(logn: u32) -> usize {
    65 + ((nbits_fg(logn) as usize) << (logn - 2)) + (1usize << logn)
}

/// Verifying (public) key size in bytes, `2 <= logn <= 10`.
pub const fn vrfy_key_size(logn: u32) -> usize {
    1 + (7 << (logn - 2))
}

/// Signature size in bytes, `2 <= logn <= 10`.
pub const fn signature_size(logn: u32) -> usize {
    44 + 3 * (256 >> (10 - logn))
        + 2 * (128 >> (10 - logn))
        + 3 * (64 >> (10 - logn))
        + 2 * (16 >> (10 - logn))
        - 2 * (2 >> (10 - logn))
        - 8 * (1 >> (10 - logn))
}

/// Identifies how the message input was pre-hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashId<'a> {
    /// Raw message, not pre-hashed.
    Raw,
    /// The input is already the 64-byte `mu` ("external mu").
    ExternalMu,
    /// Pre-hashed; the value is the DER encoding of the hash function's
    /// ASN.1 OBJECT IDENTIFIER (tag `0x06`, length, contents).
    Oid(&'a [u8]),
}

macro_rules! nist_hash_oid {
    ($name:ident, $last:expr, $doc:expr) => {
        #[doc = $doc]
        pub const $name: HashId<'static> = HashId::Oid(&[
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, $last,
        ]);
    };
}
nist_hash_oid!(HASH_ID_SHA256, 0x01, "SHA-256 (2.16.840.1.101.3.4.2.1)");
nist_hash_oid!(HASH_ID_SHA384, 0x02, "SHA-384 (2.16.840.1.101.3.4.2.2)");
nist_hash_oid!(HASH_ID_SHA512, 0x03, "SHA-512 (2.16.840.1.101.3.4.2.3)");
nist_hash_oid!(
    HASH_ID_SHA512_256,
    0x06,
    "SHA-512/256 (2.16.840.1.101.3.4.2.6)"
);
nist_hash_oid!(HASH_ID_SHA3_256, 0x08, "SHA3-256 (2.16.840.1.101.3.4.2.8)");
nist_hash_oid!(HASH_ID_SHA3_384, 0x09, "SHA3-384 (2.16.840.1.101.3.4.2.9)");
nist_hash_oid!(HASH_ID_SHA3_512, 0x0A, "SHA3-512 (2.16.840.1.101.3.4.2.10)");
nist_hash_oid!(HASH_ID_SHAKE128, 0x0B, "SHAKE128 (2.16.840.1.101.3.4.2.11)");
nist_hash_oid!(HASH_ID_SHAKE256, 0x0C, "SHAKE256 (2.16.840.1.101.3.4.2.12)");

/// SHAKE256-512 hash of an encoded verifying key; an input to `mu`.
pub fn hashed_vrfykey_from_vrfykey(vk: &[u8]) -> [u8; 64] {
    let mut r = [0u8; 64];
    let mut sh = Shake256::new();
    sh.inject(vk);
    sh.flip();
    sh.extract(&mut r);
    r
}

/// The verifying-key hash stored at the end of an encoded signing key, or
/// `None` if the key is too short to hold one.
pub fn hashed_vrfykey_from_signkey(sk: &[u8]) -> Option<[u8; 64]> {
    if sk.len() < 65 {
        return None;
    }
    let mut r = [0u8; 64];
    r.copy_from_slice(&sk[sk.len() - 64..]);
    Some(r)
}

/// Validate a DER OID identifier and return its total encoded length.
/// Mirrors `fndsa_compute_mu`: tag `0x06`, a short-form length (< 128),
/// and the contents must be present.
fn oid_len(oid: &[u8]) -> Option<usize> {
    if oid.len() < 2 || oid[0] != 0x06 || oid[1] > 127 {
        return None;
    }
    let len = 2 + oid[1] as usize;
    if oid.len() != len {
        return None;
    }
    Some(len)
}

/// Compute the message representative `mu` (64 bytes):
///
/// * raw:        `SHAKE256(hvk || 0x00 || len(ctx) || ctx || msg)`
/// * pre-hashed: `SHAKE256(hvk || 0x01 || len(ctx) || ctx || oid || hash)`
///
/// Returns `None` if `ctx` exceeds 255 bytes, the OID is malformed, or `id`
/// is [`HashId::ExternalMu`] (which has no `mu` to compute).
pub fn compute_mu(hvk: &[u8; 64], ctx: &[u8], id: HashId<'_>, hv: &[u8]) -> Option<[u8; 64]> {
    if ctx.len() > 255 {
        return None;
    }
    let (flag, oid): (u8, &[u8]) = match id {
        HashId::Raw => (0, &[]),
        HashId::Oid(o) => {
            oid_len(o)?;
            (1, o)
        }
        HashId::ExternalMu => return None,
    };
    let mut sh = Shake256::new();
    sh.inject(hvk);
    sh.inject(&[flag, ctx.len() as u8]);
    sh.inject(ctx);
    sh.inject(oid);
    sh.inject(hv);
    sh.flip();
    let mut mu = [0u8; 64];
    sh.extract(&mut mu);
    Some(mu)
}

/// Start a streamed raw-message `mu`: returns a SHAKE256 engine with
/// `hvk || 0x00 || len(ctx) || ctx` absorbed. Inject the message, flip,
/// and extract 64 bytes; use the result with [`HashId::ExternalMu`].
/// Returns `None` if `ctx` exceeds 255 bytes.
pub fn compute_mu_start(hvk: &[u8; 64], ctx: &[u8]) -> Option<Shake256> {
    if ctx.len() > 255 {
        return None;
    }
    let mut sh = Shake256::new();
    sh.inject(hvk);
    sh.inject(&[0, ctx.len() as u8]);
    sh.inject(ctx);
    Some(sh)
}

/// Resolve the `mu` used to sign or verify, honouring external mu.
pub(crate) fn resolve_mu(
    hvk: &[u8; 64],
    ctx: &[u8],
    id: HashId<'_>,
    hv: &[u8],
) -> Option<[u8; 64]> {
    match id {
        HashId::ExternalMu => <[u8; 64]>::try_from(hv).ok(),
        _ => compute_mu(hvk, ctx, id, hv),
    }
}

/// Hash `nonce || mu` to a polynomial with coefficients mod q = 12289
/// (external representation), filling all of `c`.
pub fn hash_to_point(nonce: &[u8; 40], mu: &[u8; 64], c: &mut [u16]) {
    let mut sh = Shake256::new();
    sh.inject(nonce);
    sh.inject(mu);
    sh.flip();
    let mut i = 0;
    while i < c.len() {
        let mut v = [0u8; 2];
        sh.extract(&mut v);
        let mut w = u16::from_le_bytes(v);
        // 61445 = 5 * 12289: rejection keeps the distribution uniform.
        if w < 61445 {
            while w >= 12289 {
                w -= 12289;
            }
            c[i] = w;
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_fndsa_h() {
        // (logn, sign key, verify key, signature)
        let table = [
            (2, 77, 8, 47),
            (3, 89, 15, 52),
            (4, 113, 29, 63),
            (5, 161, 57, 82),
            (6, 241, 113, 122),
            (7, 417, 225, 200),
            (8, 705, 449, 356),
            (9, 1345, 897, 666),
            (10, 2369, 1793, 1280),
        ];
        for (logn, sk, vk, sig) in table {
            assert_eq!(sign_key_size(logn), sk, "sk logn={logn}");
            assert_eq!(vrfy_key_size(logn), vk, "vk logn={logn}");
            assert_eq!(signature_size(logn), sig, "sig logn={logn}");
        }
    }

    #[test]
    fn oid_validation() {
        assert_eq!(oid_len(&[0x06, 0x01, 0x2A]), Some(3));
        assert_eq!(oid_len(&[0x06]), None);
        assert_eq!(oid_len(&[0x05, 0x01, 0x2A]), None);
        assert_eq!(oid_len(&[0x06, 0x80]), None);
        assert_eq!(oid_len(&[0x06, 0x02, 0x2A]), None);
    }

    #[test]
    fn mu_rules() {
        let hvk = [7u8; 64];
        assert!(compute_mu(&hvk, &[0u8; 256], HashId::Raw, b"m").is_none());
        assert!(compute_mu(&hvk, b"", HashId::ExternalMu, &[0u8; 64]).is_none());
        assert!(compute_mu(&hvk, b"", HashId::Oid(&[0x05, 0x00]), b"h").is_none());
        assert!(compute_mu_start(&hvk, &[0u8; 256]).is_none());

        // Raw and pre-hashed modes are domain-separated even for equal input.
        let raw = compute_mu(&hvk, b"c", HashId::Raw, b"x").unwrap();
        let pre = compute_mu(&hvk, b"c", HASH_ID_SHA256, b"x").unwrap();
        assert_ne!(raw, pre);

        // The streamed start matches the one-shot raw computation.
        let mut sh = compute_mu_start(&hvk, b"ctx").unwrap();
        sh.inject(b"mess");
        sh.inject(b"age");
        sh.flip();
        let mut mu = [0u8; 64];
        sh.extract(&mut mu);
        assert_eq!(
            mu,
            compute_mu(&hvk, b"ctx", HashId::Raw, b"message").unwrap()
        );

        // External mu passes through only at exactly 64 bytes.
        assert_eq!(resolve_mu(&hvk, b"", HashId::ExternalMu, &mu), Some(mu));
        assert!(resolve_mu(&hvk, b"", HashId::ExternalMu, &mu[..63]).is_none());
        assert_eq!(resolve_mu(&hvk, b"ctx", HashId::Raw, b"message"), Some(mu));
    }

    #[test]
    fn signkey_hash_slot() {
        assert!(hashed_vrfykey_from_signkey(&[0u8; 64]).is_none());
        let mut sk = [0u8; 70];
        sk[6..].copy_from_slice(&[9u8; 64]);
        assert_eq!(hashed_vrfykey_from_signkey(&sk), Some([9u8; 64]));
    }

    #[test]
    fn hash_to_point_is_reduced() {
        let mut c = [0u16; 1024];
        hash_to_point(&[1u8; 40], &[2u8; 64], &mut c);
        assert!(c.iter().all(|&x| x < 12289));
        // A different nonce gives a different point.
        let mut d = [0u16; 1024];
        hash_to_point(&[3u8; 40], &[2u8; 64], &mut d);
        assert_ne!(c, d);
    }
}
