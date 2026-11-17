//! Signature verification, ported from c-fn-dsa's `vrfy.c`.

use alloc::vec;

use super::{
    codec, hash_to_point, hashed_vrfykey_from_vrfykey, mq, resolve_mu, signature_size,
    vrfy_key_size, HashId,
};

/// A decoded verifying key: `h` in NTT form (internal representation) and
/// the SHAKE256 hash of its encoding, which enters `mu`.
pub struct DecodedVrfyKey {
    logn: u32,
    h: alloc::vec::Vec<u16>,
    hashed: [u8; 64],
}

impl DecodedVrfyKey {
    /// Decode a verifying key whose degree is in `logn_min..=logn_max`.
    pub fn decode(src: &[u8], logn_min: u32, logn_max: u32) -> Option<Self> {
        let head = *src.first()?;
        if (head & 0xF0) != 0x00 {
            return None;
        }
        let logn = (head & 0x0F) as u32;
        if logn < logn_min || logn > logn_max || src.len() != vrfy_key_size(logn) {
            return None;
        }
        let mut h = vec![0u16; 1 << logn];
        codec::modq_decode(&src[1..], &mut h)?;
        mq::mqpoly_ext_to_int(logn, &mut h);
        Some(DecodedVrfyKey {
            logn,
            h,
            hashed: hashed_vrfykey_from_vrfykey(src),
        })
    }

    /// Degree of the key.
    pub fn logn(&self) -> u32 {
        self.logn
    }

    /// SHAKE256 hash of the encoded key.
    pub fn hashed(&self) -> &[u8; 64] {
        &self.hashed
    }

    /// Verify `sig` over the message described by `ctx`, `id` and `hv`.
    pub fn verify(&self, sig: &[u8], ctx: &[u8], id: HashId<'_>, hv: &[u8]) -> bool {
        match resolve_mu(&self.hashed, ctx, id, hv) {
            Some(mu) => self.verify_mu(sig, &mu),
            None => false,
        }
    }

    /// Verify `sig` against a precomputed message representative.
    pub fn verify_mu(&self, sig: &[u8], mu: &[u8; 64]) -> bool {
        let logn = self.logn;
        let n = 1usize << logn;
        if sig.len() != signature_size(logn) || sig[0] != (0x30 + logn) as u8 {
            return false;
        }
        let mut s2 = vec![0i16; n];
        if !codec::comp_decode(&sig[41..], &mut s2) {
            return false;
        }
        // comp_decode() enforces |s2| <= B_INF, so this cannot overflow.
        let norm2 = mq::signed_poly_sqnorm(logn, &s2);

        let mut nonce = [0u8; 40];
        nonce.copy_from_slice(&sig[1..41]);
        let mut t1 = vec![0u16; n];
        hash_to_point(&nonce, mu, &mut t1);
        mq::mqpoly_ext_to_int(logn, &mut t1);

        // t1 <- c - s2*h = s1
        let mut t2 = vec![0u16; n];
        mq::mqpoly_signed_to_ext(logn, &s2, &mut t2);
        mq::mqpoly_ext_to_int(logn, &mut t2);
        mq::mqpoly_int_to_NTT(logn, &mut t2);
        mq::mqpoly_mul_ntt(logn, &mut t2, &self.h);
        mq::mqpoly_NTT_to_int(logn, &mut t2);
        mq::mqpoly_sub_int(logn, &mut t1, &t2);
        mq::mqpoly_int_to_ext(logn, &mut t1);

        // Saturates to 2^32-1 if |s1| exceeds B_INF or the norm overflows.
        let norm1 = mq::mqpoly_sqnorm_binf(logn, &t1);

        // The first test rejects norm1 + norm2 overflowing 32 bits.
        norm1 < norm2.wrapping_neg() && (norm1 + norm2) <= mq::SQBETA[logn as usize]
    }
}

/// Verify with a standard key (FN-DSA-512 or FN-DSA-1024), as
/// `fndsa_verify`. Any decoding failure yields `false`.
pub fn verify(sig: &[u8], vk: &[u8], ctx: &[u8], id: HashId<'_>, hv: &[u8]) -> bool {
    verify_range(sig, vk, ctx, id, hv, 9, 10)
}

/// Verify with a non-standard toy degree (`2 <= logn <= 8`), as
/// `fndsa_verify_weak`. For tests only.
pub fn verify_weak(sig: &[u8], vk: &[u8], ctx: &[u8], id: HashId<'_>, hv: &[u8]) -> bool {
    verify_range(sig, vk, ctx, id, hv, 2, 8)
}

fn verify_range(
    sig: &[u8],
    vk: &[u8],
    ctx: &[u8],
    id: HashId<'_>,
    hv: &[u8],
    logn_min: u32,
    logn_max: u32,
) -> bool {
    match DecodedVrfyKey::decode(vk, logn_min, logn_max) {
        Some(k) => k.verify(sig, ctx, id, hv),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(text: &str) -> alloc::vec::Vec<u8> {
        let line = text
            .lines()
            .find(|l| !l.starts_with('#') && !l.is_empty())
            .unwrap();
        (0..line.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
            .collect()
    }

    fn vk512() -> alloc::vec::Vec<u8> {
        fixture(include_str!(
            "../../tests/fixtures/c-fn-dsa/verify_512_vk.hex"
        ))
    }
    fn sig512() -> alloc::vec::Vec<u8> {
        fixture(include_str!(
            "../../tests/fixtures/c-fn-dsa/verify_512_sig.hex"
        ))
    }

    #[test]
    fn decode_rejects_malformed_keys() {
        let vk = vk512();
        assert!(DecodedVrfyKey::decode(&[], 9, 10).is_none());
        let mut bad = vk.clone();
        bad[0] |= 0x10;
        assert!(DecodedVrfyKey::decode(&bad, 9, 10).is_none(), "high nibble");
        assert!(DecodedVrfyKey::decode(&vk, 10, 10).is_none(), "below range");
        assert!(DecodedVrfyKey::decode(&vk, 2, 8).is_none(), "above range");
        assert!(DecodedVrfyKey::decode(&vk[..vk.len() - 1], 9, 10).is_none());
        // First coefficient forced to 0x3FFF >= q.
        let mut bad = vk.clone();
        bad[1] = 0xFF;
        bad[2] |= 0x3F;
        assert!(DecodedVrfyKey::decode(&bad, 9, 10).is_none(), "coeff >= q");

        let k = DecodedVrfyKey::decode(&vk, 9, 10).unwrap();
        assert_eq!(k.logn(), 9);
        assert_eq!(k.hashed(), &hashed_vrfykey_from_vrfykey(&vk));
    }

    #[test]
    fn verify_rejects_malformed_signatures() {
        let k = DecodedVrfyKey::decode(&vk512(), 9, 10).unwrap();
        let sig = sig512();
        assert!(k.verify(&sig, b"context", HashId::Raw, b"message"));
        assert!(!k.verify(&sig[..sig.len() - 1], b"context", HashId::Raw, b"message"));
        let mut bad = sig.clone();
        bad[0] = 0x3A;
        assert!(
            !k.verify(&bad, b"context", HashId::Raw, b"message"),
            "header"
        );
        // An all-ones body cannot be a valid compressed encoding.
        let mut bad = sig.clone();
        bad[41..].fill(0xFF);
        assert!(!k.verify(&bad, b"context", HashId::Raw, b"message"), "comp");
        // mu that cannot be resolved.
        assert!(!k.verify(&sig, b"", HashId::ExternalMu, &[0u8; 63]));
        assert!(!verify(&sig, &[], b"context", HashId::Raw, b"message"));
    }
}
