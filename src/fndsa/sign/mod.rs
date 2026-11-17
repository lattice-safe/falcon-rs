//! Signature generation, ported from c-fn-dsa's `sign*.c`.
//!
//! The signing key is decoded into the short basis `[[g, -f], [G, -F]]`
//! (in FFT form), from which a fresh Gram matrix and LDL tree are built
//! for each attempt. Each attempt `k` (at most 27) seeds its own SHAKE256
//! stream with `seed || k`: the first 40 bytes are the nonce, the rest
//! drive the Gaussian sampler.

#![allow(non_snake_case)]

use alloc::{vec, vec::Vec};

use zeroize::Zeroizing;

use super::{
    codec, hash_to_point, mq, nbits_fg, resolve_mu, sign_key_size, signature_size, vrfy_key_size,
    HashId,
};
use crate::shake::Shake256;

mod flr;
mod poly;
mod sampler;

use flr::FLR;

/// A decoded signing key, with everything derived from it once: `G`, the
/// verifying key and its hash, the private-key hash used for seed
/// derivation, and the basis in FFT form.
#[derive(Clone)]
pub struct DecodedSignKey {
    logn: u32,
    f: Zeroizing<Vec<i8>>,
    g: Zeroizing<Vec<i8>>,
    F: Zeroizing<Vec<i8>>,
    G: Zeroizing<Vec<i8>>,
    vrfy_key: Vec<u8>,
    hashed_vrfy_key: [u8; 64],
    // On the heap so that moving the decoded key moves only a pointer.
    hashed_sign_key: Zeroizing<Vec<u8>>,
    basis: Zeroizing<Vec<FLR>>,
}

impl DecodedSignKey {
    /// Decode a signing key whose degree is in `logn_min..=logn_max`
    /// (intersected with the supported `2..=10`).
    ///
    /// Fails if the encoding is malformed, if `f` is not invertible modulo
    /// `X^n+1` and `q`, if the implied `G` is out of range, or if
    /// `f*G - g*F != q` (the reference does not check this last condition;
    /// without it a crafted key can make signing loop forever). As in the
    /// reference, the stored verifying-key hash is taken as is.
    pub fn decode(src: &[u8], logn_min: u32, logn_max: u32) -> Option<Self> {
        let (logn_min, logn_max) = (logn_min.max(2), logn_max.min(10));
        let head = *src.first()?;
        if (head & 0xF0) != 0x50 {
            return None;
        }
        let logn = (head & 0x0F) as u32;
        if logn < logn_min || logn > logn_max || src.len() != sign_key_size(logn) {
            return None;
        }
        let n = 1usize << logn;
        let mut f = Zeroizing::new(vec![0i8; n]);
        let mut g = Zeroizing::new(vec![0i8; n]);
        let mut F = Zeroizing::new(vec![0i8; n]);
        let mut G = Zeroizing::new(vec![0i8; n]);

        let nb = nbits_fg(logn);
        let j = 1 + codec::trim_i8_decode(&src[1..], &mut f, nb)?;
        let j = j + codec::trim_i8_decode(&src[j..], &mut g, nb)?;

        // Hash of the encoded (f,g), for hedged seed derivation.
        let mut hashed_sign_key = Zeroizing::new(vec![0u8; 40]);
        let mut sh = Shake256::new();
        sh.inject(&src[1..j]);
        sh.flip();
        sh.extract(&mut hashed_sign_key[..]);

        let j = j + codec::trim_i8_decode(&src[j..], &mut F, 8)?;
        // F always uses 8 bits per coefficient, so this is exact.
        let mut hashed_vrfy_key = [0u8; 64];
        hashed_vrfy_key.copy_from_slice(&src[j..]);

        // h = g/f (NTT), then G = h*F; also re-encode h as the verifying key.
        let mut w0 = Zeroizing::new(vec![0u16; n]);
        let mut w1 = Zeroizing::new(vec![0u16; n]);
        mq::mqpoly_small_to_int(logn, &g, &mut w0);
        mq::mqpoly_small_to_int(logn, &f, &mut w1);
        mq::mqpoly_int_to_NTT(logn, &mut w0);
        mq::mqpoly_int_to_NTT(logn, &mut w1);
        if !mq::mqpoly_div_ntt(logn, &mut w0, &w1) {
            return None;
        }
        mq::mqpoly_small_to_int(logn, &F, &mut w1);
        mq::mqpoly_int_to_NTT(logn, &mut w1);
        mq::mqpoly_mul_ntt(logn, &mut w1, &w0);
        mq::mqpoly_int_to_ext(logn, &mut w0);
        let mut vrfy_key = vec![0u8; vrfy_key_size(logn)];
        vrfy_key[0] = logn as u8;
        codec::modq_encode(&w0, &mut vrfy_key[1..]);
        mq::mqpoly_NTT_to_int(logn, &mut w1);
        if !mq::mqpoly_int_to_small(logn, &w1, &mut G) {
            return None;
        }
        if !super::kgen::ntru_equation_holds(logn, &f, &g, &F, &G) {
            return None;
        }

        // Basis B = [[g, -f], [G, -F]] in FFT form.
        let mut basis = Zeroizing::new(vec![FLR::ZERO; 4 * n]);
        {
            let (b00, work) = basis.split_at_mut(n);
            let (b01, work) = work.split_at_mut(n);
            let (b10, b11) = work.split_at_mut(n);
            poly::poly_set_small(logn, b01, &f);
            poly::poly_set_small(logn, b00, &g);
            poly::poly_set_small(logn, b11, &F);
            poly::poly_set_small(logn, b10, &G);
            poly::FFT(logn, b01);
            poly::FFT(logn, b00);
            poly::FFT(logn, b11);
            poly::FFT(logn, b10);
            poly::poly_neg(logn, b01);
            poly::poly_neg(logn, b11);
        }

        Some(DecodedSignKey {
            logn,
            f,
            g,
            F,
            G,
            vrfy_key,
            hashed_vrfy_key,
            hashed_sign_key,
            basis,
        })
    }

    /// Degree of the key.
    pub fn logn(&self) -> u32 {
        self.logn
    }

    /// The verifying key, re-derived from `f`, `g` (as `h = g/f`).
    pub fn vrfy_key(&self) -> &[u8] {
        &self.vrfy_key
    }

    /// The verifying-key hash stored in the signing key.
    pub fn hashed_vrfy_key(&self) -> &[u8; 64] {
        &self.hashed_vrfy_key
    }

    /// Sign, as `fndsa_sign_seeded`. The per-signature seed is
    /// `SHAKE256(SHAKE256(f||g)[40] || mu || rnd)[40]`, so a fixed `rnd`
    /// gives deterministic signatures and a fresh random `rnd` gives
    /// hedged ones. Returns `None` if `mu` cannot be formed (context over
    /// 255 bytes, malformed OID, or external mu that is not 64 bytes) or,
    /// with negligible probability, if 27 attempts all fail.
    pub fn sign(&self, ctx: &[u8], id: HashId<'_>, hv: &[u8], rnd: &[u8]) -> Option<Vec<u8>> {
        let mu = resolve_mu(&self.hashed_vrfy_key, ctx, id, hv)?;
        self.sign_mu(&mu, rnd)
    }

    /// Sign a precomputed message representative.
    pub fn sign_mu(&self, mu: &[u8; 64], rnd: &[u8]) -> Option<Vec<u8>> {
        let mut seed = Zeroizing::new([0u8; 40]);
        let mut sh = Shake256::new();
        sh.inject(&self.hashed_sign_key[..]);
        sh.inject(mu);
        sh.inject(rnd);
        sh.flip();
        sh.extract(&mut seed[..]);

        let mut sig = vec![0u8; signature_size(self.logn)];
        if sign_core(self.logn, &seed, mu, &self.basis, &mut sig) {
            Some(sig)
        } else {
            None
        }
    }

    /// `(f, g, F, G)`, for tests.
    #[doc(hidden)]
    pub fn basis_polys(&self) -> (&[i8], &[i8], &[i8], &[i8]) {
        (&self.f, &self.g, &self.F, &self.G)
    }
}

/// Run the Gaussian sampler at `logn = 9` on `(mu, 1/sigma)` pairs given
/// as binary64 bit patterns, as the reference's `test_sampler`: returns the
/// 40-byte nonce drawn first and the sampled integers. For tests.
#[doc(hidden)]
pub fn sampler_test_vector(seed: &[u8], inputs: &[(u64, u64)]) -> ([u8; 40], Vec<i32>) {
    let mut samp = sampler::Sampler::new(9, seed);
    let mut nonce = [0u8; 40];
    samp.next_bytes(&mut nonce);
    let out = inputs
        .iter()
        .map(|&(mu, isigma)| {
            let mu = FLR::decode(&mu.to_le_bytes()).unwrap();
            let isigma = FLR::decode(&isigma.to_le_bytes()).unwrap();
            samp.next(mu, isigma)
        })
        .collect();
    (nonce, out)
}

// 1/q, rounded to binary64.
const INV_Q: FLR = FLR::scaled(6004310871091074, -66);

/// The signing loop of `sign_core.c`. Returns `false` only if all 27
/// attempts are rejected, which for a valid key has probability below
/// 2^-256.
fn sign_core(logn: u32, seed: &[u8; 40], mu: &[u8; 64], basis: &[FLR], sig: &mut [u8]) -> bool {
    let n = 1usize << logn;
    let mut hm = vec![0u16; n];
    let mut s2 = Zeroizing::new(vec![0i16; n]);
    let mut tmp = Zeroizing::new(vec![FLR::ZERO; 9 * n]);

    for counter in 0..27u8 {
        let mut seed2 = Zeroizing::new([0u8; 41]);
        seed2[..40].copy_from_slice(seed);
        seed2[40] = counter;
        let mut samp = sampler::Sampler::new(logn, &seed2[..]);
        let mut nonce = [0u8; 40];
        samp.next_bytes(&mut nonce);
        hash_to_point(&nonce, mu, &mut hm);

        // Gram matrix G = B*adj(B): g00, g01 (g10 = adj(g01)), g11.
        {
            let (b00, work) = basis.split_at(n);
            let (b01, work) = work.split_at(n);
            let (b10, b11) = work.split_at(n);
            let (g00, work) = tmp.split_at_mut(n);
            let (g01, work) = work.split_at_mut(n);
            let (g11, work) = work.split_at_mut(n);
            let (t0, work) = work.split_at_mut(n);
            let (t1, _) = work.split_at_mut(n);

            g00.copy_from_slice(b00);
            poly::poly_mulownadj_fft(logn, g00);
            t0.copy_from_slice(b01);
            poly::poly_mulownadj_fft(logn, t0);
            poly::poly_add(logn, g00, t0);

            g01.copy_from_slice(b00);
            poly::poly_muladj_fft(logn, g01, b10);
            t0.copy_from_slice(b01);
            poly::poly_muladj_fft(logn, t0, b11);
            poly::poly_add(logn, g01, t0);

            g11.copy_from_slice(b10);
            poly::poly_mulownadj_fft(logn, g11);
            t0.copy_from_slice(b11);
            poly::poly_mulownadj_fft(logn, t0);
            poly::poly_add(logn, g11, t0);

            // Keep b11 and b01 for the target vector.
            t0.copy_from_slice(b11);
            t1.copy_from_slice(b01);
        }

        // Target vector t = (hm, 0) * B^-1, in FFT form:
        //   t0 = hm * b11 / q,  t1 = -hm * b01 / q
        {
            let (_, work) = tmp.split_at_mut(3 * n);
            let (b11, work) = work.split_at_mut(n);
            let (b01, work) = work.split_at_mut(n);
            let (t0, work) = work.split_at_mut(n);
            let (t1, _) = work.split_at_mut(n);
            for i in 0..n {
                t0[i] = FLR::from_i32(hm[i] as i32);
            }
            poly::FFT(logn, t0);
            t1.copy_from_slice(t0);
            poly::poly_mul_fft(logn, t1, b01);
            poly::poly_mulconst(logn, t1, -INV_Q);
            poly::poly_mul_fft(logn, t0, b11);
            poly::poly_mulconst(logn, t0, INV_Q);
        }

        // Fast Fourier sampling over the Gram matrix; t0, t1 move to
        // slots 3 and 4 and receive the sampled vector.
        tmp.copy_within((5 * n)..(7 * n), 3 * n);
        {
            let (g00, work) = tmp.split_at_mut(n);
            let (g01, work) = work.split_at_mut(n);
            let (g11, work) = work.split_at_mut(n);
            let (t0, work) = work.split_at_mut(n);
            let (t1, work) = work.split_at_mut(n);
            samp.ffsamp_fft(t0, t1, g00, g01, g11, work);
        }
        // A draw that never accepted means the basis is degenerate (not a
        // valid key): retrying cannot help.
        if samp.failed {
            return false;
        }

        // Lattice point v = z * B; the signature is s = (hm, 0) - v.
        tmp.copy_within((3 * n)..(5 * n), 4 * n);
        tmp[..(4 * n)].copy_from_slice(&basis[..(4 * n)]);
        let (b00, work) = tmp.split_at_mut(n);
        let (b01, work) = work.split_at_mut(n);
        let (b10, work) = work.split_at_mut(n);
        let (b11, work) = work.split_at_mut(n);
        let (t0, work) = work.split_at_mut(n);
        let (t1, work) = work.split_at_mut(n);
        let (tx, work) = work.split_at_mut(n);
        let (ty, _) = work.split_at_mut(n);
        tx.copy_from_slice(t0);
        ty.copy_from_slice(t1);
        poly::poly_mul_fft(logn, tx, b00);
        poly::poly_mul_fft(logn, ty, b10);
        poly::poly_add(logn, tx, ty);
        ty.copy_from_slice(t0);
        poly::poly_mul_fft(logn, ty, b01);
        t0.copy_from_slice(tx);
        poly::poly_mul_fft(logn, t1, b11);
        poly::poly_add(logn, t1, ty);
        poly::iFFT(logn, t0);
        poly::iFFT(logn, t1);

        // s1 = hm - v0, s2 = -v1. Accumulate the squared norm; any
        // overflow or |s1| > B_INF saturates it so the attempt is rejected.
        let mut sqn = 0u32;
        let mut ng = 0u32;
        for i in 0..n {
            let z = (hm[i] as i32) - (t0[i].rint() as i32);
            let z = (z as i16) as i32;
            sqn = sqn.wrapping_add((z * z) as u32);
            ng |= sqn;
            ng |= (codec::B_INF - z) as u32;
            ng |= (codec::B_INF + z) as u32;
        }
        for i in 0..n {
            let sz = (-t1[i].rint()) as i16;
            let z = sz as i32;
            sqn = sqn.wrapping_add((z * z) as u32);
            ng |= sqn;
            s2[i] = sz;
        }
        sqn |= ((ng as i32) >> 31) as u32;

        // Reject if too long, or if s2 does not fit the encoding
        // (|s2| > B_INF, or the compressed form exceeds the fixed size).
        if sqn <= mq::SQBETA[logn as usize] && codec::comp_encode(&s2, &mut sig[41..]) {
            sig[0] = 0x30 + logn as u8;
            sig[1..41].copy_from_slice(&nonce);
            return true;
        }
    }
    false
}

/// Sign with a standard key (FN-DSA-512 or -1024), as `fndsa_sign_seeded`.
///
/// Unlike [`crate::safe_api`], this does not verify the signature before
/// returning it, so it offers no fault detection.
pub fn sign(sk: &[u8], ctx: &[u8], id: HashId<'_>, hv: &[u8], rnd: &[u8]) -> Option<Vec<u8>> {
    DecodedSignKey::decode(sk, 9, 10)?.sign(ctx, id, hv, rnd)
}

/// Sign with a toy degree (`2 <= logn <= 8`), as `fndsa_sign_weak_seeded`.
/// For tests only.
pub fn sign_weak(sk: &[u8], ctx: &[u8], id: HashId<'_>, hv: &[u8], rnd: &[u8]) -> Option<Vec<u8>> {
    DecodedSignKey::decode(sk, 2, 8)?.sign(ctx, id, hv, rnd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fndsa::{kgen, vrfy};

    fn key(logn: u32) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
        kgen::keygen_seeded(logn, &[0xA5, logn as u8])
    }

    #[test]
    fn decoded_key_matches_keygen() {
        for logn in [2u32, 9] {
            let (sk, vk) = key(logn);
            let k = DecodedSignKey::decode(&sk, 2, 10).unwrap();
            assert_eq!(k.logn(), logn);
            assert_eq!(k.vrfy_key(), &vk[..]);
            assert_eq!(&k.hashed_vrfy_key()[..], &sk[sk.len() - 64..]);
            let kp = kgen::keygen_polys(logn, &[0xA5, logn as u8]);
            let (f, g, F, G) = k.basis_polys();
            assert_eq!(f, &kp.f[..]);
            assert_eq!(g, &kp.g[..]);
            assert_eq!(F, &kp.F[..]);
            assert_eq!(G, &kp.G[..]);
        }
    }

    #[test]
    fn decode_rejects_bad_keys() {
        let (sk, _) = key(9);
        assert!(DecodedSignKey::decode(&[], 2, 10).is_none());
        let mut bad = sk.to_vec();
        bad[0] = 0x49;
        assert!(DecodedSignKey::decode(&bad, 2, 10).is_none(), "header");
        assert!(DecodedSignKey::decode(&sk, 10, 10).is_none(), "range");
        assert!(DecodedSignKey::decode(&sk[..sk.len() - 1], 2, 10).is_none());
        // First f coefficient set to the forbidden 6-bit pattern 0b100000.
        let mut bad = sk.to_vec();
        bad[1] = (bad[1] & 0xC0) | 0x20;
        assert!(DecodedSignKey::decode(&bad, 2, 10).is_none(), "f coding");

        let n = 512usize;
        let flen = n * nbits_fg(9) as usize / 8;
        // f = 0 is not invertible.
        let mut zero = sk.to_vec();
        zero[1..1 + flen].fill(0);
        assert!(DecodedSignKey::decode(&zero, 2, 10).is_none(), "f = 0");

        // Forbidden encodings in g (6-bit 0b100000) and in F (8-bit 0x80).
        let mut bad = sk.to_vec();
        bad[1 + flen] = (bad[1 + flen] & 0xC0) | 0x20;
        assert!(DecodedSignKey::decode(&bad, 2, 10).is_none(), "g coding");
        let mut bad = sk.to_vec();
        bad[1 + 2 * flen] = 0x80;
        assert!(DecodedSignKey::decode(&bad, 2, 10).is_none(), "F coding");

        // A degree range wider than 2..=10 is clamped, not trusted.
        let mut bad = sk.to_vec();
        bad[0] = 0x5B;
        assert!(DecodedSignKey::decode(&bad, 2, 15).is_none(), "logn 11");
        assert!(DecodedSignKey::decode(&sk, 0, 15).is_some());

        // F = 0 gives G = 0: in range and consistent mod q, but not an NTRU
        // basis; signing with it would never terminate.
        let mut bad = sk.to_vec();
        let off = 1 + 2 * flen;
        bad[off..off + n].fill(0);
        assert!(DecodedSignKey::decode(&bad, 2, 10).is_none(), "F = 0");

        // Replacing F with a large constant pushes G = (g/f)*F out of range.
        let mut bad = sk.to_vec();
        let off = 1 + 2 * flen;
        bad[off..off + n].fill(0x7F);
        assert!(DecodedSignKey::decode(&bad, 2, 10).is_none(), "G range");
    }

    #[test]
    fn sign_and_verify_modes() {
        let (sk, vk) = key(9);
        let k = DecodedSignKey::decode(&sk, 9, 10).unwrap();
        let sig = k.sign(b"ctx", HashId::Raw, b"msg", b"rnd").unwrap();
        assert!(vrfy::verify(&sig, &vk, b"ctx", HashId::Raw, b"msg"));
        // Same inputs, same signature (deterministic for a fixed rnd).
        assert_eq!(sig, k.sign(b"ctx", HashId::Raw, b"msg", b"rnd").unwrap());
        // mu that cannot be formed.
        assert!(k.sign(&[0u8; 256], HashId::Raw, b"msg", b"").is_none());
        assert!(sign(&sk[..10], b"", HashId::Raw, b"m", b"").is_none());
        assert!(sign_weak(&sk, b"", HashId::Raw, b"m", b"").is_none());
    }

    // A basis of the wrong lattice: c*I with c = 130 (about the normal
    // Gram-Schmidt norm, so the sampler's sigma stays in range) yields
    // lattice points near (c^2/q)*hm instead of hm, so every attempt fails
    // the norm check and the signer gives up after 27 attempts.
    #[test]
    fn signer_gives_up_on_a_wrong_basis() {
        let logn = 2;
        let n = 4;
        let c = FLR::from_i32(130);
        let mut basis = vec![FLR::ZERO; 4 * n];
        // b00 = b11 = constant polynomial c (FFT: real parts c, imag 0).
        basis[0] = c;
        basis[1] = c;
        basis[3 * n] = c;
        basis[3 * n + 1] = c;
        let k = DecodedSignKey {
            logn,
            f: Zeroizing::new(vec![0; n]),
            g: Zeroizing::new(vec![0; n]),
            F: Zeroizing::new(vec![0; n]),
            G: Zeroizing::new(vec![0; n]),
            vrfy_key: vec![],
            hashed_vrfy_key: [0; 64],
            hashed_sign_key: Zeroizing::new(vec![0; 40]),
            basis: Zeroizing::new(basis),
        };
        assert!(k.sign_mu(&[0u8; 64], b"").is_none());
    }

    // A basis whose Gram-Schmidt norms are far above the design range makes
    // every draw's sigma far below sigma_min; draws then never accept, hit
    // the iteration cap, and the signer stops at once instead of hanging.
    #[test]
    fn signer_stops_when_draws_cannot_accept() {
        let logn = 2;
        let n = 4;
        let c = FLR::from_i32(1 << 30);
        let mut basis = vec![FLR::ZERO; 4 * n];
        // b00 = b11 = constant polynomial c (FFT: real parts c, imag 0).
        basis[0] = c;
        basis[1] = c;
        basis[3 * n] = c;
        basis[3 * n + 1] = c;
        let k = DecodedSignKey {
            logn,
            f: Zeroizing::new(vec![0; n]),
            g: Zeroizing::new(vec![0; n]),
            F: Zeroizing::new(vec![0; n]),
            G: Zeroizing::new(vec![0; n]),
            vrfy_key: vec![],
            hashed_vrfy_key: [0; 64],
            hashed_sign_key: Zeroizing::new(vec![0; 40]),
            basis: Zeroizing::new(basis),
        };
        assert!(k.sign_mu(&[0u8; 64], b"").is_none());
    }
}
