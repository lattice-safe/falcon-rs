//! Key pair generation, ported from c-fn-dsa's `kgen*.c`.
//!
//! The NTRU solver works on 31-bit-prime RNS integers (`zint31`, `mp31`)
//! and 64-bit fixed-point approximations (`fxp`, `vect`), following
//! eprint 2025/1239. It never uses floating point.

#![allow(non_snake_case)]

use alloc::{vec, vec::Vec};

use zeroize::Zeroizing;

use super::{codec, hashed_vrfykey_from_vrfykey, mq, nbits_fg, sign_key_size, vrfy_key_size};
use crate::shake::Shake256Prng;

mod fxp;
mod gauss;
mod mp31;
mod ntru;
mod poly;
mod vect;
mod zint31;

/// The secret NTRU basis: `f*G - g*F = q mod X^n+1`.
pub struct KeyPolys {
    /// `f`
    pub f: Zeroizing<Vec<i8>>,
    /// `g`
    pub g: Zeroizing<Vec<i8>>,
    /// `F`
    pub F: Zeroizing<Vec<i8>>,
    /// `G`
    pub G: Zeroizing<Vec<i8>>,
}

/// Deterministically derive the secret basis from `seed`
/// (`2 <= logn <= 10`), as `keygen_from_seed` in c-fn-dsa.
pub fn keygen_polys(logn: u32, seed: &[u8]) -> KeyPolys {
    assert!((2..=10).contains(&logn), "unsupported degree");
    let n = 1usize << logn;
    let mut f = Zeroizing::new(vec![0i8; n]);
    let mut g = Zeroizing::new(vec![0i8; n]);
    let mut F = Zeroizing::new(vec![0i8; n]);
    let mut G = Zeroizing::new(vec![0i8; n]);
    let mut t16 = Zeroizing::new(vec![0u16; n]);
    let mut t32 = Zeroizing::new(vec![0u32; 5 * n]);
    let mut tfx = Zeroizing::new(vec![fxp::FXR::ZERO; 5 * (n >> 1)]);

    let mut rng = Shake256Prng::new(seed);
    loop {
        // f must be invertible mod X^n+1 mod q, so that h = g/f exists.
        gauss::sample_f(logn, &mut rng, &mut f);
        if !mq::mqpoly_small_is_invertible(logn, &f, &mut t16) {
            continue;
        }
        gauss::sample_f(logn, &mut rng, &mut g);

        // Squared norm of (f,g) must be below 1.17^2 * q = 16822.4121.
        let sn: i32 = f
            .iter()
            .zip(g.iter())
            .map(|(&a, &b)| (a as i32) * (a as i32) + (b as i32) * (b as i32))
            .sum();
        if sn >= 16823 {
            continue;
        }

        // The orthogonalized vector must also be short enough.
        if !ntru::check_ortho_norm(logn, &f, &g, &mut tfx) {
            continue;
        }

        if ntru::solve_NTRU(logn, &f, &g, &mut F, &mut G, &mut t32, &mut tfx) {
            break;
        }
    }
    KeyPolys { f, g, F, G }
}

/// Encoded key pair from `seed` (`2 <= logn <= 10`), as
/// `fndsa_keygen_seeded`. Returns `(signing key, verifying key)`.
pub fn keygen_seeded(logn: u32, seed: &[u8]) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
    let kp = keygen_polys(logn, seed);
    let n = 1usize << logn;

    // h = g/f, in NTT form with external representation.
    let mut h = vec![0u16; n];
    let mut t16 = Zeroizing::new(vec![0u16; n]);
    mq::mqpoly_div_small_nttx(logn, &kp.f, &kp.g, &mut h, &mut t16);

    let mut vk = vec![0u8; vrfy_key_size(logn)];
    vk[0] = logn as u8;
    let j = 1 + codec::modq_encode(&h, &mut vk[1..]);
    debug_assert_eq!(j, vk.len());

    let mut sk = Zeroizing::new(vec![0u8; sign_key_size(logn)]);
    sk[0] = 0x50 + logn as u8;
    let nb = nbits_fg(logn);
    let j = 1 + codec::trim_i8_encode(&kp.f, nb, &mut sk[1..]);
    let j = j + codec::trim_i8_encode(&kp.g, nb, &mut sk[j..]);
    let j = j + codec::trim_i8_encode(&kp.F, 8, &mut sk[j..]);
    sk[j..].copy_from_slice(&hashed_vrfykey_from_vrfykey(&vk));
    (sk, vk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fndsa::vrfy::DecodedVrfyKey;

    #[test]
    fn encoded_keys_are_consistent() {
        for logn in 2..=10u32 {
            let (sk, vk) = keygen_seeded(logn, &[logn as u8]);
            assert_eq!(sk.len(), sign_key_size(logn));
            assert_eq!(sk[0], 0x50 + logn as u8);
            let k = DecodedVrfyKey::decode(&vk, logn, logn).unwrap();
            assert_eq!(&sk[sk.len() - 64..], k.hashed());

            // The encoded f, g, F decode back to the derived polynomials.
            let kp = keygen_polys(logn, &[logn as u8]);
            let n = 1usize << logn;
            let nb = nbits_fg(logn);
            let mut f = vec![0i8; n];
            let mut g = vec![0i8; n];
            let mut F = vec![0i8; n];
            let j = 1 + codec::trim_i8_decode(&sk[1..], &mut f, nb).unwrap();
            let j = j + codec::trim_i8_decode(&sk[j..], &mut g, nb).unwrap();
            codec::trim_i8_decode(&sk[j..], &mut F, 8).unwrap();
            assert_eq!(&f[..], &kp.f[..]);
            assert_eq!(&g[..], &kp.g[..]);
            assert_eq!(&F[..], &kp.F[..]);
        }
    }

    #[test]
    #[should_panic(expected = "unsupported degree")]
    fn rejects_bad_degree() {
        let _ = keygen_polys(11, b"x");
    }
}
