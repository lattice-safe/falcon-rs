//! Round-3 Falcon, as in falcon-rs 0.3.x (feature `round3`).
//!
//! Everything in this module is re-exported from the published
//! `falcon-rs 0.3.1` crate, unchanged: the same API, key and signature
//! formats, and behaviour. Code written against 0.3 keeps working after
//! changing `falcon::` to `falcon::round3::`:
//!
//! ```rust
//! use falcon::round3::prelude::*;
//!
//! let kp = FnDsaKeyPair::generate_deterministic(b"a round-3 key seed", 9).unwrap();
//! let sig = kp.sign_deterministic(b"msg", b"rnd", &DomainSeparation::None).unwrap();
//! FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), b"msg",
//!     &DomainSeparation::None).unwrap();
//! ```
//!
//! **The two formats cannot be told apart from the bytes.** Public keys
//! have the same header and size in both (897 / 1793 bytes), and so does
//! the signature header. Always decide from context which API a key or
//! signature belongs to; never by trying one and falling back to the other.
//!
//! A round-3 *private* key can be converted to FN-DSA with
//! [`to_fndsa_keypair`]: both hold the same secret basis `(f, g, F)`, only
//! the encoding differs. The public key changes encoding with it, so
//! verifiers must be given the new public key. Signatures cannot be
//! converted; round-3 signatures verify only under [`FnDsaSignature`]
//! from this module (the 0.3 type re-exported here).
//!
//! The 0.3 code contains `unsafe` blocks; they stay in that crate.
//! `#![forbid(unsafe_code)]` applies to this crate's own code.

use alloc::vec;

pub use falcon_round3::*;
use zeroize::Zeroizing;

use crate::fndsa::kgen;

// Not `use crate::safe_api`: the glob above re-exports 0.3's `safe_api`,
// and this module's public names must stay exactly 0.3's.
type NewKeyPair = crate::safe_api::FnDsaKeyPair;
type NewError = crate::safe_api::FalconError;

/// Convert a round-3 (falcon-rs 0.3) private key into an FN-DSA key pair.
///
/// The secret basis is kept: the result signs with the same lattice
/// trapdoor, in the FN-DSA formats. Only FN-DSA-512 and FN-DSA-1024 keys
/// convert.
///
/// Errors: [`crate::safe_api::FalconError::FormatError`] for a malformed key or
/// one that is not a valid NTRU basis, [`crate::safe_api::FalconError::BadArgument`]
/// for a degree other than 9 or 10.
///
/// ```rust
/// use falcon::prelude::*;
///
/// let old = falcon::round3::FnDsaKeyPair::generate_deterministic(b"legacy key", 9).unwrap();
/// let new = falcon::round3::to_fndsa_keypair(old.private_key()).unwrap();
/// let sig = new.sign(b"msg", &DomainSeparation::None).unwrap();
/// FnDsaSignature::verify(sig.to_bytes(), new.public_key(), b"msg",
///     &DomainSeparation::None).unwrap();
/// ```
pub fn to_fndsa_keypair(privkey: &[u8]) -> Result<NewKeyPair, NewError> {
    use crate::safe_api::FalconError::{BadArgument, FormatError};

    let head = *privkey.first().ok_or(FormatError)?;
    if (head & 0xF0) != 0x50 {
        return Err(FormatError);
    }
    let logn = (head & 0x0F) as u32;
    if !matches!(logn, 9 | 10) {
        return Err(BadArgument);
    }
    if privkey.len() != falcon_round3::falcon::falcon_privkey_size(logn) {
        return Err(FormatError);
    }

    // Round-3 layout: header || f || g || F, with the same bit widths as
    // FN-DSA but the round-3 bit order; decode with the 0.3 codec.
    let n = 1usize << logn;
    let fg_bits = falcon_round3::codec::MAX_FG_BITS[logn as usize] as u32;
    let big_bits = falcon_round3::codec::MAX_FG_BITS_UPPER[logn as usize] as u32;
    let mut f = Zeroizing::new(vec![0i8; n]);
    let mut g = Zeroizing::new(vec![0i8; n]);
    let mut big_f = Zeroizing::new(vec![0i8; n]);
    let mut off = 1;
    for (dst, bits) in [(&mut f, fg_bits), (&mut g, fg_bits), (&mut big_f, big_bits)] {
        let used = falcon_round3::codec::trim_i8_decode(dst, logn, bits, &privkey[off..]);
        if used == 0 {
            return Err(FormatError);
        }
        off += used;
    }

    // Re-encode in the FN-DSA format, then import through the regular,
    // fully validating path (invertibility of f, range of G, the NTRU
    // equation, and the embedded public-key hash).
    let (sk, _) = kgen::encode_keypair(logn, &f, &g, &big_f);
    NewKeyPair::from_private_key(&sk)
}

/// Convert a round-3 (falcon-rs 0.3) public key into the FN-DSA public key
/// of the same key pair.
///
/// This needs no secret: anyone holding the old public key (a verifier, a
/// ledger storing account keys) computes the new one, and it is exactly
/// the public key of [`to_fndsa_keypair`] applied to the matching private
/// key. Both encode the same `h = g/f`; FN-DSA stores it in NTT form.
///
/// Anything derived from the public-key *bytes* (an address, a key hash)
/// changes with the conversion. Signatures do not convert.
///
/// Errors: [`crate::safe_api::FalconError::FormatError`] for a malformed key,
/// [`crate::safe_api::FalconError::BadArgument`] for a degree other than 9 or 10.
///
/// ```rust
/// let old = falcon::round3::FnDsaKeyPair::generate_deterministic(b"legacy key", 9).unwrap();
/// let new = falcon::round3::to_fndsa_keypair(old.private_key()).unwrap();
/// let vk = falcon::round3::to_fndsa_public_key(old.public_key()).unwrap();
/// assert_eq!(vk, new.public_key());
/// ```
pub fn to_fndsa_public_key(pubkey: &[u8]) -> Result<alloc::vec::Vec<u8>, NewError> {
    use crate::{
        fndsa::{codec, mq, vrfy_key_size},
        safe_api::FalconError::{BadArgument, FormatError},
    };

    let head = *pubkey.first().ok_or(FormatError)?;
    if (head & 0xF0) != 0x00 {
        return Err(FormatError);
    }
    let logn = head as u32;
    if !matches!(logn, 9 | 10) {
        return Err(BadArgument);
    }
    if pubkey.len() != falcon_round3::falcon::falcon_pubkey_size(logn) {
        return Err(FormatError);
    }

    // Round-3 stores h in plain form, most-significant bit first.
    let mut h = vec![0u16; 1 << logn];
    if falcon_round3::codec::modq_decode(&mut h, logn, &pubkey[1..]) == 0 {
        return Err(FormatError);
    }
    mq::mqpoly_ext_to_int(logn, &mut h);
    mq::mqpoly_int_to_NTT(logn, &mut h);
    mq::mqpoly_int_to_ext(logn, &mut h);

    let mut vk = vec![0u8; vrfy_key_size(logn)];
    vk[0] = head;
    let j = 1 + codec::modq_encode(&h, &mut vk[1..]);
    debug_assert_eq!(j, vk.len());
    Ok(vk)
}
