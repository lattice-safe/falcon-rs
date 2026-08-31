//! The full low-level cycle at a tiny degree, sized so a UB checker can
//! finish it.
//!
//! Miri executes this in minutes at logn = 2 where the real degrees would
//! take hours, and it covers every `unsafe` region on the signing and key
//! generation paths: the `tmp` buffer carving in `falcon.rs`, the raw-pointer
//! views in `sign.rs`, and the NTT/FFT `get_unchecked` walks. Four distinct
//! classes of undefined behaviour were found here — reborrowing a buffer
//! after carving it, holding a raw-derived slice across further uses of its
//! buffer, aliasing `&mut` with `&`, and building unaligned references — so
//! this stays in the suite to keep them from coming back.

use falcon::{falcon::*, shake::InnerShake256Context};

fn seeded(seed: &[u8]) -> InnerShake256Context {
    let mut sc = InnerShake256Context::new();
    shake256_init_prng_from_seed(&mut sc, seed);
    sc
}

#[test]
fn low_level_cycle_is_free_of_undefined_behaviour() {
    let logn = 2u32;
    let mut rng = seeded(b"miri");
    let mut sk = vec![0u8; falcon_privkey_size(logn)];
    let mut pk = vec![0u8; falcon_pubkey_size(logn)];
    let mut tmp = vec![0u8; falcon_tmpsize_keygen(logn)];
    assert_eq!(
        falcon_keygen_make(&mut rng, logn, &mut sk, Some(&mut pk), &mut tmp),
        0
    );

    let mut ek = vec![0u8; falcon_expandedkey_size(logn)];
    let mut etmp = vec![0u8; falcon_tmpsize_expandpriv(logn)];
    assert_eq!(falcon_expand_privkey(&mut ek, &sk, &mut etmp), 0);

    let mut derived = vec![0u8; falcon_pubkey_size(logn)];
    let mut ptmp = vec![0u8; falcon_tmpsize_makepub(logn)];
    assert_eq!(falcon_make_public(&mut derived, &sk, &mut ptmp), 0);
    assert_eq!(derived, pk);

    let msg = b"miri message";
    let cap = falcon_sig_compressed_maxsize(logn).max(falcon_sig_ct_size(logn));
    let mut vtmp = vec![0u8; falcon_tmpsize_verify(logn)];

    for &sig_type in &[FALCON_SIG_CT, FALCON_SIG_PADDED, FALCON_SIG_COMPRESSED] {
        // Expanded-key path.
        let mut sig = vec![0u8; cap];
        let mut sig_len = cap;
        let mut stmp = vec![0u8; falcon_tmpsize_signtree(logn)];
        let mut r = seeded(b"miri-tree");
        assert_eq!(
            falcon_sign_tree(
                &mut r,
                &mut sig,
                &mut sig_len,
                sig_type,
                &ek,
                msg,
                &mut stmp
            ),
            0,
            "sign_tree, format {sig_type}"
        );
        sig.truncate(sig_len);
        assert_eq!(falcon_verify(&sig, sig_type, &pk, msg, &mut vtmp), 0);

        // Dynamic path.
        let mut sig = vec![0u8; cap];
        let mut sig_len = cap;
        let mut dtmp = vec![0u8; falcon_tmpsize_signdyn(logn)];
        let mut r = seeded(b"miri-dyn");
        assert_eq!(
            falcon_sign_dyn(
                &mut r,
                &mut sig,
                &mut sig_len,
                sig_type,
                &sk,
                msg,
                &mut dtmp
            ),
            0,
            "sign_dyn, format {sig_type}"
        );
        sig.truncate(sig_len);
        assert_eq!(falcon_verify(&sig, sig_type, &pk, msg, &mut vtmp), 0);

        // A rejected signature exercises the decoder's error paths.
        let mut bad = sig.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0x55;
        assert_ne!(falcon_verify(&bad, sig_type, &pk, msg, &mut vtmp), 0);
    }
}
