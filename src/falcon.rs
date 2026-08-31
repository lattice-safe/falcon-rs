//! High-level Falcon API.
//! Ported from falcon.c.

use crate::{
    codec, common,
    fpr::Fpr,
    keygen,
    shake::{
        i_shake256_extract, i_shake256_flip, i_shake256_init, i_shake256_inject,
        InnerShake256Context,
    },
    sign, vrfy,
};

// ======================================================================
// Error codes
// ======================================================================

pub const FALCON_ERR_RANDOM: i32 = -1;
pub const FALCON_ERR_SIZE: i32 = -2;
pub const FALCON_ERR_FORMAT: i32 = -3;
pub const FALCON_ERR_BADSIG: i32 = -4;
pub const FALCON_ERR_BADARG: i32 = -5;
pub const FALCON_ERR_INTERNAL: i32 = -6;

// ======================================================================
// Signature format types
// ======================================================================

pub const FALCON_SIG_COMPRESSED: i32 = 1;
pub const FALCON_SIG_PADDED: i32 = 2;
pub const FALCON_SIG_CT: i32 = 3;

// ======================================================================
// Size computations
// ======================================================================

pub const fn falcon_privkey_size(logn: u32) -> usize {
    if logn <= 3 {
        (3 << logn) + 1
    } else {
        ((10 - (logn >> 1)) << (logn - 2)) as usize + (1 << logn) + 1
    }
}

pub const fn falcon_pubkey_size(logn: u32) -> usize {
    if logn <= 1 {
        5
    } else {
        (7 << (logn - 2)) + 1
    }
}

pub const fn falcon_sig_compressed_maxsize(logn: u32) -> usize {
    if logn < 1 || logn > 10 {
        return 0;
    }
    (((11 << logn) + (101 >> (10 - logn)) + 7) >> 3) + 41
}

pub const fn falcon_sig_padded_size(logn: u32) -> usize {
    if logn < 1 || logn > 10 {
        return 0;
    }
    44 + 3 * (256 >> (10 - logn))
        + 2 * (128 >> (10 - logn))
        + 3 * (64 >> (10 - logn))
        + 2 * (16 >> (10 - logn))
        - 2 * (2 >> (10 - logn))
        - 8 * (1 >> (10 - logn))
}

pub const fn falcon_sig_ct_size(logn: u32) -> usize {
    if logn < 1 || logn > 10 {
        return 0;
    }
    let base = (3 << (logn - 1)) + 41;
    if logn == 3 {
        base - 1
    } else {
        base
    }
}

pub const fn falcon_tmpsize_keygen(logn: u32) -> usize {
    (if logn <= 3 { 272 } else { 28 << logn }) + (3 << logn) + 7
}

pub const fn falcon_tmpsize_makepub(logn: u32) -> usize {
    (6 << logn) + 1
}

pub const fn falcon_tmpsize_signdyn(logn: u32) -> usize {
    (78 << logn) + 7
}

pub const fn falcon_tmpsize_signtree(logn: u32) -> usize {
    (50 << logn) + 7
}

pub const fn falcon_tmpsize_expandpriv(logn: u32) -> usize {
    (52 << logn) + 7
}

pub const fn falcon_expandedkey_size(logn: u32) -> usize {
    ((8 * (logn as usize) + 40) << logn) + 8
}

pub const fn falcon_tmpsize_verify(logn: u32) -> usize {
    (8 << logn) + 1
}

// ======================================================================
// Alignment helpers
// ======================================================================

// The alignment helpers mirror the C reference's tmp-buffer handling. This
// port's callers align through typed asserts instead, so they are reachable
// only from tests — kept because any new low-level entry point will need them.
#[allow(dead_code)]
fn align_u64(tmp: &mut [u8]) -> &mut [u8] {
    let addr = tmp.as_ptr() as usize;
    let off = addr & 7;
    if off != 0 {
        &mut tmp[8 - off..]
    } else {
        tmp
    }
}

#[allow(dead_code)]
fn align_u16(tmp: &mut [u8]) -> &mut [u8] {
    let addr = tmp.as_ptr() as usize;
    if addr & 1 != 0 {
        &mut tmp[1..]
    } else {
        tmp
    }
}

#[allow(dead_code)]
fn align_fpr(tmp: &mut [u8]) -> &mut [u8] {
    align_u64(tmp)
}

// ======================================================================
// SHAKE256 public API
// ======================================================================

/// Initialize a SHAKE256 context.
pub fn shake256_init(sc: &mut InnerShake256Context) {
    i_shake256_init(sc);
}

/// Inject data into a SHAKE256 context.
pub fn shake256_inject(sc: &mut InnerShake256Context, data: &[u8]) {
    i_shake256_inject(sc, data);
}

/// Flip a SHAKE256 context to output mode.
pub fn shake256_flip(sc: &mut InnerShake256Context) {
    i_shake256_flip(sc);
}

/// Extract data from a SHAKE256 context.
pub fn shake256_extract(sc: &mut InnerShake256Context, out: &mut [u8]) {
    i_shake256_extract(sc, out);
}

/// Initialize a SHAKE256 PRNG from an explicit seed.
pub fn shake256_init_prng_from_seed(sc: &mut InnerShake256Context, seed: &[u8]) {
    shake256_init(sc);
    shake256_inject(sc, seed);
    shake256_flip(sc);
}

/// Initialize a SHAKE256 PRNG from the OS-provided RNG.
///
/// Returns 0 on success, or FALCON_ERR_RANDOM (-1) if the OS RNG
/// is unavailable or fails.
pub fn shake256_init_prng_from_system(sc: &mut InnerShake256Context) -> i32 {
    let mut seed = zeroize::Zeroizing::new([0u8; 48]);
    if !crate::rng::get_seed(&mut *seed) {
        return FALCON_ERR_RANDOM;
    }
    shake256_init(sc);
    shake256_inject(sc, &*seed);
    shake256_flip(sc);
    0
}

// ======================================================================
// Key pair generation
// ======================================================================

/// Generate a new Falcon key pair.
///
/// Returns 0 on success, or a negative error code.
pub fn falcon_keygen_make(
    rng: &mut InnerShake256Context,
    logn: u32,
    privkey: &mut [u8],
    pubkey: Option<&mut [u8]>,
    tmp: &mut [u8],
) -> i32 {
    if logn < 1 || logn > 10 {
        return FALCON_ERR_BADARG;
    }
    let sk_len = falcon_privkey_size(logn);
    if privkey.len() < sk_len {
        return FALCON_ERR_SIZE;
    }
    if let Some(ref pk) = pubkey {
        if pk.len() < falcon_pubkey_size(logn) {
            return FALCON_ERR_SIZE;
        }
    }
    if tmp.len() < falcon_tmpsize_keygen(logn) {
        return FALCON_ERR_SIZE;
    }

    let n: usize = 1 << logn;

    // Use tmp for f, g, F, then the rest for the keygen algorithm.
    let f_off = 0;
    let g_off = n;
    let big_f_off = 2 * n;
    let atmp_off = {
        let base = big_f_off + n;
        let addr = unsafe { tmp.as_ptr().add(base) as usize };
        let off = addr & 7;
        if off != 0 {
            base + 8 - off
        } else {
            base
        }
    };

    // Prepare i8 slices in tmp for keygen.
    {
        // Take the length *before* deriving the raw pointer. Touching `tmp`
        // afterwards — even `tmp.len()` — reborrows the whole buffer and
        // invalidates the tags of the slices derived from `ptr`, which is
        // undefined behaviour the moment one of them is used again (Miri
        // reports it as a failed retag at the `keygen` call below).
        let tmp_len = tmp.len();
        let ptr = tmp.as_mut_ptr();
        let f = unsafe { core::slice::from_raw_parts_mut(ptr.add(f_off) as *mut i8, n) };
        let g = unsafe { core::slice::from_raw_parts_mut(ptr.add(g_off) as *mut i8, n) };
        let big_f = unsafe { core::slice::from_raw_parts_mut(ptr.add(big_f_off) as *mut i8, n) };
        let atmp =
            unsafe { core::slice::from_raw_parts_mut(ptr.add(atmp_off), tmp_len - atmp_off) };

        keygen::keygen(rng, f, g, big_f, None, None, logn, atmp);
    }

    // Encode private key.
    privkey[0] = 0x50 + logn as u8;
    let mut u: usize = 1;
    {
        let f = unsafe { core::slice::from_raw_parts(tmp[f_off..].as_ptr() as *const i8, n) };
        let v = codec::trim_i8_encode(
            Some(&mut privkey[u..]),
            f,
            logn,
            codec::MAX_FG_BITS[logn as usize] as u32,
        );
        if v == 0 {
            return FALCON_ERR_INTERNAL;
        }
        u += v;
    }
    {
        let g = unsafe { core::slice::from_raw_parts(tmp[g_off..].as_ptr() as *const i8, n) };
        let v = codec::trim_i8_encode(
            Some(&mut privkey[u..]),
            g,
            logn,
            codec::MAX_FG_BITS[logn as usize] as u32,
        );
        if v == 0 {
            return FALCON_ERR_INTERNAL;
        }
        u += v;
    }
    {
        let big_f =
            unsafe { core::slice::from_raw_parts(tmp[big_f_off..].as_ptr() as *const i8, n) };
        let v = codec::trim_i8_encode(
            Some(&mut privkey[u..]),
            big_f,
            logn,
            codec::MAX_FG_BITS_UPPER[logn as usize] as u32,
        );
        if v == 0 {
            return FALCON_ERR_INTERNAL;
        }
        u += v;
    }
    if u != sk_len {
        return FALCON_ERR_INTERNAL;
    }

    // Compute and encode public key if requested.
    if let Some(pk) = pubkey {
        let pk_len = falcon_pubkey_size(logn);
        // Length first: reborrowing `tmp` after `ptr` is derived would
        // invalidate the tags of the slices carved out of it.
        let tmp_len = tmp.len();
        let ptr = tmp.as_mut_ptr();
        let f = unsafe { core::slice::from_raw_parts(ptr.add(f_off) as *const i8, n) };
        let g = unsafe { core::slice::from_raw_parts(ptr.add(g_off) as *const i8, n) };

        // Use g+n area for h and atmp.
        let h_base = g_off + n;
        let h_addr = unsafe { ptr.add(h_base) as usize };
        let h_off = if h_addr & 1 != 0 { h_base + 1 } else { h_base };
        let h = unsafe { core::slice::from_raw_parts_mut(ptr.add(h_off) as *mut u16, n) };
        let atmp2 = unsafe {
            core::slice::from_raw_parts_mut(ptr.add(h_off + 2 * n), tmp_len - h_off - 2 * n)
        };

        if !vrfy::compute_public(h, f, g, logn, atmp2) {
            return FALCON_ERR_INTERNAL;
        }
        pk[0] = logn as u8;
        let v = codec::modq_encode(Some(&mut pk[1..]), h, logn);
        if v != pk_len - 1 {
            return FALCON_ERR_INTERNAL;
        }
    }

    0
}

/// Recompute the public key from the private key.
pub fn falcon_make_public(pubkey: &mut [u8], privkey: &[u8], tmp: &mut [u8]) -> i32 {
    if privkey.is_empty() {
        return FALCON_ERR_FORMAT;
    }
    if privkey[0] & 0xF0 != 0x50 {
        return FALCON_ERR_FORMAT;
    }
    let logn = (privkey[0] & 0x0F) as u32;
    if logn < 1 || logn > 10 {
        return FALCON_ERR_FORMAT;
    }
    if privkey.len() != falcon_privkey_size(logn) {
        return FALCON_ERR_FORMAT;
    }
    let pk_len = falcon_pubkey_size(logn);
    if pubkey.len() < pk_len {
        return FALCON_ERR_SIZE;
    }
    if tmp.len() < falcon_tmpsize_makepub(logn) {
        return FALCON_ERR_SIZE;
    }

    let n: usize = 1 << logn;

    // Decode f and g into tmp.
    // Length first: reborrowing `tmp` after `ptr` is derived would
    // invalidate the tags of the slices carved out of it.
    let tmp_len = tmp.len();
    let ptr = tmp.as_mut_ptr();
    let f = unsafe { core::slice::from_raw_parts_mut(ptr as *mut i8, n) };
    let g = unsafe { core::slice::from_raw_parts_mut(ptr.add(n) as *mut i8, n) };

    let mut u: usize = 1;
    let v = codec::trim_i8_decode(
        f,
        logn,
        codec::MAX_FG_BITS[logn as usize] as u32,
        &privkey[u..],
    );
    if v == 0 {
        return FALCON_ERR_FORMAT;
    }
    u += v;
    let v = codec::trim_i8_decode(
        g,
        logn,
        codec::MAX_FG_BITS[logn as usize] as u32,
        &privkey[u..],
    );
    if v == 0 {
        return FALCON_ERR_FORMAT;
    }

    // Compute public key.
    let h_off = if (unsafe { ptr.add(2 * n) as usize }) & 1 != 0 {
        2 * n + 1
    } else {
        2 * n
    };
    let h = unsafe { core::slice::from_raw_parts_mut(ptr.add(h_off) as *mut u16, n) };
    let atmp =
        unsafe { core::slice::from_raw_parts_mut(ptr.add(h_off + 2 * n), tmp_len - h_off - 2 * n) };
    if !vrfy::compute_public(h, f, g, logn, atmp) {
        return FALCON_ERR_FORMAT;
    }

    pubkey[0] = logn as u8;
    let v = codec::modq_encode(Some(&mut pubkey[1..]), h, logn);
    if v != pk_len - 1 {
        return FALCON_ERR_INTERNAL;
    }
    0
}

/// Get the Falcon degree from a header byte.
pub fn falcon_get_logn(obj: &[u8]) -> i32 {
    if obj.is_empty() {
        return FALCON_ERR_FORMAT;
    }
    let logn = (obj[0] & 0x0F) as i32;
    if logn < 1 || logn > 10 {
        return FALCON_ERR_FORMAT;
    }
    logn
}

// ======================================================================
// Signature generation
// ======================================================================

/// Start a signature: generate a nonce and initialize hash_data.
pub fn falcon_sign_start(
    rng: &mut InnerShake256Context,
    nonce: &mut [u8],
    hash_data: &mut InnerShake256Context,
) -> i32 {
    shake256_extract(rng, &mut nonce[..40]);
    shake256_init(hash_data);
    shake256_inject(hash_data, &nonce[..40]);
    0
}

/// Finish a signature using the raw private key ("dynamic" mode).
pub fn falcon_sign_dyn_finish(
    rng: &mut InnerShake256Context,
    sig: &mut [u8],
    sig_len: &mut usize,
    sig_type: i32,
    privkey: &[u8],
    hash_data: &mut InnerShake256Context,
    nonce: &[u8],
    tmp: &mut [u8],
) -> i32 {
    if privkey.is_empty() {
        return FALCON_ERR_FORMAT;
    }
    if privkey[0] & 0xF0 != 0x50 {
        return FALCON_ERR_FORMAT;
    }
    let logn = (privkey[0] & 0x0F) as u32;
    if logn < 1 || logn > 10 {
        return FALCON_ERR_FORMAT;
    }
    if privkey.len() != falcon_privkey_size(logn) {
        return FALCON_ERR_FORMAT;
    }
    if tmp.len() < falcon_tmpsize_signdyn(logn) {
        return FALCON_ERR_SIZE;
    }
    let es_len = *sig_len;
    if es_len < 41 {
        return FALCON_ERR_SIZE;
    }

    match sig_type {
        FALCON_SIG_COMPRESSED => {}
        FALCON_SIG_PADDED => {
            if es_len < falcon_sig_padded_size(logn) {
                return FALCON_ERR_SIZE;
            }
        }
        FALCON_SIG_CT => {
            if es_len < falcon_sig_ct_size(logn) {
                return FALCON_ERR_SIZE;
            }
        }
        _ => return FALCON_ERR_BADARG,
    }

    let n: usize = 1 << logn;
    // Length first: reborrowing `tmp` after `ptr` is derived would
    // invalidate the tags of the slices carved out of it.
    let tmp_len = tmp.len();
    let ptr = tmp.as_mut_ptr();

    // Decode private key into tmp: f, g, F, G, hm, then atmp.
    let f = unsafe { core::slice::from_raw_parts_mut(ptr as *mut i8, n) };
    let g = unsafe { core::slice::from_raw_parts_mut(ptr.add(n) as *mut i8, n) };
    let big_f = unsafe { core::slice::from_raw_parts_mut(ptr.add(2 * n) as *mut i8, n) };
    let big_g = unsafe { core::slice::from_raw_parts_mut(ptr.add(3 * n) as *mut i8, n) };

    let mut u: usize = 1;
    let v = codec::trim_i8_decode(
        f,
        logn,
        codec::MAX_FG_BITS[logn as usize] as u32,
        &privkey[u..],
    );
    if v == 0 {
        return FALCON_ERR_FORMAT;
    }
    u += v;
    let v = codec::trim_i8_decode(
        g,
        logn,
        codec::MAX_FG_BITS[logn as usize] as u32,
        &privkey[u..],
    );
    if v == 0 {
        return FALCON_ERR_FORMAT;
    }
    u += v;
    let v = codec::trim_i8_decode(
        big_f,
        logn,
        codec::MAX_FG_BITS_UPPER[logn as usize] as u32,
        &privkey[u..],
    );
    if v == 0 {
        return FALCON_ERR_FORMAT;
    }
    u += v;
    if u != privkey.len() {
        return FALCON_ERR_FORMAT;
    }

    // Complete the private key (recover G).
    //
    // The hashed point and the signature vector used to live inside `tmp`, as
    // `u16` and `i16` views of the same bytes. That required the caller's
    // byte buffer to happen to be 2-byte aligned (it is only `&mut [u8]`, so
    // nothing guarantees that) and it aliased a `&mut` with a `&`. Both are
    // undefined behaviour, and Miri reports both. They are small — n elements
    // each — so they are owned buffers now, which also leaves `atmp` larger
    // than before.
    let atmp_off = {
        let base = 4 * n;
        let addr = unsafe { ptr.add(base) as usize };
        let off = addr & 7;
        if off != 0 {
            base + 8 - off
        } else {
            base
        }
    };
    let atmp = unsafe { core::slice::from_raw_parts_mut(ptr.add(atmp_off), tmp_len - atmp_off) };
    if !vrfy::complete_private(big_g, f, g, big_f, logn, atmp) {
        return FALCON_ERR_FORMAT;
    }

    // Hash message to a point.
    shake256_flip(hash_data);
    let sav_hash_data = hash_data.clone();

    // Sign loop (may need to retry for PADDED format).
    loop {
        *hash_data = sav_hash_data.clone();

        let mut hm = alloc::vec![0u16; n];
        let atmp_full =
            unsafe { core::slice::from_raw_parts_mut(ptr.add(atmp_off), tmp_len - atmp_off) };
        if sig_type == FALCON_SIG_CT {
            common::hash_to_point_ct(hash_data, &mut hm, logn, &mut atmp_full[..]);
        } else {
            common::hash_to_point_vartime(hash_data, &mut hm, logn);
        }

        let mut sv_buf = alloc::vec![0i16; n];
        let sv: &mut [i16] = &mut sv_buf;
        sign::sign_dyn(sv, rng, f, g, big_f, big_g, &hm, logn, atmp_full);

        // Encode signature.
        sig[1..41].copy_from_slice(&nonce[..40]);
        let u_sig: usize = 41;
        match sig_type {
            FALCON_SIG_COMPRESSED => {
                sig[0] = 0x30 + logn as u8;
                let v = codec::comp_encode(Some(&mut sig[u_sig..]), sv, logn);
                if v == 0 {
                    return FALCON_ERR_SIZE;
                }
                *sig_len = u_sig + v;
                return 0;
            }
            FALCON_SIG_PADDED => {
                sig[0] = 0x30 + logn as u8;
                let tu = falcon_sig_padded_size(logn);
                let v = codec::comp_encode(Some(&mut sig[u_sig..tu]), sv, logn);
                if v == 0 {
                    // Signature too large for padded format, retry.
                    continue;
                }
                if u_sig + v < tu {
                    for i in u_sig + v..tu {
                        sig[i] = 0;
                    }
                }
                *sig_len = tu;
                return 0;
            }
            FALCON_SIG_CT => {
                sig[0] = 0x50 + logn as u8;
                let v = codec::trim_i16_encode(
                    Some(&mut sig[u_sig..]),
                    sv,
                    logn,
                    codec::MAX_SIG_BITS[logn as usize] as u32,
                );
                if v == 0 {
                    return FALCON_ERR_SIZE;
                }
                *sig_len = u_sig + v;
                return 0;
            }
            _ => return FALCON_ERR_BADARG,
        }
    }
}

/// Finish a signature using an expanded key ("tree" mode).
pub fn falcon_sign_tree_finish(
    rng: &mut InnerShake256Context,
    sig: &mut [u8],
    sig_len: &mut usize,
    sig_type: i32,
    expanded_key: &[u8],
    hash_data: &mut InnerShake256Context,
    nonce: &[u8],
    tmp: &mut [u8],
) -> i32 {
    if expanded_key.is_empty() {
        return FALCON_ERR_FORMAT;
    }
    let logn = expanded_key[0] as u32;
    if logn < 1 || logn > 10 {
        return FALCON_ERR_FORMAT;
    }
    if tmp.len() < falcon_tmpsize_signtree(logn) {
        return FALCON_ERR_SIZE;
    }
    let es_len = *sig_len;
    if es_len < 41 {
        return FALCON_ERR_SIZE;
    }

    // Get expanded key pointer (aligned to 8 bytes).
    let ek_ptr = &expanded_key[1..];
    let ek_addr = ek_ptr.as_ptr() as usize;
    let ek_off = if ek_addr & 7 != 0 {
        8 - (ek_addr & 7)
    } else {
        0
    };
    let expkey: &[Fpr] = unsafe {
        let p = ek_ptr.as_ptr().add(ek_off) as *const Fpr;
        let len = (expanded_key.len() - 1 - ek_off) / core::mem::size_of::<Fpr>();
        core::slice::from_raw_parts(p, len)
    };

    match sig_type {
        FALCON_SIG_COMPRESSED => {}
        FALCON_SIG_PADDED => {
            if es_len < falcon_sig_padded_size(logn) {
                return FALCON_ERR_SIZE;
            }
        }
        FALCON_SIG_CT => {
            if es_len < falcon_sig_ct_size(logn) {
                return FALCON_ERR_SIZE;
            }
        }
        _ => return FALCON_ERR_BADARG,
    }

    let n: usize = 1 << logn;
    // Length first: reborrowing `tmp` after `ptr` is derived would
    // invalidate the tags of the slices carved out of it.
    let tmp_len = tmp.len();
    let ptr = tmp.as_mut_ptr();

    // The hashed point and the signature vector are owned buffers rather than
    // `u16`/`i16` views into `tmp`: see the note in `falcon_sign_dyn_finish`.
    // `tmp` is therefore pure scratch here, aligned once for `Fpr`.
    let atmp_off = {
        let addr = ptr as usize;
        let off = addr & 7;
        if off != 0 {
            8 - off
        } else {
            0
        }
    };

    shake256_flip(hash_data);
    let sav_hash_data = hash_data.clone();

    loop {
        *hash_data = sav_hash_data.clone();

        let mut hm = alloc::vec![0u16; n];
        let atmp =
            unsafe { core::slice::from_raw_parts_mut(ptr.add(atmp_off), tmp_len - atmp_off) };
        if sig_type == FALCON_SIG_CT {
            common::hash_to_point_ct(hash_data, &mut hm, logn, &mut atmp[..]);
        } else {
            common::hash_to_point_vartime(hash_data, &mut hm, logn);
        }

        let mut sv_buf = alloc::vec![0i16; n];
        let sv: &mut [i16] = &mut sv_buf;
        sign::sign_tree(sv, rng, expkey, &hm, logn, atmp);

        sig[1..41].copy_from_slice(&nonce[..40]);
        let u_sig: usize = 41;
        match sig_type {
            FALCON_SIG_COMPRESSED => {
                sig[0] = 0x30 + logn as u8;
                let v = codec::comp_encode(Some(&mut sig[u_sig..]), sv, logn);
                if v == 0 {
                    return FALCON_ERR_SIZE;
                }
                *sig_len = u_sig + v;
                return 0;
            }
            FALCON_SIG_PADDED => {
                sig[0] = 0x30 + logn as u8;
                let tu = falcon_sig_padded_size(logn);
                let v = codec::comp_encode(Some(&mut sig[u_sig..tu]), sv, logn);
                if v == 0 {
                    continue;
                }
                if u_sig + v < tu {
                    for i in u_sig + v..tu {
                        sig[i] = 0;
                    }
                }
                *sig_len = tu;
                return 0;
            }
            FALCON_SIG_CT => {
                sig[0] = 0x50 + logn as u8;
                let v = codec::trim_i16_encode(
                    Some(&mut sig[u_sig..]),
                    sv,
                    logn,
                    codec::MAX_SIG_BITS[logn as usize] as u32,
                );
                if v == 0 {
                    return FALCON_ERR_SIZE;
                }
                *sig_len = u_sig + v;
                return 0;
            }
            _ => return FALCON_ERR_BADARG,
        }
    }
}

/// Sign data using the raw private key ("dynamic" mode).
///
/// This is the low-level port of the C reference API: it returns the
/// signature **without verifying it**. The fault self-check — which turns a
/// corrupted computation into an error rather than a signature that can
/// expose the private basis — lives in the high-level [`crate::safe_api`]
/// wrappers. If you sign through this layer, verify the result against the
/// public key yourself before releasing it.
pub fn falcon_sign_dyn(
    rng: &mut InnerShake256Context,
    sig: &mut [u8],
    sig_len: &mut usize,
    sig_type: i32,
    privkey: &[u8],
    data: &[u8],
    tmp: &mut [u8],
) -> i32 {
    let mut hd = InnerShake256Context::new();
    let mut nonce = [0u8; 40];
    let r = falcon_sign_start(rng, &mut nonce, &mut hd);
    if r != 0 {
        return r;
    }
    shake256_inject(&mut hd, data);
    falcon_sign_dyn_finish(rng, sig, sig_len, sig_type, privkey, &mut hd, &nonce, tmp)
}

/// Sign data using an expanded key ("tree" mode).
///
/// Like [`falcon_sign_dyn`], this low-level entry point returns the
/// signature **without verifying it**; the fault self-check lives in
/// [`crate::safe_api`].
pub fn falcon_sign_tree(
    rng: &mut InnerShake256Context,
    sig: &mut [u8],
    sig_len: &mut usize,
    sig_type: i32,
    expanded_key: &[u8],
    data: &[u8],
    tmp: &mut [u8],
) -> i32 {
    let mut hd = InnerShake256Context::new();
    let mut nonce = [0u8; 40];
    let r = falcon_sign_start(rng, &mut nonce, &mut hd);
    if r != 0 {
        return r;
    }
    shake256_inject(&mut hd, data);
    falcon_sign_tree_finish(
        rng,
        sig,
        sig_len,
        sig_type,
        expanded_key,
        &mut hd,
        &nonce,
        tmp,
    )
}

/// Expand a private key for use with sign_tree.
pub fn falcon_expand_privkey(expanded_key: &mut [u8], privkey: &[u8], tmp: &mut [u8]) -> i32 {
    if privkey.is_empty() {
        return FALCON_ERR_FORMAT;
    }
    if privkey[0] & 0xF0 != 0x50 {
        return FALCON_ERR_FORMAT;
    }
    let logn = (privkey[0] & 0x0F) as u32;
    if logn < 1 || logn > 10 {
        return FALCON_ERR_FORMAT;
    }
    if privkey.len() != falcon_privkey_size(logn) {
        return FALCON_ERR_FORMAT;
    }
    if expanded_key.len() < falcon_expandedkey_size(logn) {
        return FALCON_ERR_SIZE;
    }
    if tmp.len() < falcon_tmpsize_expandpriv(logn) {
        return FALCON_ERR_SIZE;
    }

    let n: usize = 1 << logn;
    // Length first: reborrowing `tmp` after `ptr` is derived would
    // invalidate the tags of the slices carved out of it.
    let tmp_len = tmp.len();
    let ptr = tmp.as_mut_ptr();

    // Decode private key.
    let f = unsafe { core::slice::from_raw_parts_mut(ptr as *mut i8, n) };
    let g = unsafe { core::slice::from_raw_parts_mut(ptr.add(n) as *mut i8, n) };
    let big_f = unsafe { core::slice::from_raw_parts_mut(ptr.add(2 * n) as *mut i8, n) };
    let big_g = unsafe { core::slice::from_raw_parts_mut(ptr.add(3 * n) as *mut i8, n) };

    let mut u: usize = 1;
    let v = codec::trim_i8_decode(
        f,
        logn,
        codec::MAX_FG_BITS[logn as usize] as u32,
        &privkey[u..],
    );
    if v == 0 {
        return FALCON_ERR_FORMAT;
    }
    u += v;
    let v = codec::trim_i8_decode(
        g,
        logn,
        codec::MAX_FG_BITS[logn as usize] as u32,
        &privkey[u..],
    );
    if v == 0 {
        return FALCON_ERR_FORMAT;
    }
    u += v;
    let v = codec::trim_i8_decode(
        big_f,
        logn,
        codec::MAX_FG_BITS_UPPER[logn as usize] as u32,
        &privkey[u..],
    );
    if v == 0 {
        return FALCON_ERR_FORMAT;
    }
    u += v;
    if u != privkey.len() {
        return FALCON_ERR_FORMAT;
    }

    // Complete private key (recover G).
    let atmp_off = {
        let base = 4 * n;
        let addr = unsafe { ptr.add(base) as usize };
        let off = addr & 7;
        if off != 0 {
            base + 8 - off
        } else {
            base
        }
    };
    let atmp = unsafe { core::slice::from_raw_parts_mut(ptr.add(atmp_off), tmp_len - atmp_off) };
    if !vrfy::complete_private(big_g, f, g, big_f, logn, atmp) {
        return FALCON_ERR_FORMAT;
    }

    // Expand key.
    expanded_key[0] = logn as u8;
    let ek_addr = expanded_key[1..].as_ptr() as usize;
    let ek_off = if ek_addr & 7 != 0 {
        8 - (ek_addr & 7)
    } else {
        0
    };
    let expkey: &mut [Fpr] = unsafe {
        let p = expanded_key[1..].as_mut_ptr().add(ek_off) as *mut Fpr;
        let len = (expanded_key.len() - 1 - ek_off) / core::mem::size_of::<Fpr>();
        core::slice::from_raw_parts_mut(p, len)
    };

    let atmp2 = unsafe { core::slice::from_raw_parts_mut(ptr.add(atmp_off), tmp_len - atmp_off) };
    sign::expand_privkey(expkey, f, g, big_f, big_g, logn, atmp2);
    0
}

// ======================================================================
// Signature verification
// ======================================================================

/// Start a streamed verification: extract nonce from signature and init hash.
pub fn falcon_verify_start(hash_data: &mut InnerShake256Context, sig: &[u8]) -> i32 {
    if sig.len() < 41 {
        return FALCON_ERR_FORMAT;
    }
    shake256_init(hash_data);
    shake256_inject(hash_data, &sig[1..41]);
    0
}

/// Finish a streamed verification.
pub fn falcon_verify_finish(
    sig: &[u8],
    sig_type: i32,
    pubkey: &[u8],
    hash_data: &mut InnerShake256Context,
    tmp: &mut [u8],
) -> i32 {
    if sig.len() < 41 || pubkey.is_empty() {
        return FALCON_ERR_FORMAT;
    }
    if pubkey[0] & 0xF0 != 0x00 {
        return FALCON_ERR_FORMAT;
    }
    let logn = (pubkey[0] & 0x0F) as u32;
    if logn < 1 || logn > 10 {
        return FALCON_ERR_FORMAT;
    }
    if sig[0] & 0x0F != logn as u8 {
        return FALCON_ERR_BADSIG;
    }

    let mut ct = false;
    match sig_type {
        0 => match sig[0] & 0xF0 {
            0x30 => {}
            0x50 => {
                if sig.len() != falcon_sig_ct_size(logn) {
                    return FALCON_ERR_FORMAT;
                }
                ct = true;
            }
            _ => return FALCON_ERR_BADSIG,
        },
        FALCON_SIG_COMPRESSED => {
            if sig[0] & 0xF0 != 0x30 {
                return FALCON_ERR_FORMAT;
            }
        }
        FALCON_SIG_PADDED => {
            if sig[0] & 0xF0 != 0x30 {
                return FALCON_ERR_FORMAT;
            }
            if sig.len() != falcon_sig_padded_size(logn) {
                return FALCON_ERR_FORMAT;
            }
        }
        FALCON_SIG_CT => {
            if sig[0] & 0xF0 != 0x50 {
                return FALCON_ERR_FORMAT;
            }
            if sig.len() != falcon_sig_ct_size(logn) {
                return FALCON_ERR_FORMAT;
            }
            ct = true;
        }
        _ => return FALCON_ERR_BADARG,
    }

    if pubkey.len() != falcon_pubkey_size(logn) {
        return FALCON_ERR_FORMAT;
    }
    if tmp.len() < falcon_tmpsize_verify(logn) {
        return FALCON_ERR_SIZE;
    }

    let n: usize = 1 << logn;
    // Length first: reborrowing `tmp` after `ptr` is derived would
    // invalidate the tags of the slices carved out of it.
    let tmp_len = tmp.len();
    let ptr = tmp.as_mut_ptr();

    // Align for u16.
    let base_off = if (ptr as usize) & 1 != 0 {
        1usize
    } else {
        0usize
    };
    let h = unsafe { core::slice::from_raw_parts_mut(ptr.add(base_off) as *mut u16, n) };
    let hm = unsafe { core::slice::from_raw_parts_mut(ptr.add(base_off + 2 * n) as *mut u16, n) };
    let sv = unsafe { core::slice::from_raw_parts_mut(ptr.add(base_off + 4 * n) as *mut i16, n) };
    let atmp = unsafe {
        let off = base_off + 6 * n;
        core::slice::from_raw_parts_mut(ptr.add(off), tmp_len - off)
    };

    // Decode public key.
    if codec::modq_decode(h, logn, &pubkey[1..]) != pubkey.len() - 1 {
        return FALCON_ERR_FORMAT;
    }

    // Decode signature.
    let u_sig: usize = 41;
    let v = if ct {
        codec::trim_i16_decode(
            sv,
            logn,
            codec::MAX_SIG_BITS[logn as usize] as u32,
            &sig[u_sig..],
        )
    } else {
        codec::comp_decode(sv, logn, &sig[u_sig..])
    };
    if v == 0 {
        return FALCON_ERR_FORMAT;
    }

    if u_sig + v != sig.len() {
        // Extra zero bytes tolerated only for padded format.
        if (sig_type == 0 && sig.len() == falcon_sig_padded_size(logn))
            || sig_type == FALCON_SIG_PADDED
        {
            let mut pos = u_sig + v;
            while pos < sig.len() {
                if sig[pos] != 0 {
                    return FALCON_ERR_FORMAT;
                }
                pos += 1;
            }
        } else {
            return FALCON_ERR_FORMAT;
        }
    }

    // Hash message to point.
    shake256_flip(hash_data);
    if ct {
        common::hash_to_point_ct(hash_data, hm, logn, atmp);
    } else {
        common::hash_to_point_vartime(hash_data, hm, logn);
    }

    // Verify signature.
    vrfy::to_ntt_monty(h, logn);
    if !vrfy::verify_raw(hm, sv, h, logn, atmp) {
        return FALCON_ERR_BADSIG;
    }
    0
}

/// Verify a signature against a public key and data.
pub fn falcon_verify(sig: &[u8], sig_type: i32, pubkey: &[u8], data: &[u8], tmp: &mut [u8]) -> i32 {
    let mut hd = InnerShake256Context::new();
    let r = falcon_verify_start(&mut hd, sig);
    if r < 0 {
        return r;
    }
    shake256_inject(&mut hd, data);
    falcon_verify_finish(sig, sig_type, pubkey, &mut hd, tmp)
}

#[cfg(test)]
mod alignment_tests {
    use super::*;

    /// The alignment helpers must advance a misaligned buffer to the next
    /// boundary and leave an aligned one untouched. Callers rely on this
    /// before reinterpreting the scratch buffer as `u16`/`u64`/`Fpr`.
    #[test]
    fn align_helpers_advance_misaligned_buffers() {
        let mut backing = [0u8; 64];

        for skew in 0..8usize {
            let slice = &mut backing[skew..];
            let base = slice.as_ptr() as usize;

            let aligned = align_u64(slice);
            assert_eq!(
                aligned.as_ptr() as usize % 8,
                0,
                "align_u64 left a misaligned pointer (skew {skew})"
            );
            let advanced = aligned.as_ptr() as usize - base;
            assert_eq!(advanced, (8 - (base & 7)) & 7);

            let slice = &mut backing[skew..];
            let base = slice.as_ptr() as usize;
            let aligned = align_u16(slice);
            assert_eq!(
                aligned.as_ptr() as usize % 2,
                0,
                "align_u16 left a misaligned pointer (skew {skew})"
            );
            assert_eq!(aligned.as_ptr() as usize - base, base & 1);
        }
    }

    /// `align_fpr` must agree with `align_u64`: `Fpr` is 8-byte aligned on
    /// both backends.
    #[test]
    fn align_fpr_matches_u64() {
        assert_eq!(core::mem::align_of::<Fpr>(), 8);
        let mut backing = [0u8; 32];
        for skew in 0..8usize {
            let a = align_fpr(&mut backing[skew..]).as_ptr() as usize;
            let b = align_u64(&mut backing[skew..]).as_ptr() as usize;
            assert_eq!(a, b);
        }
    }

    /// The two SHAKE256 PRNG constructors are part of the low-level API and
    /// must produce a usable, deterministic (respectively fresh) stream.
    ///
    /// `std`-only: seeding from the system RNG needs an entropy source.
    #[cfg(feature = "std")]
    #[test]
    fn shake256_prng_constructors() {
        let mut a = InnerShake256Context::new();
        shake256_init_prng_from_seed(&mut a, b"a fixed seed");
        let mut b = InnerShake256Context::new();
        shake256_init_prng_from_seed(&mut b, b"a fixed seed");

        let (mut oa, mut ob) = ([0u8; 32], [0u8; 32]);
        shake256_extract(&mut a, &mut oa);
        shake256_extract(&mut b, &mut ob);
        assert_eq!(oa, ob, "the same seed must give the same stream");

        let mut c = InnerShake256Context::new();
        assert_eq!(shake256_init_prng_from_system(&mut c), 0);
        let mut oc = [0u8; 32];
        shake256_extract(&mut c, &mut oc);
        assert_ne!(oc, oa, "an OS-seeded stream must differ from a fixed one");
    }
}
