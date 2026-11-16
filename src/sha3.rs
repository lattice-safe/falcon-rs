//! SHA3-224/256/384/512 (FIPS 202), on the crate's Keccak-f\[1600\] core.
//!
//! Ported from `sha3_init` / `sha3_update` / `sha3_close` in c-fn-dsa's
//! `sha3.c`. FN-DSA itself only needs SHAKE256, but the reference defines
//! SHA3 pre-hash identifiers and its end-to-end test vectors pre-hash with
//! SHA3-256, so the port needs a matching implementation.

use zeroize::Zeroize;

use crate::shake::process_block;

/// Incremental SHA3 context. The output size (224, 256, 384 or 512 bits)
/// is fixed at construction.
#[derive(Clone)]
pub struct Sha3Context {
    st: [u64; 25],
    dptr: usize,
    rate: usize,
}

impl Sha3Context {
    /// Create a context for SHA3 with an output of `bits` bits.
    ///
    /// # Panics
    ///
    /// If `bits` is not 224, 256, 384 or 512.
    pub fn new(bits: usize) -> Self {
        assert!(
            matches!(bits, 224 | 256 | 384 | 512),
            "unsupported SHA3 output size: {bits}"
        );
        Sha3Context {
            st: [0u64; 25],
            dptr: 0,
            // The capacity is twice the output size.
            rate: 200 - (bits >> 2),
        }
    }

    /// Output length in bytes.
    pub fn output_len(&self) -> usize {
        (200 - self.rate) >> 1
    }

    /// Absorb more input.
    pub fn update(&mut self, data: &[u8]) {
        let mut dptr = self.dptr;
        for &b in data {
            self.st[dptr >> 3] ^= (b as u64) << ((dptr & 7) << 3);
            dptr += 1;
            if dptr == self.rate {
                process_block(&mut self.st);
                dptr = 0;
            }
        }
        self.dptr = dptr;
    }

    /// Finish the computation and write the digest into `out`, which must
    /// be exactly [`output_len`](Self::output_len) bytes. The context is
    /// reset afterwards, as in the reference, and can be reused.
    ///
    /// # Panics
    ///
    /// If `out` has the wrong length.
    pub fn finalize_into(&mut self, out: &mut [u8]) {
        let len = self.output_len();
        assert_eq!(out.len(), len, "SHA3 output buffer has the wrong length");

        // SHA3 domain-separation padding is '01' then pad10*1, which is
        // 0x06 ... 0x80 (SHAKE uses 0x1F instead of 0x06).
        let v = self.dptr;
        self.st[v >> 3] ^= 0x06u64 << ((v & 7) << 3);
        let v = self.rate - 1;
        self.st[v >> 3] ^= 0x80u64 << ((v & 7) << 3);
        process_block(&mut self.st);

        for (i, o) in out.iter_mut().enumerate() {
            *o = (self.st[i >> 3] >> ((i & 7) << 3)) as u8;
        }

        self.st.zeroize();
        self.dptr = 0;
    }
}

impl Drop for Sha3Context {
    fn drop(&mut self) {
        self.st.zeroize();
        self.dptr = 0;
    }
}

/// One-shot SHA3-256.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut sc = Sha3Context::new(256);
    sc.update(data);
    sc.finalize_into(&mut out);
    out
}

/// One-shot SHA3-512.
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut sc = Sha3Context::new(512);
    sc.update(data);
    sc.finalize_into(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS 202 empty-input digests.
    #[test]
    fn empty_input() {
        assert_eq!(
            sha3_256(b""),
            *b"\xa7\xff\xc6\xf8\xbf\x1e\xd7\x66\x51\xc1\x47\x56\xa0\x61\xd6\x62\
               \xf5\x80\xff\x4d\xe4\x3b\x49\xfa\x82\xd8\x0a\x4b\x80\xf8\x43\x4a"
        );
        let d = sha3_512(b"");
        assert_eq!(&d[..4], b"\xa6\x9f\x73\xcc");
        assert_eq!(&d[60..], b"\x28\x1d\xcd\x26");
    }

    #[test]
    fn context_is_reusable_after_finalize() {
        let mut sc = Sha3Context::new(256);
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        sc.update(b"abc");
        sc.finalize_into(&mut a);
        sc.update(b"abc");
        sc.finalize_into(&mut b);
        assert_eq!(a, b);
    }

    #[test]
    #[should_panic(expected = "unsupported SHA3 output size")]
    fn rejects_bad_size() {
        let _ = Sha3Context::new(128);
    }

    #[test]
    #[should_panic(expected = "wrong length")]
    fn rejects_bad_output_len() {
        let mut sc = Sha3Context::new(256);
        sc.finalize_into(&mut [0u8; 31]);
    }
}
