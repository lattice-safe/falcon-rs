/// NIST Known Answer Tests for Falcon.
///
/// Reproduces the exact NIST PQC KAT test procedure:
/// - AES-256-CTR DRBG for deterministic randomness
/// - 100 iterations of keygen → sign → verify
/// - SHA-1 hash of all outputs compared against reference hashes
///
/// Reference SHA-1 hashes from the C implementation:
/// - Falcon-512: a57400cbaee7109358859a56c735a3cf048a9da2
/// - Falcon-1024: affdeb3aa83bf9a2039fa9c17d65fd3e3b9828e2
use falcon::shake::{i_shake256_flip, i_shake256_init, i_shake256_inject, InnerShake256Context};
use falcon::{codec, common, fpr::Fpr, keygen, sign, vrfy};

// ======================================================================
// AES-256 implementation (for NIST DRBG only)
// ======================================================================

static S: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

static RCON: [u32; 10] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000,
];

fn dec32be(src: &[u8]) -> u32 {
    (src[0] as u32) << 24 | (src[1] as u32) << 16 | (src[2] as u32) << 8 | src[3] as u32
}

fn enc32be(dst: &mut [u8], val: u32) {
    dst[0] = (val >> 24) as u8;
    dst[1] = (val >> 16) as u8;
    dst[2] = (val >> 8) as u8;
    dst[3] = val as u8;
}

fn sub_word(x: u32) -> u32 {
    (S[(x >> 24) as usize] as u32) << 24
        | (S[((x >> 16) & 0xFF) as usize] as u32) << 16
        | (S[((x >> 8) & 0xFF) as usize] as u32) << 8
        | S[(x & 0xFF) as usize] as u32
}

fn aes256_keysched(skey: &mut [u32; 60], key: &[u8]) {
    for i in 0..8 {
        skey[i] = dec32be(&key[i << 2..]);
    }
    let (mut j, mut k) = (0usize, 0usize);
    for i in 8..60 {
        let mut tmp = skey[i - 1];
        if j == 0 {
            tmp = tmp.rotate_left(8);
            tmp = sub_word(tmp) ^ RCON[k];
        } else if j == 4 {
            tmp = sub_word(tmp);
        }
        skey[i] = skey[i - 8] ^ tmp;
        j += 1;
        if j == 8 {
            j = 0;
            k += 1;
        }
    }
}

#[rustfmt::skip]
static SSM0: [u32; 256] = [
    0xC66363A5,0xF87C7C84,0xEE777799,0xF67B7B8D,0xFFF2F20D,0xD66B6BBD,0xDE6F6FB1,0x91C5C554,
    0x60303050,0x02010103,0xCE6767A9,0x562B2B7D,0xE7FEFE19,0xB5D7D762,0x4DABABE6,0xEC76769A,
    0x8FCACA45,0x1F82829D,0x89C9C940,0xFA7D7D87,0xEFFAFA15,0xB25959EB,0x8E4747C9,0xFBF0F00B,
    0x41ADADEC,0xB3D4D467,0x5FA2A2FD,0x45AFAFEA,0x239C9CBF,0x53A4A4F7,0xE4727296,0x9BC0C05B,
    0x75B7B7C2,0xE1FDFD1C,0x3D9393AE,0x4C26266A,0x6C36365A,0x7E3F3F41,0xF5F7F702,0x83CCCC4F,
    0x6834345C,0x51A5A5F4,0xD1E5E534,0xF9F1F108,0xE2717193,0xABD8D873,0x62313153,0x2A15153F,
    0x0804040C,0x95C7C752,0x46232365,0x9DC3C35E,0x30181828,0x379696A1,0x0A05050F,0x2F9A9AB5,
    0x0E070709,0x24121236,0x1B80809B,0xDFE2E23D,0xCDEBEB26,0x4E272769,0x7FB2B2CD,0xEA75759F,
    0x1209091B,0x1D83839E,0x582C2C74,0x341A1A2E,0x361B1B2D,0xDC6E6EB2,0xB45A5AEE,0x5BA0A0FB,
    0xA45252F6,0x763B3B4D,0xB7D6D661,0x7DB3B3CE,0x5229297B,0xDDE3E33E,0x5E2F2F71,0x13848497,
    0xA65353F5,0xB9D1D168,0x00000000,0xC1EDED2C,0x40202060,0xE3FCFC1F,0x79B1B1C8,0xB65B5BED,
    0xD46A6ABE,0x8DCBCB46,0x67BEBED9,0x7239394B,0x944A4ADE,0x984C4CD4,0xB05858E8,0x85CFCF4A,
    0xBBD0D06B,0xC5EFEF2A,0x4FAAAAE5,0xEDFBFB16,0x864343C5,0x9A4D4DD7,0x66333355,0x11858594,
    0x8A4545CF,0xE9F9F910,0x04020206,0xFE7F7F81,0xA05050F0,0x783C3C44,0x259F9FBA,0x4BA8A8E3,
    0xA25151F3,0x5DA3A3FE,0x804040C0,0x058F8F8A,0x3F9292AD,0x219D9DBC,0x70383848,0xF1F5F504,
    0x63BCBCDF,0x77B6B6C1,0xAFDADA75,0x42212163,0x20101030,0xE5FFFF1A,0xFDF3F30E,0xBFD2D26D,
    0x81CDCD4C,0x180C0C14,0x26131335,0xC3ECEC2F,0xBE5F5FE1,0x359797A2,0x884444CC,0x2E171739,
    0x93C4C457,0x55A7A7F2,0xFC7E7E82,0x7A3D3D47,0xC86464AC,0xBA5D5DE7,0x3219192B,0xE6737395,
    0xC06060A0,0x19818198,0x9E4F4FD1,0xA3DCDC7F,0x44222266,0x542A2A7E,0x3B9090AB,0x0B888883,
    0x8C4646CA,0xC7EEEE29,0x6BB8B8D3,0x2814143C,0xA7DEDE79,0xBC5E5EE2,0x160B0B1D,0xADDBDB76,
    0xDBE0E03B,0x64323256,0x743A3A4E,0x140A0A1E,0x924949DB,0x0C06060A,0x4824246C,0xB85C5CE4,
    0x9FC2C25D,0xBDD3D36E,0x43ACACEF,0xC46262A6,0x399191A8,0x319595A4,0xD3E4E437,0xF279798B,
    0xD5E7E732,0x8BC8C843,0x6E373759,0xDA6D6DB7,0x018D8D8C,0xB1D5D564,0x9C4E4ED2,0x49A9A9E0,
    0xD86C6CB4,0xAC5656FA,0xF3F4F407,0xCFEAEA25,0xCA6565AF,0xF47A7A8E,0x47AEAEE9,0x10080818,
    0x6FBABAD5,0xF0787888,0x4A25256F,0x5C2E2E72,0x381C1C24,0x57A6A6F1,0x73B4B4C7,0x97C6C651,
    0xCBE8E823,0xA1DDDD7C,0xE874749C,0x3E1F1F21,0x964B4BDD,0x61BDBDDC,0x0D8B8B86,0x0F8A8A85,
    0xE0707090,0x7C3E3E42,0x71B5B5C4,0xCC6666AA,0x904848D8,0x06030305,0xF7F6F601,0x1C0E0E12,
    0xC26161A3,0x6A35355F,0xAE5757F9,0x69B9B9D0,0x17868691,0x99C1C158,0x3A1D1D27,0x279E9EB9,
    0xD9E1E138,0xEBF8F813,0x2B9898B3,0x22111133,0xD26969BB,0xA9D9D970,0x078E8E89,0x339494A7,
    0x2D9B9BB6,0x3C1E1E22,0x15878792,0xC9E9E920,0x87CECE49,0xAA5555FF,0x50282878,0xA5DFDF7A,
    0x038C8C8F,0x59A1A1F8,0x09898980,0x1A0D0D17,0x65BFBFDA,0xD7E6E631,0x844242C6,0xD06868B8,
    0x824141C3,0x299999B0,0x5A2D2D77,0x1E0F0F11,0x7BB0B0CB,0xA85454FC,0x6DBBBBD6,0x2C16163A,
];

fn rotr(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}

fn aes256_encrypt(skey: &[u32; 60], data: &mut [u8; 16]) {
    let mut s0 = dec32be(&data[0..]) ^ skey[0];
    let mut s1 = dec32be(&data[4..]) ^ skey[1];
    let mut s2 = dec32be(&data[8..]) ^ skey[2];
    let mut s3 = dec32be(&data[12..]) ^ skey[3];
    for u in 1..14u32 {
        let v0 = SSM0[(s0 >> 24) as usize]
            ^ rotr(SSM0[((s1 >> 16) & 0xFF) as usize], 8)
            ^ rotr(SSM0[((s2 >> 8) & 0xFF) as usize], 16)
            ^ rotr(SSM0[(s3 & 0xFF) as usize], 24);
        let v1 = SSM0[(s1 >> 24) as usize]
            ^ rotr(SSM0[((s2 >> 16) & 0xFF) as usize], 8)
            ^ rotr(SSM0[((s3 >> 8) & 0xFF) as usize], 16)
            ^ rotr(SSM0[(s0 & 0xFF) as usize], 24);
        let v2 = SSM0[(s2 >> 24) as usize]
            ^ rotr(SSM0[((s3 >> 16) & 0xFF) as usize], 8)
            ^ rotr(SSM0[((s0 >> 8) & 0xFF) as usize], 16)
            ^ rotr(SSM0[(s1 & 0xFF) as usize], 24);
        let v3 = SSM0[(s3 >> 24) as usize]
            ^ rotr(SSM0[((s0 >> 16) & 0xFF) as usize], 8)
            ^ rotr(SSM0[((s1 >> 8) & 0xFF) as usize], 16)
            ^ rotr(SSM0[(s2 & 0xFF) as usize], 24);
        s0 = v0 ^ skey[(u << 2) as usize];
        s1 = v1 ^ skey[((u << 2) + 1) as usize];
        s2 = v2 ^ skey[((u << 2) + 2) as usize];
        s3 = v3 ^ skey[((u << 2) + 3) as usize];
    }
    let t0 = (S[(s0 >> 24) as usize] as u32) << 24
        | (S[((s1 >> 16) & 0xFF) as usize] as u32) << 16
        | (S[((s2 >> 8) & 0xFF) as usize] as u32) << 8
        | S[(s3 & 0xFF) as usize] as u32;
    let t1 = (S[(s1 >> 24) as usize] as u32) << 24
        | (S[((s2 >> 16) & 0xFF) as usize] as u32) << 16
        | (S[((s3 >> 8) & 0xFF) as usize] as u32) << 8
        | S[(s0 & 0xFF) as usize] as u32;
    let t2 = (S[(s2 >> 24) as usize] as u32) << 24
        | (S[((s3 >> 16) & 0xFF) as usize] as u32) << 16
        | (S[((s0 >> 8) & 0xFF) as usize] as u32) << 8
        | S[(s1 & 0xFF) as usize] as u32;
    let t3 = (S[(s3 >> 24) as usize] as u32) << 24
        | (S[((s0 >> 16) & 0xFF) as usize] as u32) << 16
        | (S[((s1 >> 8) & 0xFF) as usize] as u32) << 8
        | S[(s2 & 0xFF) as usize] as u32;
    enc32be(&mut data[0..], t0 ^ skey[56]);
    enc32be(&mut data[4..], t1 ^ skey[57]);
    enc32be(&mut data[8..], t2 ^ skey[58]);
    enc32be(&mut data[12..], t3 ^ skey[59]);
}

// ======================================================================
// NIST AES-256-CTR DRBG
// ======================================================================

struct NistDrbg {
    key: [u8; 32],
    v: [u8; 16],
}

impl NistDrbg {
    fn new() -> Self {
        NistDrbg {
            key: [0u8; 32],
            v: [0u8; 16],
        }
    }

    fn update(&mut self, provided_data: Option<&[u8; 48]>) {
        let mut skey = [0u32; 60];
        aes256_keysched(&mut skey, &self.key);
        let mut tmp = [0u8; 48];
        for i in 0..3 {
            let mut cc: u32 = 1;
            for j in (0..16).rev() {
                let w = self.v[j] as u32 + cc;
                self.v[j] = w as u8;
                cc = w >> 8;
            }
            let mut block = [0u8; 16];
            block.copy_from_slice(&self.v);
            aes256_encrypt(&skey, &mut block);
            tmp[i * 16..(i + 1) * 16].copy_from_slice(&block);
        }
        if let Some(pd) = provided_data {
            for i in 0..48 {
                tmp[i] ^= pd[i];
            }
        }
        self.key.copy_from_slice(&tmp[..32]);
        self.v.copy_from_slice(&tmp[32..48]);
    }

    fn init(&mut self, ei: &[u8; 48]) {
        self.key = [0u8; 32];
        self.v = [0u8; 16];
        let mut e = [0u8; 48];
        e.copy_from_slice(ei);
        self.update(Some(&e));
    }

    fn randombytes(&mut self, buf: &mut [u8]) {
        let (mut off, mut rem) = (0, buf.len());
        while rem > 0 {
            let mut cc: u32 = 1;
            for j in (0..16).rev() {
                let w = self.v[j] as u32 + cc;
                self.v[j] = w as u8;
                cc = w >> 8;
            }
            let mut skey = [0u32; 60];
            aes256_keysched(&mut skey, &self.key);
            let mut block = [0u8; 16];
            block.copy_from_slice(&self.v);
            aes256_encrypt(&skey, &mut block);
            let c = std::cmp::min(rem, 16);
            buf[off..off + c].copy_from_slice(&block[..c]);
            off += c;
            rem -= c;
        }
        self.update(None);
    }
}

// ======================================================================
// SHA-1
// ======================================================================

struct Sha1 {
    buf: [u8; 64],
    val: [u32; 5],
    count: u64,
}

impl Sha1 {
    fn new() -> Self {
        Sha1 {
            buf: [0u8; 64],
            val: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            count: 0,
        }
    }

    fn round_inner(buf: &[u8; 64], val: &mut [u32; 5]) {
        let mut m = [0u32; 80];
        for (i, mi) in m.iter_mut().enumerate().take(16) {
            *mi = dec32be(&buf[i << 2..]);
        }
        for i in 16..80 {
            let x = m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16];
            m[i] = x.rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (val[0], val[1], val[2], val[3], val[4]);
        for mi in m.iter().take(20) {
            let t = a
                .rotate_left(5)
                .wrapping_add((b & c) ^ (!b & d))
                .wrapping_add(e)
                .wrapping_add(0x5A827999)
                .wrapping_add(*mi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for mi in m.iter().skip(20).take(20) {
            let t = a
                .rotate_left(5)
                .wrapping_add(b ^ c ^ d)
                .wrapping_add(e)
                .wrapping_add(0x6ED9EBA1)
                .wrapping_add(*mi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for mi in m.iter().skip(40).take(20) {
            let t = a
                .rotate_left(5)
                .wrapping_add((b & c) | (b & d) | (c & d))
                .wrapping_add(e)
                .wrapping_add(0x8F1BBCDC)
                .wrapping_add(*mi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for mi in m.iter().skip(60) {
            let t = a
                .rotate_left(5)
                .wrapping_add(b ^ c ^ d)
                .wrapping_add(e)
                .wrapping_add(0xCA62C1D6)
                .wrapping_add(*mi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        val[0] = val[0].wrapping_add(a);
        val[1] = val[1].wrapping_add(b);
        val[2] = val[2].wrapping_add(c);
        val[3] = val[3].wrapping_add(d);
        val[4] = val[4].wrapping_add(e);
    }

    fn update(&mut self, data: &[u8]) {
        let mut ptr = (self.count & 63) as usize;
        self.count += data.len() as u64;
        let (mut off, mut rem) = (0, data.len());
        while rem > 0 {
            let c = std::cmp::min(64 - ptr, rem);
            self.buf[ptr..ptr + c].copy_from_slice(&data[off..off + c]);
            off += c;
            rem -= c;
            ptr += c;
            if ptr == 64 {
                let buf_copy = self.buf;
                Self::round_inner(&buf_copy, &mut self.val);
                ptr = 0;
            }
        }
    }

    fn finalize(&self) -> [u8; 20] {
        let mut buf = [0u8; 64];
        let mut val = self.val;
        let ptr = (self.count & 63) as usize;
        buf[..ptr].copy_from_slice(&self.buf[..ptr]);
        buf[ptr] = 0x80;
        if ptr > 55 {
            Self::round_inner(&buf, &mut val);
            buf = [0u8; 64];
        } else {
            buf[ptr + 1..56].fill(0);
        }
        enc32be(&mut buf[56..], (self.count >> 29) as u32);
        enc32be(&mut buf[60..], (self.count << 3) as u32);
        Self::round_inner(&buf, &mut val);
        let mut out = [0u8; 20];
        for i in 0..5 {
            enc32be(&mut out[i << 2..], val[i]);
        }
        out
    }

    fn print_line(&mut self, s: &str) {
        self.update(s.as_bytes());
        self.update(b"\n");
    }
    fn print_line_with_int(&mut self, prefix: &str, x: u32) {
        self.update(prefix.as_bytes());
        self.update(format!("{}", x).as_bytes());
        self.update(b"\n");
    }
    fn print_line_with_hex(&mut self, prefix: &str, data: &[u8]) {
        self.update(prefix.as_bytes());
        for b in data {
            let hi = "0123456789ABCDEF".as_bytes()[(b >> 4) as usize];
            let lo = "0123456789ABCDEF".as_bytes()[(b & 0x0F) as usize];
            self.update(&[hi, lo]);
        }
        self.update(b"\n");
    }
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// ======================================================================
// NIST KAT Test
// ======================================================================

fn run_nist_kat(logn: u32, expected_hash: &str) {
    let n: usize = 1 << logn;
    let sk_len = if logn == 9 { 1281 } else { 2305 };
    let pk_len = if logn == 9 { 897 } else { 1793 };
    let over_len = if logn == 9 { 690 } else { 1330 };

    let mut hhc = Sha1::new();
    hhc.print_line_with_int("# Falcon-", n as u32);
    hhc.print_line("");

    let mut entropy_input = [0u8; 48];
    for (i, byte) in entropy_input.iter_mut().enumerate() {
        *byte = i as u8;
    }
    let mut drbg = NistDrbg::new();
    drbg.init(&entropy_input);

    let tmp_size: usize = 84 << logn;
    let mut tmp = vec![0u8; tmp_size];
    let mut msg = vec![0u8; 3300];
    let mut sk = vec![0u8; sk_len];
    let mut pk = vec![0u8; pk_len];
    let mut sm = vec![0u8; 3300 + over_len];

    for i in 0..100u32 {
        let mut seed = [0u8; 48];
        drbg.randombytes(&mut seed);
        let mlen = 33 * (i as usize + 1);
        drbg.randombytes(&mut msg[..mlen]);

        let drbg_sav_key = drbg.key;
        let drbg_sav_v = drbg.v;
        drbg.init(&seed);

        let mut seed2 = [0u8; 48];
        drbg.randombytes(&mut seed2);

        let mut sc = InnerShake256Context::new();
        i_shake256_init(&mut sc);
        i_shake256_inject(&mut sc, &seed2);
        i_shake256_flip(&mut sc);

        let ptr = tmp.as_mut_ptr();
        let f_off = 72usize << logn;
        let f: &mut [i8] = unsafe { core::slice::from_raw_parts_mut(ptr.add(f_off) as *mut i8, n) };
        let g: &mut [i8] =
            unsafe { core::slice::from_raw_parts_mut(ptr.add(f_off + n) as *mut i8, n) };
        let big_f: &mut [i8] =
            unsafe { core::slice::from_raw_parts_mut(ptr.add(f_off + 2 * n) as *mut i8, n) };
        let big_g: &mut [i8] =
            unsafe { core::slice::from_raw_parts_mut(ptr.add(f_off + 3 * n) as *mut i8, n) };
        let h: &mut [u16] =
            unsafe { core::slice::from_raw_parts_mut(ptr.add(f_off + 4 * n) as *mut u16, n) };
        let hm: &mut [u16] = unsafe {
            core::slice::from_raw_parts_mut(ptr.add(f_off + 4 * n + 2 * n) as *mut u16, n)
        };
        let sig: &mut [i16] = unsafe {
            core::slice::from_raw_parts_mut(ptr.add(f_off + 4 * n + 4 * n) as *mut i16, n)
        };
        let sig2: &mut [i16] = unsafe {
            core::slice::from_raw_parts_mut(ptr.add(f_off + 4 * n + 6 * n) as *mut i16, n)
        };

        keygen::keygen(
            &mut sc,
            f,
            g,
            big_f,
            Some(big_g),
            Some(h),
            logn,
            &mut tmp[..f_off],
        );

        // Encode private key
        sk[0] = 0x50 + logn as u8;
        let mut u: usize = 1;
        let v = codec::trim_i8_encode(
            Some(&mut sk[u..]),
            f,
            logn,
            codec::MAX_FG_BITS[logn as usize] as u32,
        );
        assert!(v > 0, "ERR encoding sk(f)");
        u += v;
        let v = codec::trim_i8_encode(
            Some(&mut sk[u..]),
            g,
            logn,
            codec::MAX_FG_BITS[logn as usize] as u32,
        );
        assert!(v > 0, "ERR encoding sk(g)");
        u += v;
        let v = codec::trim_i8_encode(
            Some(&mut sk[u..]),
            big_f,
            logn,
            codec::MAX_FG_BITS_UPPER[logn as usize] as u32,
        );
        assert!(v > 0, "ERR encoding sk(F)");
        u += v;
        assert_eq!(u, sk_len, "wrong private key length");

        // Encode public key
        pk[0] = logn as u8;
        let v = codec::modq_encode(Some(&mut pk[1..]), h, logn);
        assert_eq!(1 + v, pk_len, "wrong public key length");

        // Sign
        let mut nonce = [0u8; 40];
        drbg.randombytes(&mut nonce);
        let mut sc2 = InnerShake256Context::new();
        i_shake256_init(&mut sc2);
        i_shake256_inject(&mut sc2, &nonce);
        i_shake256_inject(&mut sc2, &msg[..mlen]);
        i_shake256_flip(&mut sc2);
        common::hash_to_point_vartime(&mut sc2, hm, logn);

        drbg.randombytes(&mut seed2);
        i_shake256_init(&mut sc);
        i_shake256_inject(&mut sc, &seed2);
        i_shake256_flip(&mut sc);
        sign::sign_dyn(
            sig,
            &mut sc,
            f,
            g,
            big_f,
            big_g,
            hm,
            logn,
            &mut tmp[..f_off],
        );

        // Verify with expanded key
        let esk_size = ((8 * logn as usize + 40) << logn) / core::mem::size_of::<Fpr>();
        let mut esk = vec![Fpr(0.0); esk_size];
        sign::expand_privkey(&mut esk, f, g, big_f, big_g, logn, &mut tmp[..f_off]);
        i_shake256_init(&mut sc);
        i_shake256_inject(&mut sc, &seed2);
        i_shake256_flip(&mut sc);
        sign::sign_tree(sig2, &mut sc, &esk, hm, logn, &mut tmp[..f_off]);

        for j in 0..n {
            assert_eq!(sig[j], sig2[j], "Sign dyn/tree mismatch at {}", j);
        }

        // Verify
        vrfy::to_ntt_monty(h, logn);
        assert!(
            vrfy::verify_raw(hm, sig, h, logn, &mut tmp[..f_off]),
            "Invalid signature"
        );

        // Encode signature bundle
        sm[2..42].copy_from_slice(&nonce);
        sm[42..42 + mlen].copy_from_slice(&msg[..mlen]);
        sm[42 + mlen] = 0x20 + logn as u8;
        let u_enc = codec::comp_encode(
            Some(&mut sm[43 + mlen..43 + mlen + over_len - 43]),
            sig,
            logn,
        );
        assert!(u_enc > 0, "Could not encode signature");
        let smlen = 42 + mlen + u_enc + 1;
        sm[0] = ((u_enc + 1) >> 8) as u8;
        sm[1] = (u_enc + 1) as u8;

        drbg.key = drbg_sav_key;
        drbg.v = drbg_sav_v;

        hhc.print_line_with_int("count = ", i);
        hhc.print_line_with_hex("seed = ", &seed);
        hhc.print_line_with_int("mlen = ", mlen as u32);
        hhc.print_line_with_hex("msg = ", &msg[..mlen]);
        hhc.print_line_with_hex("pk = ", &pk[..pk_len]);
        hhc.print_line_with_hex("sk = ", &sk[..sk_len]);
        hhc.print_line_with_int("smlen = ", smlen as u32);
        hhc.print_line_with_hex("sm = ", &sm[..smlen]);
        hhc.print_line("");
    }

    let hhv = hhc.finalize();
    let expected = hex_to_bytes(expected_hash);
    assert_eq!(&hhv[..], &expected[..], "NIST KAT SHA-1 hash mismatch");
}

#[test]
fn test_nist_kat_falcon512() {
    run_nist_kat(9, "a57400cbaee7109358859a56c735a3cf048a9da2");
}

#[test]
fn test_nist_kat_falcon1024() {
    run_nist_kat(10, "affdeb3aa83bf9a2039fa9c17d65fd3e3b9828e2");
}
