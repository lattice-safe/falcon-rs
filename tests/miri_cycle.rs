//! The full key generation / sign / verify cycle at a toy degree, sized so
//! that Miri can finish it.
//!
//! The crate is `#![forbid(unsafe_code)]`, so Miri has no unsafe region to
//! police here; what it still checks is that the core never hits arithmetic
//! overflow, out-of-bounds indexing or other panics on the full path, with
//! the interpreter's stricter evaluation. Real degrees take far too long
//! under Miri; logn = 2 exercises every function on the path.
//!
//! Run with: `cargo +nightly miri test --features fpemu --test miri_cycle`

use falcon::fndsa::{kgen, sign, vrfy, HashId};

#[test]
fn toy_degree_cycle() {
    let (sk, vk) = kgen::keygen_seeded(2, b"miri");
    let sig = sign::sign_weak(&sk, b"ctx", HashId::Raw, b"message", b"rnd").unwrap();
    assert!(vrfy::verify_weak(
        &sig,
        &vk,
        b"ctx",
        HashId::Raw,
        b"message"
    ));
    assert!(!vrfy::verify_weak(
        &sig,
        &vk,
        b"ctx",
        HashId::Raw,
        b"messagf"
    ));
}
