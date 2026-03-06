//! Sign a message and verify the signature — demonstrating all FIPS 206 domain modes.
//!
//! Run with: `cargo run --release --example sign_verify`

use falcon::prelude::*;

fn main() {
    let message = b"Hello, post-quantum world!";

    // ── Key generation ──────────────────────────────────────────────────────────
    println!("🔑 Generating FN-DSA-512 key pair...");
    let kp = FnDsaKeyPair::generate(9).expect("keygen failed");
    println!("   Variant:    {}", kp.variant_name());
    println!("   Public key: {} bytes", kp.public_key().len());

    // ── Pure FN-DSA, no context (DomainSeparation::None) ────────────────────────
    println!("\n── Pure FN-DSA (no context) ──");
    let sig = kp
        .sign(message, &DomainSeparation::None)
        .expect("sign failed");
    println!("   Signature: {} bytes", sig.len());
    FnDsaSignature::verify(
        sig.to_bytes(),
        kp.public_key(),
        message,
        &DomainSeparation::None,
    )
    .expect("verification failed");
    println!("   ✅ Verified!");

    // ── Pure FN-DSA with protocol context (DomainSeparation::Context) ───────────
    println!("\n── Pure FN-DSA with context string ──");
    let ctx = DomainSeparation::Context(b"my-protocol-v1");
    let sig_ctx = kp.sign(message, &ctx).expect("sign with context failed");
    FnDsaSignature::verify(sig_ctx.to_bytes(), kp.public_key(), message, &ctx)
        .expect("context verify failed");
    println!("   ✅ Verified with context 'my-protocol-v1'!");

    // Cross-context rejection
    let wrong_ctx = DomainSeparation::Context(b"different-protocol");
    let result = FnDsaSignature::verify(sig_ctx.to_bytes(), kp.public_key(), message, &wrong_ctx);
    assert!(result.is_err());
    println!("   ✅ Correctly rejected by wrong context (cross-protocol protection)!");

    // ── HashFN-DSA with SHA-256 (DomainSeparation::Prehashed) ───────────────────
    println!("\n── HashFN-DSA (SHA-256 pre-hash) ──");
    let ph256 = DomainSeparation::Prehashed {
        alg: PreHashAlgorithm::Sha256,
        context: b"my-protocol-v2",
    };
    let sig_ph = kp.sign(message, &ph256).expect("HashFN-DSA sign failed");
    println!("   Signature: {} bytes", sig_ph.len());
    FnDsaSignature::verify(sig_ph.to_bytes(), kp.public_key(), message, &ph256)
        .expect("HashFN-DSA verify failed");
    println!("   ✅ HashFN-DSA SHA-256 verified!");

    // ── HashFN-DSA with SHA-512 ──────────────────────────────────────────────────
    println!("\n── HashFN-DSA (SHA-512 pre-hash) ──");
    let ph512 = DomainSeparation::Prehashed {
        alg: PreHashAlgorithm::Sha512,
        context: b"",
    };
    let sig_ph512 = kp.sign(message, &ph512).expect("SHA-512 sign failed");
    FnDsaSignature::verify(sig_ph512.to_bytes(), kp.public_key(), message, &ph512)
        .expect("SHA-512 verify failed");
    println!("   ✅ HashFN-DSA SHA-512 verified!");

    // Cross-mode rejection: pure sig won't verify as HashFN-DSA
    let cross = FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), message, &ph256);
    assert!(cross.is_err());
    println!("   ✅ Pure sig correctly rejected under Prehashed domain!");

    // ── Tamper detection ─────────────────────────────────────────────────────────
    println!("\n── Tamper detection ──");
    let result = FnDsaSignature::verify(
        sig.to_bytes(),
        kp.public_key(),
        b"wrong message",
        &DomainSeparation::None,
    );
    assert!(result.is_err());
    println!(
        "   ✅ Wrong-message correctly rejected: {}",
        result.unwrap_err()
    );
}
