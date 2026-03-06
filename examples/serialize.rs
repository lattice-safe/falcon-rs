//! Demonstrate key and signature serialization round-trips including HashFN-DSA.
//!
//! Run with: `cargo run --release --example serialize`

use falcon::prelude::*;

fn main() {
    println!("=== FN-DSA Key & Signature Serialization ===\n");

    let kp = FnDsaKeyPair::generate(9).expect("keygen failed");
    let message = b"Serialization round-trip test";

    // ── Key export / import ──────────────────────────────────────────────────────
    println!("📦 Exporting keys...");
    let sk_bytes = kp.private_key().to_vec();
    let pk_bytes = kp.public_key().to_vec();
    println!("   Private key: {} bytes", sk_bytes.len());
    println!("   Public key:  {} bytes", pk_bytes.len());

    println!("\n📥 Restoring from (private_key, public_key)...");
    let kp2 = FnDsaKeyPair::from_keys(&sk_bytes, &pk_bytes).expect("from_keys failed");
    assert_eq!(kp.public_key(), kp2.public_key());
    println!("   ✅ Keys match!");

    println!("\n📥 Restoring from private_key only...");
    let kp3 = FnDsaKeyPair::from_private_key(&sk_bytes).expect("from_private_key failed");
    assert_eq!(kp.public_key(), kp3.public_key());
    println!("   ✅ Recomputed public key matches!");

    // ── Pure FN-DSA signature round-trip ────────────────────────────────────────
    println!("\n📦 Signing with DomainSeparation::None...");
    let sig = kp
        .sign(message, &DomainSeparation::None)
        .expect("sign failed");
    println!("   Signature: {} bytes", sig.to_bytes().len());
    let sig_bytes = sig.to_bytes().to_vec();
    let sig2 = FnDsaSignature::from_bytes(sig_bytes);
    FnDsaSignature::verify(sig2.to_bytes(), &pk_bytes, message, &DomainSeparation::None)
        .expect("round-trip verify failed");
    println!("   ✅ Pure FN-DSA round-trip successful!");

    // ── Context-string signature round-trip ──────────────────────────────────────
    println!("\n📦 Signing with DomainSeparation::Context...");
    let ctx = DomainSeparation::Context(b"my-protocol-v1");
    let sig_ctx = kp.sign(message, &ctx).expect("context sign failed");
    let sig_ctx_bytes = sig_ctx.to_bytes().to_vec();
    let sig_ctx2 = FnDsaSignature::from_bytes(sig_ctx_bytes);
    FnDsaSignature::verify(sig_ctx2.to_bytes(), &pk_bytes, message, &ctx)
        .expect("context round-trip verify failed");
    println!("   ✅ Context FN-DSA round-trip successful!");

    // ── HashFN-DSA round-trip ────────────────────────────────────────────────────
    println!("\n📦 Signing with DomainSeparation::Prehashed (SHA-256)...");
    let ph = DomainSeparation::Prehashed {
        alg: PreHashAlgorithm::Sha256,
        context: b"my-protocol-v2",
    };
    let sig_ph = kp.sign(message, &ph).expect("prehash sign failed");
    let sig_ph_bytes = sig_ph.to_bytes().to_vec();
    let sig_ph2 = FnDsaSignature::from_bytes(sig_ph_bytes);
    FnDsaSignature::verify(sig_ph2.to_bytes(), &pk_bytes, message, &ph)
        .expect("prehash round-trip verify failed");
    println!("   ✅ HashFN-DSA SHA-256 round-trip successful!");
}
