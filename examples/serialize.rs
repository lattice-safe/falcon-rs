//! Demonstrate key and signature serialization round-trips.
//!
//! Run with: `cargo run --release --example serialize`

use falcon::safe_api::{FnDsaKeyPair, FnDsaSignature, DomainSeparation};

fn main() {
    println!("=== FN-DSA Key & Signature Serialization ===\n");

    // Generate key pair
    let kp = FnDsaKeyPair::generate(9).expect("keygen failed");
    let message = b"Serialization round-trip test";

    // Sign
    let sig = kp.sign(message, &DomainSeparation::None).expect("sign failed");

    // ---- Key serialization ----
    println!("📦 Exporting keys...");
    let sk_bytes = kp.private_key().to_vec();
    let pk_bytes = kp.public_key().to_vec();
    println!("   Private key: {} bytes", sk_bytes.len());
    println!("   Public key:  {} bytes", pk_bytes.len());

    // Restore from both keys
    println!("\n📥 Restoring from (private_key, public_key)...");
    let kp2 = FnDsaKeyPair::from_keys(&sk_bytes, &pk_bytes).expect("from_keys failed");
    assert_eq!(kp.public_key(), kp2.public_key());
    println!("   ✅ Keys match!");

    // Restore from private key only
    println!("\n📥 Restoring from private_key only...");
    let kp3 = FnDsaKeyPair::from_private_key(&sk_bytes).expect("from_private_key failed");
    assert_eq!(kp.public_key(), kp3.public_key());
    println!("   ✅ Recomputed public key matches!");

    // ---- Signature serialization ----
    println!("\n📦 Exporting signature...");
    let sig_bytes = sig.to_bytes().to_vec();
    println!("   Signature: {} bytes", sig_bytes.len());

    // Restore signature
    println!("\n📥 Restoring signature from bytes...");
    let sig2 = FnDsaSignature::from_bytes(sig_bytes);

    // Verify restored signature with restored public key
    println!("🔍 Verifying restored signature with restored key...");
    FnDsaSignature::verify(sig2.to_bytes(), &pk_bytes, message, &DomainSeparation::None).expect("verification failed");
    println!("   ✅ Round-trip successful!");
}
