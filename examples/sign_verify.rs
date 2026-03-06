//! Sign a message and verify the signature.
//!
//! Run with: `cargo run --release --example sign_verify`

use falcon::safe_api::{FnDsaKeyPair, FnDsaSignature, DomainSeparation};

fn main() {
    let message = b"Hello, post-quantum world!";

    // Generate key pair
    println!("🔑 Generating FN-DSA-512 key pair...");
    let kp = FnDsaKeyPair::generate(9).expect("keygen failed");

    // Sign
    println!(
        "✍️  Signing message: {:?}",
        std::str::from_utf8(message).unwrap()
    );
    let sig = kp.sign(message, &DomainSeparation::None).expect("sign failed");
    println!("   Signature: {} bytes", sig.len());
    println!("   First 16 bytes: {:02x?}", &sig.to_bytes()[..16]);

    // Verify
    println!("\n🔍 Verifying signature...");
    FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), message, &DomainSeparation::None).expect("verification failed");
    println!("   ✅ Signature valid!");

    // Tamper detection
    println!("\n🔍 Verifying with wrong message...");
    let result = FnDsaSignature::verify(sig.to_bytes(), kp.public_key(), b"wrong message", &DomainSeparation::None);
    match result {
        Err(e) => println!("   ✅ Correctly rejected: {}", e),
        Ok(()) => panic!("Should have rejected tampered message!"),
    }
}
