//! Sign a message and verify the signature.
//!
//! Run with: `cargo run --release --example sign_verify`

use falcon::safe_api::{FalconKeyPair, FalconSignature};

fn main() {
    let message = b"Hello, post-quantum world!";

    // Generate key pair
    println!("🔑 Generating Falcon-512 key pair...");
    let kp = FalconKeyPair::generate(9).expect("keygen failed");

    // Sign
    println!("✍️  Signing message: {:?}", std::str::from_utf8(message).unwrap());
    let sig = kp.sign(message).expect("sign failed");
    println!("   Signature: {} bytes", sig.len());
    println!("   First 16 bytes: {:02x?}", &sig.to_bytes()[..16]);

    // Verify
    println!("\n🔍 Verifying signature...");
    FalconSignature::verify(sig.to_bytes(), kp.public_key(), message)
        .expect("verification failed");
    println!("   ✅ Signature valid!");

    // Tamper detection
    println!("\n🔍 Verifying with wrong message...");
    let result = FalconSignature::verify(sig.to_bytes(), kp.public_key(), b"wrong message");
    match result {
        Err(e) => println!("   ✅ Correctly rejected: {}", e),
        Ok(()) => panic!("Should have rejected tampered message!"),
    }
}
