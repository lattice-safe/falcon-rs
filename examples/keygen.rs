//! Generate a Falcon-512 key pair and print key sizes.
//!
//! Run with: `cargo run --release --example keygen`

use falcon::safe_api::FalconKeyPair;

fn main() {
    println!("Generating Falcon-512 key pair...");
    let kp = FalconKeyPair::generate(9).expect("keygen failed");

    println!("  Variant:     {}", kp.variant_name());
    println!("  Private key: {} bytes", kp.private_key().len());
    println!("  Public key:  {} bytes", kp.public_key().len());

    // Export keys
    let sk = kp.private_key().to_vec();
    let pk = kp.public_key().to_vec();
    println!("\n  Private key (first 16 bytes): {:02x?}", &sk[..16]);
    println!("  Public key  (first 16 bytes): {:02x?}", &pk[..16]);

    // Reconstruct from private key only
    let restored = FalconKeyPair::from_private_key(&sk).expect("restore failed");
    assert_eq!(pk, restored.public_key());
    println!("\n✅ Key pair reconstructed from private key — public keys match!");
}
