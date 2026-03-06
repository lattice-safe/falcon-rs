//! Generate FN-DSA key pairs (512 and 1024) and inspect sizes / round-trip.
//!
//! Run with: `cargo run --release --example keygen`

use falcon::prelude::*;

fn main() {
    for logn in [9u32, 10] {
        let variant = if logn == 9 {
            "FN-DSA-512"
        } else {
            "FN-DSA-1024"
        };
        println!("🔑 Generating {} key pair...", variant);
        let kp = FnDsaKeyPair::generate(logn).expect("keygen failed");

        println!("  Variant:     {}", kp.variant_name());
        println!("  Private key: {} bytes", kp.private_key().len());
        println!("  Public key:  {} bytes", kp.public_key().len());

        let sk = kp.private_key().to_vec();
        let pk = kp.public_key().to_vec();
        println!("  Private key (first 16 bytes): {:02x?}", &sk[..16]);
        println!("  Public key  (first 16 bytes): {:02x?}", &pk[..16]);

        // Reconstruct from private key only
        let restored = FnDsaKeyPair::from_private_key(&sk).expect("restore failed");
        assert_eq!(
            pk,
            restored.public_key(),
            "public key mismatch after restore"
        );
        println!("  ✅ Public key reconstructed from private key — match!\n");
    }
}
