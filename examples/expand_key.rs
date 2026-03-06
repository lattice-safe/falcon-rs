//! Demonstrate the FnDsaExpandedKey API for amortized multi-signature workloads.
//!
//! Run with: `cargo run --release --example expand_key`

use falcon::prelude::*;

fn main() {
    let message1 = b"First document to sign";
    let message2 = b"Second document to sign";
    let message3 = b"Third document to sign - no re-expansion needed";

    // ── Generate key pair ────────────────────────────────────────────────────────
    println!("🔑 Generating FN-DSA-512 key pair...");
    let kp = FnDsaKeyPair::generate(9).expect("keygen failed");
    println!("   Variant: {}", kp.variant_name());

    // ── Expand once ──────────────────────────────────────────────────────────────
    // The expanded key contains the precomputed Falcon LDL tree.
    // This is ~2.5× the cost of a single sign() — paid only once.
    println!("\n🌲 Expanding private key into signing tree...");
    let ek = kp.expand().expect("expand failed");
    println!(
        "   Public key same as kp: {}",
        ek.public_key() == kp.public_key()
    );
    println!("   logn = {}", ek.logn());

    // ── Sign multiple messages — no re-expansion ─────────────────────────────────
    // Each sign() is now ~1.5× faster than FnDsaKeyPair::sign().
    println!("\n✍️  Signing three messages with the expanded key...");

    let messages: [&[u8]; 3] = [message1, message2, message3];
    for (i, msg) in messages.iter().enumerate() {
        let sig = ek.sign(msg, &DomainSeparation::None).expect("sign failed");
        FnDsaSignature::verify(
            sig.to_bytes(),
            ek.public_key(),
            msg,
            &DomainSeparation::None,
        )
        .expect("verify failed");
        println!(
            "   [{}/3] ✅ Signed and verified ({} bytes)",
            i + 1,
            sig.len()
        );
    }

    // ── Works with all domain separation modes ───────────────────────────────────
    println!("\n── HashFN-DSA with expanded key ──");
    let ph = DomainSeparation::Prehashed {
        alg: PreHashAlgorithm::Sha256,
        context: b"my-protocol-v1",
    };
    let sig_ph = ek.sign(message1, &ph).expect("prehashed sign failed");
    FnDsaSignature::verify(sig_ph.to_bytes(), ek.public_key(), message1, &ph)
        .expect("prehashed verify failed");
    println!("   ✅ HashFN-DSA SHA-256 verified with expanded key!");

    // ── Expanded key is independent of the original key pair ────────────────────
    // You can drop `kp` after expanding — `ek` is self-contained.
    println!("\n── Drop original key pair, keep only expanded key ──");
    drop(kp); // private key bytes are zeroized here
    let sig = ek
        .sign_deterministic(message2, b"deterministic-seed", &DomainSeparation::None)
        .expect("sign_deterministic failed");
    FnDsaSignature::verify(
        sig.to_bytes(),
        ek.public_key(),
        message2,
        &DomainSeparation::None,
    )
    .expect("verify failed");
    println!("   ✅ Works after dropping original key pair!");
    println!("\n🎉 Expanded-key demo complete.");
}
