//! The high-level API against the C reference.
//!
//! `tests/fixtures/c-fn-dsa/api_vectors.txt` is produced by c-fn-dsa's own
//! public API (`fndsa_keygen_seeded`, `fndsa_sign_seeded`,
//! `fndsa_compute_mu`), one case per domain-separation mode and context,
//! at both standard degrees; see `scripts/c-fn-dsa/gen_api_vectors.py`.
//! `FnDsaKeyPair::generate_deterministic` and `sign_deterministic` must
//! reproduce every key and signature byte, and the results must verify.

use falcon::prelude::*;

struct Case {
    logn: u32,
    key_seed: Vec<u8>,
    ctx: Vec<u8>,
    mode: String,
    msg: Vec<u8>,
    sign_seed: Vec<u8>,
    sk: Vec<u8>,
    vk: Vec<u8>,
    mu: Vec<u8>,
    sig: Vec<u8>,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn cases() -> Vec<Case> {
    include_str!("fixtures/c-fn-dsa/api_vectors.txt")
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('|').collect();
            assert_eq!(f.len(), 10);
            Case {
                logn: f[0].parse().unwrap(),
                key_seed: unhex(f[1]),
                ctx: unhex(f[2]),
                mode: f[3].to_string(),
                msg: unhex(f[4]),
                sign_seed: unhex(f[5]),
                sk: unhex(f[6]),
                vk: unhex(f[7]),
                mu: unhex(f[8]),
                sig: unhex(f[9]),
            }
        })
        .collect()
}

fn domain<'a>(c: &'a Case) -> DomainSeparation<'a> {
    let alg = |alg| DomainSeparation::Prehashed {
        alg,
        context: &c.ctx,
    };
    match c.mode.as_str() {
        "raw" if c.ctx.is_empty() => DomainSeparation::None,
        "raw" => DomainSeparation::Context(&c.ctx),
        "sha256" => alg(PreHashAlgorithm::Sha256),
        "sha512" => alg(PreHashAlgorithm::Sha512),
        "sha3_256" => alg(PreHashAlgorithm::Sha3_256),
        "sha3_512" => alg(PreHashAlgorithm::Sha3_512),
        "extmu" => DomainSeparation::ExternalMu(&c.mu),
        m => panic!("unknown mode {m}"),
    }
}

#[test]
fn api_matches_c_reference() {
    let cases = cases();
    assert_eq!(cases.len(), 26);
    for (i, c) in cases.iter().enumerate() {
        let d = domain(c);
        let kp = FnDsaKeyPair::generate_deterministic(&c.key_seed, c.logn).unwrap();
        assert_eq!(kp.private_key(), &c.sk[..], "case {i}: private key");
        assert_eq!(kp.public_key(), &c.vk[..], "case {i}: public key");

        let sig = kp.sign_deterministic(&c.msg, &c.sign_seed, &d).unwrap();
        assert_eq!(
            sig.to_bytes(),
            &c.sig[..],
            "case {i} ({}): signature",
            c.mode
        );
        let ek = kp.expand().unwrap();
        let sig2 = ek.sign_deterministic(&c.msg, &c.sign_seed, &d).unwrap();
        assert_eq!(
            sig2.to_bytes(),
            &c.sig[..],
            "case {i}: expanded-key signature"
        );

        FnDsaSignature::verify(&c.sig, &c.vk, &c.msg, &d).unwrap();
        assert_eq!(
            FnDsaSignature::verify(&c.sig, &c.vk, b"WRONG_MSG", &d).is_err(),
            c.mode != "extmu",
            "case {i}: external mu ignores the message, every other mode binds it"
        );

        // The C mu matches the one the crate computes from the public key.
        let hvk = falcon::fndsa::hashed_vrfykey_from_vrfykey(&c.vk);
        let id = if c.mode == "extmu" || c.mode == "raw" {
            falcon::fndsa::HashId::Raw
        } else {
            continue;
        };
        let mu = falcon::fndsa::compute_mu(&hvk, &c.ctx, id, &c.msg).unwrap();
        assert_eq!(&mu[..], &c.mu[..], "case {i}: mu");
    }
}
