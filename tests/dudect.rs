//! Statistical constant-time tests (dudect-style Welch t-test).
//!
//! The other constant-time evidence in this crate is static:
//! `scripts/check_no_fp.sh` proves the `fpemu` build contains no
//! floating-point instruction. That does not show what the CPU actually
//! *does* with the code. These tests measure it, through the public API and
//! the sampler's test hook (the floating-point type itself is private).
//!
//! Method, following Reparaz–Balasch–Verbauwhede's `dudect`: run the
//! operation under test with two input classes — one fixed, one random —
//! interleaved in random order, and apply Welch's t-test to the two timing
//! distributions. Under the null hypothesis (timing independent of the
//! input) the statistic stays small; `|t| > 4.5` is dudect's threshold for
//! declaring leakage. Because the tail of a timing distribution is mostly
//! scheduler noise, the statistic is also computed on percentile-cropped
//! subsets and the largest value is reported.
//!
//! Run with:
//!
//! ```sh
//! cargo test --release --features fpemu --test dudect -- --ignored --nocapture
//! ```
//!
//! `DUDECT_N` scales the number of measurements (default is sized for a
//! few seconds per test).

use std::{hint::black_box, time::Instant};

use falcon::{fndsa::sign::sampler_test_vector, prelude::*};

/// dudect's leakage threshold. Below this, the measurements give no
/// evidence of input-dependent timing; above it, they do.
const T_THRESHOLD: f64 = 4.5;

/// A timing distribution's tail is dominated by preemption and interrupts,
/// which are not properties of the code. dudect handles this by also
/// testing subsets below a set of percentile cutoffs.
const CROPS: [f64; 8] = [1.0, 0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3];

// ======================================================================
// Harness
// ======================================================================

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn bit(&mut self) -> bool {
        self.next() >> 63 != 0
    }
}

fn scale(base: usize) -> usize {
    match std::env::var("DUDECT_N") {
        Ok(v) => v.parse::<usize>().unwrap_or(base),
        Err(_) => base,
    }
}

fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    if a.len() < 2 || b.len() < 2 {
        return 0.0;
    }
    let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
    let (ma, mb) = (mean(a), mean(b));
    let var = |v: &[f64], m: f64| {
        v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (v.len() as f64 - 1.0)
    };
    let (va, vb) = (var(a, ma), var(b, mb));
    let se = (va / a.len() as f64 + vb / b.len() as f64).sqrt();
    if se == 0.0 {
        return 0.0;
    }
    (ma - mb) / se
}

/// Largest |t| over the full sample and the percentile-cropped subsets.
fn max_abs_t(class0: &[f64], class1: &[f64]) -> f64 {
    let mut all: Vec<f64> = class0.iter().chain(class1.iter()).copied().collect();
    all.sort_by(|x, y| x.partial_cmp(y).unwrap());

    let mut worst: f64 = 0.0;
    for crop in CROPS {
        let cutoff = all[((all.len() - 1) as f64 * crop) as usize];
        let a: Vec<f64> = class0.iter().copied().filter(|x| *x <= cutoff).collect();
        let b: Vec<f64> = class1.iter().copied().filter(|x| *x <= cutoff).collect();
        worst = worst.max(welch_t(&a, &b).abs());
    }
    worst
}

/// Measure `run` under both input classes, interleaved randomly, and
/// return the largest |t| statistic.
fn measure<F: FnMut(bool) -> u64>(n: usize, seed: u64, mut run: F) -> f64 {
    let mut rng = Rng(seed);

    // Warm up caches, branch predictors and the frequency governor.
    for _ in 0..(n / 20).max(50) {
        black_box(run(rng.bit()));
    }

    let mut c0 = Vec::with_capacity(n / 2);
    let mut c1 = Vec::with_capacity(n / 2);
    for _ in 0..n {
        let class = rng.bit();
        let dt = run(class) as f64;
        if class {
            c1.push(dt);
        } else {
            c0.push(dt);
        }
    }
    max_abs_t(&c0, &c1)
}

/// Run the measurement three times and judge by the MEDIAN.
///
/// A single run on a shared CI machine can exceed the threshold because of a
/// neighbouring process rather than because of the code, so one measurement
/// is not enough to fail on. But "pass if any attempt is clean" is far too
/// weak in the other direction: a run of 6.4, 7.7, 2.3 would be declared
/// clean on the strength of its quietest sample. The median tolerates one
/// noisy run while still failing when the majority of measurements say the
/// timing depends on the input.
fn assert_constant_time<F: FnMut(bool) -> u64>(name: &str, n: usize, mut run: F) {
    let mut seen = Vec::new();
    for attempt in 0..3 {
        let t = measure(n, 0xD0D0_CAFE_0000_0001 + attempt, &mut run);
        println!("  {name}: attempt {} max|t| = {t:.2}", attempt + 1);
        seen.push(t);
    }

    let mut sorted = seen.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = sorted[1];
    println!("  {name}: median max|t| = {median:.2} (threshold {T_THRESHOLD})");

    assert!(
        median < T_THRESHOLD,
        "{name}: input-dependent timing — median max|t| = {median:.2} over \
         attempts {seen:?}, threshold {T_THRESHOLD}"
    );
}

// ======================================================================
// Harness self-test
// ======================================================================

/// The measurement rig must be able to see a leak, or a clean result from
/// the tests below would mean nothing.
///
/// This runs a deliberately variable-time routine — the loop count differs
/// by 2% between the two classes — and requires the t-test to flag it. A
/// failure here means the timer resolution, `black_box`, or the optimiser
/// is hiding real differences, and the rest of this file should not be
/// trusted until it is fixed.
#[test]
#[ignore]
fn harness_detects_known_leak() {
    let n = scale(20_000);
    println!("harness self-test (n = {n}):");

    let t = measure(n, 0xFACE_B00C_1234_5678, |class| {
        let iters = if class { 1000u64 } else { 1020 };
        let start = Instant::now();
        let mut acc = 0u64;
        for i in 0..iters {
            acc = acc
                .wrapping_mul(6364136223846793005)
                .wrapping_add(black_box(i));
        }
        black_box(acc);
        start.elapsed().as_nanos() as u64
    });
    println!("  known 2% difference: max|t| = {t:.2}");
    assert!(
        t > T_THRESHOLD,
        "the harness did not detect a deliberate 2% timing difference \
         (max|t| = {t:.2}): the measurements are not sensitive enough to \
         support the other tests in this file"
    );
}

// ======================================================================
// The signing path
// ======================================================================

/// The discrete Gaussian sampler's centre comes from the private basis, so
/// its timing must not depend on it. The sampler's rejection loop runs a
/// variable number of times by design; what must hold is that the *number
/// of iterations does not correlate with the centre*, which is exactly what
/// this measures. Each call also seeds a fresh SHAKE256 stream, which is the
/// same work for both classes.
#[test]
#[ignore]
fn sampler_timing_vs_centre() {
    let n = scale(60_000);
    println!("sampler, fixed vs random centre (n = {n}):");

    let isigma = (1.0f64 / 1.55).to_bits();
    let fixed_mu = 0.375f64.to_bits();
    let mut rng = Rng(0x9999_8888_7777_6666);
    let mut ctr = 0u64;

    assert_constant_time("sampler(mu)", n, |class| {
        // Draw for both classes so the work before the clock is identical.
        let u = (rng.next() >> 11) as f64 / (1u64 << 53) as f64;
        let drawn = (u * 16.0 - 8.0).to_bits(); // a centre in [-8, 8)
        let mu = if class { drawn } else { fixed_mu };
        ctr += 1;
        let seed = ctr.to_le_bytes();
        let start = Instant::now();
        black_box(sampler_test_vector(
            black_box(&seed),
            &[(black_box(mu), isigma)],
        ));
        start.elapsed().as_nanos() as u64
    });
}

/// Signing time must not depend on the message content. (Message *length*
/// does change the SHAKE256 absorb cost, so both classes use the same
/// length.)
#[test]
#[ignore]
fn sign_timing_vs_message() {
    let n = scale(1_200);
    println!("sign, fixed vs random message (n = {n}):");

    let kp = FnDsaKeyPair::generate(9).expect("keygen");
    let fixed = [0xA5u8; 128];
    let mut random = [0u8; 128];
    let mut rng = Rng(0x2468_1357_9BDF_0246);

    assert_constant_time("sign(message)", n, |class| {
        let msg: &[u8] = if class {
            for chunk in random.chunks_mut(8) {
                chunk.copy_from_slice(&rng.next().to_le_bytes()[..chunk.len()]);
            }
            &random
        } else {
            &fixed
        };
        let start = Instant::now();
        black_box(
            kp.sign(black_box(msg), &DomainSeparation::None)
                .expect("sign"),
        );
        start.elapsed().as_nanos() as u64
    });
}

/// Verification handles only public data, so this is reported rather than
/// asserted: a rejected signature legitimately exits early from the codec
/// decode, before any lattice arithmetic runs.
#[test]
#[ignore]
fn verify_timing_valid_vs_invalid() {
    let n = scale(20_000);
    println!("verify, valid vs corrupted signature (n = {n}):");

    let kp = FnDsaKeyPair::generate(9).expect("keygen");
    let msg = b"dudect verification target";
    let good: Vec<u8> = kp
        .sign(msg, &DomainSeparation::None)
        .expect("sign")
        .into_bytes();
    let mut bad = good.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 0xFF;

    let pk = kp.public_key().to_vec();
    let t = measure(n, 0x1357_2468_ACE0_BDF1, |class| {
        let sig: &[u8] = if class { &bad } else { &good };
        let start = Instant::now();
        let _ = black_box(FnDsaSignature::verify(
            black_box(sig),
            &pk,
            msg,
            &DomainSeparation::None,
        ));
        start.elapsed().as_nanos() as u64
    });
    println!("  verify(valid/invalid): max|t| = {t:.2} (informational)");
}
