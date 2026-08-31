//! Statistical constant-time tests (dudect-style Welch t-test).
//!
//! The other constant-time evidence in this crate is static: the source is
//! branchless, and `scripts/check_no_fp.sh` proves the compiler emitted no
//! floating-point instruction. Neither shows what the CPU actually *does*
//! with the code. These tests measure it.
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

use falcon::{
    fpr::*,
    prelude::*,
    rng::{prng_init, Prng},
    shake::{i_shake256_flip, i_shake256_init, i_shake256_inject, InnerShake256Context},
    sign::{sampler, SamplerContext},
};

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

/// Three measurements, reported as their median.
fn measure_median<F: FnMut(bool) -> u64>(n: usize, seed: u64, run: &mut F) -> f64 {
    let mut t: Vec<f64> = Vec::with_capacity(3);
    for i in 0..3 {
        t.push(measure(n, seed + i, &mut *run));
    }
    t.sort_by(|a, b| a.partial_cmp(b).unwrap());
    t[1]
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
// The floating-point backend
// ======================================================================

/// The "fixed" class: one operand pair, reused.
const FIXED_A: f64 = 1.2345678901234567;
const FIXED_B: f64 = 9.876543210987654e-40;

/// A random normal operand, spread across the exponent range Falcon uses.
fn random_operand(rng: &mut Rng) -> Fpr {
    let exp = 900 + (rng.next() % 250);
    let mant = rng.next() & ((1u64 << 52) - 1);
    Fpr::new(f64::from_bits(
        ((rng.next() & 1) << 63) | (exp << 52) | mant,
    ))
}

/// Repetitions per measurement: enough that the batch is far longer than the
/// clock's resolution.
const BATCH: usize = 512;

macro_rules! fpr_timing_test {
    ($name:ident, $label:literal, $op:expr) => {
        fn $name(n: usize) -> f64 {
            let mut rng = Rng(0xABCD_0000_1234_5678);
            let mut runner = |class: bool| -> u64 {
                // Operands live in registers for the whole measurement. An
                // earlier version swept a buffer, which made the measurement
                // depend on how the memory subsystem treats a page of
                // identical values versus a page of random ones — a real
                // hardware effect, but not a property of the operation under
                // test, and large enough on x86 to drown everything else.
                // Draw for both classes and discard for the fixed one, so the
                // work before the clock starts is identical. Drawing only for
                // the random class left a constant setup difference, which
                // showed up as a t-statistic that grew with the length of the
                // operation being measured.
                let drawn = (random_operand(&mut rng), random_operand(&mut rng));
                let (a, b) = if class {
                    drawn
                } else {
                    (Fpr::new(FIXED_A), Fpr::new(FIXED_B))
                };
                let start = Instant::now();
                for _ in 0..BATCH {
                    black_box($op(black_box(a), black_box(b)));
                }
                start.elapsed().as_nanos() as u64
            };
            let t = measure_median(n, 0x1111_2222_3333_4444, &mut runner);
            println!("  fpr_{}: median max|t| = {t:.2}", $label);
            t
        }
    };
}

fpr_timing_test!(t_add, "add", fpr_add);
fpr_timing_test!(t_sub, "sub", fpr_sub);
fpr_timing_test!(t_mul, "mul", fpr_mul);
fpr_timing_test!(t_div, "div", fpr_div);
fpr_timing_test!(t_sqrt, "sqrt", |a: Fpr, _b: Fpr| fpr_sqrt(fpr_mul(a, a)));

/// A control: the same measurement shape over an operation that cannot
/// possibly depend on its operands' values. If this ever rises with the
/// others, the harness is measuring the machine rather than the code.
fn t_control(n: usize) -> f64 {
    let mut rng = Rng(0x0F0F_0F0F_0F0F_0F0F);
    let mut runner = |class: bool| -> u64 {
        // Draw for both classes and discard for the fixed one, so the
        // work before the clock starts is identical. Drawing only for
        // the random class left a constant setup difference, which
        // showed up as a t-statistic that grew with the length of the
        // operation being measured.
        let drawn = (random_operand(&mut rng), random_operand(&mut rng));
        let (a, b) = if class {
            drawn
        } else {
            (Fpr::new(FIXED_A), Fpr::new(FIXED_B))
        };
        let start = Instant::now();
        for _ in 0..BATCH {
            black_box(black_box(a).0 ^ black_box(b).0);
        }
        start.elapsed().as_nanos() as u64
    };
    let t = measure_median(n, 0x2222_3333_4444_5555, &mut runner);
    println!("  control (xor): median max|t| = {t:.2}");
    t
}

/// Every `Fpr` operation must take the same time on a fixed operand pair as
/// on random ones.
///
/// With `--features fpemu` this is asserted: the backend is branchless
/// integer code and must not vary. On the default backend the result is only
/// reported, because hardware floating-point division and square root have
/// data-dependent latency on many CPUs — which is precisely the side channel
/// `fpemu` exists to remove.
///
/// The `control` row runs the same measurement over a bare XOR. It cannot
/// depend on its operands, so if it ever rises with the rest, the harness is
/// measuring the machine and the other rows mean nothing.
#[test]
#[ignore]
fn fpr_operations() {
    let n = scale(40_000);
    println!("fpr operations (n = {n} measurements each):");
    let results = [
        ("control", t_control(n)),
        ("add", t_add(n)),
        ("sub", t_sub(n)),
        ("mul", t_mul(n)),
        ("div", t_div(n)),
        ("sqrt", t_sqrt(n)),
    ];

    // The control sets the noise floor for this machine at this moment. An
    // operation is judged against it rather than against a fixed number: a
    // shared CI runner can push everything above 4.5 at once, which says
    // nothing about the code, while a real leak stands far above a control
    // that stayed low. An operation passes if it is under the absolute
    // threshold, or no worse than the control.
    let control = results[0].1;
    let ceiling = T_THRESHOLD.max(control);
    println!("  (threshold {T_THRESHOLD}, control {control:.2} -> ceiling {ceiling:.2})");

    if cfg!(feature = "fpemu") {
        let leaks: Vec<_> = results
            .iter()
            .skip(1)
            .filter(|(_, t)| *t > ceiling)
            .map(|(name, t)| format!("{name} (|t| = {t:.2})"))
            .collect();
        assert!(
            leaks.is_empty(),
            "fpemu backend shows input-dependent timing in: {}",
            leaks.join(", ")
        );
    } else {
        println!("  (native backend: reported only — enable `fpemu` to assert)");
    }
}

/// Normal vs subnormal operands — the classic floating-point timing leak.
///
/// On many CPUs an operation on a subnormal value traps into a microcode
/// assist costing tens to hundreds of cycles, which makes the timing of a
/// floating-point routine depend on the magnitude of its operands. The
/// `fpemu` backend flushes subnormals to zero in branchless code, so it
/// cannot exhibit this; the native backend's behaviour is up to the CPU
/// (Apple Silicon, for instance, handles subnormals at full rate).
#[test]
#[ignore]
fn fpr_subnormal_operands() {
    let n = scale(40_000);
    println!("fpr mul, normal vs subnormal operands (n = {n}):");

    let normal = Fpr::new(1.2345678901234567e-100);
    // Below 2^-1022: subnormal for the hardware, flushed to zero by `fpemu`.
    let subnormal = Fpr::new(f64::from_bits(0x0000_0000_0001_0001));

    let mut runner = |class: bool| -> u64 {
        let x = if class { subnormal } else { normal };
        let start = Instant::now();
        for _ in 0..BATCH {
            black_box(fpr_mul(black_box(x), black_box(x)));
        }
        start.elapsed().as_nanos() as u64
    };

    let t = measure_median(n, 0x7777_3333_1111_5555, &mut runner);
    println!("  fpr_mul(subnormal): median max|t| = {t:.2}");

    if cfg!(feature = "fpemu") {
        assert!(
            t < T_THRESHOLD,
            "fpemu backend timing depends on operand magnitude: max|t| = {t:.2}"
        );
    } else {
        println!("  (native backend: reported only — a large value here is a CPU property)");
    }
}

// ======================================================================
// The signing path
// ======================================================================

fn seeded_shake(seed: &[u8]) -> InnerShake256Context {
    let mut sc = InnerShake256Context::new();
    i_shake256_init(&mut sc);
    i_shake256_inject(&mut sc, seed);
    i_shake256_flip(&mut sc);
    sc
}

/// The discrete Gaussian sampler's centre comes from the private basis, so
/// its timing must not depend on it. The sampler's rejection loop runs a
/// variable number of times by design; what must hold is that the *number
/// of iterations does not correlate with the centre*, which is exactly what
/// this measures.
#[test]
#[ignore]
fn sampler_timing_vs_centre() {
    let n = scale(60_000);
    println!("sampler, fixed vs random centre (n = {n}):");

    let mut src = seeded_shake(b"dudect-sampler");
    let mut ctx = SamplerContext {
        p: Prng::new(),
        sigma_min: FPR_SIGMA_MIN[9],
    };
    prng_init(&mut ctx.p, &mut src);

    let isigma = Fpr::new(1.0 / 1.55);
    let fixed_mu = Fpr::new(0.375);
    let mut rng = Rng(0x9999_8888_7777_6666);

    assert_constant_time("sampler(mu)", n, |class| {
        let mu = if class {
            // A random centre in [-8, 8), the range ff-Sampling produces.
            let u = (rng.next() >> 11) as f64 / (1u64 << 53) as f64;
            Fpr::new(u * 16.0 - 8.0)
        } else {
            fixed_mu
        };
        let start = Instant::now();
        black_box(sampler(&mut ctx, black_box(mu), black_box(isigma)));
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
