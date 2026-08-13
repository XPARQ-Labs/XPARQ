use std::hint::black_box;
use std::time::{Duration, Instant};
use xparq::crypto::SignatureContext;
use xparq::crypto::sqisign_candidate::{
    KeyPair, Signature, generate_keypair, sign as sign_sqisign, verify as verify_sqisign,
};

const MESSAGE: &[u8] = b"xparq sqisign level 5 candidate benchmark";

fn timed<T>(operation: impl FnOnce() -> T) -> (T, Duration) {
    let started = Instant::now();
    let value = operation();
    (value, started.elapsed())
}

fn average(total: Duration, iterations: u32) -> Duration {
    total / iterations
}

fn main() {
    let iterations = std::env::var("XPARQ_SQISIGN_BENCH_ITERATIONS")
        .or_else(|_| std::env::var("xparq_SQISIGN_BENCH_ITERATIONS"))
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(3);

    let (signer, keygen) = timed(|| generate_keypair().expect("key generation"));
    let (signature, initial_sign) = timed(|| sign(&signer, MESSAGE));
    assert!(verify(&signer, MESSAGE, &signature));

    let mut sign_total = Duration::ZERO;
    for _ in 0..iterations {
        let (_, elapsed) = timed(|| black_box(sign(&signer, MESSAGE)));
        sign_total += elapsed;
    }

    let mut verify_total = Duration::ZERO;
    for _ in 0..iterations {
        let (_, elapsed) = timed(|| {
            black_box(verify(
                black_box(&signer),
                black_box(MESSAGE),
                black_box(&signature),
            ))
        });
        verify_total += elapsed;
    }

    println!("SQIsign Level 5 candidate ({iterations} measured iterations)");
    println!("keygen:                {keygen:?}");
    println!("initial sign:          {initial_sign:?}");
    println!(
        "average sign:          {:?}",
        average(sign_total, iterations)
    );
    println!(
        "average verify:        {:?}",
        average(verify_total, iterations)
    );

    let timing_samples = std::env::var("XPARQ_SQISIGN_TIMING_SAMPLES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value >= 2)
        .unwrap_or(0);
    if timing_samples > 0 {
        report_timing_diagnostic(&signer, timing_samples);
    }
}

fn sign(signer: &KeyPair, message: &[u8]) -> Signature {
    sign_sqisign(
        SignatureContext::ProtocolTransaction,
        &signer.secret_key,
        message,
    )
    .expect("signing")
}

fn verify(signer: &KeyPair, message: &[u8], signature: &Signature) -> bool {
    verify_sqisign(
        SignatureContext::ProtocolTransaction,
        &signer.public_key,
        message,
        signature,
    )
}

fn report_timing_diagnostic(signer: &KeyPair, samples: usize) {
    let class_a = [0_u8; 32];
    let class_b = [0xff_u8; 32];
    let mut timings_a = Vec::with_capacity(samples);
    let mut timings_b = Vec::with_capacity(samples);

    for _ in 0..samples {
        let (_, elapsed_a) = timed(|| sign(signer, &class_a));
        let (_, elapsed_b) = timed(|| sign(signer, &class_b));
        timings_a.push(elapsed_a.as_secs_f64());
        timings_b.push(elapsed_b.as_secs_f64());
    }

    let (mean_a, variance_a) = sample_stats(&timings_a);
    let (mean_b, variance_b) = sample_stats(&timings_b);
    let denominator = (variance_a / samples as f64 + variance_b / samples as f64).sqrt();
    let welch_t = if denominator == 0.0 {
        0.0
    } else {
        (mean_a - mean_b) / denominator
    };
    println!("timing diagnostic ({samples} paired samples per class)");
    println!("class A mean: {mean_a:.6} s");
    println!("class B mean: {mean_b:.6} s");
    println!("Welch t statistic: {welch_t:.3}");
    println!("diagnostic only; this is not a constant-time or side-channel certification");
}

fn sample_stats(samples: &[f64]) -> (f64, f64) {
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    let variance = samples
        .iter()
        .map(|sample| {
            let delta = sample - mean;
            delta * delta
        })
        .sum::<f64>()
        / (samples.len() - 1) as f64;
    (mean, variance)
}
