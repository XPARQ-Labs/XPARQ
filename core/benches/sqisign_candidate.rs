use std::hint::black_box;
use std::time::{Duration, Instant};
use xparq::crypto::SignatureContext;
use xparq::crypto::sqisign_candidate::{
    DualAuthorization, KeyPair, generate_keypair, sign_dual, verify_dual,
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

    let (owner, owner_keygen) = timed(|| generate_keypair().expect("owner key generation"));
    let (authorization, authorization_keygen) =
        timed(|| generate_keypair().expect("authorization key generation"));
    let (signatures, initial_sign) = timed(|| sign(&owner, &authorization));
    assert!(verify(&owner, &authorization, &signatures));

    let mut sign_total = Duration::ZERO;
    for _ in 0..iterations {
        let (_, elapsed) = timed(|| black_box(sign(&owner, &authorization)));
        sign_total += elapsed;
    }

    let mut verify_total = Duration::ZERO;
    for _ in 0..iterations {
        let (_, elapsed) = timed(|| {
            black_box(verify(
                black_box(&owner),
                black_box(&authorization),
                black_box(&signatures),
            ))
        });
        verify_total += elapsed;
    }

    println!("SQIsign Level 5 candidate ({iterations} measured iterations)");
    println!("owner keygen:          {owner_keygen:?}");
    println!("authorization keygen:  {authorization_keygen:?}");
    println!("initial dual sign:      {initial_sign:?}");
    println!(
        "average dual sign:      {:?}",
        average(sign_total, iterations)
    );
    println!(
        "average dual verify:    {:?}",
        average(verify_total, iterations)
    );

    let timing_samples = std::env::var("XPARQ_SQISIGN_TIMING_SAMPLES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value >= 2)
        .unwrap_or(0);
    if timing_samples > 0 {
        report_timing_diagnostic(&owner, &authorization, timing_samples);
    }
}

fn sign(owner: &KeyPair, authorization: &KeyPair) -> DualAuthorization {
    sign_dual(
        SignatureContext::ProtocolTransaction,
        &owner.secret_key,
        &authorization.secret_key,
        MESSAGE,
    )
    .expect("dual signing")
}

fn verify(owner: &KeyPair, authorization: &KeyPair, signatures: &DualAuthorization) -> bool {
    verify_dual(
        SignatureContext::ProtocolTransaction,
        &owner.public_key,
        &authorization.public_key,
        MESSAGE,
        signatures,
    )
}

fn report_timing_diagnostic(owner: &KeyPair, authorization: &KeyPair, samples: usize) {
    let class_a = [0_u8; 32];
    let class_b = [0xff_u8; 32];
    let mut timings_a = Vec::with_capacity(samples);
    let mut timings_b = Vec::with_capacity(samples);

    for _ in 0..samples {
        let (_, elapsed_a) = timed(|| {
            sign_dual(
                SignatureContext::ProtocolTransaction,
                &owner.secret_key,
                &authorization.secret_key,
                &class_a,
            )
            .expect("timing class A signing")
        });
        let (_, elapsed_b) = timed(|| {
            sign_dual(
                SignatureContext::ProtocolTransaction,
                &owner.secret_key,
                &authorization.secret_key,
                &class_b,
            )
            .expect("timing class B signing")
        });
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
