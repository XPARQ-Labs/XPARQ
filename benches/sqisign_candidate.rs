use paqus::crypto::SignatureContext;
use paqus::crypto::sqisign_candidate::{
    DualAuthorization, KeyPair, generate_keypair, sign_dual, verify_dual,
};
use std::hint::black_box;
use std::time::{Duration, Instant};

const MESSAGE: &[u8] = b"paqus sqisign level 5 candidate benchmark";

fn timed<T>(operation: impl FnOnce() -> T) -> (T, Duration) {
    let started = Instant::now();
    let value = operation();
    (value, started.elapsed())
}

fn average(total: Duration, iterations: u32) -> Duration {
    total / iterations
}

fn main() {
    let iterations = std::env::var("PAQUS_SQISIGN_BENCH_ITERATIONS")
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
