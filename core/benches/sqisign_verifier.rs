use sqisign_rs::{Level5, PublicKey as RawPublicKey};
use std::hint::black_box;
use std::time::{Duration, Instant};
use xparq::crypto::{
    PublicKey, Signature, cached_verifying_key, clear_verifying_key_cache, keypair_from_seed, sign,
    verify, verify_batch_parallel_accounted, verify_dual_parallel,
};

const MESSAGE: &[u8] = b"xparq SQIsign Level 5 verifier benchmark";
const BATCH_TRANSACTIONS: usize = 16;

fn measured(iterations: u32, mut operation: impl FnMut()) -> Duration {
    let started = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    started.elapsed() / iterations
}

fn main() {
    let iterations = std::env::var("XPARQ_SQISIGN_BENCH_ITERATIONS")
        .or_else(|_| std::env::var("xparq_SQISIGN_BENCH_ITERATIONS"))
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(10);

    let owner = keypair_from_seed(&[31; 32]);
    let authorization = keypair_from_seed(&[47; 32]);
    let owner_signature = sign(&owner.secret_key, MESSAGE);
    let auth_signature = sign(&authorization.secret_key, MESSAGE);

    let decode = measured(iterations, || {
        black_box(
            RawPublicKey::<Level5>::from_bytes(black_box(&owner.public_key.0))
                .expect("valid public key"),
        );
    });
    let cold_single = measured(iterations, || {
        clear_verifying_key_cache();
        assert!(verify(
            black_box(&owner.public_key),
            black_box(MESSAGE),
            black_box(&owner_signature),
        ));
    });
    clear_verifying_key_cache();
    let cached = cached_verifying_key(&owner.public_key);
    let warm_single = measured(iterations, || {
        assert!(
            cached
                .verify(black_box(MESSAGE), black_box(&owner_signature))
                .is_ok()
        );
    });
    let dual = measured(iterations, || {
        assert_eq!(
            verify_dual_parallel(
                black_box(&owner.public_key),
                black_box(&authorization.public_key),
                black_box(MESSAGE),
                black_box(&owner_signature),
                black_box(&auth_signature),
            ),
            (true, true)
        );
    });

    let mut block_jobs =
        Vec::<(PublicKey, Vec<u8>, Signature)>::with_capacity(BATCH_TRANSACTIONS * 2);
    for _ in 0..BATCH_TRANSACTIONS {
        block_jobs.push((owner.public_key, MESSAGE.to_vec(), owner_signature));
        block_jobs.push((authorization.public_key, MESSAGE.to_vec(), auth_signature));
    }
    let mut accounted_work = None;
    let batch = measured(iterations, || {
        let (results, work) = verify_batch_parallel_accounted(black_box(&block_jobs));
        accounted_work = Some(work);
        assert!(results.into_iter().all(|valid| valid));
    });
    let accounted_work = accounted_work.expect("benchmark work accounting");

    println!("SQIsign Level 5 verifier ({iterations} iterations)");
    println!("decode public key:             {decode:?}");
    println!("single verify, cold cache:     {cold_single:?}");
    println!("single verify, warm cache:     {warm_single:?}");
    println!("dual verify, persistent pool:  {dual:?}");
    println!("batch/block verify ({BATCH_TRANSACTIONS} dual tx): {batch:?}");
    println!(
        "accounted work: {} signatures, {} worst-case key decodes, {} message bytes",
        accounted_work.signature_checks,
        accounted_work.public_key_decodes,
        accounted_work.message_bytes
    );
}
