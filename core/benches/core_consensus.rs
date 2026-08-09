use std::hint::black_box;
use std::time::{Duration, Instant};
use xparq::block::MAX_BLOCK_WEIGHT;
use xparq::codec::{canonical_bytes, canonical_deserialize};
use xparq::consensus::supply::{Amount, BASE_BLOCK_REWARD};
use xparq::consensus::{
    DIFFICULTY_START, WBDA_WINDOW, next_difficulty_from_window, next_reward_from_window,
};
use xparq::crypto::{Address, address_from_string, address_to_string, argon2id_pow_hash};
use xparq::genesis::{decode_genesis_xparq, genesis_xparq_bytes};
use xparq::qcash::{
    QCASH_FILE_VERSION, QCashCoinFile, QCashDenomination, decode_qcash_coin_file,
    encode_qcash_coin_file, format_qcash_coins,
};

fn measure(iterations: u32, mut operation: impl FnMut()) -> Duration {
    let started = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    started.elapsed() / iterations
}

fn report(label: &str, elapsed: Duration) {
    println!("{label:<34} {elapsed:?}/operation");
}

fn main() {
    let iterations = std::env::var("xparq_CORE_BENCH_ITERATIONS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(25);

    println!("xparq core benchmark ({iterations} measured iterations)");

    let address = Address([7; 20]);
    let encoded_address = address_to_string(&address);
    report(
        "address encode",
        measure(iterations, || {
            black_box(address_to_string(black_box(&address)));
        }),
    );
    report(
        "address decode",
        measure(iterations, || {
            black_box(address_from_string(black_box(&encoded_address))).unwrap();
        }),
    );

    let half_window = vec![MAX_BLOCK_WEIGHT / 2; WBDA_WINDOW];
    let full_window = vec![MAX_BLOCK_WEIGHT; WBDA_WINDOW];
    report(
        "WBDA difficulty (2048 blocks)",
        measure(iterations, || {
            black_box(next_difficulty_from_window(
                DIFFICULTY_START,
                black_box(&half_window),
            ))
            .unwrap();
        }),
    );
    report(
        "WBDA reward (2048 blocks)",
        measure(iterations, || {
            black_box(next_reward_from_window(
                Amount(BASE_BLOCK_REWARD),
                black_box(&full_window),
            ))
            .unwrap();
        }),
    );

    let coin = QCashCoinFile {
        version: QCASH_FILE_VERSION,
        coin_id: [3; 32],
        denomination: QCashDenomination::OneHundred,
        redeem_secret: [9; 32],
    };
    let encoded_coin = encode_qcash_coin_file(&coin).unwrap();
    report(
        "QCash coin encode",
        measure(iterations, || {
            black_box(encode_qcash_coin_file(black_box(&coin))).unwrap();
        }),
    );
    report(
        "QCash coin decode",
        measure(iterations, || {
            black_box(decode_qcash_coin_file(black_box(&encoded_coin))).unwrap();
        }),
    );
    report(
        "QCash denomination selection",
        measure(iterations, || {
            black_box(format_qcash_coins(black_box(Amount(1_234_567_000_000)))).unwrap();
        }),
    );

    let canonical = canonical_bytes(&coin).unwrap();
    report(
        "canonical QCash serialize",
        measure(iterations, || {
            black_box(canonical_bytes(black_box(&coin))).unwrap();
        }),
    );
    report(
        "canonical QCash deserialize",
        measure(iterations, || {
            black_box(canonical_deserialize::<QCashCoinFile>(black_box(
                &canonical,
            )))
            .unwrap();
        }),
    );

    let genesis = genesis_xparq_bytes().expect("canonical genesis artifact");
    report(
        "genesis artifact validation",
        measure(iterations.min(5), || {
            black_box(decode_genesis_xparq(black_box(&genesis))).unwrap();
        }),
    );

    let pow_iterations = iterations.min(3);
    report(
        "Argon2id proof-of-work hash",
        measure(pow_iterations, || {
            black_box(argon2id_pow_hash(black_box(b"xparq-core-benchmark-header"))).unwrap();
        }),
    );
}
