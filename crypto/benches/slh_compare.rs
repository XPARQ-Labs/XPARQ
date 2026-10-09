// Manual backend comparison; SHA2 remains unavailable to consensus accounts.
use slh_dsa::{Sha2_256s, Shake256s, SigningKey, VerifyingKey};
use std::{hint::black_box, time::Instant};

#[derive(Default)]
struct Measurements {
    keygen: Vec<f64>,
    signing: Vec<f64>,
    valid: Vec<f64>,
    invalid_first: Vec<f64>,
    invalid_last: Vec<f64>,
}
const VERIFY_ROUNDS: usize = 100;

macro_rules! trial {
    ($params:ty, $index:expr, $row:expr) => {{
        // Same independent FIPS input seeds and 32-byte message for both backends.
        // Seed expansion is excluded, as is network/storage work.
        let start = Instant::now();
        let key = SigningKey::<$params>::slh_keygen_internal(
            black_box(&[$index + 1; 32]),
            &[0x32; 32],
            &[0x33; 32],
        );
        let keygen = start.elapsed().as_secs_f64() * 1000.;
        let public: &VerifyingKey<$params> = key.as_ref();
        let public_bytes = public.to_vec();
        let message = [$index; 32];
        let start = Instant::now();
        let signature = key
            .try_sign_with_context(black_box(&message), b"", None)
            .unwrap()
            .to_vec();
        let signing = start.elapsed().as_secs_f64() * 1000.;
        assert_eq!(public_bytes.len(), 64);
        assert_eq!(signature.len(), 29792);
        let mut first = signature.clone();
        first[0] ^= 1;
        let mut last = signature.clone();
        *last.last_mut().unwrap() ^= 1;
        let mut times = Vec::new();
        for (bytes, expected) in [(&signature, true), (&first, false), (&last, false)] {
            let start = Instant::now();
            for _ in 0..VERIFY_ROUNDS {
                // Include parsing, just as XPARQ's backend verification does.
                let public =
                    VerifyingKey::<$params>::try_from(black_box(public_bytes.as_slice())).unwrap();
                let signature =
                    slh_dsa::Signature::<$params>::try_from(black_box(bytes.as_slice())).unwrap();
                let valid = public
                    .try_verify_with_context(black_box(&message), b"", &signature)
                    .is_ok();
                assert_eq!(black_box(valid), expected);
            }
            times.push(start.elapsed().as_secs_f64() * 1000. / VERIFY_ROUNDS as f64);
        }
        $row.keygen.push(keygen);
        $row.signing.push(signing);
        $row.valid.push(times[0]);
        $row.invalid_first.push(times[1]);
        $row.invalid_last.push(times[2]);
    }};
}
fn stats(values: &[f64]) -> String {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    format!(
        "{:.3} [{:.3}..{:.3}]",
        sorted[sorted.len() / 2],
        sorted[0],
        sorted[sorted.len() - 1]
    )
}
fn main() {
    println!("SLH-DSA Pure 256s, empty context, deterministic signing, 32-byte message");
    println!(
        "1 warmup + 5 measured trials/backend; {} verifications/case/trial; alternating backend order",
        VERIFY_ROUNDS
    );
    let mut warmup = Measurements::default();
    trial!(Sha2_256s, 0, warmup);
    trial!(Shake256s, 0, warmup);
    let mut sha2 = Measurements::default();
    let mut shake = Measurements::default();
    for i in 1..=5u8 {
        if i % 2 == 1 {
            trial!(Sha2_256s, i, sha2);
            trial!(Shake256s, i, shake);
        } else {
            trial!(Shake256s, i, shake);
            trial!(Sha2_256s, i, sha2);
        }
        println!("trial {i}/5 completed");
    }
    println!("All times in milliseconds: median [min..max]");
    println!("operation,SHA2-256s,SHAKE-256s");
    for (name, a, b) in [
        ("keygen", &sha2.keygen, &shake.keygen),
        ("sign_prepared_key", &sha2.signing, &shake.signing),
        ("verify_valid", &sha2.valid, &shake.valid),
        (
            "verify_invalid_first_byte",
            &sha2.invalid_first,
            &shake.invalid_first,
        ),
        (
            "verify_invalid_last_byte",
            &sha2.invalid_last,
            &shake.invalid_last,
        ),
    ] {
        println!("{name},{},{}", stats(a), stats(b));
    }
}
