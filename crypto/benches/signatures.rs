#[path = "../../benches/support/mod.rs"]
mod support;

use crypto::{AccountSignatureScheme, SigningSeed, verify};
use std::hint::black_box;
use support::{Config, report, timed};

fn main() {
    let config = Config::from_args();
    for scheme in AccountSignatureScheme::ALL {
        let name = format!("{scheme:?}");
        let mut rows: [Vec<f64>; 6] = std::array::from_fn(|_| Vec::new());
        println!(
            "# {name}: public_key_bytes={}, signature_bytes={}",
            scheme.public_key_size(),
            scheme.signature_size()
        );
        for sample in 0..=config.samples {
            // 32-byte public benchmark seed, never real wallet material.
            let seed = [(sample as u8).wrapping_add(31); 32];
            let message = [sample as u8; 32];
            let (cold_signature, cold_ms) = timed(|| {
                let key = SigningSeed::new(scheme, Box::new(seed));
                black_box(key.sign(black_box(&message)))
            });
            let key = SigningSeed::new(scheme, Box::new(seed));
            let (public, keygen_ms) = timed(|| key.public_key());
            let (signature, prepared_ms) = timed(|| key.sign(black_box(&message)));
            // ML-DSA signing is randomized; signatures need not match.
            assert!(verify(&public, &message, &cold_signature));
            assert!(verify(&public, &message, &signature));
            let mut first = signature.clone();
            first.bytes[0] ^= 1;
            let mut last = signature.clone();
            *last.bytes.last_mut().unwrap() ^= 1;
            let mut values = vec![keygen_ms, cold_ms, prepared_ms];
            for (signature, expected) in [(&signature, true), (&first, false), (&last, false)] {
                let (_, ms) = timed(|| {
                    for _ in 0..config.verify_rounds {
                        assert_eq!(
                            black_box(verify(
                                black_box(&public),
                                black_box(&message),
                                black_box(signature)
                            )),
                            expected
                        );
                    }
                });
                values.push(ms / config.verify_rounds as f64);
            }
            if sample != 0 {
                for (row, value) in rows.iter_mut().zip(values) {
                    row.push(value);
                }
            }
            println!("# {name}: sample {sample}/{} complete", config.samples);
        }
        for (operation, values) in [
            "prepare_public_key",
            "sign_cold_with_keygen_and_drop",
            "sign_prepared",
            "verify_valid",
            "verify_invalid_first_byte",
            "verify_invalid_last_byte",
        ]
        .into_iter()
        .zip(&rows)
        {
            report(&name, operation, values);
        }
    }
}
