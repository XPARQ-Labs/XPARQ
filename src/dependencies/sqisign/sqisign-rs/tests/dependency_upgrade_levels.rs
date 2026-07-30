//! Regression coverage for the rand/rand_core/signature dependency migration.

use rand::rngs::StdRng;
use rand::SeedableRng;
use sqisign_rs::{generate, Level1, Level3, Level5, Verifier};

macro_rules! level_roundtrip {
    ($name:ident, $level:ty, $seed:expr) => {
        #[test]
        fn $name() {
            let mut rng = StdRng::from_seed([$seed; 32]);
            let (public_key, signing_key) = generate::<$level>(&mut rng);
            let message = concat!("SQIsign dependency migration ", stringify!($level)).as_bytes();
            let signature = signing_key
                .sign(message, &mut rng)
                .expect("signing succeeds");

            public_key
                .verify(message, &signature)
                .expect("signature verifies");
            assert!(public_key.verify(b"modified message", &signature).is_err());
        }
    };
}

level_roundtrip!(level1_keygen_sign_verify, Level1, 1);
level_roundtrip!(level3_keygen_sign_verify, Level3, 3);
level_roundtrip!(level5_keygen_sign_verify, Level5, 5);

#[test]
fn malformed_level1_inputs_fail_closed() {
    let mut rng = StdRng::from_seed([11; 32]);
    let (public_key, signing_key) = generate::<Level1>(&mut rng);
    let message = b"malformed input corpus";
    let signature = signing_key
        .sign(message, &mut rng)
        .expect("signing succeeds");
    let valid = signature.to_bytes();

    assert!(sqisign_rs::Signature::<Level1>::from_bytes(&valid[..valid.len() - 1]).is_err());

    let zero_public_key =
        sqisign_rs::PublicKey::<Level1>::from_bytes(&[0; 65]).expect("canonical curve encoding");
    let zero_result = std::panic::catch_unwind(|| {
        let Ok(signature) = sqisign_rs::Signature::<Level1>::from_bytes(&vec![0; valid.len()])
        else {
            return false;
        };
        zero_public_key.verify(message, &signature).is_ok()
    });
    assert!(
        matches!(zero_result, Ok(false)),
        "all-zero inputs must fail closed"
    );

    for index in [
        0,
        1,
        valid.len() / 3,
        valid.len() / 2,
        valid.len() - 2,
        valid.len() - 1,
    ] {
        let mut mutated = valid.as_slice().to_vec();
        mutated[index] ^= 0x80;
        let result = std::panic::catch_unwind(|| {
            let Ok(signature) = sqisign_rs::Signature::<Level1>::from_bytes(&mutated) else {
                return false;
            };
            public_key.verify(message, &signature).is_ok()
        });

        assert!(
            matches!(result, Ok(false)),
            "mutation at byte {index} must fail closed"
        );
    }
}
