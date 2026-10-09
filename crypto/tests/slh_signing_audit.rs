use slh_dsa::signature::Keypair;
use slh_dsa::{Shake128s, Shake192s, Shake256s, SigningKey};

// Public NIST ACVP keys and complete signatures, not XPARQ wallet material.
macro_rules! signing_case {
    ($name:ident, $param:ty, $size:literal) => {
        #[test]
        fn $name() {
            let key = SigningKey::<$param>::try_from(
                include_bytes!(concat!("vectors/slhdsa/", $size, "-siggen.sk")).as_slice(),
            )
            .unwrap();
            let debug = format!("{key:?}");
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains("sk_seed"));
            assert!(!debug.contains("sk_prf"));
            assert_eq!(
                key.verifying_key().to_bytes().as_slice(),
                include_bytes!(concat!("vectors/slhdsa/", $size, "-siggen.pk"))
            );
            let message = include_bytes!(concat!("vectors/slhdsa/", $size, "-siggen.message"));
            let context = include_bytes!(concat!("vectors/slhdsa/", $size, "-siggen.context"));
            let signature = key.try_sign_with_context(message, context, None).unwrap();
            assert_eq!(
                signature.to_bytes().as_slice(),
                include_bytes!(concat!("vectors/slhdsa/", $size, "-siggen.signature"))
            );
            assert!(
                key.verifying_key()
                    .try_verify_with_context(message, context, &signature)
                    .is_ok()
            );
            assert!(
                key.verifying_key()
                    .try_verify_with_context(message, b"changed-context", &signature)
                    .is_err()
            );
        }
    };
}

signing_case!(nist_pure_shake128s_signing, Shake128s, "128s");
signing_case!(nist_pure_shake192s_signing, Shake192s, "192s");
signing_case!(nist_pure_shake256s_signing, Shake256s, "256s");
