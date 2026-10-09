//! Pure SLH-DSA SHAKE small variants (FIPS 205), empty context.
//! The wallet's 32-byte master seed expands into the three FIPS keygen seeds.
use crate::signature::{AccountSignature, AccountSignatureScheme, PublicKey};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use slh_dsa::{Shake128s, Shake192s, Shake256s, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

pub const SEED_EXPANSION_DOMAIN: &[u8] = b"XPARQ_SLH_DSA_KEYGEN_V1";

fn expanded_seed(account: AccountSignatureScheme, seed: &[u8; 32]) -> Zeroizing<[u8; 96]> {
    let mut xof = Shake256::default();
    xof.update(SEED_EXPANSION_DOMAIN);
    xof.update(&[account.id()]);
    xof.update(seed);
    let mut bytes = Zeroizing::new([0; 96]);
    xof.finalize_xof().read(bytes.as_mut());
    bytes
}

macro_rules! key {
    ($params:ty, $account:expr, $seed:expr) => {{
        let expanded = expanded_seed($account, $seed);
        let n = $account.public_key_size() / 2;
        SigningKey::<$params>::slh_keygen_internal(
            &expanded[..n],
            &expanded[n..2 * n],
            &expanded[2 * n..3 * n],
        )
    }};
}

/// Expanded secret material stays local to a signing session; each typed key zeroizes on drop.
pub(crate) enum PreparedKey {
    SlhDsaShake128s(Box<SigningKey<Shake128s>>),
    SlhDsaShake192s(Box<SigningKey<Shake192s>>),
    SlhDsaShake256s(Box<SigningKey<Shake256s>>),
}
impl PreparedKey {
    pub(crate) fn new(account: AccountSignatureScheme, seed: &[u8; 32]) -> Self {
        match account {
            AccountSignatureScheme::SlhDsaShake128s => {
                Self::SlhDsaShake128s(Box::new(key!(Shake128s, account, seed)))
            }
            AccountSignatureScheme::SlhDsaShake192s => {
                Self::SlhDsaShake192s(Box::new(key!(Shake192s, account, seed)))
            }
            AccountSignatureScheme::SlhDsaShake256s => {
                Self::SlhDsaShake256s(Box::new(key!(Shake256s, account, seed)))
            }
            _ => unreachable!("wrong signature family"),
        }
    }
    pub(crate) fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            Self::SlhDsaShake128s(key) => {
                let public: &VerifyingKey<Shake128s> = key.as_ref().as_ref();
                public.to_vec()
            }
            Self::SlhDsaShake192s(key) => {
                let public: &VerifyingKey<Shake192s> = key.as_ref().as_ref();
                public.to_vec()
            }
            Self::SlhDsaShake256s(key) => {
                let public: &VerifyingKey<Shake256s> = key.as_ref().as_ref();
                public.to_vec()
            }
        }
    }
    pub(crate) fn sign_bytes(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::SlhDsaShake128s(key) => key
                .try_sign_with_context(message, b"", None)
                .expect("empty context is valid")
                .to_vec(),
            Self::SlhDsaShake192s(key) => key
                .try_sign_with_context(message, b"", None)
                .expect("empty context is valid")
                .to_vec(),
            Self::SlhDsaShake256s(key) => key
                .try_sign_with_context(message, b"", None)
                .expect("empty context is valid")
                .to_vec(),
        }
    }
}

pub(crate) fn public_key_from_seed(account: AccountSignatureScheme, seed: &[u8; 32]) -> PublicKey {
    PublicKey {
        account,
        bytes: PreparedKey::new(account, seed).public_key_bytes(),
    }
}
pub(crate) fn sign_from_seed(
    account: AccountSignatureScheme,
    seed: &[u8; 32],
    message: &[u8],
) -> AccountSignature {
    AccountSignature {
        account,
        bytes: PreparedKey::new(account, seed).sign_bytes(message),
    }
}

pub(crate) fn verify(public_key: &PublicKey, message: &[u8], signature: &AccountSignature) -> bool {
    macro_rules! verify {
        ($params:ty) => {{
            let Ok(key) = VerifyingKey::<$params>::try_from(public_key.bytes.as_slice()) else {
                return false;
            };
            let Ok(sig) = slh_dsa::Signature::<$params>::try_from(signature.bytes.as_slice())
            else {
                return false;
            };
            key.try_verify_with_context(message, b"", &sig).is_ok()
        }};
    }
    match public_key.scheme() {
        AccountSignatureScheme::SlhDsaShake128s => verify!(Shake128s),
        AccountSignatureScheme::SlhDsaShake192s => verify!(Shake192s),
        AccountSignatureScheme::SlhDsaShake256s => verify!(Shake256s),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SigningSeed, verify};

    #[test]
    fn selected_slh_variants_sign_verify_and_reject_forgery() {
        for scheme in AccountSignatureScheme::ALL
            .into_iter()
            .filter(|s| s.is_slh_dsa())
        {
            let key = SigningSeed::new(scheme, Box::new([31; 32]));
            let public = key.public_key();
            let mut signature = key.sign(b"XPARQ commitment");
            assert_eq!(public.bytes.len(), scheme.public_key_size());
            assert_eq!(signature.bytes.len(), scheme.signature_size());
            assert!(verify(&public, b"XPARQ commitment", &signature));
            for other in AccountSignatureScheme::ALL {
                if other != scheme {
                    let mut retagged = signature.clone();
                    retagged.account = other;
                    assert!(!verify(&public, b"XPARQ commitment", &retagged));
                }
            }
            let mut foreign_public = public.clone();
            foreign_public.bytes[0] ^= 1;
            assert!(!verify(&foreign_public, b"XPARQ commitment", &signature));
            assert!(!verify(&public, b"different commitment", &signature));
            signature.bytes[0] ^= 1;
            assert!(!verify(&public, b"XPARQ commitment", &signature));
            signature.bytes.pop();
            assert!(!verify(&public, b"XPARQ commitment", &signature));
        }
    }
    #[test]
    fn seed_expansion_matches_python_hashlib() {
        assert_eq!(
            hex::encode(
                expanded_seed(AccountSignatureScheme::SlhDsaShake128s, &[31; 32]).as_slice()
            ),
            "1fcc4c0d8bff7016c076389f6ba63cde9f15299c8fc1fe0a16fba80498e67d2339b523182eb906e2e45bbe469aa17875033212c1bda4a0b29b337c5dae39c6db86c53a17e1ed2ae0c426ba3e86a7f48d7ac33103f32988897c6d70a0bf9e2287"
        );
        assert_eq!(
            hex::encode(
                expanded_seed(AccountSignatureScheme::SlhDsaShake192s, &[31; 32]).as_slice()
            ),
            "952013ce9599ab879fd00874a9aa37d4ca8798b5515c89db477919171be2256f5cd53df3cac82a3793a8570f91d28cf7adf5e4fdefc85c578e81b5e065b7ec9b6e1b38c50a3f771dba29a59f70209056ebff9cdae170aa6ef8e7282d2419583f"
        );
        assert_eq!(
            hex::encode(
                expanded_seed(AccountSignatureScheme::SlhDsaShake256s, &[31; 32]).as_slice()
            ),
            "bd7075bd185db8fad478fce839ce39cfba1b0276ae26fc1d116499a12248caf2c207b3682632b842bc7d828248d95cbbe369328dee0f7f9b7e8f83e2684e6e180ad43aa525f3a02d809396dc1ded8f43f4ebdd6babd92b7808d8d60f21744ad5"
        );
    }

    #[test]
    fn nist_acvp_keygen_known_answers() {
        let key = SigningKey::<Shake128s>::slh_keygen_internal(
            &hex::decode("C151951F3811029239B74ADD24C506AF").unwrap(),
            &hex::decode("DD30363E156E6FE936EC6ED0231FEB5C").unwrap(),
            &hex::decode("529FFE86200D1F32C2B60D0CD909F190").unwrap(),
        );
        let public: &VerifyingKey<Shake128s> = key.as_ref();
        assert_eq!(
            public.to_vec(),
            hex::decode("529FFE86200D1F32C2B60D0CD909F1900761F9B727AFA724B47223016BB5B2BA")
                .unwrap()
        );
        let key = SigningKey::<Shake192s>::slh_keygen_internal(
            &hex::decode("8732621860E9A6E1887BE55F7AF692B98EB4C10B2599F94A").unwrap(),
            &hex::decode("D5CC9D6470D8B21136158E8B1710F1FBE03ECED37ED4AC68").unwrap(),
            &hex::decode("53FC64D46D7E1653EBBB36ED5FBC12C6E7CEF3CB756482C8").unwrap(),
        );
        let public: &VerifyingKey<Shake192s> = key.as_ref();
        assert_eq!(public.to_vec(), hex::decode("53FC64D46D7E1653EBBB36ED5FBC12C6E7CEF3CB756482C8C620452E864E8497E1B38A7B04449219ACD9E4393F9C88EF").unwrap());
        let key = SigningKey::<Shake256s>::slh_keygen_internal(
            &hex::decode("E440E39644A11A6A58E850C09C8F03C273E465237F3BEF7C58DE62281E676CEA")
                .unwrap(),
            &hex::decode("99C199C00DB30F8499A61B5B9DC8A361725F6AE80E97037176F408C30B38844D")
                .unwrap(),
            &hex::decode("D7B5E755B4879FDE3288A21AF3E32FBB006FD9B8BC2B180EB9B0D82C9F3157AF")
                .unwrap(),
        );
        let public: &VerifyingKey<Shake256s> = key.as_ref();
        assert_eq!(public.to_vec(), hex::decode("D7B5E755B4879FDE3288A21AF3E32FBB006FD9B8BC2B180EB9B0D82C9F3157AF02ACD6B3198EE1C9FE9AFE61FD86D1E0877AD9061980B57B178CE27191D8EB1B").unwrap());
    }

    #[test]
    fn nist_acvp_pure_signature_verification_known_answers() {
        // Official NIST ACVP sigVer FIPS205, tcId 342.
        let key = VerifyingKey::<Shake128s>::try_from(
            include_bytes!("../tests/vectors/slhdsa/128s-true.pk").as_slice(),
        )
        .unwrap();
        let result = slh_dsa::Signature::<Shake128s>::try_from(
            include_bytes!("../tests/vectors/slhdsa/128s-true.signature").as_slice(),
        )
        .is_ok_and(|sig| {
            key.try_verify_with_context(
                include_bytes!("../tests/vectors/slhdsa/128s-true.message"),
                include_bytes!("../tests/vectors/slhdsa/128s-true.context"),
                &sig,
            )
            .is_ok()
        });
        assert!(result);
        // Official NIST ACVP sigVer FIPS205, tcId 337.
        let key = VerifyingKey::<Shake128s>::try_from(
            include_bytes!("../tests/vectors/slhdsa/128s-false.pk").as_slice(),
        )
        .unwrap();
        let result = slh_dsa::Signature::<Shake128s>::try_from(
            include_bytes!("../tests/vectors/slhdsa/128s-false.signature").as_slice(),
        )
        .is_ok_and(|sig| {
            key.try_verify_with_context(
                include_bytes!("../tests/vectors/slhdsa/128s-false.message"),
                include_bytes!("../tests/vectors/slhdsa/128s-false.context"),
                &sig,
            )
            .is_ok()
        });
        assert!(!result);
        // Official NIST ACVP sigVer FIPS205, tcId 368.
        let key = VerifyingKey::<Shake192s>::try_from(
            include_bytes!("../tests/vectors/slhdsa/192s-true.pk").as_slice(),
        )
        .unwrap();
        let result = slh_dsa::Signature::<Shake192s>::try_from(
            include_bytes!("../tests/vectors/slhdsa/192s-true.signature").as_slice(),
        )
        .is_ok_and(|sig| {
            key.try_verify_with_context(
                include_bytes!("../tests/vectors/slhdsa/192s-true.message"),
                include_bytes!("../tests/vectors/slhdsa/192s-true.context"),
                &sig,
            )
            .is_ok()
        });
        assert!(result);
        // Official NIST ACVP sigVer FIPS205, tcId 365.
        let key = VerifyingKey::<Shake192s>::try_from(
            include_bytes!("../tests/vectors/slhdsa/192s-false.pk").as_slice(),
        )
        .unwrap();
        let result = slh_dsa::Signature::<Shake192s>::try_from(
            include_bytes!("../tests/vectors/slhdsa/192s-false.signature").as_slice(),
        )
        .is_ok_and(|sig| {
            key.try_verify_with_context(
                include_bytes!("../tests/vectors/slhdsa/192s-false.message"),
                include_bytes!("../tests/vectors/slhdsa/192s-false.context"),
                &sig,
            )
            .is_ok()
        });
        assert!(!result);
        // Official NIST ACVP sigVer FIPS205, tcId 399.
        let key = VerifyingKey::<Shake256s>::try_from(
            include_bytes!("../tests/vectors/slhdsa/256s-true.pk").as_slice(),
        )
        .unwrap();
        let result = slh_dsa::Signature::<Shake256s>::try_from(
            include_bytes!("../tests/vectors/slhdsa/256s-true.signature").as_slice(),
        )
        .is_ok_and(|sig| {
            key.try_verify_with_context(
                include_bytes!("../tests/vectors/slhdsa/256s-true.message"),
                include_bytes!("../tests/vectors/slhdsa/256s-true.context"),
                &sig,
            )
            .is_ok()
        });
        assert!(result);
        // Official NIST ACVP sigVer FIPS205, tcId 393.
        let key = VerifyingKey::<Shake256s>::try_from(
            include_bytes!("../tests/vectors/slhdsa/256s-false.pk").as_slice(),
        )
        .unwrap();
        let result = slh_dsa::Signature::<Shake256s>::try_from(
            include_bytes!("../tests/vectors/slhdsa/256s-false.signature").as_slice(),
        )
        .is_ok_and(|sig| {
            key.try_verify_with_context(
                include_bytes!("../tests/vectors/slhdsa/256s-false.message"),
                include_bytes!("../tests/vectors/slhdsa/256s-false.context"),
                &sig,
            )
            .is_ok()
        });
        assert!(!result);
    }
    #[test]
    fn shared_shake_preserves_pre_refactor_public_keys_and_signatures() {
        let key = SigningSeed::new(AccountSignatureScheme::SlhDsaShake128s, Box::new([31; 32]));
        assert_eq!(
            hex::encode(key.public_key().bytes),
            "39b523182eb906e2e45bbe469aa1787566d316300fad6e848b96e3f21048edf0"
        );
        let signature = key.sign(b"dependency-sharing-regression");
        assert_eq!(
            crate::hash_bytes(&signature.bytes).to_string(),
            "950372a1253a2b5e143d158683aa626a3460b82f4c19c42eabc0a40b3eec6616"
        );
        let key = SigningSeed::new(AccountSignatureScheme::SlhDsaShake192s, Box::new([31; 32]));
        assert_eq!(
            hex::encode(key.public_key().bytes),
            "adf5e4fdefc85c578e81b5e065b7ec9b6e1b38c50a3f771dba6cf20651322de9e6eff5263e0eb8bbc6bc0635ea775e07"
        );
        let signature = key.sign(b"dependency-sharing-regression");
        assert_eq!(
            crate::hash_bytes(&signature.bytes).to_string(),
            "a22716b4d29045f49c001aded4d361ab65cee943db9e10263f5fb88551921e3a"
        );
        let key = SigningSeed::new(AccountSignatureScheme::SlhDsaShake256s, Box::new([31; 32]));
        assert_eq!(
            hex::encode(key.public_key().bytes),
            "0ad43aa525f3a02d809396dc1ded8f43f4ebdd6babd92b7808d8d60f21744ad5da7bc74c8f0f1acea935721a4aba8ed5ea25bd029f2f4dfce4a12e7fb8e75e87"
        );
        let signature = key.sign(b"dependency-sharing-regression");
        assert_eq!(
            crate::hash_bytes(&signature.bytes).to_string(),
            "098c3eef21f7ea6ae74f6f4988e0454d4b11c6bfd1f61236ccd4ee5a3fa36869"
        );
    }
}
