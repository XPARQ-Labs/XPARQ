use borsh::{BorshDeserialize, BorshSerialize};
use ml_dsa::{Keypair, MlDsa44, SignatureEncoding, Signer, SigningKey, Verifier, VerifyingKey};

use crate::{
    FalconLevel, FalconPublicKey, FalconSignature, falcon_keypair_from_seed, falcon_sign,
    falcon_verify,
};

pub const QCASH_PUBLIC_KEY_SIZE: usize = 1_312;
pub const QCASH_SIGNATURE_SIZE: usize = 2_420;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct QCashPublicKey(pub [u8; QCASH_PUBLIC_KEY_SIZE]);

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct QCashSignature(pub [u8; QCASH_SIGNATURE_SIZE]);

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct FalconQCashPublicKey(pub FalconPublicKey);

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct FalconQCashSignature(pub FalconSignature);

pub fn falcon_qcash_public_key_from_seed(seed: &[u8; 32]) -> FalconQCashPublicKey {
    FalconQCashPublicKey(
        falcon_keypair_from_seed(FalconLevel::Level1, seed)
            .expect("fixed Falcon-512 seed derivation must succeed")
            .public_key,
    )
}

pub fn falcon_qcash_sign_from_seed(seed: &[u8; 32], message: &[u8]) -> FalconQCashSignature {
    let keypair = falcon_keypair_from_seed(FalconLevel::Level1, seed)
        .expect("fixed Falcon-512 seed derivation must succeed");
    FalconQCashSignature(
        falcon_sign(&keypair.secret_key, message).expect("valid Falcon-512 signing key"),
    )
}

pub fn falcon_qcash_verify(
    public_key: &FalconQCashPublicKey,
    message: &[u8],
    signature: &FalconQCashSignature,
) -> bool {
    public_key.0.level() == FalconLevel::Level1
        && signature.0.level() == FalconLevel::Level1
        && falcon_verify(&public_key.0, message, &signature.0).unwrap_or(false)
}

pub fn qcash_public_key_from_seed(seed: &[u8; 32]) -> QCashPublicKey {
    let key = SigningKey::<MlDsa44>::from_seed(&(*seed).into());
    QCashPublicKey(key.verifying_key().encode().into())
}

pub fn qcash_sign_from_seed(seed: &[u8; 32], message: &[u8]) -> QCashSignature {
    let key = SigningKey::<MlDsa44>::from_seed(&(*seed).into());
    let signature: ml_dsa::Signature<MlDsa44> = key.sign(message);
    QCashSignature(signature.to_bytes().into())
}

pub fn qcash_verify(
    public_key: &QCashPublicKey,
    message: &[u8],
    signature: &QCashSignature,
) -> bool {
    let key = VerifyingKey::<MlDsa44>::decode(&public_key.0.into());
    let Some(signature) = ml_dsa::Signature::<MlDsa44>::decode(&signature.0.into()) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_seed_signatures_verify_and_bind_the_message() {
        let seed = [7; 32];
        let public_key = qcash_public_key_from_seed(&seed);
        let signature = qcash_sign_from_seed(&seed, b"QCash intent");
        assert!(qcash_verify(&public_key, b"QCash intent", &signature));
        assert!(!qcash_verify(&public_key, b"tampered intent", &signature));
    }

    #[test]
    fn falcon_compact_seed_signatures_verify_and_bind_the_message() {
        let seed = [8; 32];
        let first = falcon_qcash_public_key_from_seed(&seed);
        let second = falcon_qcash_public_key_from_seed(&seed);
        assert_eq!(first, second);
        let signature = falcon_qcash_sign_from_seed(&seed, b"Falcon QCash intent");
        assert!(falcon_qcash_verify(
            &first,
            b"Falcon QCash intent",
            &signature
        ));
        assert!(!falcon_qcash_verify(&first, b"tampered", &signature));
    }
}
