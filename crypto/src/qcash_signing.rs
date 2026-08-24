use borsh::{BorshDeserialize, BorshSerialize};
use ml_dsa::{Keypair, MlDsa44, SignatureEncoding, Signer, SigningKey, Verifier, VerifyingKey};

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
}
