use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    FalconLevel, FalconPublicKey, FalconSignature, falcon_keypair_from_seed, falcon_sign,
    falcon_verify,
};

pub const QCASH_PUBLIC_KEY_SIZE: usize = 897;
pub const QCASH_SIGNATURE_SIZE: usize = 666;
pub const QCASH_SIGNATURE_ALGORITHM: &str = "qcash-signature";

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct QCashPublicKey(pub [u8; QCASH_PUBLIC_KEY_SIZE]);

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct QCashSignature(pub [u8; QCASH_SIGNATURE_SIZE]);

pub fn qcash_public_key_from_seed(seed: &[u8; 32]) -> QCashPublicKey {
    let keypair = falcon_keypair_from_seed(FalconLevel::Level1, seed)
        .expect("fixed Falcon-512 seed derivation must succeed");
    QCashPublicKey(
        keypair
            .public_key
            .as_bytes()
            .try_into()
            .expect("Falcon-512 public key size is fixed"),
    )
}

pub fn qcash_sign_from_seed(seed: &[u8; 32], message: &[u8]) -> QCashSignature {
    let keypair = falcon_keypair_from_seed(FalconLevel::Level1, seed)
        .expect("fixed Falcon-512 seed derivation must succeed");
    let signature =
        falcon_sign(&keypair.secret_key, message).expect("valid Falcon-512 signing key");
    QCashSignature(
        signature
            .as_bytes()
            .try_into()
            .expect("Falcon-512 signature size is fixed"),
    )
}

pub fn qcash_verify(
    public_key: &QCashPublicKey,
    message: &[u8],
    signature: &QCashSignature,
) -> bool {
    let Ok(public_key) = FalconPublicKey::from_bytes(FalconLevel::Level1, public_key.0.to_vec())
    else {
        return false;
    };
    let Ok(signature) = FalconSignature::from_bytes(FalconLevel::Level1, signature.0.to_vec())
    else {
        return false;
    };
    falcon_verify(&public_key, message, &signature).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn falcon_512_qcash_signatures_have_fixed_compact_sizes_and_bind_the_message() {
        assert_eq!(FalconLevel::Level1.public_key_size(), QCASH_PUBLIC_KEY_SIZE);
        assert_eq!(FalconLevel::Level1.signature_size(), QCASH_SIGNATURE_SIZE);
        let seed = [7; 32];
        let public_key = qcash_public_key_from_seed(&seed);
        let signature = qcash_sign_from_seed(&seed, b"QCash intent");
        assert!(qcash_verify(&public_key, b"QCash intent", &signature));
        assert!(!qcash_verify(&public_key, b"tampered intent", &signature));
    }
}
