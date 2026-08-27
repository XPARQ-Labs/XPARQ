use borsh::{BorshDeserialize, BorshSerialize};
use xparq_crypto::{
    QCashPublicKey, QCashSignature, qcash_public_key_from_seed, qcash_sign_from_seed,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const QCASH_SIGNING_SEED_SIZE: usize = 32;

/// Plaintext Falcon-512 signing seed stored inside a portable QCash file.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, BorshSerialize, BorshDeserialize)]
pub struct QCashSigningSeed([u8; QCASH_SIGNING_SEED_SIZE]);

impl QCashSigningSeed {
    pub const fn from_bytes(bytes: [u8; QCASH_SIGNING_SEED_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn random() -> Result<Self, getrandom::Error> {
        let mut bytes = [0; QCASH_SIGNING_SEED_SIZE];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; QCASH_SIGNING_SEED_SIZE] {
        &self.0
    }

    pub fn public_key(&self) -> QCashPublicKey {
        qcash_public_key_from_seed(&self.0)
    }

    pub fn sign(&self, message: &[u8]) -> QCashSignature {
        qcash_sign_from_seed(&self.0, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn falcon_512_seed_signs_and_rejects_tampering() {
        let key = QCashSigningSeed::from_bytes([23; 32]);
        let signature = key.sign(b"QCash Falcon-512");
        assert!(xparq_crypto::qcash_verify(
            &key.public_key(),
            b"QCash Falcon-512",
            &signature
        ));
        assert!(!xparq_crypto::qcash_verify(
            &key.public_key(),
            b"tampered",
            &signature
        ));
    }
}
