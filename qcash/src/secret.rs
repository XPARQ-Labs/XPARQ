use borsh::{BorshDeserialize, BorshSerialize};
use xparq_crypto::{
    FalconQCashPublicKey, FalconQCashSignature, ProfilePublicKey, ProfileSignature,
    ProfileSigningSeed, QCashPublicKey, QCashSignature, SignatureProfile,
    falcon_qcash_public_key_from_seed, falcon_qcash_sign_from_seed, qcash_public_key_from_seed,
    qcash_sign_from_seed,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const QCASH_SIGNING_SEED_SIZE: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum QCashSignatureScheme {
    MlDsa44,
    MlDsa65,
    MlDsa87,
    Falcon512,
    Falcon1024,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum QCashBearerPublicKey {
    MlDsa44(QCashPublicKey),
    Falcon512(FalconQCashPublicKey),
    Profile(ProfilePublicKey),
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum QCashBearerSignature {
    MlDsa44(QCashSignature),
    Falcon512(FalconQCashSignature),
    Profile(ProfileSignature),
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, BorshSerialize, BorshDeserialize)]
pub enum QCashSigningKey {
    MlDsa44(QCashSigningSeed),
    Falcon512(FalconQCashSigningSeed),
    MlDsa65(ProfileSigningSeed),
    MlDsa87(ProfileSigningSeed),
    Falcon1024(ProfileSigningSeed),
}

/// Plaintext ML-DSA-44 signing seed stored inside a portable QCash file.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, BorshSerialize, BorshDeserialize)]
pub struct QCashSigningSeed([u8; QCASH_SIGNING_SEED_SIZE]);

/// Plaintext Falcon-512 bearer seed. It is a distinct type so callers cannot
/// accidentally authorize a legacy ML-DSA QCash output with the wrong scheme.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, BorshSerialize, BorshDeserialize)]
pub struct FalconQCashSigningSeed([u8; QCASH_SIGNING_SEED_SIZE]);

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

impl FalconQCashSigningSeed {
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

    pub fn public_key(&self) -> FalconQCashPublicKey {
        falcon_qcash_public_key_from_seed(&self.0)
    }

    pub fn sign(&self, message: &[u8]) -> FalconQCashSignature {
        falcon_qcash_sign_from_seed(&self.0, message)
    }
}

impl QCashSigningKey {
    pub const fn from_seed(scheme: QCashSignatureScheme, seed: [u8; 32]) -> Self {
        match scheme {
            QCashSignatureScheme::MlDsa44 => Self::MlDsa44(QCashSigningSeed::from_bytes(seed)),
            QCashSignatureScheme::MlDsa65 => {
                Self::MlDsa65(ProfileSigningSeed::new(SignatureProfile::MlDsa65, seed))
            }
            QCashSignatureScheme::MlDsa87 => {
                Self::MlDsa87(ProfileSigningSeed::new(SignatureProfile::MlDsa87, seed))
            }
            QCashSignatureScheme::Falcon512 => {
                Self::Falcon512(FalconQCashSigningSeed::from_bytes(seed))
            }
            QCashSignatureScheme::Falcon1024 => {
                Self::Falcon1024(ProfileSigningSeed::new(SignatureProfile::Falcon1024, seed))
            }
        }
    }

    pub fn random(scheme: QCashSignatureScheme) -> Result<Self, getrandom::Error> {
        let mut seed = [0; QCASH_SIGNING_SEED_SIZE];
        getrandom::fill(&mut seed)?;
        Ok(Self::from_seed(scheme, seed))
    }

    pub const fn scheme(&self) -> QCashSignatureScheme {
        match self {
            Self::MlDsa44(_) => QCashSignatureScheme::MlDsa44,
            Self::Falcon512(_) => QCashSignatureScheme::Falcon512,
            Self::MlDsa65(_) => QCashSignatureScheme::MlDsa65,
            Self::MlDsa87(_) => QCashSignatureScheme::MlDsa87,
            Self::Falcon1024(_) => QCashSignatureScheme::Falcon1024,
        }
    }

    pub fn public_key(&self) -> QCashBearerPublicKey {
        match self {
            Self::MlDsa44(seed) => QCashBearerPublicKey::MlDsa44(seed.public_key()),
            Self::Falcon512(seed) => QCashBearerPublicKey::Falcon512(seed.public_key()),
            Self::MlDsa65(seed) | Self::MlDsa87(seed) | Self::Falcon1024(seed) => {
                QCashBearerPublicKey::Profile(seed.public_key())
            }
        }
    }

    pub fn sign(&self, message: &[u8]) -> QCashBearerSignature {
        match self {
            Self::MlDsa44(seed) => QCashBearerSignature::MlDsa44(seed.sign(message)),
            Self::Falcon512(seed) => QCashBearerSignature::Falcon512(seed.sign(message)),
            Self::MlDsa65(seed) | Self::MlDsa87(seed) | Self::Falcon1024(seed) => {
                QCashBearerSignature::Profile(seed.sign(message))
            }
        }
    }
}

impl std::fmt::Debug for QCashSigningKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QCashSigningKey")
            .field("scheme", &self.scheme())
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl std::fmt::Debug for FalconQCashSigningSeed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FalconQCashSigningSeed([REDACTED])")
    }
}

pub fn verify_qcash_bearer_signature(
    public_key: &QCashBearerPublicKey,
    message: &[u8],
    signature: &QCashBearerSignature,
) -> bool {
    match (public_key, signature) {
        (QCashBearerPublicKey::MlDsa44(public_key), QCashBearerSignature::MlDsa44(signature)) => {
            xparq_crypto::qcash_verify(public_key, message, signature)
        }
        (
            QCashBearerPublicKey::Falcon512(public_key),
            QCashBearerSignature::Falcon512(signature),
        ) => xparq_crypto::falcon_qcash_verify(public_key, message, signature),
        (QCashBearerPublicKey::Profile(public_key), QCashBearerSignature::Profile(signature)) => {
            xparq_crypto::profile_verify(public_key, message, signature)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_can_choose_each_qcash_signature_scheme() {
        for scheme in [
            QCashSignatureScheme::MlDsa44,
            QCashSignatureScheme::MlDsa65,
            QCashSignatureScheme::MlDsa87,
            QCashSignatureScheme::Falcon512,
            QCashSignatureScheme::Falcon1024,
        ] {
            let key = QCashSigningKey::from_seed(scheme, [23; 32]);
            assert_eq!(key.scheme(), scheme);
            let public_key = key.public_key();
            let signature = key.sign(b"selectable QCash scheme");
            assert!(verify_qcash_bearer_signature(
                &public_key,
                b"selectable QCash scheme",
                &signature
            ));
            assert!(!verify_qcash_bearer_signature(
                &public_key,
                b"tampered",
                &signature
            ));
        }
    }

    #[test]
    fn mixed_qcash_key_and_signature_schemes_are_rejected() {
        let ml = QCashSigningKey::from_seed(QCashSignatureScheme::MlDsa44, [24; 32]);
        let falcon = QCashSigningKey::from_seed(QCashSignatureScheme::Falcon512, [25; 32]);
        assert!(!verify_qcash_bearer_signature(
            &ml.public_key(),
            b"message",
            &falcon.sign(b"message")
        ));
    }
}
