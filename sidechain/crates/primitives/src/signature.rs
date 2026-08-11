use borsh::{BorshDeserialize, BorshSerialize};
use sqisign_rs::{Level5, PublicKey as SqisignPublicKey, Signature as SqisignSignature, Verifier};
use thiserror::Error;

pub const SQISIGN_LEVEL: u8 = 5;
pub const PUBLIC_KEY_SIZE: usize = 129;
pub const SIGNATURE_SIZE: usize = 292;

#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct PublicKey(pub [u8; PUBLIC_KEY_SIZE]);

impl PublicKey {
    pub fn validate(&self) -> Result<(), SignatureError> {
        if self.0.iter().all(|byte| *byte == 0) {
            return Err(SignatureError::InvalidPublicKey);
        }
        SqisignPublicKey::<Level5>::from_bytes(&self.0)
            .map(|_| ())
            .map_err(|_| SignatureError::InvalidPublicKey)
    }
}

#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct Signature(pub [u8; SIGNATURE_SIZE]);

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    #[error("invalid SQIsign Level 5 public key")]
    InvalidPublicKey,
    #[error("invalid SQIsign Level 5 signature encoding")]
    InvalidSignatureEncoding,
    #[error("SQIsign Level 5 signature verification failed")]
    VerificationFailed,
}

pub fn verify(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), SignatureError> {
    let public_key = SqisignPublicKey::<Level5>::from_bytes(&public_key.0)
        .map_err(|_| SignatureError::InvalidPublicKey)?;
    let signature = SqisignSignature::<Level5>::from_bytes(&signature.0)
        .map_err(|_| SignatureError::InvalidSignatureEncoding)?;
    public_key
        .verify(message, &signature)
        .map_err(|_| SignatureError::VerificationFailed)
}

/// Verify the ordered owner and authorization signatures over the same
/// canonical signing message.
pub fn verify_dual(
    owner_public_key: &PublicKey,
    authorization_public_key: &PublicKey,
    message: &[u8],
    owner_signature: &Signature,
    authorization_signature: &Signature,
) -> Result<(), SignatureError> {
    verify(owner_public_key, message, owner_signature)?;
    verify(authorization_public_key, message, authorization_signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqisign_rs::{Level5, generate};

    #[test]
    fn zero_public_key_is_rejected_before_verification() {
        assert_eq!(
            PublicKey([0; PUBLIC_KEY_SIZE]).validate(),
            Err(SignatureError::InvalidPublicKey)
        );
    }

    #[test]
    fn level5_signature_roundtrip_uses_the_sidechain_wire_types() {
        let mut rng = rand_10::rng();
        let (public_key, signing_key) = generate::<Level5>(&mut rng);
        let message = b"xparq-sidechain-sqisign-roundtrip-v1";
        let signature = signing_key.sign(message, &mut rng).unwrap();
        let public_key = PublicKey(public_key.to_bytes().as_slice().try_into().unwrap());
        let signature = Signature(signature.to_bytes().as_slice().try_into().unwrap());

        assert_eq!(verify(&public_key, message, &signature), Ok(()));
        assert_eq!(
            verify(&public_key, b"tampered", &signature),
            Err(SignatureError::VerificationFailed)
        );
    }
}
