//! Experimental SQIsign Level 5 single-authority implementation.
//!
//! This module is compiled only with `sqisign-candidate`. Its types are not
//! accepted by XPARQ transactions or consensus.

use rand_10::rand_core::UnwrapErr;
use rand_10::rngs::SysRng;
use sqisign_rs::{
    Level5, PublicKey as SqisignPublicKey, Signature as SqisignSignature,
    SigningKey as SqisignSigningKey, Verifier, generate,
};

use crate::crypto::agility::{SignatureContext, SignatureScheme};

pub const PUBLIC_KEY_SIZE: usize = 129;
pub const SECRET_KEY_SIZE: usize = 705;
pub const SIGNATURE_SIZE: usize = 292;

const SIGNATURE_DOMAIN: &[u8] = b"XPARQ_SQISIGN_LEVEL5_SIGNATURE_V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; PUBLIC_KEY_SIZE]);

#[derive(PartialEq, Eq)]
pub struct SecretKey([u8; SECRET_KEY_SIZE]);

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SecretKey([REDACTED])")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_SIZE]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_SIZE]) -> Result<Self, CandidateError> {
        SqisignPublicKey::<Level5>::from_bytes(&bytes)
            .map(|_| Self(bytes))
            .map_err(|_| CandidateError::InvalidPublicKey)
    }

    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.0
    }
}

impl SecretKey {
    pub fn from_bytes(bytes: [u8; SECRET_KEY_SIZE]) -> Result<Self, CandidateError> {
        SqisignSigningKey::<Level5>::from_bytes(&bytes)
            .map(|_| Self(bytes))
            .map_err(|_| CandidateError::InvalidSecretKey)
    }

    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_SIZE] {
        &self.0
    }
}

impl Signature {
    pub fn from_bytes(bytes: [u8; SIGNATURE_SIZE]) -> Result<Self, CandidateError> {
        SqisignSignature::<Level5>::from_bytes(&bytes)
            .map(|_| Self(bytes))
            .map_err(|_| CandidateError::InvalidSignature)
    }

    pub fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateError {
    InvalidPublicKey,
    InvalidSecretKey,
    InvalidSignature,
    SigningFailed,
    InternalPanic,
}

pub fn generate_keypair() -> Result<KeyPair, CandidateError> {
    let (public_key, signing_key) =
        std::panic::catch_unwind(|| generate::<Level5>(&mut UnwrapErr(SysRng)))
            .map_err(|_| CandidateError::InternalPanic)?;
    let secret_key = signing_key
        .to_bytes()
        .map_err(|_| CandidateError::SigningFailed)?;
    Ok(KeyPair {
        public_key: PublicKey(
            public_key
                .to_bytes()
                .as_slice()
                .try_into()
                .map_err(|_| CandidateError::InvalidPublicKey)?,
        ),
        secret_key: SecretKey(
            secret_key
                .as_slice()
                .try_into()
                .map_err(|_| CandidateError::InvalidSecretKey)?,
        ),
    })
}

pub fn sign(
    context: SignatureContext,
    secret_key: &SecretKey,
    message: &[u8],
) -> Result<Signature, CandidateError> {
    let separated = context_message(context, message);
    let signature = std::panic::catch_unwind(|| {
        let signing_key = SqisignSigningKey::<Level5>::from_bytes(&secret_key.0)
            .map_err(|_| CandidateError::InvalidSecretKey)?;
        signing_key
            .sign(&separated, &mut UnwrapErr(SysRng))
            .map_err(|_| CandidateError::SigningFailed)
    })
    .map_err(|_| CandidateError::InternalPanic)??;
    Ok(Signature(
        signature
            .to_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| CandidateError::InvalidSignature)?,
    ))
}

pub fn verify(
    context: SignatureContext,
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> bool {
    let Ok(public_key) = SqisignPublicKey::<Level5>::from_bytes(&public_key.0) else {
        return false;
    };
    let Ok(signature) = SqisignSignature::<Level5>::from_bytes(&signature.0) else {
        return false;
    };
    public_key
        .verify(&context_message(context, message), &signature)
        .is_ok()
}

fn context_message(context: SignatureContext, message: &[u8]) -> Vec<u8> {
    let mut separated =
        Vec::with_capacity(SIGNATURE_DOMAIN.len() + 2 + size_of::<u64>() + message.len());
    separated.extend_from_slice(SIGNATURE_DOMAIN);
    separated.push(SignatureScheme::SqisignLevel5 as u8);
    separated.push(context as u8);
    separated.extend_from_slice(&(message.len() as u64).to_le_bytes());
    separated.extend_from_slice(message);
    separated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_level5_wire_format() {
        assert_eq!(PUBLIC_KEY_SIZE, 129);
        assert_eq!(SECRET_KEY_SIZE, 576 + 129);
        assert_eq!(SIGNATURE_SIZE, 292);
    }

    #[test]
    fn protocol_contexts_are_domain_separated() {
        let message = b"same canonical bytes";
        assert_ne!(
            context_message(SignatureContext::ProtocolTransaction, message),
            context_message(SignatureContext::QCashTransaction, message)
        );
        assert_ne!(
            context_message(SignatureContext::ProtocolTransaction, message),
            context_message(SignatureContext::RecoveryProof, message)
        );
    }
}
