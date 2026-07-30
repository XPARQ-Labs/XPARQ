//! Experimental SQIsign Level 5 dual authorization.
//!
//! This module is compiled only with `sqisign-candidate`. Its types are not
//! accepted by Paqus transactions or consensus.

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

const DUAL_AUTH_DOMAIN: &[u8] = b"PAQUS_SQISIGN_LEVEL5_DUAL_AUTH_V1";
const OWNER_ROLE: u8 = 0;
const AUTHORIZATION_ROLE: u8 = 1;

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

    #[cfg(test)]
    pub(crate) fn from_bytes_unchecked(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        Self(bytes)
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DualAuthorization {
    pub owner_signature: Signature,
    pub authorization_signature: Signature,
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

pub fn sign_owner(
    context: SignatureContext,
    secret_key: &SecretKey,
    message: &[u8],
) -> Result<Signature, CandidateError> {
    sign_for_role(context, secret_key, OWNER_ROLE, message)
}

pub fn sign_authorization(
    context: SignatureContext,
    secret_key: &SecretKey,
    message: &[u8],
) -> Result<Signature, CandidateError> {
    sign_for_role(context, secret_key, AUTHORIZATION_ROLE, message)
}

pub fn sign_dual(
    context: SignatureContext,
    owner_secret_key: &SecretKey,
    authorization_secret_key: &SecretKey,
    message: &[u8],
) -> Result<DualAuthorization, CandidateError> {
    Ok(DualAuthorization {
        owner_signature: sign_owner(context, owner_secret_key, message)?,
        authorization_signature: sign_authorization(context, authorization_secret_key, message)?,
    })
}

pub fn verify_dual(
    context: SignatureContext,
    owner_public_key: &PublicKey,
    authorization_public_key: &PublicKey,
    message: &[u8],
    signatures: &DualAuthorization,
) -> bool {
    std::panic::catch_unwind(|| {
        verify_for_role(
            context,
            owner_public_key,
            OWNER_ROLE,
            message,
            &signatures.owner_signature,
        ) && verify_for_role(
            context,
            authorization_public_key,
            AUTHORIZATION_ROLE,
            message,
            &signatures.authorization_signature,
        )
    })
    .unwrap_or(false)
}

fn sign_for_role(
    context: SignatureContext,
    secret_key: &SecretKey,
    role: u8,
    message: &[u8],
) -> Result<Signature, CandidateError> {
    let separated = role_message(context, role, message);
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

fn verify_for_role(
    context: SignatureContext,
    public_key: &PublicKey,
    role: u8,
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
        .verify(&role_message(context, role, message), &signature)
        .is_ok()
}

fn role_message(context: SignatureContext, role: u8, message: &[u8]) -> Vec<u8> {
    let mut separated =
        Vec::with_capacity(DUAL_AUTH_DOMAIN.len() + 3 + size_of::<u64>() + message.len());
    separated.extend_from_slice(DUAL_AUTH_DOMAIN);
    separated.push(SignatureScheme::SqisignLevel5 as u8);
    separated.push(context as u8);
    separated.push(role);
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
    fn role_domains_are_distinct() {
        assert_ne!(
            role_message(
                SignatureContext::ProtocolTransaction,
                OWNER_ROLE,
                b"transaction"
            ),
            role_message(
                SignatureContext::ProtocolTransaction,
                AUTHORIZATION_ROLE,
                b"transaction"
            )
        );
    }

    #[test]
    fn protocol_contexts_are_domain_separated() {
        let message = b"same canonical bytes";
        assert_ne!(
            role_message(SignatureContext::ProtocolTransaction, OWNER_ROLE, message),
            role_message(SignatureContext::QCashTransaction, OWNER_ROLE, message)
        );
        assert_ne!(
            role_message(SignatureContext::GovernanceAction, OWNER_ROLE, message),
            role_message(SignatureContext::RecoveryProof, OWNER_ROLE, message)
        );
    }
}
