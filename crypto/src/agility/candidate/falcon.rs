//! Inactive FN-DSA/Falcon candidate implementations.
//!
//! Falcon defines two standard parameter sets: Falcon-512 at NIST security
//! level I and Falcon-1024 at level V. The upstream FN-DSA format is still
//! pre-standard and may change; these types are therefore not consensus APIs.

use fn_dsa::{
    DOMAIN_NONE, FN_DSA_LOGN_512, FN_DSA_LOGN_1024, HASH_ID_RAW, KeyPairGenerator,
    KeyPairGenerator512, KeyPairGenerator1024, SigningKey, SigningKey512, SigningKey1024,
    VerifyingKey, VerifyingKey512, VerifyingKey1024, sign_key_size, signature_size, vrfy_key_size,
};
use rand_core_06::OsRng;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FalconLevel {
    Level1,
    Level5,
}

impl FalconLevel {
    pub const fn logn(self) -> u32 {
        match self {
            Self::Level1 => FN_DSA_LOGN_512,
            Self::Level5 => FN_DSA_LOGN_1024,
        }
    }

    pub fn public_key_size(self) -> usize {
        vrfy_key_size(self.logn())
    }

    pub fn secret_key_size(self) -> usize {
        sign_key_size(self.logn())
    }

    pub fn signature_size(self) -> usize {
        signature_size(self.logn())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FalconPublicKey {
    level: FalconLevel,
    bytes: Vec<u8>,
}

impl FalconPublicKey {
    pub fn from_bytes(level: FalconLevel, bytes: Vec<u8>) -> Result<Self, FalconCandidateError> {
        if bytes.len() != level.public_key_size() || !valid_public_key(level, &bytes) {
            return Err(FalconCandidateError::InvalidPublicKey);
        }
        Ok(Self { level, bytes })
    }

    pub const fn level(&self) -> FalconLevel {
        self.level
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct FalconSecretKey {
    #[zeroize(skip)]
    level: FalconLevel,
    bytes: Vec<u8>,
}

impl fmt::Debug for FalconSecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FalconSecretKey([REDACTED])")
    }
}

impl FalconSecretKey {
    pub fn from_bytes(level: FalconLevel, bytes: Vec<u8>) -> Result<Self, FalconCandidateError> {
        if bytes.len() != level.secret_key_size() || !valid_secret_key(level, &bytes) {
            return Err(FalconCandidateError::InvalidSecretKey);
        }
        Ok(Self { level, bytes })
    }

    pub const fn level(&self) -> FalconLevel {
        self.level
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FalconSignature {
    level: FalconLevel,
    bytes: Vec<u8>,
}

impl FalconSignature {
    pub fn from_bytes(level: FalconLevel, bytes: Vec<u8>) -> Result<Self, FalconCandidateError> {
        if bytes.len() != level.signature_size() {
            return Err(FalconCandidateError::InvalidSignature);
        }
        Ok(Self { level, bytes })
    }

    pub const fn level(&self) -> FalconLevel {
        self.level
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct FalconKeyPair {
    pub public_key: FalconPublicKey,
    pub secret_key: FalconSecretKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FalconCandidateError {
    InvalidPublicKey,
    InvalidSecretKey,
    InvalidSignature,
    LevelMismatch,
    KeyGenerationFailed,
    SigningFailed,
}

pub fn generate_keypair(level: FalconLevel) -> Result<FalconKeyPair, FalconCandidateError> {
    let mut secret = vec![0_u8; level.secret_key_size()];
    let mut public = vec![0_u8; level.public_key_size()];
    match level {
        FalconLevel::Level1 => KeyPairGenerator512::default().keygen(
            level.logn(),
            &mut OsRng,
            &mut secret,
            &mut public,
        ),
        FalconLevel::Level5 => KeyPairGenerator1024::default().keygen(
            level.logn(),
            &mut OsRng,
            &mut secret,
            &mut public,
        ),
    }
    Ok(FalconKeyPair {
        public_key: FalconPublicKey::from_bytes(level, public)
            .map_err(|_| FalconCandidateError::KeyGenerationFailed)?,
        secret_key: FalconSecretKey::from_bytes(level, secret)
            .map_err(|_| FalconCandidateError::KeyGenerationFailed)?,
    })
}

pub fn derive_public_key(
    secret_key: &FalconSecretKey,
) -> Result<FalconPublicKey, FalconCandidateError> {
    let level = secret_key.level;
    let mut public = vec![0_u8; level.public_key_size()];
    match level {
        FalconLevel::Level1 => SigningKey512::decode(&secret_key.bytes)
            .ok_or(FalconCandidateError::InvalidSecretKey)?
            .to_verifying_key(&mut public),
        FalconLevel::Level5 => SigningKey1024::decode(&secret_key.bytes)
            .ok_or(FalconCandidateError::InvalidSecretKey)?
            .to_verifying_key(&mut public),
    }
    FalconPublicKey::from_bytes(level, public)
}

pub fn sign(
    secret_key: &FalconSecretKey,
    message: &[u8],
) -> Result<FalconSignature, FalconCandidateError> {
    let level = secret_key.level;
    let mut signature = vec![0_u8; level.signature_size()];
    let result = match level {
        FalconLevel::Level1 => SigningKey512::decode(&secret_key.bytes)
            .ok_or(FalconCandidateError::InvalidSecretKey)?
            .sign(
                &mut OsRng,
                &DOMAIN_NONE,
                &HASH_ID_RAW,
                message,
                &mut signature,
            ),
        FalconLevel::Level5 => SigningKey1024::decode(&secret_key.bytes)
            .ok_or(FalconCandidateError::InvalidSecretKey)?
            .sign(
                &mut OsRng,
                &DOMAIN_NONE,
                &HASH_ID_RAW,
                message,
                &mut signature,
            ),
    };
    result.ok_or(FalconCandidateError::SigningFailed)?;
    FalconSignature::from_bytes(level, signature)
}

pub fn verify(
    public_key: &FalconPublicKey,
    message: &[u8],
    signature: &FalconSignature,
) -> Result<bool, FalconCandidateError> {
    if public_key.level != signature.level {
        return Err(FalconCandidateError::LevelMismatch);
    }
    let valid = match public_key.level {
        FalconLevel::Level1 => VerifyingKey512::decode(&public_key.bytes)
            .ok_or(FalconCandidateError::InvalidPublicKey)?
            .verify(&signature.bytes, &DOMAIN_NONE, &HASH_ID_RAW, message),
        FalconLevel::Level5 => VerifyingKey1024::decode(&public_key.bytes)
            .ok_or(FalconCandidateError::InvalidPublicKey)?
            .verify(&signature.bytes, &DOMAIN_NONE, &HASH_ID_RAW, message),
    };
    Ok(valid)
}

fn valid_public_key(level: FalconLevel, bytes: &[u8]) -> bool {
    match level {
        FalconLevel::Level1 => VerifyingKey512::decode(bytes).is_some(),
        FalconLevel::Level5 => VerifyingKey1024::decode(bytes).is_some(),
    }
}

fn valid_secret_key(level: FalconLevel, bytes: &[u8]) -> bool {
    match level {
        FalconLevel::Level1 => SigningKey512::decode(bytes).is_some(),
        FalconLevel::Level5 => SigningKey1024::decode(bytes).is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_standard_levels_round_trip_and_reject_tampering() {
        assert_eq!(FalconLevel::Level1.secret_key_size(), 1345);
        assert_eq!(FalconLevel::Level1.public_key_size(), 897);
        assert_eq!(FalconLevel::Level1.signature_size(), 666);
        assert_eq!(FalconLevel::Level5.secret_key_size(), 2369);
        assert_eq!(FalconLevel::Level5.public_key_size(), 1793);
        assert_eq!(FalconLevel::Level5.signature_size(), 1280);
        for level in [FalconLevel::Level1, FalconLevel::Level5] {
            let keypair = generate_keypair(level).unwrap();
            assert_eq!(
                derive_public_key(&keypair.secret_key).unwrap(),
                keypair.public_key
            );
            let signature = sign(&keypair.secret_key, b"xparq falcon candidate").unwrap();
            assert!(verify(&keypair.public_key, b"xparq falcon candidate", &signature).unwrap());
            assert!(!verify(&keypair.public_key, b"tampered", &signature).unwrap());
        }
    }

    #[test]
    fn levels_cannot_be_mixed() {
        let level1 = generate_keypair(FalconLevel::Level1).unwrap();
        let level5 = generate_keypair(FalconLevel::Level5).unwrap();
        let signature = sign(&level5.secret_key, b"message").unwrap();
        assert_eq!(
            verify(&level1.public_key, b"message", &signature),
            Err(FalconCandidateError::LevelMismatch)
        );
    }
}
