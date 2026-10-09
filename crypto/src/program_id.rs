//! Universal program-instance identity. Public keys are authorization witnesses,
//! never a separate ledger-owner type.
use crate::{
    AccountSignatureScheme, CodecError, CryptoError, HASH_SIZE, HashDomain, PublicKey,
    canonical_bytes, domain,
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

pub const ACCOUNT_SALT_SIZE: usize = 32;
pub type AccountSalt = [u8; ACCOUNT_SALT_SIZE];
pub const DEFAULT_ACCOUNT_SALT: AccountSalt = [0; ACCOUNT_SALT_SIZE];

pub const PROGRAM_ID_SIZE: usize = HASH_SIZE;
pub const PROGRAM_ID_STRING_LEN: usize = 2 * PROGRAM_ID_SIZE;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct ProgramId(pub [u8; PROGRAM_ID_SIZE]);

impl ProgramId {
    pub const ZERO: Self = Self([0; PROGRAM_ID_SIZE]);
    pub const fn from_bytes(bytes: [u8; PROGRAM_ID_SIZE]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; PROGRAM_ID_SIZE] {
        &self.0
    }
    pub const fn into_bytes(self) -> [u8; PROGRAM_ID_SIZE] {
        self.0
    }

    pub fn signature_account(
        scheme: AccountSignatureScheme,
        public_key: &[u8],
    ) -> Result<Self, CryptoError> {
        Self::signature_account_with_salt(scheme, public_key, &DEFAULT_ACCOUNT_SALT)
    }

    pub fn signature_account_with_salt(
        scheme: AccountSignatureScheme,
        public_key: &[u8],
        salt: &AccountSalt,
    ) -> Result<Self, CryptoError> {
        if public_key.len() != scheme.public_key_size() {
            return Err(CryptoError::InvalidPublicKeyLength);
        }
        let mut material = Vec::with_capacity(26 + public_key.len() + ACCOUNT_SALT_SIZE);
        material.extend_from_slice(b"xparq:signature-policy:v2");
        material.push(scheme.id());
        material.extend_from_slice(public_key);
        material.extend_from_slice(salt);
        Ok(Self(
            domain(HashDomain::ProgramAccount, &material).into_bytes(),
        ))
    }

    /// Immutable deployed instance: deploying principal, nonce and code hash.
    pub fn derive(
        code_owner: Self,
        nonce: u64,
        code_hash: impl AsRef<[u8; HASH_SIZE]>,
    ) -> Result<Self, CodecError> {
        let bytes = canonical_bytes(&(
            b"xparq:program-id:v2",
            code_owner,
            nonce,
            code_hash.as_ref(),
        ))?;
        Ok(Self(domain(HashDomain::XPARQArtifact, &bytes).into_bytes()))
    }
}

impl fmt::Display for ProgramId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for ProgramId {
    type Err = CryptoError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != PROGRAM_ID_STRING_LEN {
            return Err(CryptoError::InvalidProgramIdEncoding);
        }
        let mut bytes = [0; PROGRAM_ID_SIZE];
        hex::decode_to_slice(value, &mut bytes)
            .map_err(|_| CryptoError::InvalidProgramIdEncoding)?;
        Ok(Self(bytes))
    }
}

pub fn program_id_from_public_key(public_key: &PublicKey) -> Result<ProgramId, CryptoError> {
    ProgramId::signature_account(public_key.scheme(), &public_key.bytes)
}
pub fn program_id_from_public_key_with_salt(
    public_key: &PublicKey,
    salt: &AccountSalt,
) -> Result<ProgramId, CryptoError> {
    ProgramId::signature_account_with_salt(public_key.scheme(), &public_key.bytes, salt)
}
pub fn program_id_from_string(value: &str) -> Result<ProgramId, CryptoError> {
    value.parse()
}
pub fn program_id_to_string(id: &ProgramId) -> String {
    id.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn salts_separate_instances_without_changing_the_key() {
        for scheme in AccountSignatureScheme::ALL {
            let key = PublicKey {
                account: scheme,
                bytes: vec![0xa5; scheme.public_key_size()],
            };
            let zero = program_id_from_public_key(&key).unwrap();
            let a = program_id_from_public_key_with_salt(&key, &[1; 32]).unwrap();
            let b = program_id_from_public_key_with_salt(&key, &[2; 32]).unwrap();
            // Independent Python hashlib fixture for a nonzero account salt.
            let expected = match scheme.id() {
                1 => "44af36b8b03e8101b2b9f91a20461d7addb05f40401209ee2ebd50c29812bada",
                2 => "18e5bebdda03b18f0f26373cd06f8d6b87079849988332979eeb30a9ee82ace5",
                3 => "63c8ed79e031d7dec6f07768e925dd794ea0207cc58770cb57071825ed40eb3f",
                5 => "881f0b33a30bef1b30e64507eda36644282449b1fed35a25a0e3ac45a281e156",
                6 => "fab5d8933657699b4c591e69419a6e7b302b7b901cbdc3e8e911565438412886",
                7 => "d0b2cf6ebafe8b4e8a91cbf51bf4fef1a08325501eeb510870648f91d1882794",
                _ => unreachable!(),
            };
            assert_eq!(a.to_string(), expected);
            assert_ne!(zero, a);
            assert_ne!(a, b);
            assert_ne!(zero, b);
            assert_eq!(
                a,
                ProgramId::signature_account_with_salt(scheme, &key.bytes, &[1; 32]).unwrap()
            );
        }
    }

    #[test]
    fn program_ids_have_one_bounded_hex_encoding() {
        let id = ProgramId([0xab; PROGRAM_ID_SIZE]);
        assert_eq!(id.to_string(), "ab".repeat(32));
        assert_eq!(id.to_string().parse(), Ok(id));
        assert_eq!("AB".repeat(32).parse(), Ok(id));
        for invalid in [
            "a".repeat(63),
            "a".repeat(65),
            "z".repeat(64),
            "0".repeat(45),
        ] {
            assert!(invalid.parse::<ProgramId>().is_err());
        }
    }
    #[test]
    fn signature_policy_identity_binds_scheme_full_key_and_policy_domain() {
        let mut ids = Vec::new();
        for scheme in AccountSignatureScheme::ALL {
            let bytes = vec![0xa5; scheme.public_key_size()];
            let id = ProgramId::signature_account(scheme, &bytes).unwrap();
            // Independent Python hashlib SHA3-256 fixtures for the framed preimage.
            let expected = match scheme.id() {
                1 => "fc6646f88ebf852c4e1c393e5101e6ae1a5e476e57241bf8c2abac1819bbde60",
                2 => "d04d5404b7d15cdad674789d7998d70e540d1023c79c671cda21b89d0e9a4d9a",
                3 => "56094227bae261c7a5c7cd0ac06638d83d0abcdd246fa2cf71c20c68a2e40616",
                5 => "5c294f0aff3737f4eedcf5cc8d765aa35ba8752333fa7944e3ea833fe2db9dd2",
                6 => "ced768db6f50e983aec9a0bf946c24562b113bc538f5004de518eb97b1ad8825",
                7 => "6f66d28b36bb8db24320efac6053241ad87e22ec43a789d8856bcd113b2dedb3",
                _ => unreachable!(),
            };
            assert_eq!(id.to_string(), expected);
            assert_eq!(
                program_id_from_public_key(&PublicKey {
                    account: scheme,
                    bytes: bytes.clone()
                }),
                Ok(id)
            );
            let mut changed = bytes.clone();
            *changed.last_mut().unwrap() ^= 1;
            assert_ne!(id, ProgramId::signature_account(scheme, &changed).unwrap());
            assert!(ProgramId::signature_account(scheme, &bytes[..bytes.len() - 1]).is_err());
            ids.push(id);
        }
        assert_eq!(
            ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
            ids.len()
        );
    }
}
