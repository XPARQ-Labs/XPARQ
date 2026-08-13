use crate::crypto::{CryptoUpgradePlan, SignatureScheme, signature_scheme_active_at_height};
#[cfg(feature = "devnet")]
use crate::crypto::{
    INITIAL_SIGNATURE_SCHEME, PublicKey, Signature, address_from_public_key, verify,
};
use crate::error::TransactionError;
use borsh::{BorshDeserialize, BorshSerialize};

#[cfg(feature = "devnet")]
use super::Transfer;
pub use super::{AuthorizationProof, ValidityWindow};

pub const AUTHORIZATION_PROOF_VERSION: u8 = 1;
pub const ML_DSA_44_PUBLIC_KEY_SIZE: usize = 1_312;
pub const ML_DSA_44_SIGNATURE_SIZE: usize = 2_420;
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1_952;
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3_309;
pub const ML_DSA_87_PUBLIC_KEY_SIZE: usize = 2_592;
pub const ML_DSA_87_SIGNATURE_SIZE: usize = 4_627;
pub const SQISIGN_LEVEL5_PUBLIC_KEY_SIZE: usize = 129;
pub const SQISIGN_LEVEL5_SIGNATURE_SIZE: usize = 292;

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum AuthorizationProofKeyMode {
    Register = 0,
    Stored = 1,
}

/// Algorithm-tagged authorization_proof format used by crypto-agility protocol upgrades.
///
/// Vectors are bounded by [`AgileAuthorizationProof::validate_shape`]. Network decoders must
/// retain their enclosing transaction/message size limit before deserializing.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct AgileAuthorizationProof {
    pub version: u8,
    pub scheme: SignatureScheme,
    pub key_mode: AuthorizationProofKeyMode,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl AgileAuthorizationProof {
    pub fn new_registered(
        scheme: SignatureScheme,
        public_key: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<Self, TransactionError> {
        let authorization_proof = Self {
            version: AUTHORIZATION_PROOF_VERSION,
            scheme,
            key_mode: AuthorizationProofKeyMode::Register,
            public_key,
            signature,
        };
        authorization_proof.validate_shape()?;
        Ok(authorization_proof)
    }

    pub fn new_stored(
        scheme: SignatureScheme,
        signature: Vec<u8>,
    ) -> Result<Self, TransactionError> {
        let authorization_proof = Self {
            version: AUTHORIZATION_PROOF_VERSION,
            scheme,
            key_mode: AuthorizationProofKeyMode::Stored,
            public_key: Vec::new(),
            signature,
        };
        authorization_proof.validate_shape()?;
        Ok(authorization_proof)
    }

    pub const fn expected_sizes(scheme: SignatureScheme) -> (usize, usize) {
        match scheme {
            SignatureScheme::MlDsa44 => (ML_DSA_44_PUBLIC_KEY_SIZE, ML_DSA_44_SIGNATURE_SIZE),
            SignatureScheme::MlDsa65 => (ML_DSA_65_PUBLIC_KEY_SIZE, ML_DSA_65_SIGNATURE_SIZE),
            SignatureScheme::MlDsa87 => (ML_DSA_87_PUBLIC_KEY_SIZE, ML_DSA_87_SIGNATURE_SIZE),
            SignatureScheme::SqisignLevel5 => (
                SQISIGN_LEVEL5_PUBLIC_KEY_SIZE,
                SQISIGN_LEVEL5_SIGNATURE_SIZE,
            ),
        }
    }

    pub fn validate_shape(&self) -> Result<(), TransactionError> {
        if self.version != AUTHORIZATION_PROOF_VERSION {
            return Err(TransactionError::UnsupportedVersion);
        }
        let (public_key_size, signature_size) = Self::expected_sizes(self.scheme);
        match self.key_mode {
            AuthorizationProofKeyMode::Register => {
                if self.public_key.len() != public_key_size || all_zero(&self.public_key) {
                    return Err(TransactionError::InvalidAuthorizationProofEncoding);
                }
            }
            AuthorizationProofKeyMode::Stored => {
                if !self.public_key.is_empty() {
                    return Err(TransactionError::InvalidAuthorizationProofEncoding);
                }
            }
        }
        if self.signature.len() != signature_size || all_zero(&self.signature) {
            return Err(TransactionError::InvalidAuthorizationProofEncoding);
        }
        Ok(())
    }

    pub fn validate_for_height(
        &self,
        height: u64,
        upgrade: Option<CryptoUpgradePlan>,
    ) -> Result<(), TransactionError> {
        self.validate_shape()?;
        if !signature_scheme_active_at_height(self.scheme, height, upgrade) {
            return Err(TransactionError::UnsupportedSignatureScheme);
        }
        Ok(())
    }
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// Crypto-agile single-transfer envelope enabled on development networks.
///
/// It remains separate from `SignedProtocolTransaction` until a protocol
/// activation assigns its final enum tag.
#[cfg(feature = "devnet")]
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignedAgileTransfer {
    pub transaction: Transfer,
    pub authorization_proof: AgileAuthorizationProof,
}

#[cfg(feature = "devnet")]
impl SignedAgileTransfer {
    pub fn new(transaction: Transfer, authorization_proof: AgileAuthorizationProof) -> Self {
        Self {
            transaction,
            authorization_proof,
        }
    }

    pub fn validate_signed_for_height(
        &self,
        height: crate::block::BlockHeight,
        upgrade: Option<CryptoUpgradePlan>,
    ) -> Result<(), TransactionError> {
        self.transaction.validate_for_height(height)?;
        self.authorization_proof
            .validate_for_height(height.0, upgrade)?;
        if self.authorization_proof.key_mode != AuthorizationProofKeyMode::Register {
            return Err(TransactionError::InvalidAuthorizationProofEncoding);
        }
        let public_key = self.compiled_public_key()?;
        if address_from_public_key(&public_key) != self.transaction.from {
            return Err(TransactionError::SenderAddressMismatch);
        }
        self.verify(&public_key)
    }

    pub fn validate_stored_keys_for_height(
        &self,
        height: crate::block::BlockHeight,
        public_key: &PublicKey,
        upgrade: Option<CryptoUpgradePlan>,
    ) -> Result<(), TransactionError> {
        self.transaction.validate_for_height(height)?;
        self.authorization_proof
            .validate_for_height(height.0, upgrade)?;
        if self.authorization_proof.key_mode != AuthorizationProofKeyMode::Stored {
            return Err(TransactionError::InvalidAuthorizationProofEncoding);
        }
        self.verify(public_key)
    }

    fn verify(&self, public_key: &PublicKey) -> Result<(), TransactionError> {
        let signature = self.compiled_signature()?;
        let payload = self.transaction.signing_bytes()?;
        if !verify(public_key, &payload, &signature) {
            return Err(TransactionError::InvalidSignature);
        }
        Ok(())
    }

    fn compiled_public_key(&self) -> Result<PublicKey, TransactionError> {
        self.require_compiled_scheme()?;
        Ok(PublicKey(
            self.authorization_proof
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| TransactionError::InvalidAuthorizationProofEncoding)?,
        ))
    }

    fn compiled_signature(&self) -> Result<Signature, TransactionError> {
        self.require_compiled_scheme()?;
        Ok(Signature(
            self.authorization_proof
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| TransactionError::InvalidAuthorizationProofEncoding)?,
        ))
    }

    fn require_compiled_scheme(&self) -> Result<(), TransactionError> {
        if self.authorization_proof.scheme != INITIAL_SIGNATURE_SCHEME {
            return Err(TransactionError::UnsupportedSignatureScheme);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CryptoPrimitive;

    fn bytes(size: usize, value: u8) -> Vec<u8> {
        vec![value; size]
    }

    #[test]
    fn validates_every_registered_wire_shape() {
        for scheme in [
            SignatureScheme::MlDsa44,
            SignatureScheme::MlDsa65,
            SignatureScheme::MlDsa87,
            SignatureScheme::SqisignLevel5,
        ] {
            let (public_key_size, signature_size) = AgileAuthorizationProof::expected_sizes(scheme);
            AgileAuthorizationProof::new_registered(
                scheme,
                bytes(public_key_size, 1),
                bytes(signature_size, 2),
            )
            .unwrap();
        }
    }

    #[test]
    fn enforces_height_aware_signature_policy() {
        let plan = CryptoUpgradePlan {
            authorization_id: [8; 32],
            from: CryptoPrimitive::Signature(SignatureScheme::SqisignLevel5),
            to: CryptoPrimitive::Signature(SignatureScheme::MlDsa44),
            transition_height: 10,
            activation_height: 20,
            protocol_version: 1,
        };
        let authorization_proof = AgileAuthorizationProof::new_stored(
            SignatureScheme::SqisignLevel5,
            bytes(SQISIGN_LEVEL5_SIGNATURE_SIZE, 1),
        )
        .unwrap();
        assert!(
            authorization_proof
                .validate_for_height(19, Some(plan))
                .is_ok()
        );
        assert_eq!(
            authorization_proof.validate_for_height(20, Some(plan)),
            Err(TransactionError::UnsupportedSignatureScheme)
        );
    }

    #[test]
    fn rejects_wrong_sizes_and_zero_sentinels() {
        assert_eq!(
            AgileAuthorizationProof::new_stored(
                SignatureScheme::MlDsa44,
                vec![1; ML_DSA_44_SIGNATURE_SIZE - 1],
            ),
            Err(TransactionError::InvalidAuthorizationProofEncoding)
        );
        assert_eq!(
            AgileAuthorizationProof::new_stored(
                SignatureScheme::SqisignLevel5,
                vec![0; SQISIGN_LEVEL5_SIGNATURE_SIZE],
            ),
            Err(TransactionError::InvalidAuthorizationProofEncoding)
        );
    }

    #[cfg(feature = "devnet")]
    #[test]
    fn signed_agile_transfer_verifies_with_network_scheme() {
        use crate::consensus::supply::Amount;
        use crate::crypto::{address_from_public_key, generate_keypair, sign};

        let owner = generate_keypair();
        let sender = address_from_public_key(&owner.public_key);
        let transaction = Transfer::new(
            sender,
            vec![crate::state::XpqCoinId([4; crate::crypto::HASH_SIZE])],
            crate::crypto::Address([9; crate::crypto::ADDRESS_SIZE]),
            Amount(1),
        );
        let payload = transaction.signing_bytes().unwrap();
        let authorization_proof = AgileAuthorizationProof::new_registered(
            INITIAL_SIGNATURE_SCHEME,
            owner.public_key.0.to_vec(),
            sign(&owner.secret_key, &payload).0.to_vec(),
        )
        .unwrap();
        SignedAgileTransfer::new(transaction, authorization_proof)
            .validate_signed_for_height(crate::block::Height(0), None)
            .unwrap();
    }
}
