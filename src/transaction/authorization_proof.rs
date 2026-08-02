use crate::crypto::{
    CryptoUpgradePlan, INITIAL_SIGNATURE_SCHEME, SignatureScheme, signature_scheme_active_at_height,
};
#[cfg(any(feature = "devnet", feature = "testnet"))]
use crate::crypto::{PublicKey, Signature, dual_address_from_public_keys, verify_dual_parallel};
use crate::error::TransactionError;
use borsh::{BorshDeserialize, BorshSerialize};

#[cfg(any(feature = "devnet", feature = "testnet"))]
use super::Transaction;
pub use super::{AuthorizationProof, ValidityWindow};

pub const AUTHORIZATION_PROOF_V2_VERSION: u8 = 2;
pub const ML_DSA_44_PUBLIC_KEY_SIZE: usize = 1_312;
pub const ML_DSA_44_SIGNATURE_SIZE: usize = 2_420;
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
/// Vectors are bounded by [`AuthorizationProofV2::validate_shape`]. Network decoders must
/// retain their enclosing transaction/message size limit before deserializing.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct AuthorizationProofV2 {
    pub version: u8,
    pub scheme: SignatureScheme,
    pub key_mode: AuthorizationProofKeyMode,
    pub public_key: Vec<u8>,
    pub auth_public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub auth_signature: Vec<u8>,
}

impl AuthorizationProofV2 {
    pub fn new_registered(
        scheme: SignatureScheme,
        public_key: Vec<u8>,
        auth_public_key: Vec<u8>,
        signature: Vec<u8>,
        auth_signature: Vec<u8>,
    ) -> Result<Self, TransactionError> {
        let authorization_proof = Self {
            version: AUTHORIZATION_PROOF_V2_VERSION,
            scheme,
            key_mode: AuthorizationProofKeyMode::Register,
            public_key,
            auth_public_key,
            signature,
            auth_signature,
        };
        authorization_proof.validate_shape()?;
        Ok(authorization_proof)
    }

    pub fn new_stored(
        scheme: SignatureScheme,
        signature: Vec<u8>,
        auth_signature: Vec<u8>,
    ) -> Result<Self, TransactionError> {
        let authorization_proof = Self {
            version: AUTHORIZATION_PROOF_V2_VERSION,
            scheme,
            key_mode: AuthorizationProofKeyMode::Stored,
            public_key: Vec::new(),
            auth_public_key: Vec::new(),
            signature,
            auth_signature,
        };
        authorization_proof.validate_shape()?;
        Ok(authorization_proof)
    }

    pub const fn expected_sizes(scheme: SignatureScheme) -> (usize, usize) {
        match scheme {
            SignatureScheme::MlDsa44 => (ML_DSA_44_PUBLIC_KEY_SIZE, ML_DSA_44_SIGNATURE_SIZE),
            SignatureScheme::SqisignLevel5 => (
                SQISIGN_LEVEL5_PUBLIC_KEY_SIZE,
                SQISIGN_LEVEL5_SIGNATURE_SIZE,
            ),
        }
    }

    pub fn validate_shape(&self) -> Result<(), TransactionError> {
        if self.version != AUTHORIZATION_PROOF_V2_VERSION {
            return Err(TransactionError::UnsupportedVersion);
        }
        let (public_key_size, signature_size) = Self::expected_sizes(self.scheme);
        match self.key_mode {
            AuthorizationProofKeyMode::Register => {
                if self.public_key.len() != public_key_size
                    || self.auth_public_key.len() != public_key_size
                    || all_zero(&self.public_key)
                    || all_zero(&self.auth_public_key)
                {
                    return Err(TransactionError::InvalidAuthorizationProofEncoding);
                }
            }
            AuthorizationProofKeyMode::Stored => {
                if !self.public_key.is_empty() || !self.auth_public_key.is_empty() {
                    return Err(TransactionError::InvalidAuthorizationProofEncoding);
                }
            }
        }
        if self.signature.len() != signature_size
            || self.auth_signature.len() != signature_size
            || all_zero(&self.signature)
            || all_zero(&self.auth_signature)
        {
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

    pub fn from_legacy(authorization_proof: &AuthorizationProof) -> Result<Self, TransactionError> {
        if authorization_proof.carries_registration_keys() {
            Self::new_registered(
                INITIAL_SIGNATURE_SCHEME,
                authorization_proof.public_key.0.to_vec(),
                authorization_proof.auth_public_key.0.to_vec(),
                authorization_proof.signature.0.to_vec(),
                authorization_proof.auth_signature.0.to_vec(),
            )
        } else if authorization_proof.uses_stored_keys() {
            Self::new_stored(
                INITIAL_SIGNATURE_SCHEME,
                authorization_proof.signature.0.to_vec(),
                authorization_proof.auth_signature.0.to_vec(),
            )
        } else {
            Err(TransactionError::InvalidAuthorizationProofEncoding)
        }
    }
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// Version-2 single-transfer envelope enabled on development networks.
///
/// It remains separate from `SignedProtocolTransaction` until a protocol
/// activation assigns its final enum tag.
#[cfg(any(feature = "devnet", feature = "testnet"))]
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignedSingleTransferV2 {
    pub transaction: Transaction,
    pub authorization_proof: AuthorizationProofV2,
}

#[cfg(any(feature = "devnet", feature = "testnet"))]
impl SignedSingleTransferV2 {
    pub fn new(transaction: Transaction, authorization_proof: AuthorizationProofV2) -> Self {
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
        let (owner_public_key, auth_public_key) = self.compiled_public_keys()?;
        if dual_address_from_public_keys(&owner_public_key, &auth_public_key)
            != self.transaction.from
        {
            return Err(TransactionError::SenderAddressMismatch);
        }
        self.verify(&owner_public_key, &auth_public_key)
    }

    pub fn validate_stored_keys_for_height(
        &self,
        height: crate::block::BlockHeight,
        owner_public_key: &PublicKey,
        auth_public_key: &PublicKey,
        upgrade: Option<CryptoUpgradePlan>,
    ) -> Result<(), TransactionError> {
        self.transaction.validate_for_height(height)?;
        self.authorization_proof
            .validate_for_height(height.0, upgrade)?;
        if self.authorization_proof.key_mode != AuthorizationProofKeyMode::Stored {
            return Err(TransactionError::InvalidAuthorizationProofEncoding);
        }
        self.verify(owner_public_key, auth_public_key)
    }

    fn verify(
        &self,
        owner_public_key: &PublicKey,
        auth_public_key: &PublicKey,
    ) -> Result<(), TransactionError> {
        let (signature, auth_signature) = self.compiled_signatures()?;
        let payload = self.transaction.signing_bytes()?;
        let (owner_valid, auth_valid) = verify_dual_parallel(
            owner_public_key,
            auth_public_key,
            &payload,
            &signature,
            &auth_signature,
        );
        if !owner_valid {
            return Err(TransactionError::InvalidSignature);
        }
        if !auth_valid {
            return Err(TransactionError::InvalidAuthorizationSignature);
        }
        Ok(())
    }

    fn compiled_public_keys(&self) -> Result<(PublicKey, PublicKey), TransactionError> {
        self.require_compiled_scheme()?;
        let owner = PublicKey(
            self.authorization_proof
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| TransactionError::InvalidAuthorizationProofEncoding)?,
        );
        let auth = PublicKey(
            self.authorization_proof
                .auth_public_key
                .as_slice()
                .try_into()
                .map_err(|_| TransactionError::InvalidAuthorizationProofEncoding)?,
        );
        Ok((owner, auth))
    }

    fn compiled_signatures(&self) -> Result<(Signature, Signature), TransactionError> {
        self.require_compiled_scheme()?;
        let owner = Signature(
            self.authorization_proof
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| TransactionError::InvalidAuthorizationProofEncoding)?,
        );
        let auth = Signature(
            self.authorization_proof
                .auth_signature
                .as_slice()
                .try_into()
                .map_err(|_| TransactionError::InvalidAuthorizationProofEncoding)?,
        );
        Ok((owner, auth))
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
    fn validates_both_registered_wire_shapes() {
        for scheme in [SignatureScheme::MlDsa44, SignatureScheme::SqisignLevel5] {
            let (public_key_size, signature_size) = AuthorizationProofV2::expected_sizes(scheme);
            AuthorizationProofV2::new_registered(
                scheme,
                bytes(public_key_size, 1),
                bytes(public_key_size, 2),
                bytes(signature_size, 3),
                bytes(signature_size, 4),
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
            protocol_version: 2,
        };
        let authorization_proof = AuthorizationProofV2::new_stored(
            SignatureScheme::SqisignLevel5,
            bytes(SQISIGN_LEVEL5_SIGNATURE_SIZE, 1),
            bytes(SQISIGN_LEVEL5_SIGNATURE_SIZE, 2),
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
            AuthorizationProofV2::new_stored(
                SignatureScheme::MlDsa44,
                vec![1; ML_DSA_44_SIGNATURE_SIZE - 1],
                vec![2; ML_DSA_44_SIGNATURE_SIZE],
            ),
            Err(TransactionError::InvalidAuthorizationProofEncoding)
        );
        assert_eq!(
            AuthorizationProofV2::new_stored(
                SignatureScheme::SqisignLevel5,
                vec![0; SQISIGN_LEVEL5_SIGNATURE_SIZE],
                vec![2; SQISIGN_LEVEL5_SIGNATURE_SIZE],
            ),
            Err(TransactionError::InvalidAuthorizationProofEncoding)
        );
    }

    #[cfg(any(feature = "devnet", feature = "testnet"))]
    #[test]
    fn signed_single_transfer_v2_verifies_with_network_scheme() {
        use crate::consensus::supply::Amount;
        use crate::crypto::{dual_address_from_public_keys, generate_keypair, sign};
        use crate::transaction::TransferOutput;

        let owner = generate_keypair();
        let authorization = generate_keypair();
        let sender = dual_address_from_public_keys(&owner.public_key, &authorization.public_key);
        let transaction = Transaction::new(
            sender,
            vec![TransferOutput {
                to: (crate::crypto::Address([9; crate::crypto::ADDRESS_SIZE])).into(),
                amount: Amount(1),
            }],
        );
        let payload = transaction.signing_bytes().unwrap();
        let authorization_proof = AuthorizationProofV2::new_registered(
            INITIAL_SIGNATURE_SCHEME,
            owner.public_key.0.to_vec(),
            authorization.public_key.0.to_vec(),
            sign(&owner.secret_key, &payload).0.to_vec(),
            sign(&authorization.secret_key, &payload).0.to_vec(),
        )
        .unwrap();
        SignedSingleTransferV2::new(transaction, authorization_proof)
            .validate_signed_for_height(crate::block::Height(0), None)
            .unwrap();
    }
}
