use crate::block::BlockHeight;
use crate::crypto::TransactionHash;
use crate::crypto::{Address, PublicKey, address_from_public_key};
pub use crate::error::TransactionError;
use borsh::{BorshDeserialize, BorshSerialize};
use static_assertions::const_assert;

use super::qcash::{self, SignedQCashTransaction};
use super::transfer::{AuthorizationProof, MAX_TX_SIZE, SignedTransfer, ValidityWindow};

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SignedProtocolTransaction {
    Transfer(Box<SignedTransfer>),
    QCash(Box<SignedQCashTransaction>),
}

// Keep unified transaction containers pointer-sized per variant. This prevents
// a block or mempool vector from reserving the largest protocol payload inline.
const_assert!(std::mem::size_of::<SignedProtocolTransaction>() <= 2 * std::mem::size_of::<usize>());

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransactionFamily {
    Transfer,
    QCash,
}

/// Maximum canonical unified envelope size.
pub const MAX_PROTOCOL_TRANSACTION_SIZE: usize = qcash::MAX_QCASH_TX_SIZE + 1;
const_assert!(MAX_TX_SIZE <= qcash::MAX_QCASH_TX_SIZE);

impl SignedProtocolTransaction {
    pub fn authorization_proof(&self) -> &AuthorizationProof {
        match self {
            Self::Transfer(tx) => &tx.authorization_proof,
            Self::QCash(tx) => &tx.authorization_proof,
        }
    }

    pub fn authorization_proof_mut(&mut self) -> &mut AuthorizationProof {
        match self {
            Self::Transfer(tx) => &mut tx.authorization_proof,
            Self::QCash(tx) => &mut tx.authorization_proof,
        }
    }

    pub fn authorization_proof_public_keys_all(&self) -> Vec<&PublicKey> {
        let authorization_proof = self.authorization_proof();
        if authorization_proof.carries_registration_keys() {
            vec![
                &authorization_proof.public_key,
                &authorization_proof.auth_public_key,
            ]
        } else {
            Vec::new()
        }
    }

    pub fn family(&self) -> TransactionFamily {
        match self {
            Self::Transfer(_) => TransactionFamily::Transfer,
            Self::QCash(_) => TransactionFamily::QCash,
        }
    }

    pub fn hash(&self) -> Result<TransactionHash, crate::error::CodecError> {
        Ok(TransactionHash(
            crate::codec::domain_hash(crate::codec::HashDomain::Transaction, &self.to_bytes()?).0,
        ))
    }

    /// Unified payload size without public keys or signatures.
    pub fn stripped_size(&self) -> Result<usize, crate::error::CodecError> {
        Ok(1 + match self {
            Self::Transfer(tx) => tx.transaction.to_bytes()?.len(),
            Self::QCash(tx) => tx.transaction.to_bytes()?.len(),
        })
    }

    pub fn authorization_proof_size(&self) -> Result<usize, crate::error::CodecError> {
        Ok(self.to_bytes()?.len().saturating_sub(self.stripped_size()?))
    }

    pub fn weight(&self) -> Result<usize, crate::error::CodecError> {
        Ok(self.to_bytes()?.len())
    }

    pub fn virtual_size(&self) -> Result<usize, crate::error::CodecError> {
        Ok(self.to_bytes()?.len())
    }

    pub fn signer(&self) -> Address {
        match self {
            Self::Transfer(tx) => tx.transaction.from,
            Self::QCash(tx) => tx.transaction.signer,
        }
    }

    pub fn validity(&self) -> ValidityWindow {
        match self {
            Self::Transfer(tx) => tx.transaction.validity,
            Self::QCash(tx) => tx.transaction.validity,
        }
    }

    /// Returns every public key carried by the transaction authorization proof.
    ///
    /// This is an inspection API; callers must still run normal transaction
    /// validation before trusting the key or its derived address.
    pub fn authorization_proof_public_keys(&self) -> Vec<&PublicKey> {
        self.authorization_proof_public_keys_all()
    }

    /// Returns the envelope's single authorization_proof public key.
    pub fn single_authorization_proof_public_key(&self) -> Option<&PublicKey> {
        self.authorization_proof()
            .carries_registration_keys()
            .then_some(&self.authorization_proof().public_key)
    }

    /// Derives signer addresses from all public keys carried by the authorization_proof.
    pub fn authorization_proof_addresses(&self) -> Vec<Address> {
        self.authorization_proof_public_keys()
            .into_iter()
            .map(address_from_public_key)
            .collect()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::CodecError> {
        crate::codec::signed_protocol_transaction_bytes(self)
    }

    pub fn validate_with_account_authorization(
        &self,
        account: &crate::state::Account,
        height: BlockHeight,
    ) -> Result<Option<(PublicKey, PublicKey)>, TransactionError> {
        self.authorization_proof().validate_shape()?;
        if self.to_bytes()?.len() > MAX_PROTOCOL_TRANSACTION_SIZE {
            return Err(TransactionError::TransactionTooLarge);
        }
        if let Some(authorization) = &account.authorization {
            if self.authorization_proof().carries_registration_keys() {
                if self.authorization_proof().public_key != authorization.owner_public_key
                    || self.authorization_proof().auth_public_key != authorization.auth_public_key
                {
                    return Err(TransactionError::SenderAddressMismatch);
                }
                match self {
                    Self::Transfer(tx) => tx.validate_signed_for_height(height)?,
                    Self::QCash(tx) => tx.validate_signed_for_height(height)?,
                }
            } else {
                match self {
                    Self::Transfer(tx) => tx.validate_stored_keys_for_height(
                        height,
                        &authorization.owner_public_key,
                        &authorization.auth_public_key,
                    )?,
                    Self::QCash(tx) => tx.validate_stored_keys_for_height(
                        height,
                        &authorization.owner_public_key,
                        &authorization.auth_public_key,
                    )?,
                }
            }
            Ok(None)
        } else {
            match self {
                Self::Transfer(tx) => tx.validate_signed_for_height(height)?,
                Self::QCash(tx) => tx.validate_signed_for_height(height)?,
            }
            let authorization_proof = self.authorization_proof();
            Ok(Some((
                authorization_proof.public_key,
                authorization_proof.auth_public_key,
            )))
        }
    }

    pub fn validate_envelope_for_height(
        &self,
        height: BlockHeight,
    ) -> Result<(), TransactionError> {
        self.authorization_proof().validate_shape()?;
        if self.to_bytes()?.len() > MAX_PROTOCOL_TRANSACTION_SIZE {
            return Err(TransactionError::TransactionTooLarge);
        }
        match self {
            Self::Transfer(tx) if tx.authorization_proof.carries_registration_keys() => {
                tx.validate_signed_for_height(height)
            }
            Self::QCash(tx) if tx.authorization_proof.carries_registration_keys() => {
                tx.validate_signed_for_height(height)
            }
            Self::Transfer(tx) => tx.transaction.validate_for_height(height),
            Self::QCash(tx) => tx.transaction.validate_for_height(height),
        }
    }
}

impl From<SignedTransfer> for SignedProtocolTransaction {
    fn from(transaction: SignedTransfer) -> Self {
        Self::Transfer(Box::new(transaction))
    }
}
impl From<SignedQCashTransaction> for SignedProtocolTransaction {
    fn from(transaction: SignedQCashTransaction) -> Self {
        Self::QCash(Box::new(transaction))
    }
}
