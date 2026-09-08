use borsh::{BorshDeserialize, BorshSerialize};

use crypto::{HASH_SIZE, HashDomain, canonical_bytes, domain};

use crate::transaction::{
    AuthorizedTransaction, ChainContext, IntentError, TransactionEncodingError,
};

/// Hash committed on-chain before an authorized transaction is revealed.
///
/// No random nonce is used by design. The chain genesis hash is included so a
/// commitment cannot be reused unchanged across XPARQ chains.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct TransactionCommitment([u8; HASH_SIZE]);

impl TransactionCommitment {
    pub fn derive(
        chain: ChainContext,
        transaction: &AuthorizedTransaction,
    ) -> Result<Self, TransactionEncodingError> {
        let bytes = canonical_bytes(&(chain.genesis_hash, transaction))
            .map_err(|_| TransactionEncodingError::Encoding)?;

        Ok(Self(
            domain(HashDomain::TransactionCommit, &bytes).into_bytes(),
        ))
    }

    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; HASH_SIZE] {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CommitTransaction {
    pub commitment: TransactionCommitment,
}

impl CommitTransaction {
    pub const fn new(commitment: TransactionCommitment) -> Self {
        Self { commitment }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RevealTransaction {
    pub transaction: AuthorizedTransaction,
}

impl RevealTransaction {
    pub fn new(transaction: AuthorizedTransaction) -> Self {
        Self { transaction }
    }

    pub fn commitment(
        &self,
        chain: ChainContext,
    ) -> Result<TransactionCommitment, TransactionEncodingError> {
        TransactionCommitment::derive(chain, &self.transaction)
    }

    pub fn matches(
        &self,
        chain: ChainContext,
        expected: TransactionCommitment,
    ) -> Result<bool, TransactionEncodingError> {
        Ok(self.commitment(chain)? == expected)
    }

    pub fn validate_structure(&self) -> Result<(), IntentError> {
        self.transaction.validate_structure()
    }
}

/// Canonical on-chain transaction envelope.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Transaction {
    Commit(CommitTransaction),
    Reveal(Box<RevealTransaction>),
}

impl Transaction {
    pub fn id(&self) -> Result<[u8; HASH_SIZE], TransactionEncodingError> {
        // Tag 1 separates the outer transaction ID from AuthorizedTransaction::id().
        let bytes =
            canonical_bytes(&(1_u8, self)).map_err(|_| TransactionEncodingError::Encoding)?;
        Ok(domain(HashDomain::Transaction, &bytes).into_bytes())
    }

    pub fn commitment(&self) -> Option<TransactionCommitment> {
        match self {
            Self::Commit(transaction) => Some(transaction.commitment),
            Self::Reveal(_) => None,
        }
    }

    pub fn reveal(&self) -> Option<&RevealTransaction> {
        match self {
            Self::Commit(_) => None,
            Self::Reveal(transaction) => Some(transaction.as_ref()),
        }
    }
}
