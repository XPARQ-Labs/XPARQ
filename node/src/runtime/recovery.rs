use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::BTreeSet;
use xparq::block::BlockHeight;
use xparq::block::merkle::MerkleInclusionProof;
use xparq::codec::canonical_bytes;
use xparq::crypto::{Address, BlockHash, TransactionHash, hash_bytes};
use xparq::qcash::recovery::ChainHeader;
use xparq::transaction::{QCashTransactionKind, SignedProtocolTransaction, TransactionFamily};

#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct RollbackIssueId(pub [u8; 32]);

#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct RollbackProofContextId(pub [u8; 32]);

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct RollbackProofContext {
    pub id: RollbackProofContextId,
    pub losing_headers: Vec<ChainHeader>,
    pub canonical_headers: Vec<ChainHeader>,
    pub common_ancestor: BlockHash,
}

impl RollbackProofContext {
    pub fn new(
        losing_headers: Vec<ChainHeader>,
        canonical_headers: Vec<ChainHeader>,
        common_ancestor: BlockHash,
    ) -> Result<Self, xparq::error::CodecError> {
        let bytes = canonical_bytes(&(
            b"xparq_ROLLBACK_PROOF_CONTEXT_V1".to_vec(),
            &losing_headers,
            &canonical_headers,
            common_ancestor,
        ))?;
        Ok(Self {
            id: RollbackProofContextId(hash_bytes(&bytes).0),
            losing_headers,
            canonical_headers,
            common_ancestor,
        })
    }
}

impl RollbackIssueId {
    pub fn for_transaction(
        block_hash: BlockHash,
        transaction_hash: TransactionHash,
    ) -> Result<Self, xparq::error::CodecError> {
        let bytes = canonical_bytes(&(
            b"xparq_ROLLBACK_ISSUE_V1".to_vec(),
            block_hash,
            transaction_hash,
        ))?;
        Ok(Self(hash_bytes(&bytes).0))
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum RollbackRecoveryStatus {
    Detected,
    Requeued,
    Reconfirmed {
        block_height: BlockHeight,
        block_hash: BlockHash,
    },
    Conflict,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct RollbackIssue {
    pub id: RollbackIssueId,
    pub disconnected_block_height: BlockHeight,
    pub disconnected_block_hash: BlockHash,
    pub transaction_index: u32,
    pub transaction_hash: TransactionHash,
    pub family: TransactionFamily,
    pub affected_accounts: Vec<Address>,
    pub transaction: SignedProtocolTransaction,
    pub proof_context_id: RollbackProofContextId,
    pub transaction_proof: MerkleInclusionProof,
    pub status: RollbackRecoveryStatus,
    pub detected_at: u64,
    pub retry_attempts: u32,
    pub last_error: Option<String>,
}

impl RollbackIssue {
    pub fn new(
        block_height: BlockHeight,
        block_hash: BlockHash,
        transaction_index: u32,
        transaction: SignedProtocolTransaction,
        proof_context_id: RollbackProofContextId,
        transaction_proof: MerkleInclusionProof,
        detected_at: u64,
    ) -> Result<Self, xparq::error::CodecError> {
        let transaction_hash = transaction.hash()?;
        if transaction_proof.leaf_index < transaction_index {
            return Err(xparq::error::CodecError::InvalidBlock);
        }
        Ok(Self {
            id: RollbackIssueId::for_transaction(block_hash, transaction_hash)?,
            disconnected_block_height: block_height,
            disconnected_block_hash: block_hash,
            transaction_index,
            transaction_hash,
            family: transaction.family(),
            affected_accounts: affected_accounts(&transaction),
            transaction,
            proof_context_id,
            transaction_proof,
            status: RollbackRecoveryStatus::Detected,
            detected_at,
            retry_attempts: 0,
            last_error: None,
        })
    }

    pub fn is_reconfirmed(&self) -> bool {
        matches!(self.status, RollbackRecoveryStatus::Reconfirmed { .. })
    }
}

pub fn affected_accounts(transaction: &SignedProtocolTransaction) -> Vec<Address> {
    let mut addresses = BTreeSet::from([transaction.signer()]);
    match transaction {
        SignedProtocolTransaction::Transfer(transaction) => {
            for output in &transaction.transaction.outputs {
                if let Some(address) = output.to.address() {
                    addresses.insert(address);
                }
            }
        }
        SignedProtocolTransaction::QCash(transaction) => {
            if let QCashTransactionKind::Redeem { outputs, .. } = &transaction.transaction.kind {
                addresses.extend(outputs.iter().filter_map(|output| output.to.address()));
            }
        }
    }
    addresses.into_iter().collect()
}
