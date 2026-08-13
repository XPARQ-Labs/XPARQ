//! Durable, internal retry records for transactions disconnected by a reorg.

use borsh::{BorshDeserialize, BorshSerialize};
use xparq::block::BlockHeight;
use xparq::codec::canonical_bytes;
use xparq::crypto::{BlockHash, TransactionHash, hash_bytes};
use xparq::transaction::{SignedProtocolTransaction, TransactionFamily};

pub const REORG_TRANSACTION_VERSION: u8 = 1;

#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct ReorgTransactionId(pub [u8; 32]);

impl ReorgTransactionId {
    pub fn for_transaction(
        block_hash: BlockHash,
        transaction_hash: TransactionHash,
    ) -> Result<Self, xparq::error::CodecError> {
        let bytes = canonical_bytes(&(
            b"xparq_REORG_TRANSACTION_V1".to_vec(),
            block_hash,
            transaction_hash,
        ))?;
        Ok(Self(hash_bytes(&bytes).0))
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum ReorgTransactionStatus {
    Pending,
    Requeued,
    Reconfirmed {
        block_height: BlockHeight,
        block_hash: BlockHash,
    },
    Conflict,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct ReorgTransaction {
    pub version: u8,
    pub id: ReorgTransactionId,
    pub disconnected_block_height: BlockHeight,
    pub disconnected_block_hash: BlockHash,
    pub transaction_index: u32,
    pub transaction_hash: TransactionHash,
    pub family: TransactionFamily,
    pub transaction: SignedProtocolTransaction,
    pub status: ReorgTransactionStatus,
    pub detected_at: u64,
    pub retry_attempts: u32,
    pub last_error: Option<String>,
}

impl ReorgTransaction {
    pub fn new(
        block_height: BlockHeight,
        block_hash: BlockHash,
        transaction_index: u32,
        transaction: SignedProtocolTransaction,
        detected_at: u64,
    ) -> Result<Self, xparq::error::CodecError> {
        let transaction_hash = transaction.hash()?;
        Ok(Self {
            version: REORG_TRANSACTION_VERSION,
            id: ReorgTransactionId::for_transaction(block_hash, transaction_hash)?,
            disconnected_block_height: block_height,
            disconnected_block_hash: block_hash,
            transaction_index,
            transaction_hash,
            family: transaction.family(),
            transaction,
            status: ReorgTransactionStatus::Pending,
            detected_at,
            retry_attempts: 0,
            last_error: None,
        })
    }

    pub fn is_reconfirmed(&self) -> bool {
        matches!(self.status, ReorgTransactionStatus::Reconfirmed { .. })
    }
}
