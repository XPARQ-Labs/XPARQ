use crate::runtime::mempool::Mempool;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use xparq::block::{Block, BlockBody, BlockHeader, MAX_BLOCK_DECODE_ITEMS};
use xparq::crypto::{BlockHash, HashDomain, TransactionHash, domain_hash};
use xparq::transaction::SignedProtocolTransaction;

pub const COMPACT_SHORT_ID_BYTES: usize = 8;
pub const MAX_COMPACT_MISSING_TRANSACTIONS: usize = MAX_BLOCK_DECODE_ITEMS;
pub const MAX_COMPACT_RECOVERY_TRANSACTIONS: usize = 1_024;

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct CompactBlock {
    pub height: xparq::block::BlockHeight,
    pub header: BlockHeader,
    pub coinbase: Option<xparq::block::EmissionTransaction>,
    pub short_ids: Vec<u64>,
}

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct IndexedBlockTransaction {
    pub index: u32,
    pub transaction: SignedProtocolTransaction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompactBlockReconstruction {
    Complete(Box<Block>),
    Missing(Vec<u32>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompactBlockError {
    TooManyTransactions,
    InvalidTransactionIndex,
    DuplicateTransactionIndex,
    ShortIdCollision,
    TransactionShortIdMismatch,
    Serialization,
}

impl fmt::Display for CompactBlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooManyTransactions => "compact block transaction count exceeds limit",
            Self::InvalidTransactionIndex => "compact block transaction index is invalid",
            Self::DuplicateTransactionIndex => "compact block transaction index is duplicated",
            Self::ShortIdCollision => "compact block short transaction ID collision",
            Self::TransactionShortIdMismatch => {
                "compact block transaction does not match its short ID"
            }
            Self::Serialization => "compact block hashing failed",
        })
    }
}

impl Error for CompactBlockError {}

impl CompactBlock {
    pub fn from_block(block: &Block) -> Result<Self, CompactBlockError> {
        if block.transactions().len() > MAX_BLOCK_DECODE_ITEMS {
            return Err(CompactBlockError::TooManyTransactions);
        }
        let block_hash = block.hash().map_err(|_| CompactBlockError::Serialization)?;
        let short_ids = block
            .transactions()
            .iter()
            .map(|transaction| {
                transaction
                    .hash()
                    .map(|hash| compact_short_id(block_hash, hash))
                    .map_err(|_| CompactBlockError::Serialization)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if short_ids.iter().copied().collect::<BTreeSet<_>>().len() != short_ids.len() {
            return Err(CompactBlockError::ShortIdCollision);
        }
        Ok(Self {
            height: block.height(),
            header: block.header.clone(),
            coinbase: block.coinbase().cloned(),
            short_ids,
        })
    }

    pub fn block_hash(&self) -> Result<BlockHash, CompactBlockError> {
        self.header
            .hash()
            .map_err(|_| CompactBlockError::Serialization)
    }

    pub fn reconstruct(
        &self,
        mempool: &Mempool,
        supplied: &[IndexedBlockTransaction],
    ) -> Result<CompactBlockReconstruction, CompactBlockError> {
        if self.short_ids.len() > MAX_BLOCK_DECODE_ITEMS
            || supplied.len() > MAX_COMPACT_MISSING_TRANSACTIONS
        {
            return Err(CompactBlockError::TooManyTransactions);
        }
        if self
            .short_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != self.short_ids.len()
        {
            return Err(CompactBlockError::ShortIdCollision);
        }
        let block_hash = self.block_hash()?;
        let mut supplied_by_index = BTreeMap::new();
        for item in supplied {
            let index = usize::try_from(item.index)
                .map_err(|_| CompactBlockError::InvalidTransactionIndex)?;
            let expected = self
                .short_ids
                .get(index)
                .ok_or(CompactBlockError::InvalidTransactionIndex)?;
            let hash = item
                .transaction
                .hash()
                .map_err(|_| CompactBlockError::Serialization)?;
            if compact_short_id(block_hash, hash) != *expected {
                return Err(CompactBlockError::TransactionShortIdMismatch);
            }
            if supplied_by_index
                .insert(index, item.transaction.clone())
                .is_some()
            {
                return Err(CompactBlockError::DuplicateTransactionIndex);
            }
        }

        let wanted = self.short_ids.iter().copied().collect::<BTreeSet<_>>();
        let mut mempool_by_short_id = BTreeMap::new();
        for transaction in mempool.transactions() {
            let hash = transaction
                .hash()
                .map_err(|_| CompactBlockError::Serialization)?;
            let short_id = compact_short_id(block_hash, hash);
            if !wanted.contains(&short_id) {
                continue;
            }
            if mempool_by_short_id
                .insert(short_id, transaction.clone())
                .is_some()
            {
                return Err(CompactBlockError::ShortIdCollision);
            }
        }

        let mut transactions = Vec::with_capacity(self.short_ids.len());
        let mut missing = Vec::new();
        for (index, short_id) in self.short_ids.iter().enumerate() {
            if let Some(transaction) = supplied_by_index.remove(&index) {
                transactions.push(transaction);
            } else if let Some(transaction) = mempool_by_short_id.get(short_id).cloned() {
                transactions.push(transaction);
            } else {
                missing.push(index as u32);
            }
        }
        if !missing.is_empty() {
            return Ok(CompactBlockReconstruction::Missing(missing));
        }
        Ok(CompactBlockReconstruction::Complete(Box::new(Block {
            header: self.header.clone(),
            height: self.height,
            body: BlockBody {
                emission: self.coinbase.clone(),
                transactions,
            },
        })))
    }
}

pub fn compact_short_id(block_hash: BlockHash, transaction_hash: TransactionHash) -> u64 {
    let mut bytes = Vec::with_capacity(21 + 64);
    bytes.extend_from_slice(b"xparq_COMPACT_BLOCK_V1");
    bytes.extend_from_slice(&block_hash.0);
    bytes.extend_from_slice(&transaction_hash.0);
    let hash = domain_hash(HashDomain::Raw, &bytes);
    u64::from_le_bytes(hash.0[..COMPACT_SHORT_ID_BYTES].try_into().unwrap())
}
