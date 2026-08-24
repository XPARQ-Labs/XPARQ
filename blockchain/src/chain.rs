use crate::{Block, BlockHeight, Header, Height};
use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::BTreeMap;
use xparq_crypto::{BlockHash, HASH_SIZE, Hash};

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Chain {
    headers: BTreeMap<BlockHeight, Header>,
    blocks: BTreeMap<BlockHeight, Block>,
    tip_height: Option<BlockHeight>,
    tip_hash: Option<BlockHash>,
}

impl Chain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_block(&mut self, block: Block) -> Result<(), ChainError> {
        self.validate_next_block(&block)?;
        let height = block.height();
        let hash = block.hash()?;
        self.headers.insert(height, block.header.clone());
        self.blocks.insert(height, block);
        self.tip_height = Some(height);
        self.tip_hash = Some(hash);
        Ok(())
    }

    pub fn block(&self, height: &BlockHeight) -> Option<&Block> {
        self.blocks.get(height)
    }

    pub fn has_blocks(&self) -> bool {
        self.tip_height.is_some()
    }

    pub fn header(&self, height: &BlockHeight) -> Option<&Header> {
        self.headers.get(height)
    }

    pub fn chain_headers(&self) -> Vec<(BlockHeight, Header)> {
        self.headers
            .iter()
            .map(|(height, header)| (*height, header.clone()))
            .collect()
    }

    pub fn blocks(&self) -> impl DoubleEndedIterator<Item = &Block> {
        self.blocks.values()
    }

    pub fn tip_height(&self) -> Option<BlockHeight> {
        self.tip_height
    }

    pub fn tip_hash(&self) -> Option<BlockHash> {
        self.tip_hash
    }

    pub fn validate_next_block(&self, block: &Block) -> Result<(), ChainError> {
        if self.headers.contains_key(&block.height()) {
            return Err(ChainError::DuplicateBlock);
        }
        match (self.tip_height, self.tip_hash) {
            (None, None) => {
                if block.height() != Height(0) || block.previous_hash() != Hash([0; HASH_SIZE]) {
                    return Err(ChainError::InvalidHeight);
                }
            }
            (Some(tip_height), Some(tip_hash)) => {
                if block.height().0 != tip_height.0.saturating_add(1) {
                    return Err(ChainError::InvalidHeight);
                }
                if block.previous_hash() != tip_hash {
                    return Err(ChainError::InvalidParent);
                }
            }
            _ => return Err(ChainError::InvalidParent),
        }
        Ok(())
    }

    pub fn remove_tip(&mut self, expected_hash: BlockHash) -> Result<Block, ChainError> {
        if self.tip_hash != Some(expected_hash) {
            return Err(ChainError::InvalidParent);
        }
        let height = self.tip_height.ok_or(ChainError::InvalidHeight)?;
        let block = self.blocks.remove(&height).ok_or(ChainError::MissingBody)?;
        self.headers.remove(&height);
        let previous_height = height.0.checked_sub(1).map(Height);
        self.tip_height = previous_height;
        self.tip_hash = match previous_height.and_then(|previous| self.headers.get(&previous)) {
            Some(previous) => Some(previous.hash()?),
            None => None,
        };
        Ok(block)
    }
}

pub use crate::error::ChainError;
