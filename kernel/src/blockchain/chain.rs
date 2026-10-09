use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};

use crypto::{BlockHash, PreviousHash};

use crate::common::Height;

use super::{Block, ChainError, Header};

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Chain {
    headers: BTreeMap<Height, Header>,
    blocks: BTreeMap<Height, Block>,
    tip_height: Option<Height>,
    tip_hash: Option<BlockHash>,
}

impl Chain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_block(&mut self, block: Block) -> Result<(), ChainError> {
        // Ledger commit relies on all fallible operations preceding mutation.
        self.validate_next_block(&block)?;

        let height = block.height();
        let hash = block.hash()?;

        self.headers.insert(height, block.header.clone());
        self.blocks.insert(height, block);
        self.tip_height = Some(height);
        self.tip_hash = Some(hash);

        Ok(())
    }

    pub fn block(&self, height: &Height) -> Option<&Block> {
        self.blocks.get(height)
    }

    pub fn has_blocks(&self) -> bool {
        self.tip_height.is_some()
    }

    pub fn header(&self, height: &Height) -> Option<&Header> {
        self.headers.get(height)
    }

    pub fn chain_headers(&self) -> Vec<(Height, Header)> {
        self.headers
            .iter()
            .map(|(height, header)| (*height, header.clone()))
            .collect()
    }

    /// Resident bodies only; an evicted body must be read from durable storage.
    pub fn blocks(&self) -> impl DoubleEndedIterator<Item = &Block> {
        self.blocks.values()
    }

    /// Headers remain authoritative even when historical bodies leave a node cache.
    pub fn headers(&self) -> impl DoubleEndedIterator<Item = (&Height, &Header)> {
        self.headers.iter()
    }

    /// Drop old resident bodies only. Callers must durably store them first.
    /// Genesis and the tip remain resident; their bytes are included in the budget.
    pub fn retain_recent_bodies(
        &mut self,
        max_bytes: usize,
        max_blocks: usize,
    ) -> Result<(), ChainError> {
        let mut bytes = 0_usize;
        let mut count = 0_usize;
        let mut remove = Vec::new();
        for (height, block) in self.blocks.iter().rev() {
            let size = block.weight()?;
            let pinned = height.0 == 0 || Some(*height) == self.tip_height;
            if pinned || (count < max_blocks && size <= max_bytes.saturating_sub(bytes)) {
                bytes = bytes.saturating_add(size);
                count += 1;
            } else {
                remove.push(*height);
            }
        }
        for height in remove {
            self.blocks.remove(&height);
        }
        Ok(())
    }

    /// Rehydrate an already known body without changing chain position or state.
    pub fn cache_known_block(&mut self, block: Block) -> Result<(), ChainError> {
        if self.headers.get(&block.height()) != Some(&block.header) {
            return Err(ChainError::InvalidParent);
        }
        block
            .validate_structure()
            .map_err(|_| ChainError::InvalidParent)?;
        self.blocks.insert(block.height(), block);
        Ok(())
    }

    pub const fn tip_height(&self) -> Option<Height> {
        self.tip_height
    }

    pub const fn tip_hash(&self) -> Option<BlockHash> {
        self.tip_hash
    }

    pub fn validate_next_block(&self, block: &Block) -> Result<(), ChainError> {
        if self.headers.contains_key(&block.height()) {
            return Err(ChainError::DuplicateBlock);
        }

        match (self.tip_height, self.tip_hash) {
            (None, None) => {
                if block.height() != Height(0) || block.previous_hash() != PreviousHash::ZERO {
                    return Err(ChainError::InvalidHeight);
                }
            }
            (Some(tip_height), Some(tip_hash)) => {
                if block.height().0 != tip_height.0.saturating_add(1) {
                    return Err(ChainError::InvalidHeight);
                }

                if BlockHash(block.previous_hash().0) != tip_hash {
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
