use crate::block::{Block, BlockHeader};
use crate::block::{BlockHeight, Height};
use crate::crypto::{BlockHash, HASH_SIZE, Hash};
use crate::error::LedgerError;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Chain {
    /// Authenticated canonical headers, including pruned history.
    pub headers: BTreeMap<BlockHeight, BlockHeader>,
    /// Full blocks retained locally. Snapshot-bootstrapped nodes may not have
    /// bodies below their checkpoint.
    pub blocks: BTreeMap<BlockHeight, Block>,
    pub tip_height: Option<BlockHeight>,
    pub tip_hash: Option<BlockHash>,
    /// A reorg may never disconnect this height or anything below it.
    pub checkpoint_height: Option<BlockHeight>,
}

impl Chain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_block(&mut self, block: Block) -> Result<(), LedgerError> {
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

    pub fn header(&self, height: &BlockHeight) -> Option<&BlockHeader> {
        self.headers.get(height)
    }

    /// Installs a complete header chain that has already passed the public
    /// PoW verifier and pins its tip as the local snapshot checkpoint.
    pub(crate) fn install_verified_headers(
        &mut self,
        headers: &[BlockHeader],
        checkpoint_height: BlockHeight,
    ) -> Result<(), LedgerError> {
        crate::qcash::recovery::verify_header_chain(headers)
            .map_err(|_| LedgerError::InvalidParent)?;
        self.headers.clear();
        self.blocks.clear();
        for header in headers {
            self.headers.insert(header.height, header.clone());
        }
        let tip = headers.last().ok_or(LedgerError::InvalidParent)?;
        self.tip_height = Some(tip.height);
        self.tip_hash = Some(tip.hash()?);
        if checkpoint_height > tip.height {
            return Err(LedgerError::InvalidBlockHeight);
        }
        self.checkpoint_height = Some(checkpoint_height);
        Ok(())
    }

    /// Attaches an available body to an already authenticated canonical header.
    pub(crate) fn attach_full_block(&mut self, block: Block) -> Result<(), LedgerError> {
        let header = self
            .headers
            .get(&block.height())
            .ok_or(LedgerError::InvalidParent)?;
        if header != &block.header {
            return Err(LedgerError::InvalidParent);
        }
        self.blocks.insert(block.height(), block);
        Ok(())
    }

    pub fn tip_height(&self) -> Option<BlockHeight> {
        self.tip_height
    }

    pub fn tip_hash(&self) -> Option<BlockHash> {
        self.tip_hash
    }

    pub fn validate_next_block(&self, block: &Block) -> Result<(), LedgerError> {
        if self.headers.contains_key(&block.height()) {
            return Err(LedgerError::DuplicateBlock);
        }

        match (self.tip_height, self.tip_hash) {
            (None, None) => {
                if block.height() != Height(0) || block.previous_hash() != Hash([0; HASH_SIZE]) {
                    return Err(LedgerError::InvalidBlockHeight);
                }
            }
            (Some(tip_height), Some(tip_hash)) => {
                if block.height().0 != tip_height.0.saturating_add(1) {
                    return Err(LedgerError::InvalidBlockHeight);
                }

                if block.previous_hash() != tip_hash {
                    return Err(LedgerError::InvalidParent);
                }

                let _ = tip_height;
            }
            _ => return Err(LedgerError::InvalidParent),
        }

        Ok(())
    }

    pub fn remove_tip(&mut self, expected_hash: BlockHash) -> Result<Block, LedgerError> {
        if self.tip_hash != Some(expected_hash) {
            return Err(LedgerError::InvalidParent);
        }
        let height = self.tip_height.ok_or(LedgerError::InvalidBlockHeight)?;
        if self
            .checkpoint_height
            .is_some_and(|checkpoint| height <= checkpoint)
        {
            return Err(LedgerError::InvalidBlockHeight);
        }
        let block = self
            .blocks
            .remove(&height)
            .ok_or(LedgerError::InvalidBlockHeight)?;
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
