use std::collections::BTreeMap;
use std::sync::Arc;
use xparq::block::{Block, BlockHeight};
use xparq::crypto::BlockHash;
use xparq::ledger::Ledger;

pub const MAX_CACHED_BLOCKS: usize = 32;
pub const MAX_CACHED_BLOCK_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug)]
struct CachedBlock {
    block: Arc<Block>,
    serialized_size: usize,
}

#[derive(Clone, Debug, Default)]
pub struct CoreCache {
    blocks_by_height: BTreeMap<BlockHeight, CachedBlock>,
    block_heights_by_hash: BTreeMap<BlockHash, BlockHeight>,
    cached_block_bytes: usize,
}

impl CoreCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_ledger(ledger: &Ledger) -> Result<Self, xparq::error::CodecError> {
        let mut cache = Self::new();

        for block in ledger.chain.blocks.values() {
            cache.insert_block(block.clone())?;
        }
        Ok(cache)
    }

    pub fn insert_block(&mut self, block: Block) -> Result<(), xparq::error::CodecError> {
        let serialized_size = block.serialized_size()?;
        self.insert_block_sized(block, serialized_size)
    }

    fn insert_block_sized(
        &mut self,
        block: Block,
        serialized_size: usize,
    ) -> Result<(), xparq::error::CodecError> {
        let height = block.height();
        let hash = block.hash()?;

        if let Some(existing_height) = self.block_heights_by_hash.get(&hash).copied() {
            self.remove_block_at(existing_height);
        }
        self.remove_block_at(height);

        self.blocks_by_height.insert(
            height,
            CachedBlock {
                block: Arc::new(block),
                serialized_size,
            },
        );
        self.block_heights_by_hash.insert(hash, height);
        self.cached_block_bytes = self.cached_block_bytes.saturating_add(serialized_size);
        self.evict_oldest_blocks();
        Ok(())
    }

    pub fn block_by_height(&self, height: &BlockHeight) -> Option<&Block> {
        self.blocks_by_height
            .get(height)
            .map(|cached| cached.block.as_ref())
    }

    pub fn block_by_hash(&self, hash: &BlockHash) -> Option<&Block> {
        self.block_heights_by_hash
            .get(hash)
            .and_then(|height| self.block_by_height(height))
    }

    pub fn cached_block_count(&self) -> usize {
        self.blocks_by_height.len()
    }

    pub fn cached_block_bytes(&self) -> usize {
        self.cached_block_bytes
    }

    fn evict_oldest_blocks(&mut self) {
        while self.blocks_by_height.len() > MAX_CACHED_BLOCKS
            || self.cached_block_bytes > MAX_CACHED_BLOCK_BYTES
        {
            let Some(oldest_height) = self.blocks_by_height.first_key_value().map(|(h, _)| *h)
            else {
                break;
            };
            self.remove_block_at(oldest_height);
        }
    }

    fn remove_block_at(&mut self, height: BlockHeight) {
        let Some(cached) = self.blocks_by_height.remove(&height) else {
            return;
        };
        if let Ok(hash) = cached.block.hash() {
            self.block_heights_by_hash.remove(&hash);
        }
        self.cached_block_bytes = self
            .cached_block_bytes
            .saturating_sub(cached.serialized_size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xparq::block::{Block, Height, Nonce};

    fn block(height: u64) -> Block {
        let mut block = Block::genesis().unwrap();
        block.height = Height(height);
        block.header.nonce = Nonce(height);
        block
    }

    #[test]
    fn indexes_one_block_all_both_keys_without_duplicate_ownership() {
        let mut cache = CoreCache::new();
        let block = block(7);
        let hash = block.hash().unwrap();
        let size = block.serialized_size().unwrap();
        cache.insert_block(block.clone()).unwrap();

        assert_eq!(cache.block_by_height(&Height(7)), Some(&block));
        assert_eq!(cache.block_by_hash(&hash), Some(&block));
        assert_eq!(cache.cached_block_count(), 1);
        assert_eq!(cache.cached_block_bytes(), size);
    }

    #[test]
    fn evicts_oldest_block_after_count_limit() {
        let mut cache = CoreCache::new();
        for height in 0..=MAX_CACHED_BLOCKS as u64 {
            cache.insert_block(block(height)).unwrap();
        }

        assert_eq!(cache.cached_block_count(), MAX_CACHED_BLOCKS);
        assert!(cache.block_by_height(&Height(0)).is_none());
        assert!(
            cache
                .block_by_height(&Height(MAX_CACHED_BLOCKS as u64))
                .is_some()
        );
    }

    #[test]
    fn evicts_oldest_block_after_byte_limit() {
        let mut cache = CoreCache::new();
        cache
            .insert_block_sized(block(1), 40 * 1024 * 1024)
            .unwrap();
        cache
            .insert_block_sized(block(2), 40 * 1024 * 1024)
            .unwrap();

        assert_eq!(cache.cached_block_count(), 1);
        assert_eq!(cache.cached_block_bytes(), 40 * 1024 * 1024);
        assert!(cache.block_by_height(&Height(1)).is_none());
        assert!(cache.block_by_height(&Height(2)).is_some());
    }

    #[test]
    fn replacing_height_removes_stale_hash_index() {
        let mut cache = CoreCache::new();
        let original = block(4);
        let original_hash = original.hash().unwrap();
        cache.insert_block(original).unwrap();

        let mut replacement = block(4);
        replacement.header.nonce = Nonce(999);
        let replacement_hash = replacement.hash().unwrap();
        cache.insert_block(replacement).unwrap();

        assert!(cache.block_by_hash(&original_hash).is_none());
        assert!(cache.block_by_hash(&replacement_hash).is_some());
        assert_eq!(cache.cached_block_count(), 1);
    }
}
