use std::collections::BTreeMap;
use xparq::block::Block;
use xparq::block::BlockHeight;
use xparq::crypto::{Address, BlockHash};
use xparq::ledger::Ledger;
use xparq::state::Account;

#[derive(Clone, Debug, Default)]
pub struct CoreCache {
    accounts: BTreeMap<Address, Account>,
    blocks_by_height: BTreeMap<BlockHeight, Block>,
    blocks_by_hash: BTreeMap<BlockHash, Block>,
    tip_height: Option<BlockHeight>,
    tip_hash: Option<BlockHash>,
}

impl CoreCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_ledger(ledger: &Ledger) -> Result<Self, xparq::error::CodecError> {
        let mut cache = Self::new();

        for account in ledger.accounts().values() {
            cache.insert_account(account.clone());
        }

        for block in ledger.chain.blocks.values() {
            cache.insert_block(block.clone())?;
        }

        cache.tip_height = ledger.tip_height();
        cache.tip_hash = ledger.tip_hash();
        Ok(cache)
    }

    pub fn insert_account(&mut self, account: Account) {
        self.accounts.insert(account.address, account);
    }

    pub fn account(&self, address: &Address) -> Option<&Account> {
        self.accounts.get(address)
    }

    pub fn insert_block(&mut self, block: Block) -> Result<(), xparq::error::CodecError> {
        let height = block.height();
        let hash = block.hash()?;

        self.blocks_by_height.insert(height, block.clone());
        self.blocks_by_hash.insert(hash, block);
        self.tip_height = Some(height);
        self.tip_hash = Some(hash);
        Ok(())
    }

    pub fn block_by_height(&self, height: &BlockHeight) -> Option<&Block> {
        self.blocks_by_height.get(height)
    }

    pub fn block_by_hash(&self, hash: &BlockHash) -> Option<&Block> {
        self.blocks_by_hash.get(hash)
    }

    pub fn tip_height(&self) -> Option<BlockHeight> {
        self.tip_height
    }

    pub fn tip_hash(&self) -> Option<BlockHash> {
        self.tip_hash
    }
}

// Legacy fixtures predate the xparq 0.2.20 block constructors.
#[cfg(all(test, any()))]
mod test {
    use super::CoreCache;
    use crate::test_support::BlockTestExt;
    use xparq::block::{Block, Height, Nonce};
    use xparq::consensus::supply::Amount;
    use xparq::crypto::{Address, HASH_SIZE, Hash};
    use xparq::ledger::Ledger;
    use xparq::state::Account;

    fn address(byte: u8) -> Address {
        Address([byte; 20])
    }

    #[test]
    fn caches_accounts_and_blocks() {
        let mut cache = CoreCache::new();
        let account = Account::new(address(1), Amount(100));
        let block = Block::new(
            Height(0),
            Hash([0; HASH_SIZE]),
            address(9),
            1_700_000_000,
            Nonce(0),
            vec![],
        );
        let block_hash = block.hash().unwrap();

        cache.insert_account(account.clone());
        cache.insert_block(block.clone()).unwrap();

        assert_eq!(cache.account(&address(1)), Some(&account));
        assert_eq!(cache.block_by_height(&Height(0)), Some(&block));
        assert_eq!(cache.block_by_hash(&block_hash), Some(&block));
        assert_eq!(cache.tip_height(), Some(Height(0)));
        assert_eq!(cache.tip_hash(), Some(block_hash));
    }

    #[test]
    fn builds_from_ledger_state() {
        let mut ledger = Ledger::new();
        let block = Block::new(
            Height(0),
            Hash([0; HASH_SIZE]),
            address(9),
            1_700_000_000,
            Nonce(0),
            vec![],
        );
        let block_hash = block.hash().unwrap();

        ledger.create_account(address(1), Amount(100)).unwrap();
        ledger.chain.insert_block(block).unwrap();

        let cache = CoreCache::from_ledger(&ledger).unwrap();

        assert_eq!(cache.account(&address(1)).unwrap().balance, Amount(100));
        assert_eq!(cache.tip_height(), Some(Height(0)));
        assert_eq!(cache.tip_hash(), Some(block_hash));
    }
}
