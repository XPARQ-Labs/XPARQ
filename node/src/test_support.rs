use xparq::block::{Block, EmissionTransaction, Nonce};
use xparq::consensus::DIFFICULTY_START;
use xparq::consensus::supply::Amount;
use xparq::crypto::{Address, BlockHash, Hash, PreviousHash};
use xparq::transaction::{SignedProtocolTransaction, SignedTransaction};

pub trait BlockTestExt {
    fn new<P: TestPreviousHash>(
        height: xparq::block::Height,
        previous_hash: P,
        miner: Address,
        timestamp: u64,
        nonce: Nonce,
        transactions: Vec<SignedTransaction>,
    ) -> Block;

    fn with_difficulty<P: TestPreviousHash>(
        height: xparq::block::Height,
        previous_hash: P,
        miner: Address,
        difficulty: u32,
        timestamp: u64,
        nonce: Nonce,
        transactions: Vec<SignedTransaction>,
    ) -> Block;

    fn with_coinbase<P: TestPreviousHash>(
        height: xparq::block::Height,
        previous_hash: P,
        miner: Address,
        difficulty: u32,
        timestamp: u64,
        nonce: Nonce,
        coinbase: Option<EmissionTransaction>,
        transactions: Vec<SignedTransaction>,
    ) -> Block;
}

pub trait TestPreviousHash {
    fn test_previous_hash(self) -> PreviousHash;
}

impl TestPreviousHash for PreviousHash {
    fn test_previous_hash(self) -> PreviousHash {
        self
    }
}

impl TestPreviousHash for BlockHash {
    fn test_previous_hash(self) -> PreviousHash {
        self.into()
    }
}

impl TestPreviousHash for Hash {
    fn test_previous_hash(self) -> PreviousHash {
        self.into()
    }
}

impl TestPreviousHash for Result<BlockHash, xparq::error::CodecError> {
    fn test_previous_hash(self) -> PreviousHash {
        self.unwrap().into()
    }
}

impl BlockTestExt for Block {
    fn new<P: TestPreviousHash>(
        height: xparq::block::Height,
        previous_hash: P,
        miner: Address,
        timestamp: u64,
        nonce: Nonce,
        transactions: Vec<SignedTransaction>,
    ) -> Block {
        Self::with_difficulty(
            height,
            previous_hash,
            miner,
            DIFFICULTY_START,
            timestamp,
            nonce,
            transactions,
        )
    }

    fn with_difficulty<P: TestPreviousHash>(
        height: xparq::block::Height,
        previous_hash: P,
        miner: Address,
        difficulty: u32,
        timestamp: u64,
        nonce: Nonce,
        transactions: Vec<SignedTransaction>,
    ) -> Block {
        let fees = transactions.iter().fold(Amount(0), |total, transaction| {
            Amount(total.0.saturating_add(0))
        });
        let coinbase = (height.0 != 0)
            .then(|| EmissionTransaction::new(miner, xparq::consensus::block_reward(height)));
        Self::with_coinbase(
            height,
            previous_hash,
            miner,
            difficulty,
            timestamp,
            nonce,
            coinbase,
            transactions,
        )
    }

    fn with_coinbase<P: TestPreviousHash>(
        height: xparq::block::Height,
        previous_hash: P,
        miner: Address,
        difficulty: u32,
        timestamp: u64,
        nonce: Nonce,
        coinbase: Option<EmissionTransaction>,
        transactions: Vec<SignedTransaction>,
    ) -> Block {
        Block::from_protocol_transactions(
            height,
            previous_hash.test_previous_hash(),
            difficulty,
            nonce,
            coinbase,
            transactions
                .into_iter()
                .map(SignedProtocolTransaction::from)
                .collect(),
        )
        .unwrap()
    }
}
