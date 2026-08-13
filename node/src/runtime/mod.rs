pub mod cache;
pub mod mempool;
pub mod miner;
pub mod network;
pub mod node;
pub mod pow_verification;
pub mod reorg_journal;
pub mod storage;

pub mod params {
    pub use xparq::block::MAX_BLOCK_DECODE_ITEMS as MAX_BLOCK_TXS;
    pub use xparq::crypto::{ADDRESS_SIZE, HASH_SIZE};
    pub use xparq::genesis::CURRENT_CHAIN_PARAMS;

    pub const CHAIN_NAME: &str = CURRENT_CHAIN_PARAMS.chain_name;
    pub const CHAIN_ID: u32 = CURRENT_CHAIN_PARAMS.chain_id;
    pub const COIN_NAME: &str = CURRENT_CHAIN_PARAMS.coin_name;
    pub const PROTOCOL_STAGE: &str = CURRENT_CHAIN_PARAMS.protocol_stage;
    pub const PROTOCOL_VERSION: u8 = CURRENT_CHAIN_PARAMS.protocol_version;
    #[cfg(not(feature = "sqisign-blockchain-test"))]
    pub const SIGNATURE_SCHEME: &str = "ML-DSA-44";
    #[cfg(feature = "sqisign-blockchain-test")]
    pub const SIGNATURE_SCHEME: &str = "SQIsign-Level-5";
    /// Wire format carries owned-XPQ UTXO inputs and deterministic outputs.
    pub const P2P_WIRE_FORMAT_VERSION: u8 = 1;
    pub const NETWORK_MAGIC: [u8; 4] = CURRENT_CHAIN_PARAMS.network_magic;
    // Fresh-chain schema stores canonical height entries as block-hash pointers instead of
    // duplicating complete block bodies from the hash index.
    pub const STORAGE_VERSION: u8 = 1;
    /// Local mempool retention in seconds; zero means age-based eviction is disabled.
    pub const LOW_FEE_EXPIRY_SECS: u64 = 0;
    pub const MEMPOOL_EXPIRY_SECS: u64 = 0;
    pub const MAX_MEMPOOL_TXS: usize = 1_000;
    pub const MAX_MEMPOOL_BYTES: usize = 10 * 1024 * 1024;
    pub const MAX_NETWORK_MESSAGE_SIZE: usize = 8 * 1024 * 1024;
    /// Miner bounty rates are denominated in paqs (the smallest XPQ unit) per virtual byte.
    pub const FEE_RATE_UNIT_BYTES: usize = 1;
    pub const DEFAULT_MIN_RELAY_FEE: u64 = 1;
    pub const DEFAULT_MARKET_FEE: u64 = 0;
    pub const DYNAMIC_MARKET_FEE_MAX_MULTIPLIER: u64 = 8;
}
