use crate::block::Block;
use crate::consensus::DIFFICULTY_ALGORITHM;
#[cfg(any(feature = "devnet", feature = "testnet"))]
use crate::crypto::Address;
use crate::crypto::{HASH_SIZE, Hash};
use crate::error::GenesisError;
use crate::ledger::Ledger;

#[cfg(any(feature = "devnet", feature = "testnet"))]
pub const FAUCET_MAX_REQUEST: u64 = 1_000 * crate::consensus::supply::XPQ;
#[cfg(any(feature = "devnet", feature = "testnet"))]
const FAUCET_OWNER_SEED: [u8; 32] = [0x46; 32];
#[cfg(any(feature = "devnet", feature = "testnet"))]
const FAUCET_AUTH_SEED: [u8; 32] = [0x41; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainParams {
    pub chain_name: &'static str,
    pub patch_name: &'static str,
    pub chain_id: u32,
    pub coin_name: &'static str,
    pub unit_name: &'static str,
    pub protocol_stage: &'static str,
    pub protocol_version: u8,
    pub pow_algorithm: &'static str,
    pub pow_memory_kib: u32,
    pub pow_iterations: u32,
    pub pow_lanes: u32,
    pub difficulty_algorithm: &'static str,
    pub network_magic: [u8; 4],
    pub genesis: GenesisParams,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenesisParams {
    pub nonce: u64,
    /// Only production mainnet pins a compile-time genesis identity.
    pub frozen_hash: Option<[u8; HASH_SIZE]>,
}

pub const XPARQ_CHAIN: ChainParams = ChainParams {
    chain_name: "XPARQ",
    patch_name: "Sharksphere",
    chain_id: 747,
    coin_name: "XPQ",
    unit_name: "paqs",
    protocol_stage: "Mainnet",
    protocol_version: 1,
    pow_algorithm: "argon2id",
    pow_memory_kib: crate::crypto::POW_ARGON2_MEMORY_KIB,
    pow_iterations: crate::crypto::POW_ARGON2_ITERATIONS,
    pow_lanes: crate::crypto::POW_ARGON2_LANES,
    difficulty_algorithm: DIFFICULTY_ALGORITHM,
    network_magic: [0x58, 0x50, 0x51, 0x01],
    genesis: GenesisParams {
        nonce: 0,
        frozen_hash: Some(FROZEN_GENESIS_HASH),
    },
};

/// Mainnet consensus policy: height zero creates no XPQ. Every mainnet coin
/// after genesis must therefore originate from a validated coinbase subsidy.
pub const MAINNET_FAIR_LAUNCH: bool = true;

pub const XPARQ_TESTNET_CHAIN: ChainParams = ChainParams {
    chain_name: "XPARQ Testnet",
    patch_name: "Sharksphere",
    chain_id: 717,
    coin_name: "tXPQ",
    unit_name: "paqs",
    protocol_stage: "Testnet",
    protocol_version: 1,
    pow_algorithm: "argon2id",
    pow_memory_kib: crate::crypto::POW_ARGON2_MEMORY_KIB,
    pow_iterations: crate::crypto::POW_ARGON2_ITERATIONS,
    pow_lanes: crate::crypto::POW_ARGON2_LANES,
    difficulty_algorithm: DIFFICULTY_ALGORITHM,
    network_magic: [0x54, 0x58, 0x50, 0x51],
    genesis: GenesisParams {
        nonce: 1,
        frozen_hash: None,
    },
};

pub const XPARQ_DEVNET_CHAIN: ChainParams = ChainParams {
    chain_name: "XPARQ Devnet",
    patch_name: "Sharksphere",
    chain_id: 707,
    coin_name: "dXPQ",
    unit_name: "paqs",
    protocol_stage: "Devnet",
    protocol_version: 1,
    pow_algorithm: "argon2id",
    pow_memory_kib: crate::crypto::POW_ARGON2_MEMORY_KIB,
    pow_iterations: crate::crypto::POW_ARGON2_ITERATIONS,
    pow_lanes: crate::crypto::POW_ARGON2_LANES,
    difficulty_algorithm: DIFFICULTY_ALGORITHM,
    network_magic: [0x44, 0x58, 0x50, 0x51],
    genesis: GenesisParams {
        nonce: 2,
        frozen_hash: None,
    },
};

/// Frozen mainnet identity for the canonical encoding and block format.
/// Never update this value without defining a new chain identity.
pub const FROZEN_GENESIS_HASH: [u8; HASH_SIZE] = [
    254, 18, 22, 45, 228, 90, 109, 148, 72, 142, 104, 83, 35, 43, 69, 36, 159, 210, 194, 206, 162,
    76, 38, 242, 89, 241, 206, 8, 43, 69, 55, 215,
];

#[cfg(any(
    all(feature = "mainnet", feature = "testnet"),
    all(feature = "mainnet", feature = "devnet"),
    all(feature = "testnet", feature = "devnet"),
))]
compile_error!(
    "network features are mutually exclusive; enable exactly one of mainnet, testnet, devnet"
);
#[cfg(not(any(feature = "mainnet", feature = "testnet", feature = "devnet")))]
compile_error!("enable exactly one network feature: mainnet, testnet, or devnet");
#[cfg(all(
    any(feature = "mainnet", feature = "testnet"),
    feature = "sqisign-blockchain-test"
))]
compile_error!("mainnet and testnet consensus require ML-DSA-44; SQIsign is not permitted");
#[cfg(all(feature = "devnet", not(feature = "sqisign-blockchain-test")))]
compile_error!("devnet consensus requires SQIsign Level 5");

#[cfg(feature = "mainnet")]
pub const CURRENT_CHAIN_PARAMS: ChainParams = XPARQ_CHAIN;
#[cfg(feature = "testnet")]
pub const CURRENT_CHAIN_PARAMS: ChainParams = XPARQ_TESTNET_CHAIN;
#[cfg(feature = "devnet")]
pub const CURRENT_CHAIN_PARAMS: ChainParams = XPARQ_DEVNET_CHAIN;

pub fn create_genesis_block() -> Result<Block, GenesisError> {
    create_genesis_block_for_chain(CURRENT_CHAIN_PARAMS)
}

pub fn create_genesis_block_for_chain(params: ChainParams) -> Result<Block, GenesisError> {
    let mut block = Block::genesis()?;
    block.header.nonce = crate::block::Nonce(params.genesis.nonce);
    Ok(block)
}

#[cfg(any(feature = "devnet", feature = "testnet"))]
pub fn faucet_keypairs() -> (crate::crypto::KeyPair, crate::crypto::KeyPair) {
    // Never cache signing keys: `KeyPair` zeroizes on drop after each faucet
    // operation. These test-network seeds are public protocol constants.
    (
        crate::crypto::keypair_from_seed(&FAUCET_OWNER_SEED),
        crate::crypto::keypair_from_seed(&FAUCET_AUTH_SEED),
    )
}

#[cfg(any(feature = "devnet", feature = "testnet"))]
pub fn faucet_address() -> Address {
    let (owner, authorization) = faucet_keypairs();
    crate::crypto::dual_address_from_public_keys(&owner.public_key, &authorization.public_key)
}

pub fn create_genesis_ledger() -> Result<Ledger, GenesisError> {
    create_genesis_ledger_for_chain(CURRENT_CHAIN_PARAMS)
}

pub fn create_genesis_ledger_for_chain(params: ChainParams) -> Result<Ledger, GenesisError> {
    let mut ledger = Ledger::new();
    let block = create_genesis_block_for_chain(params)?;
    ledger.apply_block(block)?;

    Ok(ledger)
}

pub fn genesis_block() -> Result<Block, GenesisError> {
    genesis_block_for_chain(CURRENT_CHAIN_PARAMS)
}

pub fn genesis_block_for_chain(params: ChainParams) -> Result<Block, GenesisError> {
    create_genesis_block_for_chain(params)
}

pub fn validate_genesis_identity(params: ChainParams) -> Result<(), GenesisError> {
    let Some(expected) = params.genesis.frozen_hash else {
        return Ok(());
    };
    let found = genesis_block_for_chain(params)?.hash()?.0;
    if found != expected {
        return Err(GenesisError::HashMismatch { expected, found });
    }
    Ok(())
}

pub fn genesis_hash_for_chain(params: ChainParams) -> Result<Hash, crate::error::CodecError> {
    let mut block = Block::genesis()?;
    block.header.nonce = crate::block::Nonce(params.genesis.nonce);
    Ok(Hash(block.hash()?.0))
}

pub fn genesis_hash() -> Result<Hash, crate::error::CodecError> {
    genesis_hash_for_chain(CURRENT_CHAIN_PARAMS)
}

pub fn genesis_ledger() -> Result<Ledger, GenesisError> {
    genesis_ledger_for_chain(CURRENT_CHAIN_PARAMS)
}

pub fn genesis_ledger_for_chain(params: ChainParams) -> Result<Ledger, GenesisError> {
    validate_genesis_identity(params)?;
    let mut ledger = Ledger::new();
    let block = genesis_block_for_chain(params)?;
    ledger.apply_block(block)?;

    Ok(ledger)
}

pub fn create_default_genesis_ledger() -> Result<Ledger, GenesisError> {
    create_genesis_ledger()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_genesis_identity_is_valid() {
        validate_genesis_identity(CURRENT_CHAIN_PARAMS).unwrap();
    }

    #[test]
    fn configured_genesis_ledger_is_valid() {
        genesis_ledger().unwrap();
    }

    #[test]
    fn only_mainnet_has_a_frozen_genesis() {
        validate_genesis_identity(CURRENT_CHAIN_PARAMS).unwrap();
        assert_eq!(crate::crypto::POW_ARGON2_LANES, 2);
        assert_eq!(XPARQ_CHAIN.pow_lanes, 2);
        assert_eq!(XPARQ_TESTNET_CHAIN.pow_lanes, 2);
        assert_eq!(XPARQ_DEVNET_CHAIN.pow_lanes, 2);
        assert_ne!(XPARQ_CHAIN.chain_id, XPARQ_TESTNET_CHAIN.chain_id);
        assert_ne!(XPARQ_CHAIN.chain_id, XPARQ_DEVNET_CHAIN.chain_id);
        assert_ne!(
            XPARQ_TESTNET_CHAIN.network_magic,
            XPARQ_DEVNET_CHAIN.network_magic
        );
        assert_eq!(XPARQ_CHAIN.genesis.frozen_hash, Some(FROZEN_GENESIS_HASH));
        assert_eq!(XPARQ_TESTNET_CHAIN.genesis.frozen_hash, None);
        assert_eq!(XPARQ_DEVNET_CHAIN.genesis.frozen_hash, None);
        assert_ne!(
            genesis_hash_for_chain(XPARQ_CHAIN).unwrap(),
            genesis_hash_for_chain(XPARQ_TESTNET_CHAIN).unwrap()
        );
        assert_ne!(
            genesis_hash_for_chain(XPARQ_TESTNET_CHAIN).unwrap(),
            genesis_hash_for_chain(XPARQ_DEVNET_CHAIN).unwrap()
        );
    }

    #[cfg(feature = "mainnet")]
    #[test]
    fn mainnet_genesis_has_zero_supply() {
        assert!(MAINNET_FAIR_LAUNCH);
        let ledger = genesis_ledger().unwrap();
        assert_eq!(
            ledger.economic_supply().unwrap(),
            crate::consensus::supply::Amount(0)
        );
    }

    #[cfg(any(feature = "testnet", feature = "devnet"))]
    #[test]
    fn non_mainnet_genesis_is_derived_and_has_zero_supply() {
        assert_eq!(CURRENT_CHAIN_PARAMS.genesis.frozen_hash, None);
        let block = genesis_block().unwrap();
        assert_eq!(genesis_hash().unwrap().0, block.hash().unwrap().0);
        assert_eq!(
            genesis_ledger().unwrap().economic_supply().unwrap(),
            crate::consensus::supply::Amount(0)
        );
    }
}
