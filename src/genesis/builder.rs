use crate::block::{Block, GenesisAllocation};
use crate::codec::{HashDomain, canonical_bytes, domain_hash};
use crate::consensus::DIFFICULTY_ALGORITHM;
use crate::crypto::Address;
use crate::crypto::{HASH_SIZE, Hash};
use crate::error::GenesisError;
use crate::ledger::Ledger;
use borsh::BorshSerialize;

#[cfg(any(feature = "devnet", feature = "testnet"))]
pub const FAUCET_GENESIS_BALANCE: u64 = 1_000_000_000 * crate::consensus::supply::XPQ;
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
    pub miner_address: [u8; crate::crypto::ADDRESS_SIZE],
    pub timestamp: u64,
    pub nonce: u64,
    pub hash: [u8; HASH_SIZE],
}

pub const PAQUS_CHAIN: ChainParams = ChainParams {
    chain_name: "Paqus",
    patch_name: "Sharksphere",
    chain_id: 747,
    coin_name: "XPQ",
    unit_name: "paqus",
    protocol_stage: "Mainnet",
    protocol_version: 1,
    pow_algorithm: "argon2id",
    pow_memory_kib: crate::crypto::POW_ARGON2_MEMORY_KIB,
    pow_iterations: crate::crypto::POW_ARGON2_ITERATIONS,
    pow_lanes: crate::crypto::POW_ARGON2_LANES,
    difficulty_algorithm: DIFFICULTY_ALGORITHM,
    network_magic: [0x58, 0x50, 0x51, 0x01],
    genesis: GenesisParams {
        miner_address: [0; crate::crypto::ADDRESS_SIZE],
        // Fixed timestamp of the first canonical genesis build. This must stay static so all nodes
        // derive the same genesis hash.
        timestamp: 1_700_000_000,
        nonce: 0,
        hash: FROZEN_GENESIS_HASH,
    },
};

/// Mainnet consensus policy: height zero creates no XPQ. Every mainnet coin
/// after genesis must therefore originate from a validated coinbase subsidy.
pub const MAINNET_FAIR_LAUNCH: bool = true;

pub const PAQUS_TESTNET_CHAIN: ChainParams = ChainParams {
    chain_name: "Paqus Testnet",
    patch_name: "Sharksphere",
    chain_id: 717,
    coin_name: "tXPQ",
    unit_name: "paqus",
    protocol_stage: "Testnet",
    protocol_version: 1,
    pow_algorithm: "argon2id",
    pow_memory_kib: crate::crypto::POW_ARGON2_MEMORY_KIB,
    pow_iterations: crate::crypto::POW_ARGON2_ITERATIONS,
    pow_lanes: crate::crypto::POW_ARGON2_LANES,
    difficulty_algorithm: DIFFICULTY_ALGORITHM,
    network_magic: [0x54, 0x58, 0x50, 0x51],
    genesis: GenesisParams {
        miner_address: [0; crate::crypto::ADDRESS_SIZE],
        timestamp: 1_700_000_001,
        nonce: 0,
        hash: TESTNET_GENESIS_HASH,
    },
};

pub const PAQUS_DEVNET_CHAIN: ChainParams = ChainParams {
    chain_name: "Paqus Devnet",
    patch_name: "Sharksphere",
    chain_id: 707,
    coin_name: "dXPQ",
    unit_name: "paqus",
    protocol_stage: "Devnet",
    protocol_version: 1,
    pow_algorithm: "argon2id",
    pow_memory_kib: crate::crypto::POW_ARGON2_MEMORY_KIB,
    pow_iterations: crate::crypto::POW_ARGON2_ITERATIONS,
    pow_lanes: crate::crypto::POW_ARGON2_LANES,
    difficulty_algorithm: DIFFICULTY_ALGORITHM,
    network_magic: [0x44, 0x58, 0x50, 0x51],
    genesis: GenesisParams {
        miner_address: [0; crate::crypto::ADDRESS_SIZE],
        timestamp: 1_700_000_002,
        nonce: 0,
        hash: DEVNET_GENESIS_HASH,
    },
};

/// Frozen mainnet identity for the canonical encoding and block format.
/// Never update this value without defining a new protocol version and chain identity.
pub const FROZEN_GENESIS_HASH: [u8; HASH_SIZE] = [
    60, 11, 40, 86, 49, 2, 145, 228, 67, 65, 157, 119, 251, 131, 2, 163, 36, 95, 171, 68, 246, 111,
    201, 116, 29, 3, 8, 101, 32, 184, 106, 133,
];

pub const TESTNET_GENESIS_HASH: [u8; HASH_SIZE] = [
    11, 129, 165, 200, 45, 156, 6, 232, 83, 27, 36, 21, 216, 101, 108, 87, 99, 193, 173, 182, 214,
    74, 37, 135, 57, 52, 238, 38, 5, 119, 173, 95,
];
pub const DEVNET_GENESIS_HASH: [u8; HASH_SIZE] = [
    11, 66, 139, 20, 165, 58, 159, 248, 110, 71, 205, 81, 136, 108, 206, 178, 19, 251, 254, 140,
    182, 93, 118, 162, 147, 0, 24, 196, 234, 119, 41, 208,
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
#[cfg(all(feature = "mainnet", feature = "sqisign-blockchain-test"))]
compile_error!("mainnet consensus requires ML-DSA-44; SQIsign is not permitted");
#[cfg(all(
    any(feature = "testnet", feature = "devnet"),
    not(feature = "sqisign-blockchain-test")
))]
compile_error!("devnet and testnet consensus require SQIsign Level 5");

#[cfg(feature = "mainnet")]
pub const CURRENT_CHAIN_PARAMS: ChainParams = PAQUS_CHAIN;
#[cfg(feature = "testnet")]
pub const CURRENT_CHAIN_PARAMS: ChainParams = PAQUS_TESTNET_CHAIN;
#[cfg(feature = "devnet")]
pub const CURRENT_CHAIN_PARAMS: ChainParams = PAQUS_DEVNET_CHAIN;

pub const GENESIS_MINER_ADDRESS: Address = Address(CURRENT_CHAIN_PARAMS.genesis.miner_address);
pub const GENESIS_TIMESTAMP: u64 = CURRENT_CHAIN_PARAMS.genesis.timestamp;
pub const GENESIS_HASH: [u8; HASH_SIZE] = CURRENT_CHAIN_PARAMS.genesis.hash;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisConfig {
    pub miner_address: Address,
    pub timestamp: u64,
}

pub fn create_genesis_block(config: GenesisConfig) -> Result<Block, GenesisError> {
    create_genesis_block_for_chain(CURRENT_CHAIN_PARAMS, config)
}

pub fn create_genesis_block_for_chain(
    params: ChainParams,
    config: GenesisConfig,
) -> Result<Block, GenesisError> {
    let allocations = genesis_allocations_for_chain(params);
    let mut block = Block::genesis_with_chain_commitment(
        config.miner_address,
        config.timestamp,
        chain_identity_commitment(params)?,
        allocations,
    )?;
    block.header.nonce = crate::block::Nonce(params.genesis.nonce);
    Ok(block)
}

fn genesis_allocations_for_chain(params: ChainParams) -> Vec<GenesisAllocation> {
    #[cfg(any(feature = "devnet", feature = "testnet"))]
    if params.chain_id == CURRENT_CHAIN_PARAMS.chain_id {
        return vec![GenesisAllocation::new(
            faucet_address(),
            crate::consensus::supply::Amount(FAUCET_GENESIS_BALANCE),
        )];
    }
    #[cfg(feature = "mainnet")]
    let _ = params;
    Vec::new()
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

pub fn create_genesis_ledger(config: GenesisConfig) -> Result<Ledger, GenesisError> {
    create_genesis_ledger_for_chain(CURRENT_CHAIN_PARAMS, config)
}

pub fn create_genesis_ledger_for_chain(
    params: ChainParams,
    config: GenesisConfig,
) -> Result<Ledger, GenesisError> {
    let mut ledger = Ledger::new();
    let block = create_genesis_block_for_chain(params, config)?;
    let now = block.timestamp();
    ledger.apply_block_at(block, now)?;

    Ok(ledger)
}

pub fn genesis_block() -> Result<Block, GenesisError> {
    genesis_block_for_chain(CURRENT_CHAIN_PARAMS)
}

pub fn genesis_block_for_chain(params: ChainParams) -> Result<Block, GenesisError> {
    create_genesis_block_for_chain(
        params,
        GenesisConfig {
            miner_address: Address(params.genesis.miner_address),
            timestamp: params.genesis.timestamp,
        },
    )
}

pub fn validate_genesis_identity(params: ChainParams) -> Result<(), GenesisError> {
    let found = genesis_block_for_chain(params)?.hash()?.0;
    if found != params.genesis.hash {
        return Err(GenesisError::HashMismatch {
            expected: params.genesis.hash,
            found,
        });
    }
    Ok(())
}

pub fn genesis_hash() -> Hash {
    Hash(GENESIS_HASH)
}

pub fn genesis_ledger() -> Result<Ledger, GenesisError> {
    genesis_ledger_for_chain(CURRENT_CHAIN_PARAMS)
}

pub fn genesis_ledger_for_chain(params: ChainParams) -> Result<Ledger, GenesisError> {
    validate_genesis_identity(params)?;
    let mut ledger = Ledger::new();
    let block = genesis_block_for_chain(params)?;
    let now = block.timestamp();
    ledger.apply_block_at(block, now)?;

    Ok(ledger)
}

pub fn create_default_genesis_ledger(
    miner_address: Address,
    timestamp: u64,
) -> Result<Ledger, GenesisError> {
    create_genesis_ledger(GenesisConfig {
        miner_address,
        timestamp,
    })
}

#[derive(BorshSerialize)]
struct ChainIdentityCommitment {
    chain_name: String,
    patch_name: String,
    chain_id: u32,
    coin_name: String,
    unit_name: String,
    protocol_stage: String,
    protocol_version: u8,
    pow_algorithm: String,
    pow_memory_kib: u32,
    pow_iterations: u32,
    pow_lanes: u32,
    difficulty_algorithm: String,
    network_magic: [u8; 4],
}

pub fn chain_identity_commitment(params: ChainParams) -> Result<Hash, crate::error::CodecError> {
    let identity = ChainIdentityCommitment {
        chain_name: params.chain_name.to_owned(),
        patch_name: params.patch_name.to_owned(),
        chain_id: params.chain_id,
        coin_name: params.coin_name.to_owned(),
        unit_name: params.unit_name.to_owned(),
        protocol_stage: params.protocol_stage.to_owned(),
        protocol_version: params.protocol_version,
        pow_algorithm: params.pow_algorithm.to_owned(),
        pow_memory_kib: params.pow_memory_kib,
        pow_iterations: params.pow_iterations,
        pow_lanes: params.pow_lanes,
        difficulty_algorithm: params.difficulty_algorithm.to_owned(),
        network_magic: params.network_magic,
    };
    Ok(domain_hash(
        HashDomain::ChainParams,
        &canonical_bytes(&identity)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_genesis_hash_matches_current_chain_params() {
        validate_genesis_identity(CURRENT_CHAIN_PARAMS).unwrap();
    }

    #[test]
    fn frozen_genesis_ledger_is_valid() {
        genesis_ledger().unwrap();
    }

    #[test]
    fn network_identities_are_distinct_and_frozen() {
        validate_genesis_identity(CURRENT_CHAIN_PARAMS).unwrap();
        assert_ne!(PAQUS_CHAIN.chain_id, PAQUS_TESTNET_CHAIN.chain_id);
        assert_ne!(PAQUS_CHAIN.chain_id, PAQUS_DEVNET_CHAIN.chain_id);
        assert_ne!(
            PAQUS_TESTNET_CHAIN.network_magic,
            PAQUS_DEVNET_CHAIN.network_magic
        );
        assert_ne!(PAQUS_CHAIN.genesis.hash, PAQUS_TESTNET_CHAIN.genesis.hash);
        assert_ne!(PAQUS_CHAIN.genesis.hash, PAQUS_DEVNET_CHAIN.genesis.hash);
    }

    #[cfg(feature = "mainnet")]
    #[test]
    fn mainnet_genesis_has_zero_supply_and_no_allocations() {
        assert!(MAINNET_FAIR_LAUNCH);
        let block = genesis_block().unwrap();
        assert!(block.genesis_allocations.is_empty());
        let ledger = genesis_ledger().unwrap();
        assert_eq!(
            ledger.economic_supply().unwrap(),
            crate::consensus::supply::Amount(0)
        );
    }

    #[cfg(feature = "mainnet")]
    #[test]
    fn mainnet_consensus_rejects_forged_genesis_premine() {
        let block = Block::genesis(
            Address([0; crate::crypto::ADDRESS_SIZE]),
            GENESIS_TIMESTAMP,
            vec![GenesisAllocation::new(
                Address([0x55; crate::crypto::ADDRESS_SIZE]),
                crate::consensus::supply::Amount(1),
            )],
        )
        .unwrap();

        assert_eq!(
            block.validate_structure(),
            Err(crate::block::BlockError::InvalidGenesisAllocation)
        );
    }
}
