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
        nonce: 0,
        hash: DEVNET_GENESIS_HASH,
    },
};

/// Frozen mainnet identity for the canonical encoding and block format.
/// Never update this value without defining a new protocol version and chain identity.
pub const FROZEN_GENESIS_HASH: [u8; HASH_SIZE] = [
    6, 124, 227, 5, 168, 159, 56, 121, 147, 95, 72, 56, 128, 61, 122, 105, 154, 243, 64, 247, 51,
    162, 121, 24, 57, 235, 16, 201, 110, 139, 255, 171,
];

pub const TESTNET_GENESIS_HASH: [u8; HASH_SIZE] = [
    90, 130, 83, 154, 190, 205, 242, 37, 41, 192, 35, 171, 7, 205, 76, 254, 179, 184, 190, 138,
    197, 207, 98, 246, 85, 18, 110, 52, 181, 95, 99, 36,
];
pub const DEVNET_GENESIS_HASH: [u8; HASH_SIZE] = [
    198, 183, 207, 189, 60, 207, 251, 49, 23, 159, 140, 32, 112, 185, 92, 69, 173, 131, 232, 80,
    121, 195, 110, 196, 223, 203, 153, 185, 97, 113, 145, 98,
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
pub const GENESIS_HASH: [u8; HASH_SIZE] = CURRENT_CHAIN_PARAMS.genesis.hash;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisConfig {
    pub miner_address: Address,
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
        chain_identity_commitment(params)?,
        allocations,
    )?;
    block.proof.nonce = crate::block::Nonce(params.genesis.nonce);
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
    ledger.apply_block(block)?;

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
    ledger.apply_block(block)?;

    Ok(ledger)
}

pub fn create_default_genesis_ledger(miner_address: Address) -> Result<Ledger, GenesisError> {
    create_genesis_ledger(GenesisConfig { miner_address })
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
        assert!(block.body.genesis_allocations.is_empty());
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
