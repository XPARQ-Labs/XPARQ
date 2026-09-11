//! Construction and identity of the canonical chain root.

use std::{error::Error, fmt};

use crate::blockchain::{Block, MAX_BLOCK_SIZE, Nonce};
use crate::consensus::{
    BLOCK_EMISSION_START,
    BLOCK_EMISSION_STEP,
    COIN_UTXO_STATE_WEIGHT,
    DIFFICULTY_ALGORITHM,
    DIFFICULTY_START,
    EMPTY_BLOCK_ARCHIVAL_BYTES,
    EMISSION_INTERVAL,
    MAX_DIFFICULTY,
    MIN_DIFFICULTY,
    POW_ALGORITHM,
    POW_ARGON2_ITERATIONS,
    POW_ARGON2_LANES,
    POW_ARGON2_MEMORY_KIB,
    STATE_BURN_ALGORITHM,
    STATE_BURN_RATE_ZENO_PER_WEIGHT,
    TAIL_BLOCK_EMISSION,
    WBDA_DIFFICULTY_STEP,
    WBDA_TARGET_BLOCK_WEIGHT,
    WBDA_LOW_UTILIZATION_PPM,
    WBDA_HIGH_UTILIZATION_PPM,
    WBDA_WINDOW,
};

use crate::ledger::{Ledger, LedgerError};
use crate::transaction::ChainContext;

use borsh::BorshSerialize;

use crypto::{
    ADDRESS_SIZE,
    BlockHash,
    FALCON_512_ACTIVATION_HEIGHT,
    HASH_SIZE,
    Hash,
    HashDomain,
    SIGNATURE_ACTIVATION_HEIGHT,
    domain_hash,
};

const FORK_CHOICE_ALGORITHM: &str =
    "cumulative-work/cumulative-weight/hash";

// -----------------------------------------------------------------------------
// Mainnet
// -----------------------------------------------------------------------------

#[cfg(feature = "mainnet")]
pub const GENESIS_NONCE: u64 = 4;

#[cfg(feature = "mainnet")]
pub const EXPECTED_GENESIS_HASH: BlockHash = BlockHash([
    0x65, 0x40, 0x76, 0x44, 0x36, 0x56, 0x40, 0xe1,
    0x64, 0x66, 0x31, 0x9f, 0xb6, 0x07, 0xae, 0xd0,
    0x54, 0x3b, 0x1e, 0x4b, 0xed, 0xef, 0x54, 0xe1,
    0xba, 0x68, 0x66, 0x81, 0xc7, 0x8c, 0x42, 0x9f,
]);

// -----------------------------------------------------------------------------
// Testnet
// -----------------------------------------------------------------------------

#[cfg(feature = "testnet")]
pub const GENESIS_NONCE: u64 = 5;

#[cfg(feature = "testnet")]
pub const EXPECTED_GENESIS_HASH: BlockHash = BlockHash([
    0x5a, 0x0e, 0x26, 0x10, 0x08, 0x87, 0x88, 0x8c,
    0xee, 0xab, 0xd0, 0xf7, 0x8a, 0xe4, 0x80, 0xa8,
    0xc4, 0xd0, 0x9b, 0x78, 0x7f, 0xfa, 0x4b, 0xfa,
    0x6c, 0x6d, 0xab, 0x8c, 0xde, 0x5c, 0xfa, 0xcd,
]);

// -----------------------------------------------------------------------------
// Devnet
// -----------------------------------------------------------------------------

#[cfg(feature = "devnet")]
pub const GENESIS_NONCE: u64 = 6;

#[cfg(feature = "devnet")]
pub const EXPECTED_GENESIS_HASH: BlockHash = BlockHash([
    0xb1, 0x31, 0x39, 0xf1, 0x3c, 0xe5, 0x22, 0x32,
    0x8e, 0xd0, 0x7f, 0x29, 0x09, 0x9c, 0xff, 0x60,
    0x69, 0xa0, 0x50, 0x61, 0x81, 0x06, 0x71, 0x64,
    0xe4, 0xf5, 0x9d, 0x0a, 0x7c, 0x7b, 0x67, 0xc2,
]);

// -----------------------------------------------------------------------------
// Chain specification identity
// -----------------------------------------------------------------------------

/// Incremented whenever a consensus-critical field in [`ChainSpecIdentity`]
/// changes.
pub const CHAIN_SPEC_VERSION: u32 = 1;

#[derive(BorshSerialize)]
struct ChainSpecIdentity<'a> {
    version: u32,

    // Genesis
    genesis_hash: [u8; HASH_SIZE],

    // Proof of work
    pow_algorithm: &'a str,
    pow_memory_kib: u32,
    pow_iterations: u32,
    pow_lanes: u32,

    difficulty_algorithm: &'a str,
    difficulty_start: u32,
    min_difficulty: u32,
    max_difficulty: u32,
    
    wbda_window: u64,
    wbda_target_block_weight: u64,
    wbda_low_utilization_ppm: u64,
    wbda_high_utilization_ppm: u64,
    wbda_difficulty_step: u32,

    // Monetary policy
    block_emission_start: u64,
    block_emission_step: u64,
    emission_interval: u64,
    tail_block_emission: u64,

    // Protocol burn
    state_burn_algorithm: &'a str,
    state_burn_rate_zeno_per_weight: u64,
    block_state_weight: u64,
    coin_utxo_state_weight: u64,

    // Block / address / hash
    max_block_size: u64,
    address_size: u32,
    address_encoding: &'a str,
    hash_size: u32,

    // Fork choice
    fork_choice_algorithm: &'a str,

    // Signature activation
    falcon_512_activation_height: u64,
    signature_profile_activation_height: u64,

    // Native protocol identity
    native_asset_program: &'a str,
    transaction_format: &'a str,
}

/// Domain-separated identity of every consensus parameter that nodes must
/// agree on.
pub fn chain_spec_hash() -> Result<Hash, GenesisError> {
    let identity = ChainSpecIdentity {
        version: CHAIN_SPEC_VERSION,

        genesis_hash: EXPECTED_GENESIS_HASH.into_bytes(),

        // Proof of work
        pow_algorithm: POW_ALGORITHM,
        pow_memory_kib: POW_ARGON2_MEMORY_KIB,
        pow_iterations: POW_ARGON2_ITERATIONS,
        pow_lanes: POW_ARGON2_LANES,

        // Difficulty / WBDA
        difficulty_algorithm: DIFFICULTY_ALGORITHM,
        difficulty_start: DIFFICULTY_START,
        min_difficulty: MIN_DIFFICULTY,
        max_difficulty: MAX_DIFFICULTY,

        wbda_window: WBDA_WINDOW as u64,
        wbda_target_block_weight: WBDA_TARGET_BLOCK_WEIGHT as u64,
        wbda_low_utilization_ppm: WBDA_LOW_UTILIZATION_PPM,
        wbda_high_utilization_ppm: WBDA_HIGH_UTILIZATION_PPM,
        wbda_difficulty_step: WBDA_DIFFICULTY_STEP,

        // Emission
        block_emission_start: BLOCK_EMISSION_START,
        block_emission_step: BLOCK_EMISSION_STEP,
        emission_interval: EMISSION_INTERVAL,
        tail_block_emission: TAIL_BLOCK_EMISSION,

        // Protocol burn
        state_burn_algorithm: STATE_BURN_ALGORITHM,
        state_burn_rate_zeno_per_weight:
            STATE_BURN_RATE_ZENO_PER_WEIGHT,
        block_state_weight: EMPTY_BLOCK_ARCHIVAL_BYTES,
        coin_utxo_state_weight: COIN_UTXO_STATE_WEIGHT,

        // Block / address / hash
        max_block_size: MAX_BLOCK_SIZE as u64,
        address_size: ADDRESS_SIZE as u32,
        address_encoding: "xparq-0x-sha3-checksum",
        hash_size: HASH_SIZE as u32,

        // Fork choice
        fork_choice_algorithm: FORK_CHOICE_ALGORITHM,

        // Signature activation
        falcon_512_activation_height:
            FALCON_512_ACTIVATION_HEIGHT,
        signature_profile_activation_height:
            SIGNATURE_ACTIVATION_HEIGHT,

        // Native protocol identity
        native_asset_program: "xparq-native-asset-program",
        transaction_format: "direct-authorized-v1",
    };

    let bytes =
        crypto::canonical_bytes(&identity)
            .map_err(GenesisError::Encoding)?;

    Ok(domain_hash(HashDomain::ChainSpec, &bytes))
}

// -----------------------------------------------------------------------------
// Genesis
// -----------------------------------------------------------------------------

pub fn genesis_block() -> Result<Block, GenesisError> {
    let mut block =
        Block::genesis().map_err(GenesisError::Encoding)?;

    block.header.nonce = Nonce(GENESIS_NONCE);

    if block.hash().map_err(GenesisError::Encoding)?
        != EXPECTED_GENESIS_HASH
    {
        return Err(GenesisError::HashMismatch);
    }

    Ok(block)
}

pub fn genesis_hash() -> Result<BlockHash, GenesisError> {
    genesis_block()?
        .hash()
        .map_err(GenesisError::Encoding)
}

pub fn chain_context() -> Result<ChainContext, GenesisError> {
    Ok(ChainContext::new(
        genesis_hash()?.into_bytes(),
    ))
}

pub fn genesis_ledger() -> Result<Ledger, GenesisError> {
    let mut ledger = Ledger::new();
    let block = genesis_block()?;

    crate::consensus::apply_genesis(
        &mut ledger,
        block,
        EXPECTED_GENESIS_HASH,
    )
    .map_err(GenesisError::Ledger)?;

    Ok(ledger)
}

pub fn create_genesis_block() -> Result<Block, GenesisError> {
    genesis_block()
}

pub fn create_genesis_ledger() -> Result<Ledger, GenesisError> {
    genesis_ledger()
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

#[derive(Debug)]
pub enum GenesisError {
    Encoding(crypto::CodecError),
    HashMismatch,
    Ledger(LedgerError),
}

impl fmt::Display for GenesisError {
    fn fmt(
        &self,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        match self {
            Self::Encoding(error) => {
                write!(
                    formatter,
                    "genesis encoding failed: {error}"
                )
            }

            Self::HashMismatch => {
                formatter.write_str(
                    "constructed genesis does not match frozen chain identity",
                )
            }

            Self::Ledger(error) => {
                write!(
                    formatter,
                    "genesis ledger failed: {error}"
                )
            }
        }
    }
}

impl Error for GenesisError {}