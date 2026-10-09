//! Construction and identity of the canonical chain root.

use std::{error::Error, fmt};

use crate::{
    blockchain::{Block, GENESIS_TARGET_BITS, MAX_BLOCK_OPERATIONS, MAX_BLOCK_SIZE},
    common::ChainContext,
    common::Nonce,
    consensus::{
        BLOCK_EMISSION_START, COIN_UTXO_STATE_WEIGHT, DIFFICULTY_ALGORITHM, EMISSION_INTERVAL,
        EMISSION_RISING_STEPS, EMPTY_BLOCK_ARCHIVAL_BYTES, POW_ALGORITHM, POW_ARGON2_ITERATIONS,
        POW_ARGON2_LANES, POW_ARGON2_MEMORY_KIB, STATE_BURN_ALGORITHM,
        STATE_BURN_RATE_ZENO_PER_BYTE, TAIL_BLOCK_EMISSION, TARGET_BITS_START,
        WBDA_HIGH_UTILIZATION_PPM, WBDA_LOW_UTILIZATION_PPM, WBDA_TARGET_BLOCK_WEIGHT, WBDA_WINDOW,
    },
    ledger::{Ledger, LedgerError},
    monetary::coin::CoinContract,
    program::{MAX_PROGRAM_INVOCATION_SIZE, MAX_PROGRAM_ITEMS},
};

use borsh::BorshSerialize;

use crypto::{BlockHash, HASH_SIZE, Hash, HashDomain, PROGRAM_ID_SIZE, domain};

// -----------------------------------------------------------------------------
// Mainnet
// -----------------------------------------------------------------------------

#[cfg(feature = "mainnet")]
pub const GENESIS_NONCE: u64 = 4;

#[cfg(feature = "mainnet")]
pub const EXPECTED_GENESIS_HASH: BlockHash = BlockHash([
    0xd4, 0x09, 0x63, 0xc3, 0x68, 0x81, 0x4a, 0xb2, 0x23, 0x10, 0x57, 0xea, 0xc0, 0x4c, 0xe2, 0xa9,
    0xbb, 0x78, 0x24, 0xac, 0xb9, 0xf6, 0xba, 0x91, 0xed, 0x77, 0xe8, 0x83, 0xb3, 0xea, 0xbc, 0xc5,
]);

// -----------------------------------------------------------------------------
// Testnet
// -----------------------------------------------------------------------------

#[cfg(feature = "testnet")]
pub const GENESIS_NONCE: u64 = 5;

#[cfg(feature = "testnet")]
pub const EXPECTED_GENESIS_HASH: BlockHash = BlockHash([
    0xed, 0x1b, 0x1e, 0x5d, 0x6d, 0x0b, 0x34, 0xd2, 0x58, 0xb9, 0x25, 0x18, 0x66, 0x51, 0x63, 0xc1,
    0xb1, 0x23, 0xb8, 0xc7, 0xdb, 0x33, 0x4a, 0x8d, 0x0b, 0x3b, 0x81, 0x3e, 0xcb, 0x21, 0xa2, 0x44,
]);

// -----------------------------------------------------------------------------
// Devnet
// -----------------------------------------------------------------------------

#[cfg(feature = "devnet")]
pub const GENESIS_NONCE: u64 = 6;

#[cfg(feature = "devnet")]
pub const EXPECTED_GENESIS_HASH: BlockHash = BlockHash([
    0x15, 0xae, 0x31, 0x7b, 0x08, 0xe1, 0xa1, 0x73, 0x91, 0xd1, 0x8d, 0x48, 0x1e, 0xc0, 0x0d, 0x3d,
    0x84, 0xbf, 0x4e, 0x1c, 0xfa, 0x82, 0xa7, 0x8a, 0xef, 0xda, 0x80, 0x6d, 0x8a, 0x7a, 0x6a, 0x54,
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

    target_algorithm: &'a str,
    genesis_target_bits: u32,
    target_bits_start: u32,

    wbda_window: u64,
    wbda_target_block_weight: u64,
    wbda_low_utilization_ppm: u64,
    wbda_high_utilization_ppm: u64,

    // Monetary policy
    block_emission_start: u64,
    emission_rising_steps: u64,
    emission_interval: u64,
    tail_block_emission: u64,

    // Protocol burn
    state_burn_algorithm: &'a str,
    state_burn_rate_zeno_per_weight: u64,
    block_state_weight: u64,
    coin_utxo_state_weight: u64,

    // Block / program_id / hash
    max_block_size: u64,
    max_block_transactions: u64,
    max_transaction_size: u64,
    max_transaction_items: u64,
    block_accounting_rule: &'a str,
    program_id_size: u32,
    program_id_encoding: &'a str,
    hash_size: u32,

    // Native protocol identity
    native_coin_contract: [u8; HASH_SIZE],
    extension_asset_program: &'a str,
    transaction_format: &'a str,
    ownership_model: &'a str,
    account_signature_schemes: [u8; 6],
    slh_signature_profile: &'a str,
    monetary_call_format: &'a str,
    application_state_format: &'a str,
    vm_bytecode_format: &'a str,
    max_vm_code_size: u64,
    max_vm_stack_items: u16,
    max_vm_memory_pages: u16,
    vm_application_limits: [u64; 11],
    vm_call_format: &'a str,
    vm_instruction_cost: u64,
    vm_memory_page_cost: u64,
    vm_state_read_cost: u64,
    vm_state_write_cost: u64,
    vm_transfer_cost: u64,
    vm_asset_register_cost: u64,
    vm_asset_mint_cost: u64,
    max_vm_transfer_inputs: u64,
    max_vm_call_fuel: u64,
    program_instance_derivation: &'a str,
    deploy_authorization: &'a str,
    deploy_burn_rule: &'a str,
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
        target_algorithm: DIFFICULTY_ALGORITHM,
        genesis_target_bits: GENESIS_TARGET_BITS,
        target_bits_start: TARGET_BITS_START,

        wbda_window: WBDA_WINDOW as u64,
        wbda_target_block_weight: WBDA_TARGET_BLOCK_WEIGHT as u64,
        wbda_low_utilization_ppm: WBDA_LOW_UTILIZATION_PPM,
        wbda_high_utilization_ppm: WBDA_HIGH_UTILIZATION_PPM,

        // Emission
        block_emission_start: BLOCK_EMISSION_START,
        emission_rising_steps: EMISSION_RISING_STEPS,
        emission_interval: EMISSION_INTERVAL,
        tail_block_emission: TAIL_BLOCK_EMISSION,

        // Protocol burn
        state_burn_algorithm: STATE_BURN_ALGORITHM,
        state_burn_rate_zeno_per_weight: STATE_BURN_RATE_ZENO_PER_BYTE,
        block_state_weight: EMPTY_BLOCK_ARCHIVAL_BYTES,
        coin_utxo_state_weight: COIN_UTXO_STATE_WEIGHT,

        // Block / program_id / hash
        max_block_size: MAX_BLOCK_SIZE as u64,
        max_block_transactions: MAX_BLOCK_OPERATIONS as u64,
        max_transaction_size: MAX_PROGRAM_INVOCATION_SIZE as u64,
        max_transaction_items: MAX_PROGRAM_ITEMS as u64,
        block_accounting_rule: "coin-utxo-delta-v1",
        program_id_size: PROGRAM_ID_SIZE as u32,
        program_id_encoding: "program-id-32-byte-hex-64",
        hash_size: HASH_SIZE as u32,

        // Native protocol identity
        native_coin_contract: CoinContract::derive().into_bytes(),
        extension_asset_program: "xparq-unified-monetary-program-v1",
        transaction_format: "program-id-salted-signature-proof-payment-and-monetary-v3",
        account_signature_schemes: crypto::AccountSignatureScheme::ALL.map(|s| s.id()),
        slh_signature_profile: "fips205-pure-shake-s-empty-context-deterministic-wallet-seed32-shake256-XPARQ_SLH_DSA_KEYGEN_V1-scheme-seed",
        ownership_model: "program-only-tag0-signature-policy-v2-scheme-key-salt32-v3",
        monetary_call_format: "route0-transfer1-create2-mint3-burn4-currency0coin1asset-denycoinburn-legacyassetroute1",
        application_state_format: "program-owned-coin-asset-share32-and-versioned-program-kv-state-v5",
        vm_bytecode_format: "xpvm-v1-v2-v3-v4-typed-applications-metered-calls-v1",
        max_vm_code_size: crate::program::MAX_PROGRAM_CODE_SIZE as u64,
        max_vm_stack_items: crate::program::vm::MAX_STACK_ITEMS,
        max_vm_memory_pages: crate::program::vm::MAX_MEMORY_PAGES,
        vm_application_limits: [
            crate::program::vm_app::MAX_DATA_BYTES as u64,
            crate::program::vm_app::MAX_KEY_BYTES as u64,
            crate::program::vm_app::MAX_STORAGE_ENTRIES as u64,
            crate::program::vm_app::MAX_STORAGE_BYTES as u64,
            crate::program::vm_app::MAX_CALL_DEPTH as u64,
            crate::program::vm_app::MAX_CALLS as u64,
            crate::program::vm_app::MAX_ACTIONS as u64,
            crate::program::vm_app::CALL_COST,
            crate::program::vm::APPLICATION_VERSION as u64,
            crate::program::vm_app::MAX_CODE_BYTES as u64,
            crate::program::vm_app::MAX_INSTRUCTIONS as u64,
        ],
        vm_call_format: "program-id-2-opcode-0-id-or-opcode-1-id-data-v2",
        vm_instruction_cost: crate::program::vm::INSTRUCTION_COST,
        vm_memory_page_cost: crate::program::vm::MEMORY_PAGE_COST,
        vm_state_read_cost: crate::program::vm::STATE_READ_COST,
        vm_state_write_cost: crate::program::vm::STATE_WRITE_COST,
        vm_transfer_cost: crate::program::vm::TRANSFER_COST,
        vm_asset_register_cost: crate::program::vm::ASSET_REGISTER_COST,
        vm_asset_mint_cost: crate::program::vm::ASSET_MINT_COST,
        max_vm_transfer_inputs: crate::program::vm_transfer::MAX_TRANSFER_INPUTS as u64,
        max_vm_call_fuel: crate::program::vm::MAX_CALL_FUEL,
        program_instance_derivation: "xparq:program-id:v2-program-principal-nonce-code-hash",
        deploy_authorization: "xparq:deploy-program:v1",
        deploy_burn_rule: "operation-bytes-plus-registry-growth-v1",
    };

    let bytes = crypto::canonical_bytes(&identity).map_err(GenesisError::Encoding)?;

    Ok(domain(HashDomain::ChainSpec, &bytes))
}

#[cfg(all(test, feature = "mainnet"))]
mod phase3_chain_spec_tests {
    #[test]
    fn bounded_work_rules_have_frozen_mainnet_chain_spec_identity() {
        assert_eq!(super::CHAIN_SPEC_VERSION, 1);
        assert_eq!(
            super::chain_spec_hash().unwrap().into_bytes(),
            [
                214, 203, 93, 185, 196, 175, 20, 63, 33, 123, 83, 191, 223, 186, 224, 48, 31, 241,
                100, 123, 18, 122, 225, 238, 182, 156, 145, 113, 207, 102, 7, 188
            ]
        );
    }
}

// -----------------------------------------------------------------------------
// Genesis
// -----------------------------------------------------------------------------

pub fn genesis_block() -> Result<Block, GenesisError> {
    let mut block = Block::genesis().map_err(GenesisError::Encoding)?;

    block.header.nonce = Nonce(GENESIS_NONCE);

    if block.hash().map_err(GenesisError::Encoding)? != EXPECTED_GENESIS_HASH {
        return Err(GenesisError::HashMismatch);
    }

    Ok(block)
}

pub fn genesis_hash() -> Result<BlockHash, GenesisError> {
    genesis_block()?.hash().map_err(GenesisError::Encoding)
}

pub fn chain_context() -> Result<ChainContext, GenesisError> {
    Ok(ChainContext::new(genesis_hash()?.into_bytes()))
}

pub fn genesis_ledger() -> Result<Ledger, GenesisError> {
    let mut ledger = Ledger::new();
    let block = genesis_block()?;

    crate::consensus::apply_genesis(&mut ledger, block, EXPECTED_GENESIS_HASH)
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
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(error) => {
                write!(formatter, "genesis encoding failed: {error}")
            }

            Self::HashMismatch => {
                formatter.write_str("constructed genesis does not match frozen chain identity")
            }

            Self::Ledger(error) => {
                write!(formatter, "genesis ledger failed: {error}")
            }
        }
    }
}

impl Error for GenesisError {}
