use crate::runtime::mempool::Mempool;
use xparq::block::{Block, BlockError, CoinbaseTransaction, Nonce};
use xparq::consensus::{Consensus, ConsensusError};
use xparq::crypto::Address;
use xparq::genesis::GenesisError;
use xparq::genesis::create_genesis_block;
use xparq::ledger::{Ledger, LedgerError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MiningConfig {
    pub difficulty: u32,
    pub start_nonce: u64,
    pub max_attempts: u64,
    pub transaction_limit: usize,
    pub min_fee_rate: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MiningResult {
    pub block: Block,
    pub attempts: u64,
}

pub fn mine_candidate_block(
    mempool: &Mempool,
    ledger: &Ledger,
    consensus: &Consensus,
    miner_address: Address,
    _timestamp: u64,
    config: MiningConfig,
) -> Result<Option<MiningResult>, ConsensusError> {
    let block = prepare_candidate_block(
        mempool,
        ledger,
        miner_address,
        _timestamp,
        config.transaction_limit,
        config.min_fee_rate,
        config.difficulty,
    )?;
    mine_prepared_block(block, consensus, config)
}

#[allow(clippy::too_many_arguments)] // Consensus candidate inputs are explicit at this boundary.
pub fn prepare_candidate_block(
    mempool: &Mempool,
    ledger: &Ledger,
    miner_address: Address,
    _timestamp: u64,
    transaction_limit: usize,
    min_fee_rate: u64,
    difficulty: u32,
) -> Result<Block, ConsensusError> {
    if ledger.tip_height().is_none() {
        let mut genesis = create_genesis_block().map_err(genesis_to_consensus_error)?;
        genesis.header.difficulty = difficulty;
        return Ok(genesis);
    }
    let height = ledger
        .tip_height()
        .map(|height| xparq::block::Height(height.0.saturating_add(1)))
        .ok_or(ConsensusError::InvalidHeight)?;
    let previous_hash = ledger
        .tip_hash()
        .ok_or(ConsensusError::InvalidPreviousHash)?;
    let subsidy = ledger
        .mintable_subsidy(height)
        .map_err(|_| ConsensusError::InvalidBlock(BlockError::InvalidEmission))?;
    let coinbase = CoinbaseTransaction::new(miner_address, subsidy);
    let mut block = Block::from_protocol_transactions(
        height,
        previous_hash,
        difficulty,
        Nonce(0),
        Some(coinbase),
        Vec::new(),
    )?;
    mempool
        .append_selected_to_block(ledger, &mut block, transaction_limit, min_fee_rate)
        .map_err(|error| match error {
            crate::runtime::mempool::MempoolError::Serialization(_) => {
                ConsensusError::InvalidBlock(xparq::error::BlockError::InvalidTransaction)
            }
            _ => ConsensusError::InvalidBlock(xparq::error::BlockError::InvalidTransaction),
        })?;
    block.header.difficulty = difficulty;
    block.set_state_root(xparq::crypto::StateRoot::ZERO);
    let execution = ledger
        .preview_candidate_block(&block)
        .map_err(ledger_to_consensus_error)?;
    block.set_state_root(execution.state_root_after);
    Ok(block)
}

fn ledger_to_consensus_error(error: LedgerError) -> ConsensusError {
    match error {
        LedgerError::InvalidConsensus(error) => error,
        LedgerError::InvalidBlock(error) => ConsensusError::InvalidBlock(error),
        LedgerError::InvalidBlockHeight => ConsensusError::InvalidHeight,
        LedgerError::InvalidPreviousHash | LedgerError::InvalidParent => {
            ConsensusError::InvalidPreviousHash
        }
        LedgerError::InvalidStateRoot => {
            ConsensusError::InvalidBlock(xparq::block::BlockError::InvalidStateRoot)
        }
        _ => ConsensusError::InvalidBlock(xparq::block::BlockError::InvalidStateRoot),
    }
}

fn genesis_to_consensus_error(error: GenesisError) -> ConsensusError {
    match error {
        GenesisError::Codec(error) => ConsensusError::Serialization(error),
        GenesisError::Ledger(error) => ledger_to_consensus_error(error),
        _ => ConsensusError::InvalidBlock(xparq::error::BlockError::InvalidTransaction),
    }
}

pub fn mine_prepared_block(
    block: Block,
    consensus: &Consensus,
    config: MiningConfig,
) -> Result<Option<MiningResult>, ConsensusError> {
    mine_prepared_block_until(block, consensus, config, || false)
}

pub fn mine_prepared_block_until(
    block: Block,
    consensus: &Consensus,
    config: MiningConfig,
    should_stop: impl Fn() -> bool,
) -> Result<Option<MiningResult>, ConsensusError> {
    mine_prepared_block_until_with_attempts(block, consensus, config, should_stop)
        .map(|(result, _attempts)| result)
}

pub fn mine_prepared_block_until_with_attempts(
    mut block: Block,
    consensus: &Consensus,
    config: MiningConfig,
    should_stop: impl Fn() -> bool,
) -> Result<(Option<MiningResult>, u64), ConsensusError> {
    let max_attempts = if config.max_attempts == 0 {
        u64::MAX
    } else {
        config.max_attempts
    };
    for attempt in 0..max_attempts {
        if attempt % 1024 == 0 && should_stop() {
            return Ok((None, attempt));
        }
        block.header.nonce = Nonce(config.start_nonce.wrapping_add(attempt));
        if config.difficulty == 0 {
            let attempts = attempt.saturating_add(1);
            return Ok((Some(MiningResult { block, attempts }), attempts));
        }

        let hash = consensus.pow_hash(&block)?;
        if consensus
            .validate_pow_hash_with_difficulty(&hash, config.difficulty)
            .is_ok()
        {
            let attempts = attempt.saturating_add(1);
            return Ok((Some(MiningResult { block, attempts }), attempts));
        }
    }

    Ok((None, max_attempts))
}
