#[allow(clippy::module_inception)] // Preserve the established public module path.
pub mod miner;

pub use miner::{
    MiningConfig, MiningResult, mine_candidate_block, mine_prepared_block_until_with_attempts,
    prepare_candidate_block,
};
