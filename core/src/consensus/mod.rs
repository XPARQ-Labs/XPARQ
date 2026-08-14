#![allow(clippy::module_inception)]

pub mod consensus;
pub mod pow;
pub mod supply;
pub mod wbda;

pub use crate::error::ConsensusError;
pub use consensus::{
    Consensus, ConsensusConfig, DIFFICULTY_START, GENESIS_DIFFICULTY, MAX_DIFFICULTY,
    MIN_DIFFICULTY,
};
pub use pow::{
    POW_ALGORITHM, calculate_work, calculate_work_with_memory, pow_salt, pow_seed, verify_pow,
};
pub use supply::{
    BASE_BLOCK_REWARD, BLOCK_REWARD_STEP, MAX_BLOCK_REWARD, MIN_BLOCK_REWARD, base_block_reward,
};
pub use wbda::{
    WBDA_ALGORITHM, WBDA_ALGORITHM as DIFFICULTY_ALGORITHM, WBDA_DIFFICULTY_STEP,
    WBDA_HIGH_UTILIZATION_PPM, WBDA_LOW_UTILIZATION_PPM, WBDA_TARGET_BLOCK_WEIGHT, WBDA_WINDOW,
    WbdaAdjustment, adjustment_for_utilization_ppm, adjustment_for_window, average_block_weight,
    is_wbda_epoch_boundary, next_difficulty_from_window, next_reward_from_window, utilization_ppm,
};
