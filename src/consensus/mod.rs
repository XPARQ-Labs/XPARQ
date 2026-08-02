#![allow(clippy::module_inception)]

pub mod consensus;
pub mod supply;
pub mod wbda;

pub use crate::error::ConsensusError;
pub use consensus::{
    Consensus, ConsensusConfig, DIFFICULTY_START, GENESIS_DIFFICULTY, MIN_DIFFICULTY,
};
pub use supply::{TAIL_EMISSION_START_HEIGHT, block_reward, tail_emission_start_height};
pub use wbda::{
    WBDA_ALGORITHM, WBDA_ALGORITHM as DIFFICULTY_ALGORITHM, WBDA_DIFFICULTY_STEP,
    WBDA_HIGH_UTILIZATION_PPM, WBDA_LOW_UTILIZATION_PPM, WBDA_WINDOW, WbdaAdjustment,
    adjustment_for_utilization_ppm, adjustment_for_window, average_block_weight,
    is_wbda_epoch_boundary, next_difficulty_from_window, utilization_ppm,
};
