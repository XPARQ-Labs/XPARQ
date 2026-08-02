//! Weight-Based Difficulty Adjustment (WBDA).
//!
//! WBDA adjusts proof-of-work difficulty from recent block-weight utilization,
//! not from elapsed block time. The selected window and utilization thresholds
//! are consensus parameters: changing any of them changes the expected
//! difficulty schedule for the chain.

use crate::block::MAX_BLOCK_WEIGHT;

use super::MIN_DIFFICULTY;

/// Fixed number of completed blocks sampled for one WBDA epoch.
pub const WBDA_WINDOW: usize = 2048;

/// Utilization below 20% raises difficulty by one discrete unit.
pub const WBDA_LOW_UTILIZATION_PPM: u64 = 200_000;

/// Utilization above 80% lowers difficulty by one discrete unit.
pub const WBDA_HIGH_UTILIZATION_PPM: u64 = 800_000;

/// One WBDA step changes the integer difficulty by exactly one unit.
pub const WBDA_DIFFICULTY_STEP: u32 = 1;

pub const WBDA_ALGORITHM: &str = "argon2id-wbda-weight-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WbdaAdjustment {
    Decrease,
    Keep,
    Increase,
}

impl WbdaAdjustment {
    pub const fn delta(self) -> i8 {
        match self {
            Self::Decrease => -1,
            Self::Keep => 0,
            Self::Increase => 1,
        }
    }
}

/// Returns true when `height` is the first block of a new WBDA epoch.
pub const fn is_wbda_epoch_boundary(height: u64) -> bool {
    height != 0 && height.is_multiple_of(WBDA_WINDOW as u64)
}

/// Average block weight for the supplied completed window.
pub fn average_block_weight(block_weights: &[usize]) -> Option<u64> {
    if block_weights.len() != WBDA_WINDOW {
        return None;
    }

    let total = block_weights
        .iter()
        .try_fold(0u128, |total, weight| total.checked_add(*weight as u128))?;
    Some((total / WBDA_WINDOW as u128) as u64)
}

/// Utilization in parts-per-million, based on average weight over one window.
pub fn utilization_ppm(block_weights: &[usize]) -> Option<u64> {
    let average = average_block_weight(block_weights)? as u128;
    let max_weight = MAX_BLOCK_WEIGHT as u128;
    if max_weight == 0 {
        return None;
    }

    Some(((average.saturating_mul(1_000_000)) / max_weight) as u64)
}

pub fn adjustment_for_utilization_ppm(utilization_ppm: u64) -> WbdaAdjustment {
    if utilization_ppm < WBDA_LOW_UTILIZATION_PPM {
        WbdaAdjustment::Increase
    } else if utilization_ppm > WBDA_HIGH_UTILIZATION_PPM {
        WbdaAdjustment::Decrease
    } else {
        WbdaAdjustment::Keep
    }
}

pub fn adjustment_for_window(block_weights: &[usize]) -> Option<WbdaAdjustment> {
    utilization_ppm(block_weights).map(adjustment_for_utilization_ppm)
}

/// Applies WBDA to the previous difficulty when a complete window is available.
pub fn next_difficulty_from_window(
    previous_difficulty: u32,
    block_weights: &[usize],
) -> Option<u32> {
    let adjustment = adjustment_for_window(block_weights)?;
    Some(
        match adjustment {
            WbdaAdjustment::Decrease => previous_difficulty.saturating_sub(WBDA_DIFFICULTY_STEP),
            WbdaAdjustment::Keep => previous_difficulty,
            WbdaAdjustment::Increase => previous_difficulty.saturating_add(WBDA_DIFFICULTY_STEP),
        }
        .max(MIN_DIFFICULTY),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(weight: usize) -> Vec<usize> {
        vec![weight; WBDA_WINDOW]
    }

    #[test]
    fn requires_exact_window() {
        assert_eq!(average_block_weight(&window(1)), Some(1));
        assert_eq!(average_block_weight(&window(1)[..WBDA_WINDOW - 1]), None);
    }

    #[test]
    fn thresholds_are_exclusive_edges() {
        assert_eq!(
            adjustment_for_utilization_ppm(WBDA_LOW_UTILIZATION_PPM - 1),
            WbdaAdjustment::Increase
        );
        assert_eq!(
            adjustment_for_utilization_ppm(WBDA_LOW_UTILIZATION_PPM),
            WbdaAdjustment::Keep
        );
        assert_eq!(
            adjustment_for_utilization_ppm(WBDA_HIGH_UTILIZATION_PPM),
            WbdaAdjustment::Keep
        );
        assert_eq!(
            adjustment_for_utilization_ppm(WBDA_HIGH_UTILIZATION_PPM + 1),
            WbdaAdjustment::Decrease
        );
    }

    #[test]
    fn adjusts_by_one_discrete_step() {
        assert_eq!(
            next_difficulty_from_window(7, &window(MAX_BLOCK_WEIGHT / 10)),
            Some(8)
        );
        assert_eq!(
            next_difficulty_from_window(7, &window(MAX_BLOCK_WEIGHT / 2)),
            Some(7)
        );
        assert_eq!(
            next_difficulty_from_window(7, &window(MAX_BLOCK_WEIGHT)),
            Some(6)
        );
    }

    #[test]
    fn high_utilization_decrease_clamps_at_minimum_difficulty() {
        assert_eq!(
            next_difficulty_from_window(MIN_DIFFICULTY, &window(MAX_BLOCK_WEIGHT)),
            Some(MIN_DIFFICULTY)
        );
    }

    #[test]
    fn epoch_boundaries_follow_locked_window() {
        assert!(!is_wbda_epoch_boundary(0));
        assert!(!is_wbda_epoch_boundary(WBDA_WINDOW as u64 - 1));
        assert!(is_wbda_epoch_boundary(WBDA_WINDOW as u64));
        assert!(is_wbda_epoch_boundary((WBDA_WINDOW * 2) as u64));
    }
}
