//! Weight-Based Difficulty Adjustment (WBDA).
//!
//! WBDA adjusts proof-of-work difficulty from recent block-weight utilization,
//! not from elapsed block time. The selected window and utilization thresholds
//! are consensus parameters: changing any of them changes the expected
//! difficulty schedule for the chain.

#[cfg(test)]
use crate::block::MAX_BLOCK_WEIGHT;

use super::supply::{Amount, BLOCK_REWARD_STEP, MAX_BLOCK_REWARD, MIN_BLOCK_REWARD};
use super::{MAX_DIFFICULTY, MIN_DIFFICULTY};

/// Fixed number of completed blocks sampled for one WBDA epoch.
pub const WBDA_WINDOW: usize = 4100;

/// Fixed average block-weight target used to calculate epoch utilization.
pub const WBDA_TARGET_BLOCK_WEIGHT: usize = 5 * 1024 * 1024;

/// Utilization below 40% raises difficulty by one discrete unit.
pub const WBDA_LOW_UTILIZATION_PPM: u64 = 400_000;

/// Utilization above 60% lowers difficulty by one discrete unit.
pub const WBDA_HIGH_UTILIZATION_PPM: u64 = 600_000;

/// One WBDA step changes the integer difficulty by exactly one unit.
pub const WBDA_DIFFICULTY_STEP: u32 = 1;

pub const WBDA_ALGORITHM: &str = "argon2id-wbda-weight-reward-half-xpq-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WbdaAdjustment {
    Decrease,
    Keep,
    Increase,
}

/// Returns true when `height` is the first block of a new WBDA epoch.
pub const fn is_wbda_epoch_boundary(height: u64) -> bool {
    height > 1 && (height - 1).is_multiple_of(WBDA_WINDOW as u64)
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
    let target_weight = WBDA_TARGET_BLOCK_WEIGHT as u128;
    if target_weight == 0 {
        return None;
    }

    Some(((average.saturating_mul(1_000_000)) / target_weight) as u64)
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
        .clamp(MIN_DIFFICULTY, MAX_DIFFICULTY),
    )
}

/// Applies the same completed-epoch utilization signal to the block reward.
/// Sparse epochs increase the reward, normal epochs keep it, and dense epochs
/// decrease it. The result is bounded by the monetary-policy limits.
pub fn next_reward_from_window(previous_reward: Amount, block_weights: &[usize]) -> Option<Amount> {
    let adjustment = adjustment_for_window(block_weights)?;
    let reward = match adjustment {
        WbdaAdjustment::Decrease => previous_reward.0.saturating_sub(BLOCK_REWARD_STEP),
        WbdaAdjustment::Keep => previous_reward.0,
        WbdaAdjustment::Increase => previous_reward.0.saturating_add(BLOCK_REWARD_STEP),
    };
    Some(Amount(reward.clamp(MIN_BLOCK_REWARD, MAX_BLOCK_REWARD)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(weight: usize) -> Vec<usize> {
        vec![weight; WBDA_WINDOW]
    }

    #[test]
    fn locks_five_mib_target_and_forty_sixty_zone() {
        assert_eq!(WBDA_TARGET_BLOCK_WEIGHT, 5 * 1024 * 1024);
        assert_eq!(MAX_BLOCK_WEIGHT, WBDA_TARGET_BLOCK_WEIGHT);
        assert_eq!(WBDA_LOW_UTILIZATION_PPM, 400_000);
        assert_eq!(WBDA_HIGH_UTILIZATION_PPM, 600_000);
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
    fn reward_tracks_the_same_epoch_signal_with_bounds() {
        use crate::consensus::supply::{BASE_BLOCK_REWARD, MAX_BLOCK_REWARD, MIN_BLOCK_REWARD};

        assert_eq!(
            next_reward_from_window(Amount(BASE_BLOCK_REWARD), &window(MAX_BLOCK_WEIGHT / 2)),
            Some(Amount(BASE_BLOCK_REWARD))
        );
        assert_eq!(
            next_reward_from_window(Amount(BASE_BLOCK_REWARD), &window(MAX_BLOCK_WEIGHT)),
            Some(Amount(BASE_BLOCK_REWARD - BLOCK_REWARD_STEP))
        );
        assert_eq!(
            next_reward_from_window(Amount(MAX_BLOCK_REWARD), &window(MAX_BLOCK_WEIGHT / 10)),
            Some(Amount(MAX_BLOCK_REWARD))
        );
        assert_eq!(
            next_reward_from_window(Amount(MIN_BLOCK_REWARD), &window(MAX_BLOCK_WEIGHT)),
            Some(Amount(MIN_BLOCK_REWARD))
        );
    }

    #[test]
    fn prior_epoch_controls_the_following_epoch() {
        let mut difficulty = 7;
        let mut reward = Amount(crate::consensus::supply::BASE_BLOCK_REWARD);

        // Epoch 1 averages 2.5 MiB, exactly 50% of the fixed 5 MiB target.
        let half_full = window(MAX_BLOCK_WEIGHT / 2);
        difficulty = next_difficulty_from_window(difficulty, &half_full).unwrap();
        reward = next_reward_from_window(reward, &half_full).unwrap();
        assert_eq!(difficulty, 7);
        assert_eq!(reward, Amount(5 * crate::consensus::supply::XPQ));

        // Epoch 2 averages 5 MiB (100%), so epoch 3 is easier and pays less.
        let full = window(MAX_BLOCK_WEIGHT);
        difficulty = next_difficulty_from_window(difficulty, &full).unwrap();
        reward = next_reward_from_window(reward, &full).unwrap();
        assert_eq!(difficulty, 6);
        assert_eq!(
            reward,
            Amount(
                crate::consensus::supply::BASE_BLOCK_REWARD
                    - crate::consensus::supply::BLOCK_REWARD_STEP
            )
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
    fn low_utilization_increase_clamps_at_pow_width() {
        assert_eq!(
            next_difficulty_from_window(MAX_DIFFICULTY, &window(0)),
            Some(MAX_DIFFICULTY)
        );
    }

    #[test]
    fn epoch_boundaries_follow_locked_window() {
        assert!(!is_wbda_epoch_boundary(0));
        assert!(!is_wbda_epoch_boundary(1));
        assert!(!is_wbda_epoch_boundary(WBDA_WINDOW as u64));
        assert!(is_wbda_epoch_boundary(WBDA_WINDOW as u64 + 1));
        assert!(is_wbda_epoch_boundary((WBDA_WINDOW * 2) as u64 + 1));
    }
}
