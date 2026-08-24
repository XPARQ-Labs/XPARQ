//! Weight-Based Difficulty Adjustment (WBDA).
//!
//! WBDA adjusts proof-of-work difficulty from recent block-weight utilization,
//! not from elapsed block time. The selected window and utilization thresholds
//! are consensus parameters: changing any of them changes the expected
//! difficulty schedule for the chain.

#[cfg(test)]
use crate::block::MAX_BLOCK_WEIGHT;

use super::emission::{BLOCK_EMISSION_STEP, MAX_BLOCK_EMISSION, MIN_BLOCK_EMISSION};
use crate::validate::{MAX_DIFFICULTY, MIN_DIFFICULTY};
use xparq_coin::Amount;

/// Fixed number of completed blocks sampled for one WBDA epoch.
pub const WBDA_WINDOW: usize = 512;

/// Fixed average block-weight target used to calculate epoch utilization.
pub const WBDA_TARGET_BLOCK_WEIGHT: usize = 5 * 1024 * 1024;

/// Utilization below 40% raises difficulty by one discrete unit.
pub const WBDA_LOW_UTILIZATION_PPM: u64 = 400_000;

/// Utilization above 60% lowers difficulty by one discrete unit.
pub const WBDA_HIGH_UTILIZATION_PPM: u64 = 600_000;

/// One WBDA step changes the integer difficulty by exactly one unit.
pub const WBDA_DIFFICULTY_STEP: u32 = 1;

pub const WBDA_ALGORITHM: &str = "argon2id-wbda-reward-first-confirmed-difficulty-v1";

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

/// Applies difficulty only after the same non-neutral utilization signal is
/// observed in two consecutive completed epochs.
pub fn confirmed_difficulty_from_windows(
    previous_difficulty: u32,
    prior_window: Option<&[usize]>,
    current_window: &[usize],
) -> Option<u32> {
    let current = adjustment_for_window(current_window)?;
    let Some(prior) = prior_window else {
        return Some(previous_difficulty);
    };
    let prior = adjustment_for_window(prior)?;
    if current == WbdaAdjustment::Keep || current != prior {
        Some(previous_difficulty)
    } else {
        next_difficulty_from_window(previous_difficulty, current_window)
    }
}

/// Returns the difficulty required at `next_height`.
///
/// A complete weight window is required only when the next block starts a new
/// WBDA epoch. Keeping this boundary rule here prevents block admission, fork
/// choice, and header synchronization from implementing it independently.
pub fn expected_difficulty_from_windows(
    next_height: u64,
    parent_difficulty: u32,
    prior_window: Option<&[usize]>,
    current_window: &[usize],
) -> Option<u32> {
    if next_height == 1 {
        return Some(crate::DIFFICULTY_START);
    }
    if !is_wbda_epoch_boundary(next_height) {
        return Some(parent_difficulty);
    }
    confirmed_difficulty_from_windows(parent_difficulty, prior_window, current_window)
}

/// Resolves the complete WBDA rule for one candidate height.
///
/// Callers only provide branch-local weight lookup. Boundary selection,
/// window bounds, ordering, and adjustment remain owned by this function.
pub fn expected_difficulty_for_height<E>(
    next_height: u64,
    parent_difficulty: u32,
    mut weight_at: impl FnMut(u64) -> Result<usize, E>,
) -> Result<Option<u32>, E> {
    if next_height == 1 {
        return Ok(Some(crate::DIFFICULTY_START));
    }
    if !is_wbda_epoch_boundary(next_height) {
        return Ok(Some(parent_difficulty));
    }
    let has_prior_epoch = next_height > WBDA_WINDOW as u64 + 1;
    let history_len = if has_prior_epoch {
        WBDA_WINDOW as u64 * 2
    } else {
        WBDA_WINDOW as u64
    };
    let start = next_height - history_len;
    let weights = (start..next_height)
        .map(&mut weight_at)
        .collect::<Result<Vec<_>, _>>()?;
    let (prior, current) = if has_prior_epoch {
        let (prior, current) = weights.split_at(WBDA_WINDOW);
        (Some(prior), current)
    } else {
        (None, weights.as_slice())
    };
    Ok(expected_difficulty_from_windows(
        next_height,
        parent_difficulty,
        prior,
        current,
    ))
}

/// Applies the same completed-epoch utilization signal to block emission.
/// Sparse epochs increase emission, normal epochs keep it, and dense epochs
/// decrease it. The result is bounded by the monetary-policy limits.
pub fn next_emission_from_window(
    previous_emission: Amount,
    block_weights: &[usize],
) -> Option<Amount> {
    let adjustment = adjustment_for_window(block_weights)?;
    let emission = match adjustment {
        WbdaAdjustment::Decrease => previous_emission.0.saturating_sub(BLOCK_EMISSION_STEP),
        WbdaAdjustment::Keep => previous_emission.0,
        WbdaAdjustment::Increase => previous_emission.0.saturating_add(BLOCK_EMISSION_STEP),
    };
    Some(Amount(
        emission.clamp(MIN_BLOCK_EMISSION, MAX_BLOCK_EMISSION),
    ))
}

/// Changes emission on the first non-neutral signal. If the same signal is
/// repeated, emission stays fixed and the confirmed difficulty path responds.
pub fn reward_first_emission_from_windows(
    previous_emission: Amount,
    prior_window: Option<&[usize]>,
    current_window: &[usize],
) -> Option<Amount> {
    let current = adjustment_for_window(current_window)?;
    if let Some(prior_window) = prior_window {
        let prior = adjustment_for_window(prior_window)?;
        if current == prior {
            return Some(previous_emission);
        }
    }
    next_emission_from_window(previous_emission, current_window)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DIFFICULTY_START, GENESIS_DIFFICULTY};

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
    fn first_signal_changes_reward_before_difficulty() {
        assert_eq!(
            expected_difficulty_from_windows(1, GENESIS_DIFFICULTY, None, &[]),
            Some(DIFFICULTY_START)
        );
        assert_eq!(expected_difficulty_from_windows(2, 7, None, &[]), Some(7));
        assert_eq!(
            expected_difficulty_from_windows(
                WBDA_WINDOW as u64 + 1,
                7,
                None,
                &window(MAX_BLOCK_WEIGHT),
            ),
            Some(7)
        );
        assert_eq!(
            expected_difficulty_from_windows(WBDA_WINDOW as u64 + 1, 7, None, &[]),
            None
        );
    }

    #[test]
    fn shared_difficulty_resolver_owns_window_bounds_and_order() {
        let boundary = (WBDA_WINDOW * 2) as u64 + 1;
        let mut requested = Vec::new();
        let difficulty = expected_difficulty_for_height(boundary, 7, |height| {
            requested.push(height);
            Ok::<_, ()>(MAX_BLOCK_WEIGHT)
        })
        .unwrap();
        assert_eq!(difficulty, Some(6));
        assert_eq!(requested.len(), WBDA_WINDOW * 2);
        assert_eq!(
            requested.first(),
            Some(&(boundary - (WBDA_WINDOW * 2) as u64))
        );
        assert_eq!(requested.last(), Some(&(boundary - 1)));

        let mut called = false;
        assert_eq!(
            expected_difficulty_for_height(1, GENESIS_DIFFICULTY, |_| {
                called = true;
                Ok::<_, ()>(MAX_BLOCK_WEIGHT)
            }),
            Ok(Some(DIFFICULTY_START))
        );
        assert!(!called);
        assert_eq!(
            expected_difficulty_for_height(2, 7, |_| {
                called = true;
                Ok::<_, ()>(MAX_BLOCK_WEIGHT)
            }),
            Ok(Some(7))
        );
        assert!(!called);
    }

    #[test]
    fn emission_tracks_the_same_epoch_signal_with_bounds() {
        use crate::consensus::{MAX_BLOCK_EMISSION, MIN_BLOCK_EMISSION};

        assert_eq!(
            next_emission_from_window(Amount(MIN_BLOCK_EMISSION), &window(MAX_BLOCK_WEIGHT / 2)),
            Some(Amount(MIN_BLOCK_EMISSION))
        );
        assert_eq!(
            next_emission_from_window(Amount(MIN_BLOCK_EMISSION), &window(MAX_BLOCK_WEIGHT)),
            Some(Amount(MIN_BLOCK_EMISSION))
        );
        assert_eq!(
            next_emission_from_window(Amount(MAX_BLOCK_EMISSION), &window(MAX_BLOCK_WEIGHT / 10)),
            Some(Amount(MAX_BLOCK_EMISSION))
        );
        assert_eq!(
            next_emission_from_window(Amount(MIN_BLOCK_EMISSION), &window(MAX_BLOCK_WEIGHT)),
            Some(Amount(MIN_BLOCK_EMISSION))
        );
    }

    #[test]
    fn reward_moves_first_and_repeated_signal_moves_difficulty() {
        let mut difficulty = 7;
        let mut emission = Amount(crate::consensus::MIN_BLOCK_EMISSION);

        let sparse = window(MAX_BLOCK_WEIGHT / 10);
        difficulty = confirmed_difficulty_from_windows(difficulty, None, &sparse).unwrap();
        emission = reward_first_emission_from_windows(emission, None, &sparse).unwrap();
        assert_eq!(difficulty, 7);
        assert_eq!(
            emission,
            Amount(crate::consensus::MIN_BLOCK_EMISSION + BLOCK_EMISSION_STEP)
        );

        difficulty = confirmed_difficulty_from_windows(difficulty, Some(&sparse), &sparse).unwrap();
        emission = reward_first_emission_from_windows(emission, Some(&sparse), &sparse).unwrap();
        assert_eq!(difficulty, 8);
        assert_eq!(
            emission,
            Amount(crate::consensus::MIN_BLOCK_EMISSION + BLOCK_EMISSION_STEP)
        );

        let normal = window(MAX_BLOCK_WEIGHT / 2);
        assert_eq!(
            confirmed_difficulty_from_windows(difficulty, Some(&sparse), &normal),
            Some(difficulty)
        );
        assert_eq!(
            reward_first_emission_from_windows(emission, Some(&sparse), &normal),
            Some(emission)
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
