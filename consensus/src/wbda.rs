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

pub const WBDA_WINDOW: usize = 1024;
pub const WBDA_TARGET_BLOCK_WEIGHT: usize = 5 * 1024 * 1024;
pub const WBDA_LOW_UTILIZATION_PPM: u64 = 400_000;
pub const WBDA_HIGH_UTILIZATION_PPM: u64 = 600_000;
pub const WBDA_DIFFICULTY_STEP: u32 = 1;
pub const WBDA_ALGORITHM: &str = "argon2id-wbda-lockstep-v2";

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

/// Returns the difficulty required at `next_height`.
///
/// A complete weight window is required only when the next block starts a new
/// WBDA epoch. Keeping this boundary rule here prevents block admission, fork
/// choice, and header synchronization from implementing it independently.
/// Moves every epoch, in lockstep with `next_emission_from_window` — same
/// signal, same window, no confirmation delay.
pub fn expected_difficulty_from_window(
    next_height: u64,
    parent_difficulty: u32,
    current_window: &[usize],
) -> Option<u32> {
    if next_height == 1 {
        return Some(crate::DIFFICULTY_START);
    }
    if !is_wbda_epoch_boundary(next_height) {
        return Some(parent_difficulty);
    }
    next_difficulty_from_window(parent_difficulty, current_window)
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
    let start = next_height - WBDA_WINDOW as u64;
    let weights = (start..next_height)
        .map(&mut weight_at)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(expected_difficulty_from_window(
        next_height,
        parent_difficulty,
        &weights,
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
    fn difficulty_moves_with_every_completed_epoch() {
        assert_eq!(
            expected_difficulty_from_window(1, GENESIS_DIFFICULTY, &[]),
            Some(DIFFICULTY_START)
        );
        assert_eq!(expected_difficulty_from_window(2, 7, &[]), Some(7));
        assert_eq!(
            expected_difficulty_from_window(WBDA_WINDOW as u64 + 1, 7, &window(MAX_BLOCK_WEIGHT)),
            Some(6)
        );
        assert_eq!(
            expected_difficulty_from_window(WBDA_WINDOW as u64 + 1, 7, &[]),
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
        assert_eq!(requested.len(), WBDA_WINDOW);
        assert_eq!(requested.first(), Some(&(boundary - WBDA_WINDOW as u64)));
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
    fn difficulty_and_reward_move_together_every_epoch() {
        let mut difficulty = 7;
        let mut emission = Amount(crate::consensus::MIN_BLOCK_EMISSION);

        // Low utilization: both rise, same epoch, no confirmation wait.
        let sparse = window(MAX_BLOCK_WEIGHT / 10);
        difficulty = next_difficulty_from_window(difficulty, &sparse).unwrap();
        emission = next_emission_from_window(emission, &sparse).unwrap();
        assert_eq!(difficulty, 8);
        assert_eq!(
            emission,
            Amount(crate::consensus::MIN_BLOCK_EMISSION + BLOCK_EMISSION_STEP)
        );

        // Normal utilization: both hold.
        let normal = window(MAX_BLOCK_WEIGHT / 2);
        assert_eq!(next_difficulty_from_window(difficulty, &normal), Some(difficulty));
        assert_eq!(next_emission_from_window(emission, &normal), Some(emission));

        // High utilization: both fall together.
        let dense = window(MAX_BLOCK_WEIGHT);
        difficulty = next_difficulty_from_window(difficulty, &dense).unwrap();
        emission = next_emission_from_window(emission, &dense).unwrap();
        assert_eq!(difficulty, 7);
        assert_eq!(emission, Amount(crate::consensus::MIN_BLOCK_EMISSION));
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
