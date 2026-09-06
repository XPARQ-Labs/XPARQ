//! Weight-Based Difficulty Adjustment (WBDA).
//!
//! WBDA adjusts proof-of-work difficulty from recent block-weight utilization,
//! not from elapsed block time. The selected window and utilization thresholds
//! are consensus parameters: changing any of them changes the expected
//! difficulty schedule for the chain.

#[cfg(test)]
use crate::blockchain::MAX_BLOCK_WEIGHT;

use super::emission::{BLOCK_EMISSION_STEP, MAX_BLOCK_EMISSION, MIN_BLOCK_EMISSION};
use crate::coin::Zeno;
use crate::consensus::validate::{MAX_DIFFICULTY, MIN_DIFFICULTY};

pub const WBDA_WINDOW: usize = 10_000;
pub const WBDA_TARGET_BLOCK_WEIGHT: usize = 2 * 1024 * 1024;
pub const WBDA_LOW_UTILIZATION_PPM: u64 = 400_000;
pub const WBDA_HIGH_UTILIZATION_PPM: u64 = 600_000;
pub const WBDA_DIFFICULTY_STEP: u32 = 1;
pub const WBDA_ALGORITHM: &str = "argon2id-wbda-algorithm";

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
        .try_fold(0u64, |total, weight| total.checked_add(*weight as u64))?;
    Some((total / WBDA_WINDOW as u64) as u64)
}

/// Utilization in parts-per-million, based on average weight over one window.
pub fn utilization_ppm(block_weights: &[usize]) -> Option<u64> {
    let average = average_block_weight(block_weights)? as u64;
    let target_weight = WBDA_TARGET_BLOCK_WEIGHT as u64;
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
        return Some(crate::consensus::DIFFICULTY_START);
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
        return Ok(Some(crate::consensus::DIFFICULTY_START));
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
pub fn next_emission_from_window(previous_emission: Zeno, block_weights: &[usize]) -> Option<Zeno> {
    let adjustment = adjustment_for_window(block_weights)?;
    let emission = match adjustment {
        WbdaAdjustment::Decrease => previous_emission
            .as_zeno()
            .saturating_sub(BLOCK_EMISSION_STEP),
        WbdaAdjustment::Keep => previous_emission.as_zeno(),
        WbdaAdjustment::Increase => previous_emission
            .as_zeno()
            .saturating_add(BLOCK_EMISSION_STEP),
    };
    Some(Zeno::from_zeno(
        emission.clamp(MIN_BLOCK_EMISSION, MAX_BLOCK_EMISSION),
    ))
}