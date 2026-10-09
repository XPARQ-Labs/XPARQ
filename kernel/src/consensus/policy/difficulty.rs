use crate::consensus::PoWTarget;

#[cfg(test)]
mod tests;

pub const WBDA_WINDOW: usize = 2_500;
pub const WBDA_TARGET_BLOCK_WEIGHT: usize = 1024 * 1024;
pub const WBDA_LOW_UTILIZATION_PPM: u64 = 800_000;
pub const WBDA_HIGH_UTILIZATION_PPM: u64 = 1_200_000;
pub const WBDA_HARDER_PERCENT: u32 = 80;
pub const WBDA_EASIER_PERCENT: u32 = 120;
pub const DIFFICULTY_ALGORITHM: &str = "argon2id-wbda-algorithm";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WbdaAdjustment {
    Decrease,
    Keep,
    Increase,
}

pub const fn is_wbda_epoch_boundary(height: u64) -> bool {
    height > 1 && (height - 1).is_multiple_of(WBDA_WINDOW as u64)
}

pub fn average_block_weight(block_weights: &[usize]) -> Option<u64> {
    if block_weights.len() != WBDA_WINDOW {
        return None;
    }

    let total = block_weights
        .iter()
        .try_fold(0_u64, |total, weight| total.checked_add(*weight as u64))?;

    Some(total / WBDA_WINDOW as u64)
}

pub fn utilization_ppm(block_weights: &[usize]) -> Option<u64> {
    let average = average_block_weight(block_weights)?;
    let target = WBDA_TARGET_BLOCK_WEIGHT as u64;

    if target == 0 {
        return None;
    }

    Some(average.saturating_mul(1_000_000) / target)
}

pub fn adjustment_for_utilization_ppm(utilization: u64) -> WbdaAdjustment {
    if utilization < WBDA_LOW_UTILIZATION_PPM {
        WbdaAdjustment::Increase
    } else if utilization > WBDA_HIGH_UTILIZATION_PPM {
        WbdaAdjustment::Decrease
    } else {
        WbdaAdjustment::Keep
    }
}

pub fn adjustment_for_window(block_weights: &[usize]) -> Option<WbdaAdjustment> {
    utilization_ppm(block_weights).map(adjustment_for_utilization_ppm)
}

pub fn next_difficulty_from_window(
    previous_target_bits: u32,
    block_weights: &[usize],
) -> Option<u32> {
    let adjustment = adjustment_for_window(block_weights)?;

    let previous = PoWTarget::from_compact(previous_target_bits)?;

    let pow_limit = PoWTarget::from_compact(crate::consensus::TARGET_BITS_START)?;

    let next = match adjustment {
        WbdaAdjustment::Decrease => previous.scale_ratio(WBDA_EASIER_PERCENT, 100)?,

        WbdaAdjustment::Keep => previous,

        WbdaAdjustment::Increase => previous.scale_ratio(WBDA_HARDER_PERCENT, 100)?,
    };

    let next = if next > pow_limit { pow_limit } else { next };

    Some(next.to_compact())
}

pub fn expected_difficulty_from_window(
    next_height: u64,
    parent_difficulty: u32,
    current_window: &[usize],
) -> Option<u32> {
    if next_height == 1 {
        return Some(crate::consensus::TARGET_BITS_START);
    }

    if !is_wbda_epoch_boundary(next_height) {
        return Some(parent_difficulty);
    }

    next_difficulty_from_window(parent_difficulty, current_window)
}

pub fn expected_difficulty_for_height<E>(
    next_height: u64,
    parent_difficulty: u32,
    mut weight_at: impl FnMut(u64) -> Result<usize, E>,
) -> Result<Option<u32>, E> {
    if next_height == 1 {
        return Ok(Some(crate::consensus::TARGET_BITS_START));
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
