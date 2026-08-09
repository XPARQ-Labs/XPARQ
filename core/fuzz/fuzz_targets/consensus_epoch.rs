#![no_main]

use libfuzzer_sys::fuzz_target;
use xparq::block::MAX_BLOCK_WEIGHT;
use xparq::consensus::supply::{Amount, MAX_BLOCK_REWARD, MIN_BLOCK_REWARD};
use xparq::consensus::{
    MIN_DIFFICULTY, WBDA_WINDOW, average_block_weight, is_wbda_epoch_boundary,
    next_difficulty_from_window, next_reward_from_window, utilization_ppm,
};

fuzz_target!(|data: &[u8]| {
    let mut weights = vec![0_usize; WBDA_WINDOW];
    for (index, weight) in weights.iter_mut().enumerate() {
        let byte = data.get(index % data.len().max(1)).copied().unwrap_or(0) as usize;
        *weight = byte.saturating_mul(MAX_BLOCK_WEIGHT) / u8::MAX as usize;
    }

    let average = average_block_weight(&weights).expect("exact window");
    assert!(average <= MAX_BLOCK_WEIGHT as u64);
    assert!(utilization_ppm(&weights).expect("exact window") <= 1_000_000);

    let previous_difficulty = u32::from_le_bytes([
        data.first().copied().unwrap_or(0),
        data.get(1).copied().unwrap_or(0),
        data.get(2).copied().unwrap_or(0),
        data.get(3).copied().unwrap_or(0),
    ]);
    assert!(next_difficulty_from_window(previous_difficulty, &weights).unwrap() >= MIN_DIFFICULTY);

    let previous_reward = Amount(u64::from(previous_difficulty));
    let reward = next_reward_from_window(previous_reward, &weights).unwrap();
    assert!((MIN_BLOCK_REWARD..=MAX_BLOCK_REWARD).contains(&reward.0));

    let epoch = u64::from(data.first().copied().unwrap_or(0)) + 1;
    let boundary = epoch * WBDA_WINDOW as u64 + 1;
    assert!(is_wbda_epoch_boundary(boundary));
    assert!(!is_wbda_epoch_boundary(boundary - 1));
});
