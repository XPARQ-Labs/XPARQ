use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use static_assertions::const_assert;

use crate::block::BlockHeight;

pub const UNIT: u64 = 1;
pub const XPQ: u64 = 1_000_000;
pub const DECIMALS: u8 = 6;

const_assert!(XPQ == 1_000_000);

pub const BLOCK_REWARD: u64 = 15_000_000;
pub const TAIL_EMISSION: u64 = 850_000;
pub const TAIL_EMISSION_START_HEIGHT: u64 = 400_000;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct Amount(pub u64);

pub type Balance = Amount;
pub type Fee = Amount;

pub fn block_reward(height: BlockHeight) -> Amount {
    if height.0 < TAIL_EMISSION_START_HEIGHT {
        Amount(BLOCK_REWARD)
    } else {
        Amount(TAIL_EMISSION)
    }
}

pub fn tail_emission_start_height() -> u64 {
    TAIL_EMISSION_START_HEIGHT
}
