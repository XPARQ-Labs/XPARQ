use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use static_assertions::const_assert;

pub const UNIT: u64 = 1;
pub const XPQ: u64 = 1_000_000;
pub const DECIMALS: u8 = 6;

const_assert!(XPQ == 1_000_000);

/// Reward used for the first WBDA epoch.
pub const BASE_BLOCK_REWARD: u64 = 5_000_000;
/// Consensus lower bound for the epoch reward.
pub const MIN_BLOCK_REWARD: u64 = 500_000;
/// Consensus upper bound for the epoch reward.
pub const MAX_BLOCK_REWARD: u64 = 10_000_000;
/// One utilization adjustment changes the reward by exactly 0.1 XPQ.
pub const BLOCK_REWARD_STEP: u64 = 100_000;

const_assert!(MIN_BLOCK_REWARD == XPQ / 2);
const_assert!(BASE_BLOCK_REWARD == 5 * XPQ);
const_assert!(MAX_BLOCK_REWARD == 10 * XPQ);
const_assert!(BLOCK_REWARD_STEP == XPQ / 10);

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

pub const fn base_block_reward() -> Amount {
    Amount(BASE_BLOCK_REWARD)
}
