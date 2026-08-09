use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use static_assertions::const_assert;

pub const UNIT: u64 = 1;
pub const XPQ: u64 = 1_000_000;
pub const DECIMALS: u8 = 6;

const_assert!(XPQ == 1_000_000);

/// Reward used for the first WBDA epoch.
pub const BASE_BLOCK_REWARD: u64 = 10_000_000;
/// Consensus lower bound for the epoch reward.
pub const MIN_BLOCK_REWARD: u64 = 1_000_000;
/// Consensus upper bound for the epoch reward.
pub const MAX_BLOCK_REWARD: u64 = 20_000_000;
/// One utilization adjustment changes the reward by exactly 1 XPQ.
pub const BLOCK_REWARD_STEP: u64 = 1_000_000;

// Compatibility alias for consumers that used the former fixed reward name.
pub const BLOCK_REWARD: u64 = BASE_BLOCK_REWARD;

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
