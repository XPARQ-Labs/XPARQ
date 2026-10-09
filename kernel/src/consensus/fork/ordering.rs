use super::Work;
use crypto::BlockHash;
use std::cmp::Ordering;
/// Consensus ordering for valid chain tips.
///
/// Greater locally-computed cumulative work wins. Cumulative canonical block
/// weight only breaks an exact work tie; it can never compensate for less PoW.
/// If both totals tie, the numerically smaller block hash wins so every node
/// reaches the same result without trusting peer identity or arrival order.
pub fn compare_chain_tips(
    left_work: Work,
    left_weight: u64,
    left_hash: BlockHash,
    right_work: Work,
    right_weight: u64,
    right_hash: BlockHash,
) -> Ordering {
    left_work
        .cmp(&right_work)
        .then_with(|| left_weight.cmp(&right_weight))
        .then_with(|| right_hash.cmp(&left_hash))
}
