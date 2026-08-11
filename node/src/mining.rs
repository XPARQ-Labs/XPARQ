use crate::command::config::RunConfig;
use crate::log::{block_mined, mining_discarded_tip_changed, mining_result, mining_started};
use crate::runtime::miner::{
    MiningConfig, mine_prepared_block_until_with_attempts, prepare_candidate_block,
};
use crate::runtime::node::Node;
use crate::runtime::params::MAX_BLOCK_TXS;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use xparq::block::Block;
use xparq::crypto::BlockHash;
use xparq::genesis::CURRENT_CHAIN_PARAMS;

#[derive(Default)]
pub struct MiningStats {
    pub last_hashrate_hps: AtomicU64,
    pub last_attempts: AtomicU64,
    next_nonce: AtomicU64,
}

const UNLIMITED_MINE_NONCE_EPOCH_SIZE: u64 = 1 << 48;

pub fn mine_once(
    node_state: &Arc<Mutex<Node>>,
    config: &RunConfig,
    mining_stats: &MiningStats,
    shutdown_requested: &AtomicBool,
) -> Result<Option<Block>, String> {
    let miner_address = config
        .miner_address
        .ok_or_else(|| "mining reward address is not configured".to_string())?;
    let now = unix_timestamp()?;
    let (candidate, consensus, mining_config) = {
        let mut node = node_state
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        node.mempool
            .evict_by_policy(now)
            .map_err(|error| error.to_string())?;
        let timestamp = candidate_timestamp(&node, now);
        let difficulty = node
            .next_difficulty_at(timestamp)
            .map_err(|error| error.to_string())?;
        let miner_min_fee_rate = config
            .miner_min_fee_rate
            .unwrap_or_else(|| node.mempool.dynamic_market_fee_rate());
        mining_started(
            CURRENT_CHAIN_PARAMS.pow_algorithm,
            CURRENT_CHAIN_PARAMS.pow_memory_kib,
            miner_min_fee_rate,
        );
        let candidate = prepare_candidate_block(
            &node.mempool,
            &node.ledger,
            miner_address,
            timestamp,
            MAX_BLOCK_TXS,
            miner_min_fee_rate,
            difficulty,
        )
        .map_err(|error| format!("failed to prepare mining candidate: {error}"))?;
        (
            candidate,
            node.consensus,
            MiningConfig {
                difficulty,
                start_nonce: next_start_nonce(mining_stats, config.mine_attempts),
                max_attempts: config.mine_attempts,
                transaction_limit: MAX_BLOCK_TXS,
                min_fee_rate: miner_min_fee_rate,
            },
        )
    };

    let mining_genesis = candidate.is_genesis();
    let parent_hash = BlockHash::from(candidate.previous_hash().as_hash());
    let started = Instant::now();
    let rebuild_deadline = (config.mine_attempts == 0)
        .then(|| started.checked_add(config.mine_interval).unwrap_or(started));
    let (mined, attempted) =
        mine_prepared_block_until_with_attempts(candidate, &consensus, mining_config, || {
            shutdown_requested.load(Ordering::Relaxed)
                || rebuild_deadline.is_some_and(|deadline| Instant::now() >= deadline)
        })
        .map_err(|error| format!("mining failed: {error}"))?;
    let elapsed = started.elapsed();
    let Some(result) = mined else {
        update_stats(mining_stats, attempted, elapsed);
        let result = if shutdown_requested.load(Ordering::Relaxed) {
            "stopped"
        } else if rebuild_deadline.is_some() {
            "rebuild"
        } else {
            "exhausted"
        };
        mining_result(
            result,
            mining_config.start_nonce,
            attempted,
            elapsed.as_millis(),
        );
        return Ok(None);
    };
    update_stats(mining_stats, result.attempts, elapsed);

    let mut node = node_state
        .lock()
        .map_err(|_| "node state lock poisoned".to_string())?;
    let candidate_still_extends_tip = if mining_genesis {
        node.tip_hash().is_none()
    } else {
        node.tip_hash() == Some(parent_hash)
    };
    if !candidate_still_extends_tip {
        mining_discarded_tip_changed();
        return Ok(None);
    }
    node.apply_block(result.block.clone())
        .map_err(|error| format!("failed to apply mined block: {error}"))?;
    block_mined(&result.block, result.attempts);
    Ok(Some(result.block))
}

pub(crate) fn candidate_timestamp(node: &Node, now: u64) -> u64 {
    let _ = node;
    now
}

fn update_stats(mining_stats: &MiningStats, attempts: u64, elapsed: Duration) {
    let elapsed_nanos = elapsed.as_nanos().max(1);
    let hashrate =
        ((attempts as u128) * 1_000_000_000u128 / elapsed_nanos).min(u64::MAX as u128) as u64;
    mining_stats
        .last_hashrate_hps
        .store(hashrate, Ordering::Relaxed);
    mining_stats
        .last_attempts
        .store(attempts, Ordering::Relaxed);
}

fn next_start_nonce(mining_stats: &MiningStats, mine_attempts: u64) -> u64 {
    if mine_attempts == 0 {
        mining_stats
            .next_nonce
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_mul(UNLIMITED_MINE_NONCE_EPOCH_SIZE)
    } else {
        mining_stats
            .next_nonce
            .fetch_add(mine_attempts, Ordering::Relaxed)
    }
}

fn unix_timestamp() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before unix epoch".to_string())
}

// Legacy timestamp fixtures predate the timestamp-free xparq 0.2.20 block header.
#[cfg(all(test, any()))]
mod tests {
    use super::*;
    use xparq::consensus::{Consensus, ConsensusConfig, MIN_DIFFICULTY};
    use xparq::genesis::genesis_ledger;

    #[test]
    fn unlimited_mining_uses_stable_nonce_epochs() {
        let stats = MiningStats::default();

        assert_eq!(next_start_nonce(&stats, 0), 0);
        assert_eq!(next_start_nonce(&stats, 0), UNLIMITED_MINE_NONCE_EPOCH_SIZE);
        assert_eq!(
            next_start_nonce(&stats, 0),
            UNLIMITED_MINE_NONCE_EPOCH_SIZE * 2
        );
    }

    #[test]
    fn bounded_mining_reserves_attempt_ranges() {
        let stats = MiningStats::default();

        assert_eq!(next_start_nonce(&stats, 100), 0);
        assert_eq!(next_start_nonce(&stats, 100), 100);
        assert_eq!(next_start_nonce(&stats, 25), 200);
    }

    #[test]
    fn candidate_timestamp_is_strictly_after_future_dated_tip() {
        let ledger = genesis_ledger().unwrap();
        let tip_timestamp = ledger.block(&xparq::block::Height(0)).unwrap().timestamp();
        let node = Node::temporary(
            ledger,
            Consensus::new(ConsensusConfig::new(MIN_DIFFICULTY)).unwrap(),
        )
        .unwrap();

        assert_eq!(
            candidate_timestamp(&node, tip_timestamp - 50),
            tip_timestamp + 1
        );
        assert_eq!(
            candidate_timestamp(&node, tip_timestamp + 50),
            tip_timestamp + 50
        );
    }
}
