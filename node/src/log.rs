use crate::command::display::short_hash;
use std::sync::OnceLock;
use xparq::block::Block;
use xparq::crypto::BlockHash;

// Recurring mining-console formats live here so their layout can be edited
// without changing node, mining, or P2P control flow.

pub fn mining_started(algorithm: &str, memory_kib: u32, minimum_fee_rate_per_byte: u64) {
    static MINER_BANNER: OnceLock<()> = OnceLock::new();
    MINER_BANNER.get_or_init(|| {
        let memory_mib = memory_kib / 1024;
        println!(
            "[MINER] {algorithm} | memory {memory_mib} MiB | min fee {minimum_fee_rate_per_byte} xparq/vB"
        );
    });
}

pub fn mining_result(result: &str, start_nonce: u64, attempts: u64, elapsed_ms: u128) {
    if result == "rebuild" {
        return;
    }
    println!(
        "[MINER] {result} | nonce {start_nonce} | attempts {attempts} | elapsed {elapsed_ms} ms"
    );
}

pub fn mining_discarded_tip_changed() {
    println!("[MINER] candidate discarded | chain tip changed");
}

pub fn block_mined(block: &Block, attempts: u64) {
    let hash = block
        .hash()
        .map(|hash| short_hash(Some(hash)))
        .unwrap_or_else(|error| format!("encoding_error:{error}"));
    println!(
        "[BLOCK {:>8}] {} | diff {} | tx {} | attempts {}",
        block.height().0,
        hash,
        block.difficulty(),
        block.transactions().len(),
        attempts
    );
}

pub fn block_announced(height: u64, hash: BlockHash, attempted: usize, sent: usize, failed: usize) {
    if attempted == 0 && failed == 0 {
        return;
    }
    println!(
        "[P2P] block {height} {} | relayed {sent}/{attempted} | failed {failed}",
        short_hash(Some(hash))
    );
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MiningStatus {
    pub height: u64,
    pub tip: Option<BlockHash>,
    pub difficulty: String,
    pub peers: usize,
    pub outbound: usize,
    pub inbound: usize,
    pub hashrate_hps: u64,
    pub accepted_tx: u64,
    pub broadcast_tx: u64,
}

pub fn mining_status(status: MiningStatus) {
    println!(
        "[NODE] height {} | tip {} | diff {} | peers {} ({}/{}) | {} H/s | tx accepted/broadcast {}/{}",
        status.height,
        short_hash(status.tip),
        status.difficulty,
        status.peers,
        status.outbound,
        status.inbound,
        status.hashrate_hps,
        status.accepted_tx,
        status.broadcast_tx
    );
}
