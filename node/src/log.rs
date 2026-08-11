use crate::command::display::short_hash;
use std::fmt;
use std::sync::OnceLock;
use time::{OffsetDateTime, macros::format_description};
use xparq::block::Block;
use xparq::crypto::BlockHash;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO ",
            Self::Warn => "WARN ",
            Self::Error => "ERROR",
        }
    }
}

fn configured_level() -> Level {
    static LEVEL: OnceLock<Level> = OnceLock::new();
    *LEVEL.get_or_init(|| {
        match std::env::var("XPARQ_LOG")
            .unwrap_or_else(|_| "info".to_string())
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "debug" | "trace" => Level::Debug,
            "warn" | "warning" => Level::Warn,
            "error" => Level::Error,
            _ => Level::Info,
        }
    })
}

pub fn emit(level: Level, target: &str, message: fmt::Arguments<'_>) {
    if level < configured_level() {
        return;
    }
    let timestamp = OffsetDateTime::now_utc()
        .format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
        ))
        .unwrap_or_else(|_| "timestamp-unavailable".to_string());
    eprintln!("{timestamp} {} {:<9} {message}", level.label(), target);
}

#[macro_export]
macro_rules! node_debug {
    ($target:expr, $($arg:tt)*) => {
        $crate::log::emit($crate::log::Level::Debug, $target, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! node_info {
    ($target:expr, $($arg:tt)*) => {
        $crate::log::emit($crate::log::Level::Info, $target, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! node_warn {
    ($target:expr, $($arg:tt)*) => {
        $crate::log::emit($crate::log::Level::Warn, $target, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! node_error {
    ($target:expr, $($arg:tt)*) => {
        $crate::log::emit($crate::log::Level::Error, $target, format_args!($($arg)*))
    };
}

pub fn mining_started(algorithm: &str, memory_kib: u32, minimum_fee_rate_per_byte: u64) {
    static MINER_BANNER: OnceLock<()> = OnceLock::new();
    MINER_BANNER.get_or_init(|| {
        let memory_mib = memory_kib / 1024;
        node_info!("MINER", "started algorithm={algorithm} memory_mib={memory_mib} min_fee_rate={minimum_fee_rate_per_byte}");
    });
}

pub fn mining_result(result: &str, start_nonce: u64, attempts: u64, elapsed_ms: u128) {
    if result == "rebuild" {
        return;
    }
    node_info!(
        "MINER",
        "result={result} start_nonce={start_nonce} attempts={attempts} elapsed_ms={elapsed_ms}"
    );
}

pub fn mining_discarded_tip_changed() {
    node_debug!("MINER", "candidate_discarded reason=tip_changed");
}

pub fn block_mined(block: &Block, attempts: u64) {
    let hash = block
        .hash()
        .map(|hash| short_hash(Some(hash)))
        .unwrap_or_else(|error| format!("encoding_error:{error}"));
    node_info!(
        "BLOCK",
        "mined height={} hash={} difficulty={} transactions={} attempts={}",
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
    node_info!(
        "P2P",
        "block_relay height={height} hash={} sent={sent} attempted={attempted} failed={failed}",
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
    node_info!(
        "NODE",
        "status height={} tip={} difficulty={} peers_known={} peers_outbound={} peers_inbound={} hashrate_hps={} tx_accepted={} tx_broadcast={}",
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
