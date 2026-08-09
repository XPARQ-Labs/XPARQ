use super::NetworkMessage;
use std::sync::atomic::{AtomicU64, Ordering};

pub const NETWORK_CATEGORIES: [&str; 6] = [
    "control",
    "block",
    "transaction",
    "snapshot",
    "reconcile",
    "peer",
];

pub struct NetworkMetrics {
    rx_bytes: [AtomicU64; 6],
    tx_bytes: [AtomicU64; 6],
    pub duplicate_transactions: AtomicU64,
    pub compact_success: AtomicU64,
    pub compact_fallback: AtomicU64,
    pub compact_missing_transactions: AtomicU64,
}

impl NetworkMetrics {
    const fn new() -> Self {
        Self {
            rx_bytes: [const { AtomicU64::new(0) }; 6],
            tx_bytes: [const { AtomicU64::new(0) }; 6],
            duplicate_transactions: AtomicU64::new(0),
            compact_success: AtomicU64::new(0),
            compact_fallback: AtomicU64::new(0),
            compact_missing_transactions: AtomicU64::new(0),
        }
    }

    pub fn record_rx(&self, message: &NetworkMessage, bytes: u64) {
        self.rx_bytes[category(message)].fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_tx(&self, message: &NetworkMessage, bytes: u64) {
        self.tx_bytes[category(message)].fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> [(u64, u64); 6] {
        std::array::from_fn(|index| {
            (
                self.rx_bytes[index].load(Ordering::Relaxed),
                self.tx_bytes[index].load(Ordering::Relaxed),
            )
        })
    }
}

pub static NETWORK_METRICS: NetworkMetrics = NetworkMetrics::new();

fn category(message: &NetworkMessage) -> usize {
    match message {
        NetworkMessage::Block(_)
        | NetworkMessage::Blocks(_)
        | NetworkMessage::BlockHeaders(_)
        | NetworkMessage::CompactBlock(_)
        | NetworkMessage::GetBlockByHeight { .. }
        | NetworkMessage::GetBlocksByHeightRange { .. }
        | NetworkMessage::GetBlockHeadersByHeightRange { .. }
        | NetworkMessage::GetCommonAncestor { .. }
        | NetworkMessage::CommonAncestor(_)
        | NetworkMessage::GetBlockByHash { .. }
        | NetworkMessage::GetCompactBlockTransactions { .. }
        | NetworkMessage::CompactBlockTransactions { .. } => 1,
        NetworkMessage::Transaction(_)
        | NetworkMessage::Transactions(_)
        | NetworkMessage::Inventory(_)
        | NetworkMessage::GetData(_)
        | NetworkMessage::GetMempoolInventory => 2,
        NetworkMessage::GetSnapshotManifest { .. }
        | NetworkMessage::SnapshotManifest { .. }
        | NetworkMessage::GetSnapshotChunk { .. }
        | NetworkMessage::SnapshotChunk { .. } => 3,
        NetworkMessage::ReconcileMempool { .. } => 4,
        NetworkMessage::GetPeers | NetworkMessage::Peers(_) => 5,
        _ => 0,
    }
}
