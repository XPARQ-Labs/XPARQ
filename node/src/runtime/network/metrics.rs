use std::sync::atomic::AtomicU64;

pub struct NetworkMetrics {
    pub duplicate_transactions: AtomicU64,
    pub compact_success: AtomicU64,
    pub compact_fallback: AtomicU64,
    pub compact_missing_transactions: AtomicU64,
}

impl NetworkMetrics {
    const fn new() -> Self {
        Self {
            duplicate_transactions: AtomicU64::new(0),
            compact_success: AtomicU64::new(0),
            compact_fallback: AtomicU64::new(0),
            compact_missing_transactions: AtomicU64::new(0),
        }
    }
}

pub static NETWORK_METRICS: NetworkMetrics = NetworkMetrics::new();
