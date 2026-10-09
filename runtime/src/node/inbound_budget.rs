//! Local per-peer admission before decoding, validation, storage work and logging.
use litep2p::PeerId;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

const MAX_PEERS: usize = 64;
const RETENTION: Duration = Duration::from_secs(300);
const SCALE: u128 = 1_000_000_000;

#[derive(Clone, Copy)]
pub(super) enum Traffic {
    Block,
    Transaction,
    Invalid,
}

struct Bucket {
    available: u128,
    updated: Instant,
}
impl Bucket {
    fn new(capacity: u64, now: Instant) -> Self {
        Self {
            available: u128::from(capacity) * SCALE,
            updated: now,
        }
    }
    fn refill(&mut self, capacity: u64, rate: u64, now: Instant) {
        if let Some(elapsed) = now.checked_duration_since(self.updated) {
            self.available = self
                .available
                .saturating_add(elapsed.as_nanos().saturating_mul(u128::from(rate)))
                .min(u128::from(capacity) * SCALE);
            self.updated = now;
        }
    }
}

struct Limit {
    count: Bucket,
    bytes: Bucket,
}
impl Limit {
    fn new(count: u64, bytes: u64, now: Instant) -> Self {
        Self {
            count: Bucket::new(count, now),
            bytes: Bucket::new(bytes, now),
        }
    }
    fn ready(&mut self, spec: (u64, u64, u64, u64), bytes: usize, now: Instant) -> bool {
        let (count_capacity, count_rate, byte_capacity, byte_rate) = spec;
        self.count.refill(count_capacity, count_rate, now);
        self.bytes.refill(byte_capacity, byte_rate, now);
        self.count.available >= SCALE && self.bytes.available >= bytes as u128 * SCALE
    }
    fn debit(&mut self, bytes: usize) {
        self.count.available -= SCALE;
        self.bytes.available -= bytes as u128 * SCALE;
    }
    #[cfg(test)]
    fn admit(&mut self, spec: (u64, u64, u64, u64), bytes: usize, now: Instant) -> bool {
        if !self.ready(spec, bytes, now) {
            return false;
        }
        self.debit(bytes);
        true
    }
}

// Tuple: count burst, count/second, encoded-byte burst, bytes/second.
const REQUEST: (u64, u64, u64, u64) = (32, 8, 64 * 1024, 16 * 1024);
const BLOCK: (u64, u64, u64, u64) = (4, 1, 16 * 1024 * 1024, 4 * 1024 * 1024);
const TRANSACTION: (u64, u64, u64, u64) = (256, 16, 16 * 1024 * 1024, 1024 * 1024);
const INVALID: (u64, u64, u64, u64) = (4, 1, 8 * 1024 * 1024, 2 * 1024 * 1024);

struct PeerBudget {
    request: Limit,
    block: Limit,
    transaction: Limit,
    invalid: Limit,
    touched: Instant,
}
impl PeerBudget {
    fn new(now: Instant) -> Self {
        Self {
            request: Limit::new(REQUEST.0, REQUEST.2, now),
            block: Limit::new(BLOCK.0, BLOCK.2, now),
            transaction: Limit::new(TRANSACTION.0, TRANSACTION.2, now),
            invalid: Limit::new(INVALID.0, INVALID.2, now),
            touched: now,
        }
    }
}

// Shared admission limits downstream work across all peer identities.
const GLOBAL_REQUEST: (u64, u64, u64, u64) = (128, 32, 256 * 1024, 64 * 1024);
const GLOBAL_BLOCK: (u64, u64, u64, u64) = (8, 2, 32 * 1024 * 1024, 8 * 1024 * 1024);
const GLOBAL_TRANSACTION: (u64, u64, u64, u64) = (512, 32, 32 * 1024 * 1024, 2 * 1024 * 1024);
const GLOBAL_INVALID: (u64, u64, u64, u64) = (8, 2, 16 * 1024 * 1024, 4 * 1024 * 1024);
const GLOBAL_ALL: (u64, u64, u64, u64) = (1024, 64, 64 * 1024 * 1024, 8 * 1024 * 1024);

struct GlobalBudget {
    request: Limit,
    block: Limit,
    transaction: Limit,
    invalid: Limit,
    all: Limit,
}
impl GlobalBudget {
    fn new(now: Instant) -> Self {
        Self {
            request: Limit::new(GLOBAL_REQUEST.0, GLOBAL_REQUEST.2, now),
            block: Limit::new(GLOBAL_BLOCK.0, GLOBAL_BLOCK.2, now),
            transaction: Limit::new(GLOBAL_TRANSACTION.0, GLOBAL_TRANSACTION.2, now),
            invalid: Limit::new(GLOBAL_INVALID.0, GLOBAL_INVALID.2, now),
            all: Limit::new(GLOBAL_ALL.0, GLOBAL_ALL.2, now),
        }
    }
}

pub(super) struct InboundBudget(HashMap<PeerId, PeerBudget>, GlobalBudget);
impl Default for InboundBudget {
    fn default() -> Self {
        Self(HashMap::new(), GlobalBudget::new(Instant::now()))
    }
}
impl InboundBudget {
    pub(super) fn prune(&mut self, now: Instant) {
        self.0
            .retain(|_, budget| now.saturating_duration_since(budget.touched) < RETENTION);
    }
    pub(super) fn admit_request_enqueue(
        &mut self,
        peer: PeerId,
        bytes: usize,
        now: Instant,
    ) -> bool {
        if !self.0.contains_key(&peer) {
            self.prune(now);
            if self.0.len() >= MAX_PEERS {
                return false;
            }
            self.0.insert(peer, PeerBudget::new(now));
        }
        let budget = self.0.get_mut(&peer).unwrap();
        budget.touched = budget.touched.max(now);
        if !budget.request.ready(REQUEST, bytes, now) {
            return false;
        }
        budget.request.debit(bytes);
        true
    }
    pub(super) fn admit_request_work(&mut self, bytes: usize, now: Instant) -> bool {
        if !self.1.request.ready(GLOBAL_REQUEST, bytes, now) {
            return false;
        }
        self.1.request.debit(bytes);
        true
    }
    pub(super) fn admit(
        &mut self,
        peer: PeerId,
        traffic: Traffic,
        bytes: usize,
        now: Instant,
    ) -> bool {
        if !self.0.contains_key(&peer) {
            self.prune(now);
            // Do not evict another peer's unexpired budget on identity churn.
            // New identities fail closed until an existing entry expires.
            if self.0.len() >= MAX_PEERS {
                return false;
            }
            self.0.insert(peer, PeerBudget::new(now));
        }
        let budget = self.0.get_mut(&peer).expect("admitted peer budget exists");
        budget.touched = budget.touched.max(now);
        let (local, spec, shared, shared_spec) = match traffic {
            Traffic::Block => (&mut budget.block, BLOCK, &mut self.1.block, GLOBAL_BLOCK),
            Traffic::Transaction => (
                &mut budget.transaction,
                TRANSACTION,
                &mut self.1.transaction,
                GLOBAL_TRANSACTION,
            ),
            Traffic::Invalid => (
                &mut budget.invalid,
                INVALID,
                &mut self.1.invalid,
                GLOBAL_INVALID,
            ),
        };
        // Refill all relevant buckets, then debit only if every limit admits.
        let local_ready = local.ready(spec, bytes, now);
        let shared_ready = shared.ready(shared_spec, bytes, now);
        let all_ready = self.1.all.ready(GLOBAL_ALL, bytes, now);
        if !(local_ready && shared_ready && all_ready) {
            return false;
        }
        local.debit(bytes);
        shared.debit(bytes);
        self.1.all.debit(bytes);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn count_budget_refills_at_exact_boundaries_without_rejected_debits() {
        let now = Instant::now();
        let peer = PeerId::random();
        let mut budget = InboundBudget::default();
        for _ in 0..REQUEST.0 {
            assert!(budget.admit_request_enqueue(peer, 1, now));
        }
        assert!(!budget.admit_request_enqueue(peer, 1, now));
        assert!(!budget.admit_request_enqueue(peer, 1, now + Duration::from_nanos(124_999_999)));
        assert!(budget.admit_request_enqueue(peer, 1, now + Duration::from_millis(125)));
        assert!(!budget.admit_request_enqueue(peer, 1, now + Duration::from_millis(125)));
    }
    #[test]
    fn byte_budget_is_atomic_and_traffic_classes_and_peers_are_independent() {
        let now = Instant::now();
        let peer = PeerId::random();
        let mut budget = InboundBudget::default();
        assert!(!budget.admit(peer, Traffic::Transaction, TRANSACTION.2 as usize + 1, now));
        assert!(budget.admit(peer, Traffic::Transaction, TRANSACTION.2 as usize, now));
        assert!(!budget.admit(peer, Traffic::Transaction, 1, now));
        assert!(budget.admit(peer, Traffic::Block, 1, now));
        assert!(budget.admit(PeerId::random(), Traffic::Transaction, 1, now));
        assert!(budget.admit(
            peer,
            Traffic::Transaction,
            TRANSACTION.3 as usize,
            now + Duration::from_secs(1)
        ));
    }
    #[test]
    fn reconnect_does_not_reset_budget_and_identity_churn_cannot_evict_it() {
        let now = Instant::now();
        let peer = PeerId::random();
        let mut budget = InboundBudget::default();
        for _ in 0..BLOCK.0 {
            assert!(budget.admit(peer, Traffic::Block, 1, now));
        }
        // Disconnect cleanup deliberately does not remove admission history.
        assert!(!budget.admit(peer, Traffic::Block, 1, now));
        for _ in 1..MAX_PEERS {
            assert!(budget.admit_request_enqueue(PeerId::random(), 1, now));
        }
        assert!(!budget.admit_request_enqueue(PeerId::random(), 1, now));
        assert_eq!(budget.0.len(), MAX_PEERS);
        assert!(!budget.admit(peer, Traffic::Block, 1, now));
        budget.prune(now + RETENTION);
        assert!(budget.0.is_empty());
        assert!(budget.admit(peer, Traffic::Block, 1, now + RETENTION));
    }
    #[test]
    fn paced_large_sync_requests_do_not_exhaust_the_server_budget() {
        let now = Instant::now();
        let peer = PeerId::random();
        let mut budget = InboundBudget::default();
        for index in 0..10_000 {
            let arrival = now + super::super::litep2p_devnet::SYNC_REQUEST_INTERVAL * index;
            assert!(budget.admit_request_enqueue(peer, 33, arrival));
            assert!(budget.admit_request_work(33, arrival));
        }
    }

    #[test]
    fn identity_churn_cannot_reset_global_count_and_rejection_is_atomic() {
        let now = Instant::now();
        let mut budget = InboundBudget(HashMap::new(), GlobalBudget::new(now));
        for _ in 0..GLOBAL_BLOCK.0 {
            assert!(budget.admit(PeerId::random(), Traffic::Block, 1, now));
        }
        let peer = PeerId::random();
        assert!(!budget.admit(peer, Traffic::Block, 1, now));
        assert_eq!(
            budget.0[&peer].block.count.available,
            BLOCK.0 as u128 * SCALE
        );
        let remaining = budget.1.all.count.available;
        assert!(!budget.admit(peer, Traffic::Block, 1, now));
        assert_eq!(budget.1.all.count.available, remaining);
        assert!(!budget.admit(peer, Traffic::Block, 1, now + Duration::from_millis(499)));
        assert!(budget.admit(peer, Traffic::Block, 1, now + Duration::from_millis(500)));
    }

    #[test]
    fn combined_bytes_bound_mixed_traffic_without_debiting_other_limits() {
        let now = Instant::now();
        let mut budget = InboundBudget(HashMap::new(), GlobalBudget::new(now));
        for _ in 0..2 {
            assert!(budget.admit(PeerId::random(), Traffic::Block, BLOCK.2 as usize, now));
            assert!(budget.admit(
                PeerId::random(),
                Traffic::Transaction,
                TRANSACTION.2 as usize,
                now
            ));
        }
        let peer = PeerId::random();
        assert!(!budget.admit(peer, Traffic::Invalid, 1, now));
        assert_eq!(
            budget.1.request.count.available,
            GLOBAL_REQUEST.0 as u128 * SCALE
        );
        assert_eq!(
            budget.0[&peer].request.count.available,
            REQUEST.0 as u128 * SCALE
        );
        assert!(budget.admit_request_enqueue(peer, 64 * 1024, now));
        assert!(budget.admit_request_work(64 * 1024, now));
    }

    #[test]
    fn saturated_request_service_waits_without_consuming_new_peer_admission() {
        let now = Instant::now();
        let mut budget = InboundBudget(HashMap::new(), GlobalBudget::new(now));
        for _ in 0..GLOBAL_REQUEST.0 {
            assert!(budget.admit_request_work(1, now));
        }
        let healthy = PeerId::random();
        assert!(budget.admit_request_enqueue(healthy, 33, now));
        assert!(!budget.admit_request_work(33, now));
        assert!(budget.admit_request_work(33, now + Duration::from_millis(32)));
        assert!(budget.admit(healthy, Traffic::Transaction, 1, now));
    }

    #[test]
    fn large_time_steps_cap_refill_and_backward_time_cannot_mint_tokens() {
        let now = Instant::now();
        let mut bucket = Limit::new(4, 4, now);
        assert!(bucket.admit((4, 1, 4, 1), 4, now));
        assert!(!bucket.admit((4, 1, 4, 1), 1, now - Duration::from_secs(1)));
        assert!(bucket.admit((4, 1, 4, 1), 4, now + Duration::from_secs(10_000)));
        assert!(!bucket.admit((4, 1, 4, 1), 1, now + Duration::from_secs(10_000)));
    }
}
