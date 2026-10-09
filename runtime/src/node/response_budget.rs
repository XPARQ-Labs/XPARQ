//! Admission for attempted request-response payloads, independent of announcements.
use litep2p::PeerId;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
const SCALE: u128 = 1_000_000_000;
const MIB: u64 = 1024 * 1024;
const RETENTION: Duration = Duration::from_secs(300);
const MAX_PEERS: usize = 64;
#[derive(Clone, Copy)]
pub(super) enum ResponseClass {
    Control,
    Block,
}
struct Bucket {
    available: u128,
    updated: Instant,
}
impl Bucket {
    fn new(cap: u64, now: Instant) -> Self {
        Self {
            available: u128::from(cap) * SCALE,
            updated: now,
        }
    }
    fn ready(&mut self, cap: u64, rate: u64, cost: u128, now: Instant) -> bool {
        if let Some(elapsed) = now.checked_duration_since(self.updated) {
            self.available = self
                .available
                .saturating_add(elapsed.as_nanos().saturating_mul(rate as u128))
                .min(cap as u128 * SCALE);
            self.updated = now;
        }
        self.available >= cost
    }
}
struct Peer {
    control: Bucket,
    block: Bucket,
    touched: Instant,
}
pub(super) struct ResponseBudget {
    peers: HashMap<PeerId, Peer>,
    control: Bucket,
    block: Bucket,
}
impl Default for ResponseBudget {
    fn default() -> Self {
        Self::new(Instant::now())
    }
}
impl ResponseBudget {
    fn new(now: Instant) -> Self {
        Self {
            peers: HashMap::new(),
            control: Bucket::new(16 * MIB, now),
            block: Bucket::new(64 * MIB, now),
        }
    }
    pub fn prune(&mut self, now: Instant) {
        self.peers
            .retain(|_, peer| now.saturating_duration_since(peer.touched) < RETENTION);
    }
    pub fn admit(
        &mut self,
        peer: PeerId,
        class: ResponseClass,
        payload: usize,
        now: Instant,
    ) -> bool {
        if payload > super::MAX_STORED_BLOCK_SIZE + 1 {
            return false;
        }
        // Include the unsigned-varint length prefix; Noise/TCP overhead is separate.
        let mut prefix = 1usize;
        let mut value = payload;
        while value >= 128 {
            value >>= 7;
            prefix += 1;
        }
        let cost = (payload as u128 + prefix as u128) * SCALE;
        if !self.peers.contains_key(&peer) {
            self.prune(now);
            if self.peers.len() >= MAX_PEERS {
                return false;
            }
            self.peers.insert(
                peer,
                Peer {
                    control: Bucket::new(8 * MIB, now),
                    block: Bucket::new(16 * MIB, now),
                    touched: now,
                },
            );
        }
        let history = self.peers.get_mut(&peer).unwrap();
        history.touched = history.touched.max(now);
        let (local, cap, rate, global, total, refill) = match class {
            ResponseClass::Control => (
                &mut history.control,
                8 * MIB,
                4 * MIB,
                &mut self.control,
                16 * MIB,
                8 * MIB,
            ),
            ResponseClass::Block => (
                &mut history.block,
                16 * MIB,
                8 * MIB,
                &mut self.block,
                64 * MIB,
                32 * MIB,
            ),
        };
        let local_ready = local.ready(cap, rate, cost, now);
        let global_ready = global.ready(total, refill, cost, now);
        if !(local_ready && global_ready) {
            return false;
        }
        local.available -= cost;
        global.available -= cost;
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bulk_exhaustion_preserves_control_and_other_peer_capacity() {
        let now = Instant::now();
        let peer = PeerId::random();
        let mut budget = ResponseBudget::new(now);
        // 1 MiB minus its three-byte prefix costs exactly 1 MiB.
        for _ in 0..16 {
            assert!(budget.admit(peer, ResponseClass::Block, MIB as usize - 3, now));
        }
        assert!(!budget.admit(peer, ResponseClass::Block, 1, now));
        assert!(budget.admit(peer, ResponseClass::Control, 512, now));
        assert!(budget.admit(PeerId::random(), ResponseClass::Block, MIB as usize, now));
        assert!(budget.admit(
            peer,
            ResponseClass::Block,
            MIB as usize - 3,
            now + Duration::from_millis(125)
        ));
    }
    #[test]
    fn global_exhaustion_is_atomic_and_survives_identity_changes() {
        let now = Instant::now();
        let mut budget = ResponseBudget::new(now);
        let senders: Vec<_> = (0..4).map(|_| PeerId::random()).collect();
        for index in 0..64 {
            assert!(budget.admit(
                senders[index % 4],
                ResponseClass::Block,
                MIB as usize - 3,
                now
            ));
        }
        let peer = PeerId::random();
        assert!(!budget.admit(peer, ResponseClass::Block, 1, now));
        let before = budget.peers[&peer].block.available;
        assert!(!budget.admit(peer, ResponseClass::Block, 1, now));
        assert_eq!(before, budget.peers[&peer].block.available);
        assert!(!budget.admit(PeerId::random(), ResponseClass::Block, 1, now));
        assert!(budget.admit(peer, ResponseClass::Control, 1, now));
        assert!(budget.admit(
            peer,
            ResponseClass::Block,
            MIB as usize - 3,
            now + Duration::from_millis(32)
        ));
    }
    #[test]
    fn reconnect_retention_size_bounds_and_backward_time() {
        let now = Instant::now();
        let peer = PeerId::random();
        let mut budget = ResponseBudget::new(now);
        assert!(!budget.admit(
            peer,
            ResponseClass::Block,
            super::super::MAX_STORED_BLOCK_SIZE + 2,
            now
        ));
        assert!(budget.peers.is_empty());
        for _ in 0..16 {
            assert!(budget.admit(peer, ResponseClass::Block, MIB as usize - 3, now));
        }
        assert!(!budget.admit(peer, ResponseClass::Block, 1, now - Duration::from_secs(1)));
        assert!(!budget.admit(peer, ResponseClass::Block, 1, now));
        budget.prune(now + RETENTION);
        assert!(budget.peers.is_empty());
        assert!(budget.admit(peer, ResponseClass::Block, MIB as usize, now + RETENTION));
    }
}
