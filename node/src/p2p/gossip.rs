use super::{PeerConnection, PeerState};
use crate::node_debug;
use crate::runtime::network::NetworkMessage;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
#[cfg(test)]
use xparq::crypto::HASH_SIZE;
use xparq::crypto::{BlockHash, TransactionHash};

#[derive(Debug, Clone, Copy, Default)]
pub struct BroadcastReport {
    pub attempted: usize,
    pub sent: usize,
    pub failed: usize,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct GossipDedupe {
    capacity: usize,
    blocks: HashSet<BlockHash>,
    block_order: VecDeque<BlockHash>,
    transactions: HashSet<TransactionHash>,
    transaction_order: VecDeque<TransactionHash>,
}

impl GossipDedupe {
    #[allow(dead_code)]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            blocks: HashSet::new(),
            block_order: VecDeque::new(),
            transactions: HashSet::new(),
            transaction_order: VecDeque::new(),
        }
    }

    #[allow(dead_code)]
    pub fn mark_block_seen(&mut self, hash: BlockHash) -> bool {
        mark_seen(self.capacity, &mut self.blocks, &mut self.block_order, hash)
    }

    #[allow(dead_code)]
    pub fn mark_transaction_seen(&mut self, hash: TransactionHash) -> bool {
        mark_seen(
            self.capacity,
            &mut self.transactions,
            &mut self.transaction_order,
            hash,
        )
    }
}

#[allow(dead_code)]
fn mark_seen<T: Copy + Eq + std::hash::Hash>(
    capacity: usize,
    seen: &mut HashSet<T>,
    order: &mut VecDeque<T>,
    value: T,
) -> bool {
    if seen.contains(&value) {
        return false;
    }
    if capacity == 0 {
        return true;
    }
    seen.insert(value);
    order.push_back(value);
    while seen.len() > capacity {
        if let Some(evicted) = order.pop_front() {
            seen.remove(&evicted);
        }
    }
    true
}

pub fn broadcast_to_peers(
    _peers: &Arc<Mutex<HashMap<SocketAddr, PeerState>>>,
    _peer_connections: &Arc<Mutex<HashMap<SocketAddr, PeerConnection>>>,
    _inbound_connections: &Arc<Mutex<HashMap<SocketAddr, PeerConnection>>>,
    message: NetworkMessage,
) -> BroadcastReport {
    let swarm = match super::swarm::global() {
        Ok(swarm) => swarm,
        Err(error) => {
            node_debug!("P2P", "broadcast_unavailable error={error:?}");
            return BroadcastReport::default();
        }
    };
    let peers = swarm.handshaken_peers();
    let mut report = BroadcastReport {
        attempted: peers.len(),
        sent: 0,
        failed: 0,
    };
    for batch in peers.chunks(16) {
        std::thread::scope(|scope| {
            let mut requests = Vec::with_capacity(batch.len());
            for peer in batch.iter().copied() {
                let swarm = swarm.clone();
                let message = message.clone();
                requests.push((peer, scope.spawn(move || swarm.request(peer, message))));
            }
            for (peer, request) in requests {
                match request.join() {
                    Ok(Ok(_)) => report.sent += 1,
                    Ok(Err(error)) => {
                        report.failed += 1;
                        node_debug!("P2P", "broadcast_failed peer={peer} error={error:?}");
                    }
                    Err(_) => {
                        report.failed += 1;
                        node_debug!("P2P", "broadcast_failed peer={peer} error=worker_panicked");
                    }
                }
            }
        });
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupe_tracks_seen_blocks_and_transactions() {
        let mut dedupe = GossipDedupe::new(2);
        let first_block = BlockHash([1; HASH_SIZE]);
        let second_block = BlockHash([2; HASH_SIZE]);
        let third_block = BlockHash([3; HASH_SIZE]);
        let transaction = TransactionHash([4; HASH_SIZE]);

        assert!(dedupe.mark_block_seen(first_block));
        assert!(!dedupe.mark_block_seen(first_block));
        assert!(dedupe.mark_block_seen(second_block));
        assert!(dedupe.mark_block_seen(third_block));
        assert!(dedupe.mark_block_seen(first_block));

        assert!(dedupe.mark_transaction_seen(transaction));
        assert!(!dedupe.mark_transaction_seen(transaction));
    }
}
