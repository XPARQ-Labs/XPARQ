use super::{PeerConnection, PeerState};
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
    peers: &Arc<Mutex<HashMap<SocketAddr, PeerState>>>,
    peer_connections: &Arc<Mutex<HashMap<SocketAddr, PeerConnection>>>,
    inbound_connections: &Arc<Mutex<HashMap<SocketAddr, PeerConnection>>>,
    message: NetworkMessage,
) -> BroadcastReport {
    let peers = match peers.lock() {
        Ok(peers) => peers.keys().copied().collect::<Vec<_>>(),
        Err(_) => {
            eprintln!("[P2P] peer_state_lock_poisoned");
            return BroadcastReport::default();
        }
    };

    let mut report = BroadcastReport {
        attempted: peers.len(),
        sent: 0,
        failed: 0,
    };
    let known_peers = peers
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    for peer in peers {
        let result = {
            let mut connections = match peer_connections.lock() {
                Ok(connections) => connections,
                Err(_) => {
                    report.failed += 1;
                    eprintln!("[P2P] peer_connection_lock_poisoned");
                    continue;
                }
            };
            let connect_result =
                if let std::collections::hash_map::Entry::Vacant(e) = connections.entry(peer) {
                    match PeerConnection::connect(peer) {
                        Ok(connection) => {
                            println!("[P2P] connected peer={peer}");
                            e.insert(connection);
                            Ok(())
                        }
                        Err(error) => Err(error),
                    }
                } else {
                    Ok(())
                };
            connect_result.and_then(|()| {
                connections
                    .get_mut(&peer)
                    .ok_or_else(|| format!("missing peer connection for {peer}"))
                    .and_then(|connection| connection.send(message.clone()))
            })
        };
        match result {
            Ok(()) => report.sent += 1,
            Err(error) => {
                report.failed += 1;
                if let Ok(mut connections) = peer_connections.lock() {
                    connections.remove(&peer);
                }
                eprintln!("[P2P] broadcast_failed peer={peer} error=\"{error}\"");
            }
        }
    }
    let inbound_peers = match inbound_connections.lock() {
        Ok(connections) => connections.keys().copied().collect::<Vec<_>>(),
        Err(_) => {
            eprintln!("[P2P] inbound_connection_lock_poisoned");
            Vec::new()
        }
    };
    for peer in inbound_peers {
        if known_peers.contains(&peer) {
            continue;
        }
        report.attempted += 1;
        let result = {
            let mut connections = match inbound_connections.lock() {
                Ok(connections) => connections,
                Err(_) => {
                    report.failed += 1;
                    eprintln!("[P2P] inbound_connection_lock_poisoned");
                    continue;
                }
            };
            connections
                .get_mut(&peer)
                .ok_or_else(|| format!("missing inbound connection for {peer}"))
                .and_then(|connection| connection.send(message.clone()))
        };
        match result {
            Ok(()) => report.sent += 1,
            Err(error) => {
                report.failed += 1;
                if let Ok(mut connections) = inbound_connections.lock() {
                    connections.remove(&peer);
                }
                eprintln!("[P2P] broadcast_inbound_failed peer={peer} error=\"{error}\"");
            }
        }
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
