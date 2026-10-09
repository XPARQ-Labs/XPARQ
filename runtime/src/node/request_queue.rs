//! Bounded round-robin service for admitted litep2p requests.
use litep2p::{PeerId, types::RequestId};
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

pub(super) const MAX_REQUEST_BYTES: usize = 3 + super::MAX_LOCATOR_HASHES * 32;
const MAX_PEERS: usize = 32;
const PER_PEER: usize = 2;
const MAX_BYTES: usize = MAX_PEERS * PER_PEER * MAX_REQUEST_BYTES;
const MAX_AGE: Duration = Duration::from_secs(2);

pub(super) struct QueuedRequest {
    pub peer: PeerId,
    pub id: RequestId,
    pub bytes: Vec<u8>,
    arrived: Instant,
}
#[derive(Default)]
pub(super) struct RequestQueue {
    peers: HashMap<PeerId, VecDeque<QueuedRequest>>,
    rotation: VecDeque<PeerId>,
    bytes: usize,
}
impl RequestQueue {
    pub fn can_push(&self, peer: PeerId, bytes: usize) -> bool {
        bytes <= MAX_REQUEST_BYTES
            && self.bytes + bytes <= MAX_BYTES
            && self
                .peers
                .get(&peer)
                .map_or(self.peers.len() < MAX_PEERS, |queue| queue.len() < PER_PEER)
    }
    pub fn push(&mut self, peer: PeerId, id: RequestId, bytes: Vec<u8>, now: Instant) {
        assert!(self.can_push(peer, bytes.len()));
        if !self.peers.contains_key(&peer) {
            self.rotation.push_back(peer);
        }
        self.bytes += bytes.len();
        self.peers
            .entry(peer)
            .or_default()
            .push_back(QueuedRequest {
                peer,
                id,
                bytes,
                arrived: now,
            });
    }
    pub fn next_size(&self) -> Option<usize> {
        self.rotation
            .front()
            .and_then(|peer| self.peers.get(peer))
            .and_then(|queue| queue.front())
            .map(|request| request.bytes.len())
    }
    pub fn pop(&mut self) -> Option<QueuedRequest> {
        let peer = self.rotation.pop_front()?;
        let queue = self.peers.get_mut(&peer).expect("rotation peer exists");
        let request = queue.pop_front().expect("rotation queue is nonempty");
        self.bytes -= request.bytes.len();
        if queue.is_empty() {
            self.peers.remove(&peer);
        } else {
            self.rotation.push_back(peer);
        }
        Some(request)
    }
    pub fn remove(&mut self, peer: PeerId) -> Vec<RequestId> {
        self.rotation.retain(|candidate| *candidate != peer);
        self.peers
            .remove(&peer)
            .into_iter()
            .flatten()
            .map(|request| {
                self.bytes -= request.bytes.len();
                request.id
            })
            .collect()
    }
    pub fn expire(&mut self, now: Instant) -> Vec<RequestId> {
        let mut expired = Vec::new();
        self.peers.retain(|_, queue| {
            while queue
                .front()
                .is_some_and(|request| now.saturating_duration_since(request.arrived) >= MAX_AGE)
            {
                let request = queue.pop_front().unwrap();
                self.bytes -= request.bytes.len();
                expired.push(request.id);
            }
            !queue.is_empty()
        });
        self.rotation.retain(|peer| self.peers.contains_key(peer));
        expired
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn id(value: usize) -> RequestId {
        RequestId::from(value)
    }
    #[test]
    fn healthy_peer_gets_a_turn_despite_continuous_flood_refills() {
        let now = Instant::now();
        let flood = PeerId::random();
        let healthy = PeerId::random();
        let mut queue = RequestQueue::default();
        queue.push(flood, id(0), vec![1], now);
        queue.push(flood, id(1), vec![1], now);
        assert!(!queue.can_push(flood, 1));
        queue.push(healthy, id(2), vec![1], now);
        assert_eq!(queue.pop().unwrap().peer, flood);
        queue.push(flood, id(3), vec![1], now);
        assert_eq!(queue.pop().unwrap().peer, healthy);
        assert_eq!(queue.pop().unwrap().id, id(1));
        assert_eq!(queue.pop().unwrap().id, id(3));
        assert_eq!(queue.bytes, 0);
        assert!(queue.rotation.is_empty());
    }
    #[test]
    fn caps_bytes_peers_and_disconnect_releases_capacity() {
        let now = Instant::now();
        let mut queue = RequestQueue::default();
        let peers: Vec<_> = (0..MAX_PEERS).map(|_| PeerId::random()).collect();
        for (i, peer) in peers.iter().enumerate() {
            queue.push(*peer, id(i * 2), vec![0; MAX_REQUEST_BYTES], now);
            queue.push(*peer, id(i * 2 + 1), vec![0; MAX_REQUEST_BYTES], now);
        }
        assert!(!queue.can_push(PeerId::random(), 0));
        assert!(!queue.can_push(peers[0], 1));
        assert_eq!(queue.remove(peers[0]), vec![id(0), id(1)]);
        assert!(queue.can_push(PeerId::random(), MAX_REQUEST_BYTES));
        assert!(!queue.can_push(peers[1], MAX_REQUEST_BYTES + 1));
        assert_eq!(queue.bytes, MAX_BYTES - 2 * MAX_REQUEST_BYTES);
    }
    #[test]
    fn expiration_preserves_fresh_requests_and_exact_byte_accounting() {
        let now = Instant::now();
        let peer = PeerId::random();
        let mut queue = RequestQueue::default();
        queue.push(peer, id(1), vec![1; 33], now);
        queue.push(peer, id(2), vec![1; 20], now + Duration::from_secs(1));
        assert!(queue.expire(now - Duration::from_secs(1)).is_empty());
        assert_eq!(queue.expire(now + MAX_AGE), vec![id(1)]);
        assert_eq!(queue.bytes, 20);
        assert_eq!(queue.pop().unwrap().id, id(2));
        assert!(queue.peers.is_empty());
    }
}
