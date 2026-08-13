use super::{PeerConnection, PeerState};
use crate::node_debug;
use crate::runtime::network::NetworkMessage;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, Default)]
pub struct BroadcastReport {
    pub attempted: usize,
    pub sent: usize,
    pub failed: usize,
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
