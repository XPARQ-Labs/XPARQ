pub mod gossip;
pub mod swarm;
use crate::runtime::network::{
    CompactBlock, CompactBlockReconstruction, NetworkMessage, PeerInfo, TipInfo, VersionInfo,
};
use crate::runtime::node::Node;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use xparq::block::Block;
use xparq::block::Height;
use xparq::crypto::BlockHash;
use xparq::genesis::{ArtifactTrustAnchor, artifact_payload_hash};
use xparq::ledger::fork_choice::{Work, compare_chain_tips};
use xparq::qcash::recovery::ChainHeader;

const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_secs(5);
const PEER_RETRY_BASE: Duration = Duration::from_secs(2);
const PEER_RETRY_MAX: Duration = Duration::from_secs(60);
const PEER_BAN_SCORE_THRESHOLD: i32 = 100;
const PEER_FAILURE_PENALTY: i32 = 20;
const PEER_SUCCESS_REWARD: i32 = 2;
const PEER_SYNC_REWARD: i32 = 5;
const PEER_BAN_DURATION: Duration = Duration::from_secs(10 * 60);
pub const PEER_REQUEST_WINDOW: Duration = Duration::from_secs(10);
pub const MAX_PEER_REQUESTS_PER_WINDOW: u32 = 64;
const MIN_BLOCKS_PER_SYNC: u64 = 32;
const INITIAL_BLOCKS_PER_SYNC: u64 = 128;
const MAX_BLOCKS_PER_SYNC: u64 = 256;
const MAX_BLOCKS_PER_BATCH: u64 = 32;
const MAX_BLOCK_LOCATOR_HASHES: usize = 32;
const MAX_MISSING_PARENT_FETCHES_PER_POLL: usize = 64;
const MAX_MEMPOOL_INVENTORY_FETCH: usize = 128;

#[derive(Debug, Serialize, Deserialize)]
struct PeerCache {
    peers: Vec<CachedPeer>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CachedPeer {
    address: String,
    score: i32,
    failures: u32,
    last_seen_unix: Option<u64>,
    last_success_unix: Option<u64>,
    latency_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct PeerState {
    pub addr: SocketAddr,
    pub failures: u32,
    pub next_attempt: Instant,
    pub last_tip: Option<Height>,
    pub sync_window: u64,
    pub score: i32,
    pub ban_until: Option<Instant>,
    pub last_seen: Option<std::time::SystemTime>,
    pub last_success: Option<std::time::SystemTime>,
    pub latency: Option<Duration>,
}

impl PeerState {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            failures: 0,
            next_attempt: Instant::now(),
            last_tip: None,
            sync_window: INITIAL_BLOCKS_PER_SYNC,
            score: 0,
            ban_until: None,
            last_seen: Some(std::time::SystemTime::now()),
            last_success: None,
            latency: None,
        }
    }

    pub fn mark_ok(&mut self, tip: Option<Height>) {
        self.failures = 0;
        self.last_tip = tip;
        self.last_seen = Some(std::time::SystemTime::now());
        self.last_success = self.last_seen;
        self.score = self.score.saturating_sub(PEER_SUCCESS_REWARD).max(0);
        self.next_attempt = Instant::now() + DEFAULT_SYNC_INTERVAL;
    }

    pub fn mark_synced(&mut self, tip: Height, synced_blocks: usize) {
        self.failures = 0;
        self.last_tip = Some(tip);
        self.last_seen = Some(std::time::SystemTime::now());
        self.last_success = self.last_seen;
        self.score = self.score.saturating_sub(PEER_SYNC_REWARD).max(0);
        if synced_blocks as u64 >= self.sync_window {
            self.sync_window = self.sync_window.saturating_mul(2).min(MAX_BLOCKS_PER_SYNC);
        }
        self.next_attempt = Instant::now() + DEFAULT_SYNC_INTERVAL;
    }

    pub fn mark_failed(&mut self) {
        self.failures = self.failures.saturating_add(1);
        self.last_seen = Some(std::time::SystemTime::now());
        self.score = self.score.saturating_add(PEER_FAILURE_PENALTY);
        if self.score >= PEER_BAN_SCORE_THRESHOLD {
            self.ban_until = Some(Instant::now() + PEER_BAN_DURATION);
        }
        self.sync_window = self.sync_window.saturating_div(2).max(MIN_BLOCKS_PER_SYNC);
        let shift = self.failures.saturating_sub(1).min(5);
        let secs = PEER_RETRY_BASE
            .as_secs()
            .saturating_mul(1_u64 << shift)
            .min(PEER_RETRY_MAX.as_secs());
        self.next_attempt = Instant::now() + Duration::from_secs(secs);
    }

    pub fn is_banned(&self) -> bool {
        self.ban_until.is_some_and(|until| Instant::now() < until)
    }

    pub fn set_latency(&mut self, latency: Duration) {
        self.latency = Some(latency);
        self.last_seen = Some(std::time::SystemTime::now());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerPoll {
    Idle {
        remote_tip: Height,
        latency: Duration,
    },
    Synced {
        remote_tip: Height,
        synced_blocks: usize,
        latency: Duration,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParallelSyncReport {
    pub remote_tip: Height,
    pub applied_blocks: usize,
    pub used_peers: usize,
    pub used_peer_addrs: Vec<SocketAddr>,
    pub failed_peer_addrs: Vec<SocketAddr>,
}

#[derive(Clone, Debug)]
pub struct FastSyncDownload {
    pub peer: SocketAddr,
    pub headers: Vec<ChainHeader>,
    pub snapshot: Vec<u8>,
}

pub struct PeerConnection {
    addr: SocketAddr,
    handshaken: bool,
    request_ids: AtomicU64,
    node: Option<Arc<Mutex<Node>>>,
    request_window_started: Instant,
    request_count: u32,
}

impl PeerConnection {
    pub fn connect(addr: SocketAddr) -> Result<Self, String> {
        swarm::global()?.connect(addr)?;
        Ok(Self {
            addr,
            handshaken: false,
            request_ids: AtomicU64::new(1),
            node: None,
            request_window_started: Instant::now(),
            request_count: 0,
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn request(&mut self, message: NetworkMessage) -> Result<NetworkMessage, String> {
        if crate::SHUTDOWN_REQUESTED.load(AtomicOrdering::SeqCst) {
            return Err("node shutdown requested".to_string());
        }
        self.check_request_budget()?;
        swarm::global()?
            .request(self.addr, message)?
            .ok_or_else(|| "peer returned no response".to_string())
    }

    pub fn send(&mut self, message: NetworkMessage) -> Result<(), String> {
        if crate::SHUTDOWN_REQUESTED.load(AtomicOrdering::SeqCst) {
            return Err("node shutdown requested".to_string());
        }
        self.check_request_budget()?;
        if let Some(response) = swarm::global()?.request(self.addr, message)? {
            self.handle_unsolicited(response)?;
        }
        Ok(())
    }

    pub fn shutdown(&self) {
        if let Ok(swarm) = swarm::global() {
            swarm.disconnect(self.addr);
        }
    }

    pub fn is_handshaken(&self) -> bool {
        self.handshaken
    }

    pub fn mark_handshaken(&mut self) {
        self.handshaken = true;
    }

    pub fn attach_node(&mut self, node: &Arc<Mutex<Node>>) {
        self.node = Some(Arc::clone(node));
    }

    fn check_request_budget(&mut self) -> Result<(), String> {
        if self.request_window_started.elapsed() >= PEER_REQUEST_WINDOW {
            self.request_window_started = Instant::now();
            self.request_count = 0;
        }
        self.request_count = self.request_count.saturating_add(1);
        if self.request_count > MAX_PEER_REQUESTS_PER_WINDOW {
            return Err("peer request rate limit exceeded".to_string());
        }
        Ok(())
    }

    fn handle_unsolicited(&mut self, message: NetworkMessage) -> Result<(), String> {
        let message = match message {
            NetworkMessage::CompactBlock(compact) => return self.handle_compact_block(compact),
            message => message,
        };
        println!(
            "[P2P] unsolicited_message peer={} message={:?}",
            self.addr, message
        );
        let Some(node) = self.node.as_ref().cloned() else {
            return Ok(());
        };
        let response = {
            let mut node = node
                .lock()
                .map_err(|_| "node state lock poisoned".to_string())?;
            crate::runtime::network::handle_message(&mut node, message)
                .map_err(|error| format!("unsolicited message handling failed: {error}"))?
        };
        if let Some(response) = response {
            if matches!(response, NetworkMessage::GetData(_)) {
                let data = self.request(response)?;
                let follow_up = {
                    let mut node = node
                        .lock()
                        .map_err(|_| "node state lock poisoned".to_string())?;
                    crate::runtime::network::handle_message(&mut node, data).map_err(|error| {
                        format!("unsolicited data response handling failed: {error}")
                    })?
                };
                if let Some(follow_up) = follow_up {
                    self.send(follow_up)?;
                }
                return Ok(());
            }
            self.send(response)?;
        }
        Ok(())
    }

    fn handle_compact_block(&mut self, compact: CompactBlock) -> Result<(), String> {
        let block_hash = compact
            .block_hash()
            .map_err(|error| format!("invalid compact block: {error}"))?;
        let Some(node) = self.node.as_ref().cloned() else {
            return Ok(());
        };
        let first_pass = {
            let node = node
                .lock()
                .map_err(|_| "node state lock poisoned".to_string())?;
            compact.reconstruct(&node.mempool, &[])
        };
        let missing = match first_pass {
            Ok(CompactBlockReconstruction::Complete(block)) => {
                let mut node = node
                    .lock()
                    .map_err(|_| "node state lock poisoned".to_string())?;
                node.apply_block(*block)
                    .map_err(|error| format!("compact block rejected: {error}"))?;
                crate::runtime::network::metrics::NETWORK_METRICS
                    .compact_success
                    .fetch_add(1, AtomicOrdering::Relaxed);
                return Ok(());
            }
            Ok(CompactBlockReconstruction::Missing(indexes)) => {
                crate::runtime::network::metrics::NETWORK_METRICS
                    .compact_missing_transactions
                    .fetch_add(indexes.len() as u64, AtomicOrdering::Relaxed);
                if indexes.len() > crate::runtime::network::MAX_COMPACT_RECOVERY_TRANSACTIONS
                    || indexes.len().saturating_mul(4) > compact.short_ids.len().saturating_mul(3)
                {
                    return self.fetch_full_compact_fallback(block_hash, &node);
                }
                indexes
            }
            Err(error) => {
                eprintln!(
                    "[P2P] compact_reconstruction_failed peer={} hash={} error=\"{}\" fallback=full",
                    self.addr,
                    hex::encode(block_hash.0),
                    error
                );
                return self.fetch_full_compact_fallback(block_hash, &node);
            }
        };
        let response = match self.request(NetworkMessage::GetCompactBlockTransactions {
            block_hash,
            indexes: missing,
        }) {
            Ok(response) => response,
            Err(error) => {
                eprintln!(
                    "[P2P] compact_missing_request_failed peer={} hash={} error=\"{}\" fallback=full",
                    self.addr,
                    hex::encode(block_hash.0),
                    error
                );
                return self.fetch_full_compact_fallback(block_hash, &node);
            }
        };
        let NetworkMessage::CompactBlockTransactions {
            block_hash: response_hash,
            transactions,
        } = response
        else {
            return self.fetch_full_compact_fallback(block_hash, &node);
        };
        if response_hash != block_hash {
            return self.fetch_full_compact_fallback(block_hash, &node);
        }
        let reconstructed = {
            let node = node
                .lock()
                .map_err(|_| "node state lock poisoned".to_string())?;
            compact.reconstruct(&node.mempool, &transactions)
        };
        match reconstructed {
            Ok(CompactBlockReconstruction::Complete(block)) => {
                let mut node = node
                    .lock()
                    .map_err(|_| "node state lock poisoned".to_string())?;
                node.apply_block(*block)
                    .map_err(|error| format!("compact block rejected: {error}"))?;
                crate::runtime::network::metrics::NETWORK_METRICS
                    .compact_success
                    .fetch_add(1, AtomicOrdering::Relaxed);
                Ok(())
            }
            Ok(CompactBlockReconstruction::Missing(_)) | Err(_) => {
                self.fetch_full_compact_fallback(block_hash, &node)
            }
        }
    }

    fn fetch_full_compact_fallback(
        &mut self,
        block_hash: BlockHash,
        node: &Arc<Mutex<Node>>,
    ) -> Result<(), String> {
        crate::runtime::network::metrics::NETWORK_METRICS
            .compact_fallback
            .fetch_add(1, AtomicOrdering::Relaxed);
        let response = self.request(NetworkMessage::GetBlockByHash { hash: block_hash })?;
        let block = match response {
            NetworkMessage::Block(block) => block,
            NetworkMessage::Blocks(mut blocks) if blocks.len() == 1 => blocks.remove(0),
            NetworkMessage::Reject { message, .. } => {
                return Err(format!("compact full-block fallback rejected: {message}"));
            }
            _ => return Err("compact full-block fallback returned invalid response".to_string()),
        };
        if block
            .hash()
            .map_err(|error| format!("fallback block hash failed: {error}"))?
            != block_hash
        {
            return Err("compact full-block fallback hash mismatch".to_string());
        }
        let mut node = node
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        node.apply_block(block)
            .map_err(|error| format!("fallback block rejected: {error}"))
    }
}

pub fn load_peers_file(path: &str) -> Result<Vec<SocketAddr>, String> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("failed to read peers file {path}: {error}")),
    };
    if contents.trim_start().starts_with('{') {
        let cache = serde_json::from_str::<PeerCache>(&contents)
            .map_err(|error| format!("failed to parse peer cache {path}: {error}"))?;
        return cache
            .peers
            .into_iter()
            .map(|peer| {
                peer.address
                    .parse()
                    .map_err(|error| format!("invalid peer `{}` in {path}: {error}", peer.address))
            })
            .collect();
    }

    let mut peers = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        peers.push(
            line.parse()
                .map_err(|error| format!("invalid peer in {path} line {}: {error}", index + 1))?,
        );
    }
    Ok(peers)
}

pub fn save_peer_states_file(path: &str, peers: Vec<PeerState>) -> Result<(), String> {
    let cache = PeerCache {
        peers: peers
            .into_iter()
            .filter(|peer| !peer.is_banned())
            .map(|peer| CachedPeer {
                address: peer.addr.to_string(),
                score: peer.score,
                failures: peer.failures,
                last_seen_unix: unix_secs(peer.last_seen),
                last_success_unix: unix_secs(peer.last_success),
                latency_ms: peer.latency.map(|latency| latency.as_millis() as u64),
            })
            .collect(),
    };
    let contents = serde_json::to_string_pretty(&cache)
        .map_err(|error| format!("failed to encode peer cache {path}: {error}"))?;
    fs::write(path, contents).map_err(|error| format!("failed to write peers file {path}: {error}"))
}

fn unix_secs(time: Option<std::time::SystemTime>) -> Option<u64> {
    time.and_then(|time| {
        time.duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs())
    })
}

pub fn dedupe_peers(peers: &mut Vec<SocketAddr>) {
    let mut seen = HashSet::new();
    peers.retain(|peer| seen.insert(*peer));
}

pub fn poll_peer_connection(
    peer: &mut PeerConnection,
    node: &Arc<Mutex<Node>>,
    public_addrs: &[SocketAddr],
    sync_window: u64,
) -> Result<PeerPoll, String> {
    if peer.is_handshaken() {
        println!("[P2P] handshake_reuse peer={}", peer.addr());
    } else {
        println!("[P2P] handshake_start peer={}", peer.addr());
        handshake_peer(peer, node, public_addrs)?;
        peer.mark_handshaken();
        println!("[P2P] handshake_ok peer={}", peer.addr());
    }
    let latency = ping_peer(peer)?;
    let remote_tip = request_tip(peer)?;
    let local_tip = local_tip_info(node)?;
    println!(
        "[P2P] tip_check peer={} local={} remote={} remote_work={}",
        peer.addr(),
        local_tip
            .map(|tip| tip.height.0.to_string())
            .unwrap_or_else(|| "none".to_string()),
        remote_tip.height.0,
        work_hex(remote_tip.work)
    );
    if local_tip.is_none() {
        let sync_window = sync_window.clamp(MIN_BLOCKS_PER_SYNC, MAX_BLOCKS_PER_SYNC);
        let start = Height(0);
        let target = remote_tip.height.0.min(sync_window.saturating_sub(1));
        let headers = request_headers(peer, start, target, BlockHash::ZERO)?;
        request_blocks(peer, node, start, target, headers)?;
        request_missing_parent_blocks(peer, node)?;
        return Ok(PeerPoll::Synced {
            remote_tip: remote_tip.height,
            synced_blocks: target.saturating_add(1) as usize,
            latency,
        });
    }
    let Some(local_tip) = local_tip else {
        return Err("local tip became unavailable during peer synchronization".to_string());
    };
    if !is_remote_tip_better(&local_tip, &remote_tip) {
        println!(
            "[SYNC] skip_weaker_peer peer={} local_work={} remote_work={} local_height={} remote_height={}",
            peer.addr(),
            work_hex(local_tip.work),
            work_hex(remote_tip.work),
            local_tip.height.0,
            remote_tip.height.0
        );
        return Ok(PeerPoll::Idle {
            remote_tip: remote_tip.height,
            latency,
        });
    }

    let ancestor = request_common_ancestor(peer, node)?;
    let sync_window = sync_window.clamp(MIN_BLOCKS_PER_SYNC, MAX_BLOCKS_PER_SYNC);
    let target = remote_tip
        .height
        .0
        .min(ancestor.height.0.saturating_add(sync_window));
    println!(
        "[SYNC] plan peer={} ancestor={} target={} remote_tip={} window={}",
        peer.addr(),
        ancestor.height.0,
        target,
        remote_tip.height.0,
        sync_window
    );
    if target <= ancestor.height.0 {
        return Ok(PeerPoll::Idle {
            remote_tip: remote_tip.height,
            latency,
        });
    }
    let start = Height(ancestor.height.0.saturating_add(1));
    println!(
        "[SYNC] request_headers peer={} start={} target={}",
        peer.addr(),
        start.0,
        target
    );
    let headers = request_headers(peer, start, target, ancestor.hash)?;
    println!(
        "[SYNC] headers_ok peer={} count={} start={} target={}",
        peer.addr(),
        headers.len(),
        start.0,
        target
    );
    request_blocks(peer, node, start, target, headers)?;
    request_missing_parent_blocks(peer, node)?;
    Ok(PeerPoll::Synced {
        remote_tip: remote_tip.height,
        synced_blocks: target.saturating_sub(start.0).saturating_add(1) as usize,
        latency,
    })
}

pub fn sync_from_peers_parallel(
    peers: Vec<SocketAddr>,
    node: &Arc<Mutex<Node>>,
    public_addrs: &[SocketAddr],
    sync_window: u64,
) -> Result<ParallelSyncReport, String> {
    if crate::SHUTDOWN_REQUESTED.load(AtomicOrdering::SeqCst) {
        return Err("node shutdown requested".to_string());
    }
    let local_tip = local_tip_info(node)?;
    let local_height = local_tip.map(|tip| tip.height.0).unwrap_or(0);

    let mut candidates = Vec::new();
    for addr in peers {
        if crate::SHUTDOWN_REQUESTED.load(AtomicOrdering::SeqCst) {
            return Err("node shutdown requested".to_string());
        }
        let mut peer = match PeerConnection::connect(addr) {
            Ok(peer) => peer,
            Err(error) => {
                eprintln!("[SYNC] candidate_connect_failed peer={addr} error=\"{error}\"");
                continue;
            }
        };
        if let Err(error) = handshake_peer(&mut peer, node, public_addrs) {
            eprintln!("[SYNC] candidate_handshake_failed peer={addr} error=\"{error}\"");
            continue;
        }
        match request_tip(&mut peer) {
            Ok(tip) if local_tip.is_none_or(|local| is_remote_tip_better(&local, &tip)) => {
                candidates.push((addr, tip, peer))
            }
            Ok(_) => {}
            Err(error) => eprintln!("[SYNC] candidate_tip_failed peer={addr} error=\"{error}\""),
        }
    }

    let Some(leader_index) = candidates
        .iter()
        .enumerate()
        .max_by(|(_, (_, left, _)), (_, (_, right, _))| compare_tips(left, right))
        .map(|(index, _)| index)
    else {
        return Ok(ParallelSyncReport {
            remote_tip: Height(local_height),
            applied_blocks: 0,
            used_peers: 0,
            used_peer_addrs: Vec::new(),
            failed_peer_addrs: Vec::new(),
        });
    };

    let candidate_tips = candidates
        .iter()
        .map(|(addr, tip, _)| (*addr, *tip))
        .collect::<Vec<_>>();
    let (_, remote_tip, mut leader_connection) = candidates.swap_remove(leader_index);
    drop(candidates);
    let ancestor = request_common_ancestor(&mut leader_connection, node)?;
    let sync_window = sync_window.clamp(MIN_BLOCKS_PER_SYNC, MAX_BLOCKS_PER_SYNC);
    let target = remote_tip
        .height
        .0
        .min(ancestor.height.0.saturating_add(sync_window));
    if target <= ancestor.height.0 {
        return Ok(ParallelSyncReport {
            remote_tip: remote_tip.height,
            applied_blocks: 0,
            used_peers: 0,
            used_peer_addrs: Vec::new(),
            failed_peer_addrs: Vec::new(),
        });
    }
    let start = Height(ancestor.height.0.saturating_add(1));
    let headers = request_headers(&mut leader_connection, start, target, ancestor.hash)?;
    let ranges = plan_parallel_ranges(start, target, &headers, &candidate_tips);
    if ranges.is_empty() {
        return Ok(ParallelSyncReport {
            remote_tip: remote_tip.height,
            applied_blocks: 0,
            used_peers: 0,
            used_peer_addrs: Vec::new(),
            failed_peer_addrs: Vec::new(),
        });
    }

    let mut handles = Vec::new();
    for range in ranges {
        let node = Arc::clone(node);
        let public_addrs = public_addrs.to_vec();
        let candidates = candidate_tips.clone();
        handles.push(thread::spawn(move || {
            fetch_range_with_retries(range, candidates, &node, &public_addrs)
        }));
    }

    let mut downloaded = BTreeMap::new();
    let mut used_peers = HashSet::new();
    let mut failed_peers = HashSet::new();
    for handle in handles {
        let (start, peer, blocks, worker_failed_peers) = handle
            .join()
            .map_err(|_| "parallel sync worker panicked".to_string())??;
        used_peers.insert(peer);
        for failed_peer in worker_failed_peers {
            failed_peers.insert(failed_peer);
        }
        downloaded.insert(start, blocks);
    }
    let used_peer_addrs = used_peers.iter().copied().collect::<Vec<_>>();
    for peer in &used_peer_addrs {
        failed_peers.remove(peer);
    }
    let failed_peer_addrs = failed_peers.iter().copied().collect::<Vec<_>>();

    let mut node = node
        .lock()
        .map_err(|_| "node state lock poisoned".to_string())?;
    let mut expected_height = start.0;
    let mut applied_blocks = 0;
    for blocks in downloaded.into_values() {
        for block in blocks {
            let height = block.height();
            if height.0 != expected_height {
                return Err(format!(
                    "parallel sync downloaded height {} while applying height {}",
                    height.0, expected_height
                ));
            }
            node.apply_block(block).map_err(|error| {
                format!(
                    "failed to apply parallel synced block {}: {error}",
                    height.0
                )
            })?;
            expected_height = expected_height.saturating_add(1);
            applied_blocks += 1;
        }
    }

    println!(
        "[SYNC] applied through_height={} peers={} tip={}",
        expected_height.saturating_sub(1),
        used_peers.len(),
        node.tip_hash()
            .map(|hash| hex::encode(hash.0))
            .unwrap_or_else(|| "none".to_string())
    );

    Ok(ParallelSyncReport {
        remote_tip: remote_tip.height,
        applied_blocks,
        used_peers: used_peers.len(),
        used_peer_addrs,
        failed_peer_addrs,
    })
}

pub fn request_peers_connection(peer: &mut PeerConnection) -> Result<Vec<PeerInfo>, String> {
    match peer.request(NetworkMessage::GetPeers)? {
        NetworkMessage::Peers(peers) => Ok(peers),
        _ => Err("peer returned unexpected peers response".to_string()),
    }
}

pub fn sync_mempool_connection(
    peer: &mut PeerConnection,
    node: &Arc<Mutex<Node>>,
) -> Result<usize, String> {
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() / 30)
        .unwrap_or_default();
    let short_ids = {
        let node = node
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        node.mempool
            .transactions()
            .filter_map(|transaction| {
                transaction
                    .hash()
                    .ok()
                    .map(|hash| crate::runtime::network::handler::reconcile_short_id(epoch, hash))
            })
            .filter(|short_id| {
                short_id % crate::runtime::network::handler::RECONCILE_BUCKETS
                    == epoch % crate::runtime::network::handler::RECONCILE_BUCKETS
            })
            .take(crate::runtime::network::handler::MAX_RECONCILE_SHORT_IDS)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    };
    let response = peer.request(NetworkMessage::ReconcileMempool { epoch, short_ids })?;
    if matches!(response, NetworkMessage::Reject { .. }) {
        return Err("peer rejected mempool reconciliation".to_string());
    }
    let NetworkMessage::Transactions(transactions) = response else {
        return Ok(0);
    };
    let mut accepted = submit_mempool_transactions(peer, node, transactions)?;
    accepted += sync_mempool_inventory(peer, node)?;
    Ok(accepted)
}

fn sync_mempool_inventory(
    peer: &mut PeerConnection,
    node: &Arc<Mutex<Node>>,
) -> Result<usize, String> {
    let response = peer.request(NetworkMessage::GetMempoolInventory)?;
    let NetworkMessage::Inventory(items) = response else {
        return Ok(0);
    };
    let missing = {
        let node = node
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        items
            .into_iter()
            .filter_map(|item| match item {
                crate::runtime::network::InventoryItem::Transaction(hash)
                    if !node.mempool.contains(&hash) =>
                {
                    Some(crate::runtime::network::InventoryItem::Transaction(hash))
                }
                _ => None,
            })
            .take(MAX_MEMPOOL_INVENTORY_FETCH)
            .collect::<Vec<_>>()
    };
    if missing.is_empty() {
        return Ok(0);
    }
    match peer.request(NetworkMessage::GetData(missing))? {
        NetworkMessage::Transactions(transactions) => {
            submit_mempool_transactions(peer, node, transactions)
        }
        NetworkMessage::Transaction(transaction) => {
            submit_mempool_transactions(peer, node, vec![transaction])
        }
        _ => Ok(0),
    }
}

fn submit_mempool_transactions(
    peer: &PeerConnection,
    node: &Arc<Mutex<Node>>,
    transactions: Vec<xparq::transaction::SignedProtocolTransaction>,
) -> Result<usize, String> {
    let mut accepted = 0;
    let mut node = node
        .lock()
        .map_err(|_| "node state lock poisoned".to_string())?;
    for transaction in transactions {
        match node.submit_protocol_transaction(transaction) {
            Ok(_) => accepted += 1,
            Err(error) => eprintln!(
                "mempool sync rejected transaction from {}: {error}",
                peer.addr()
            ),
        }
    }
    Ok(accepted)
}

fn handshake_peer(
    peer: &mut PeerConnection,
    node: &Arc<Mutex<Node>>,
    public_addrs: &[SocketAddr],
) -> Result<(), String> {
    peer.attach_node(node);
    let tip = {
        let node = node
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        local_tip_from_node(&node)
    };
    let version = VersionInfo::local(tip);
    match peer.request(NetworkMessage::Version(version))? {
        NetworkMessage::VerAck(remote) => {
            remote
                .validate_compatibility()
                .map_err(|reason| format!("peer returned incompatible version: {reason:?}"))?;
            if !public_addrs.is_empty() {
                peer.send(NetworkMessage::Peers(
                    public_addrs
                        .iter()
                        .map(|addr| PeerInfo {
                            address: addr.to_string(),
                        })
                        .collect(),
                ))?;
            }
            Ok(())
        }
        NetworkMessage::Reject { reason, message } => {
            Err(format!("peer rejected handshake: {reason:?}: {message}"))
        }
        _ => Err("peer returned unexpected handshake response".to_string()),
    }
}

fn handshake_bootstrap_peer(peer: &mut PeerConnection) -> Result<(), String> {
    match peer.request(NetworkMessage::Version(VersionInfo::local(None)))? {
        NetworkMessage::VerAck(remote) => remote
            .validate_compatibility()
            .map_err(|reason| format!("peer returned incompatible version: {reason:?}")),
        NetworkMessage::Reject { reason, message } => {
            Err(format!("peer rejected handshake: {reason:?}: {message}"))
        }
        _ => Err("peer returned unexpected handshake response".to_string()),
    }
}

/// Downloads and independently validates complete header candidates, selects
/// the greatest-work chain, then downloads the snapshot bound to that tip.
pub fn download_authenticated_snapshot(peers: &[SocketAddr]) -> Result<FastSyncDownload, String> {
    if peers.is_empty() {
        return Err("authenticated fast-sync requires at least one peer".to_string());
    }
    let mut candidates = Vec::new();
    for addr in peers {
        let candidate = (|| {
            let mut peer = PeerConnection::connect(*addr)?;
            handshake_bootstrap_peer(&mut peer)?;
            let tip = request_tip(&mut peer)?;
            let headers = request_headers(&mut peer, Height(0), tip.height.0, BlockHash::ZERO)?;
            let (anchor, work) = ArtifactTrustAnchor::from_verified_header_chain(&headers)
                .map_err(|error| format!("header chain failed PoW validation: {error}"))?;
            if anchor.height() != tip.height
                || anchor.block_hash() != tip.hash
                || work.to_be_limbs() != tip.work
            {
                return Err("peer tip does not match its authenticated header chain".to_string());
            }
            Ok::<_, String>((*addr, tip, headers, work))
        })();
        match candidate {
            Ok(candidate) => candidates.push(candidate),
            Err(error) => {
                eprintln!("[FASTSYNC] candidate_rejected peer={addr} error=\"{error}\"")
            }
        }
    }
    let (peer_addr, tip, headers, _) = candidates
        .into_iter()
        .max_by(|(_, left, _, _), (_, right, _, _)| compare_tips(left, right))
        .ok_or_else(|| "no peer supplied a valid frozen-genesis PoW header chain".to_string())?;

    let mut peer = PeerConnection::connect(peer_addr)?;
    handshake_bootstrap_peer(&mut peer)?;
    let manifest = peer.request(NetworkMessage::GetSnapshotManifest {
        height: tip.height,
        block_hash: tip.hash,
    })?;
    let NetworkMessage::SnapshotManifest {
        height,
        block_hash,
        size,
        content_hash,
        chunk_size,
    } = manifest
    else {
        return Err("selected peer did not return a snapshot manifest".to_string());
    };
    if height != tip.height
        || block_hash != tip.hash
        || size == 0
        || size > crate::snapshot::MAX_FAST_SYNC_BUNDLE_SIZE
        || chunk_size == 0
        || chunk_size > crate::runtime::network::handler::SNAPSHOT_CHUNK_SIZE
    {
        return Err("selected peer returned an invalid snapshot manifest".to_string());
    }
    let capacity =
        usize::try_from(size).map_err(|_| "snapshot size exceeds this platform".to_string())?;
    let mut snapshot = Vec::with_capacity(capacity);
    while snapshot.len() < capacity {
        let offset = snapshot.len() as u64;
        let remaining = capacity - snapshot.len();
        let length = remaining.min(chunk_size as usize) as u32;
        match peer.request(NetworkMessage::GetSnapshotChunk {
            height,
            block_hash,
            offset,
            length,
        })? {
            NetworkMessage::SnapshotChunk {
                height: chunk_height,
                block_hash: chunk_hash,
                offset: chunk_offset,
                compression,
                uncompressed_length,
                bytes,
            } if chunk_height == height
                && chunk_hash == block_hash
                && chunk_offset == offset
                && !bytes.is_empty()
                && uncompressed_length == length
                && bytes.len() <= length as usize =>
            {
                let decoded = crate::snapshot::decompress_chunk(
                    compression,
                    &bytes,
                    uncompressed_length as usize,
                )?;
                snapshot.extend_from_slice(&decoded);
            }
            _ => return Err("selected peer returned an invalid snapshot chunk".to_string()),
        }
    }
    if snapshot.len() != capacity || artifact_payload_hash(&snapshot) != content_hash {
        return Err("downloaded snapshot content hash mismatch".to_string());
    }
    Ok(FastSyncDownload {
        peer: peer_addr,
        headers,
        snapshot,
    })
}

fn request_tip(peer: &mut PeerConnection) -> Result<TipInfo, String> {
    match peer.request(NetworkMessage::GetTip)? {
        NetworkMessage::Tip(tip) => Ok(tip),
        _ => Err("peer returned unexpected tip response".to_string()),
    }
}

fn ping_peer(peer: &mut PeerConnection) -> Result<Duration, String> {
    let nonce = peer.request_ids.fetch_add(1, AtomicOrdering::Relaxed);
    let started = Instant::now();
    match peer.request(NetworkMessage::Ping { nonce })? {
        NetworkMessage::Pong {
            nonce: response_nonce,
        } if response_nonce == nonce => Ok(started.elapsed()),
        NetworkMessage::Reject { message, .. } => Err(format!("peer rejected ping: {message}")),
        _ => Err("peer returned unexpected ping response".to_string()),
    }
}

fn local_tip_info(node: &Arc<Mutex<Node>>) -> Result<Option<TipInfo>, String> {
    let node = node
        .lock()
        .map_err(|_| "node state lock poisoned".to_string())?;
    Ok(local_tip_from_node(&node))
}

fn local_tip_from_node(node: &Node) -> Option<TipInfo> {
    Some(TipInfo {
        height: node.tip_height()?,
        hash: node.tip_hash()?,
        work: node.tip_work()?,
    })
}

fn is_remote_tip_better(local: &TipInfo, remote: &TipInfo) -> bool {
    compare_tips(remote, local).is_gt()
}

fn compare_tips(left: &TipInfo, right: &TipInfo) -> Ordering {
    compare_chain_tips(
        Work::from_be_limbs(left.work),
        left.hash,
        Work::from_be_limbs(right.work),
        right.hash,
    )
}

fn work_hex(work: [u64; 8]) -> String {
    let mut bytes = Vec::with_capacity(64);
    for limb in work {
        bytes.extend_from_slice(&limb.to_be_bytes());
    }
    let encoded = hex::encode(bytes);
    let trimmed = encoded.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

fn request_blocks(
    peer: &mut PeerConnection,
    node: &Arc<Mutex<Node>>,
    start: Height,
    target: u64,
    headers: Vec<ChainHeader>,
) -> Result<(), String> {
    let blocks = fetch_blocks(peer, start, target, headers)?;
    let mut node = node
        .lock()
        .map_err(|_| "node state lock poisoned".to_string())?;
    for block in blocks {
        if crate::SHUTDOWN_REQUESTED.load(AtomicOrdering::SeqCst) {
            return Err("node shutdown requested".to_string());
        }
        let height = block.height();
        node.apply_block(block).map_err(|error| {
            format!(
                "failed to apply block {} from {}: {error}",
                height.0,
                peer.addr()
            )
        })?;
    }
    println!(
        "synced blocks through height {} from {} |tip::{}|",
        target,
        peer.addr(),
        node.tip_hash()
            .map(|hash| hex::encode(hash.0))
            .unwrap_or_else(|| "none".to_string())
    );
    Ok(())
}

fn fetch_blocks(
    peer: &mut PeerConnection,
    start: Height,
    target: u64,
    headers: Vec<ChainHeader>,
) -> Result<Vec<Block>, String> {
    let mut downloaded = Vec::new();
    let mut next_height = start.0;
    let mut expected_headers = headers.into_iter().peekable();
    while next_height <= target {
        if crate::SHUTDOWN_REQUESTED.load(AtomicOrdering::SeqCst) {
            return Err("node shutdown requested".to_string());
        }
        let remaining = target.saturating_sub(next_height).saturating_add(1);
        let limit = remaining.min(MAX_BLOCKS_PER_BATCH) as u32;
        println!(
            "peer {} downloading blocks:: |start::{}|limit::{}|target::{}|",
            peer.addr(),
            next_height,
            limit,
            target
        );
        let response = peer.request(NetworkMessage::GetBlocksByHeightRange {
            start: Height(next_height),
            limit,
        })?;
        let NetworkMessage::Blocks(blocks) = response else {
            return Err(format!(
                "peer did not return block range starting at height {}",
                next_height
            ));
        };
        if blocks.is_empty() {
            return Err(format!(
                "peer returned empty block range starting at height {}",
                next_height
            ));
        }

        for block in blocks {
            let height = block.height();
            if height.0 != next_height {
                return Err(format!(
                    "peer returned height {} while syncing height {}",
                    height.0, next_height
                ));
            }
            let Some(expected_header) = expected_headers.next() else {
                return Err(format!(
                    "peer returned block {} without a prevalidated header",
                    height.0
                ));
            };
            if block.header != expected_header.header {
                return Err(format!(
                    "peer returned block {} that does not match its prevalidated header",
                    height.0
                ));
            }
            downloaded.push(block);
            next_height = next_height.saturating_add(1);
        }
    }
    Ok(downloaded)
}

#[derive(Debug, Clone)]
struct SyncRange {
    peer: SocketAddr,
    start: Height,
    target: u64,
    headers: Vec<ChainHeader>,
}

fn fetch_range_with_retries(
    range: SyncRange,
    candidates: Vec<(SocketAddr, TipInfo)>,
    node: &Arc<Mutex<Node>>,
    public_addrs: &[SocketAddr],
) -> Result<(u64, SocketAddr, Vec<Block>, Vec<SocketAddr>), String> {
    let mut peers = Vec::new();
    peers.push(range.peer);
    peers.extend(
        candidates
            .into_iter()
            .filter(|(addr, tip)| *addr != range.peer && tip.height.0 >= range.target)
            .map(|(addr, _)| addr),
    );

    let mut last_error = None;
    let mut failed_peers = Vec::new();
    for peer_addr in peers {
        if crate::SHUTDOWN_REQUESTED.load(AtomicOrdering::SeqCst) {
            return Err("node shutdown requested".to_string());
        }
        let mut peer = match PeerConnection::connect(peer_addr) {
            Ok(peer) => peer,
            Err(error) => {
                failed_peers.push(peer_addr);
                last_error = Some(format!("connect {peer_addr} failed: {error}"));
                continue;
            }
        };
        if let Err(error) = handshake_peer(&mut peer, node, public_addrs) {
            failed_peers.push(peer_addr);
            last_error = Some(format!("handshake {peer_addr} failed: {error}"));
            continue;
        }
        match fetch_blocks(&mut peer, range.start, range.target, range.headers.clone()) {
            Ok(blocks) => {
                if peer_addr != range.peer {
                    println!(
                        "parallel sync reassigned range {}..{} from {} to {}",
                        range.start.0, range.target, range.peer, peer_addr
                    );
                }
                return Ok((range.start.0, peer_addr, blocks, failed_peers));
            }
            Err(error) => {
                failed_peers.push(peer_addr);
                last_error = Some(format!(
                    "download {}..{} from {} failed: {error}",
                    range.start.0, range.target, peer_addr
                ));
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        format!(
            "no peer could download range {}..{}",
            range.start.0, range.target
        )
    }))
}

fn plan_parallel_ranges(
    start: Height,
    target: u64,
    headers: &[ChainHeader],
    candidates: &[(SocketAddr, TipInfo)],
) -> Vec<SyncRange> {
    let mut available = candidates
        .iter()
        .copied()
        .filter(|(_, tip)| tip.height.0 >= target)
        .collect::<Vec<_>>();
    available.sort_by(|(_, left), (_, right)| compare_tips(right, left));
    let available = available
        .into_iter()
        .map(|(addr, _)| addr)
        .collect::<Vec<_>>();
    if available.is_empty() {
        return Vec::new();
    }

    let mut ranges = Vec::new();
    let mut next_height = start.0;
    let mut header_index = 0;
    while next_height <= target {
        let remaining = target.saturating_sub(next_height).saturating_add(1);
        let count = remaining.min(MAX_BLOCKS_PER_BATCH) as usize;
        let peer = available[ranges.len() % available.len()];
        ranges.push(SyncRange {
            peer,
            start: Height(next_height),
            target: next_height.saturating_add(count as u64).saturating_sub(1),
            headers: headers[header_index..header_index + count].to_vec(),
        });
        next_height = next_height.saturating_add(count as u64);
        header_index += count;
    }
    ranges
}

fn request_headers(
    peer: &mut PeerConnection,
    start: Height,
    target: u64,
    anchor_hash: BlockHash,
) -> Result<Vec<ChainHeader>, String> {
    let mut next_height = start.0;
    let mut previous_hash = anchor_hash;
    let mut headers = Vec::new();

    while next_height <= target {
        let remaining = target.saturating_sub(next_height).saturating_add(1);
        let limit = remaining.min(MAX_BLOCKS_PER_BATCH) as u32;
        let response = peer.request(NetworkMessage::GetBlockHeadersByHeightRange {
            start: Height(next_height),
            limit,
        })?;
        let NetworkMessage::BlockHeaders(batch) = response else {
            return Err(format!(
                "peer did not return header range starting at height {}",
                next_height
            ));
        };
        if batch.is_empty() {
            return Err(format!(
                "peer returned empty header range starting at height {}",
                next_height
            ));
        }

        for header in batch {
            if header.height.0 != next_height {
                return Err(format!(
                    "peer returned header height {} while syncing height {}",
                    header.height.0, next_height
                ));
            }
            if header.header.previous_hash.0 != previous_hash.0 {
                return Err(format!(
                    "peer returned header {} with unexpected parent {}",
                    header.height.0,
                    hex::encode(header.header.previous_hash.0)
                ));
            }
            previous_hash = header.hash().map_err(|error| error.to_string())?;
            headers.push(header);
            next_height = next_height.saturating_add(1);
        }
    }

    Ok(headers)
}

fn request_common_ancestor(
    peer: &mut PeerConnection,
    node: &Arc<Mutex<Node>>,
) -> Result<TipInfo, String> {
    let locator = block_locator(node)?;
    match peer.request(NetworkMessage::GetCommonAncestor { locator })? {
        NetworkMessage::CommonAncestor(Some(ancestor)) => Ok(ancestor),
        NetworkMessage::CommonAncestor(None) => {
            Err("peer did not find a common ancestor from local locator".to_string())
        }
        _ => Err("peer returned unexpected common ancestor response".to_string()),
    }
}

fn block_locator(node: &Arc<Mutex<Node>>) -> Result<Vec<BlockHash>, String> {
    let node = node
        .lock()
        .map_err(|_| "node state lock poisoned".to_string())?;
    let Some(tip_height) = node.tip_height() else {
        return Ok(Vec::new());
    };

    let mut locator = Vec::new();
    let mut height = tip_height.0;
    let mut step = 1_u64;
    loop {
        if let Some(header) = node.ledger.chain.header(&Height(height)) {
            locator.push(header.hash().map_err(|error| error.to_string())?);
        }
        if height == 0 || locator.len() >= MAX_BLOCK_LOCATOR_HASHES {
            break;
        }
        height = height.saturating_sub(step);
        if locator.len() >= 10 {
            step = step.saturating_mul(2);
        }
    }

    if locator.last().is_some_and(|hash| {
        node.ledger
            .chain
            .header(&Height(0))
            .is_some_and(|header| header.hash() != Ok(*hash))
    }) && let Some(genesis) = node.ledger.chain.header(&Height(0))
    {
        locator.push(genesis.hash().map_err(|error| error.to_string())?);
    }

    Ok(locator)
}

fn request_missing_parent_blocks(
    peer: &mut PeerConnection,
    node: &Arc<Mutex<Node>>,
) -> Result<bool, String> {
    let mut requested = false;
    let mut fetched = 0_usize;
    let mut missing = 0_usize;
    let mut first_hash = None;
    let mut last_hash = None;
    while fetched < MAX_MISSING_PARENT_FETCHES_PER_POLL {
        let hashes = node
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?
            .drain_missing_parent_requests();
        if hashes.is_empty() {
            break;
        }
        for hash in hashes {
            if fetched >= MAX_MISSING_PARENT_FETCHES_PER_POLL {
                node.lock()
                    .map_err(|_| "node state lock poisoned".to_string())?
                    .retry_missing_parent_request(hash);
                break;
            }
            requested = true;
            first_hash.get_or_insert(hash);
            last_hash = Some(hash);
            fetched = fetched.saturating_add(1);
            match request_block_by_hash(peer, node, hash) {
                Ok(true) => {}
                Ok(false) => {
                    missing = missing.saturating_add(1);
                }
                Err(error) => {
                    node.lock()
                        .map_err(|_| "node state lock poisoned".to_string())?
                        .retry_missing_parent_request(hash);
                    return Err(error);
                }
            }
            if missing > 0 {
                node.lock()
                    .map_err(|_| "node state lock poisoned".to_string())?
                    .retry_missing_parent_request(hash);
                break;
            }
        }
    }
    if fetched > 0 {
        let tip = node
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?
            .tip_hash()
            .map(|hash| hex::encode(hash.0))
            .unwrap_or_else(|| "none".to_string());
        println!(
            "[SYNC] missing_parent_batch peer={} requested={} fetched={} missing={} first={} last={} tip={} limit={}",
            peer.addr(),
            fetched,
            fetched.saturating_sub(missing),
            missing,
            first_hash
                .map(|hash| hex::encode(hash.0))
                .unwrap_or_else(|| "none".to_string()),
            last_hash
                .map(|hash| hex::encode(hash.0))
                .unwrap_or_else(|| "none".to_string()),
            tip,
            MAX_MISSING_PARENT_FETCHES_PER_POLL
        );
    }
    Ok(requested)
}

fn request_block_by_hash(
    peer: &mut PeerConnection,
    node: &Arc<Mutex<Node>>,
    hash: BlockHash,
) -> Result<bool, String> {
    let response = peer.request(NetworkMessage::GetBlockByHash { hash })?;
    let block = match response {
        NetworkMessage::Block(block) => block,
        NetworkMessage::Reject { reason, message } => {
            println!(
                "[SYNC] missing_parent_unavailable hash={} peer={} reason={reason:?} message=\"{}\"",
                hex::encode(hash.0),
                peer.addr(),
                message
            );
            return Ok(false);
        }
        _ => {
            return Err(format!(
                "peer did not return block hash {}",
                hex::encode(hash.0)
            ));
        }
    };
    let mut node = node
        .lock()
        .map_err(|_| "node state lock poisoned".to_string())?;
    node.apply_block(block).map_err(|error| {
        format!(
            "failed to apply missing parent from {}: {error}",
            peer.addr()
        )
    })?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xparq::crypto::HASH_SIZE;

    fn tip(height: u64, work: [u64; 8], hash_byte: u8) -> TipInfo {
        TipInfo {
            height: Height(height),
            hash: BlockHash([hash_byte; HASH_SIZE]),
            work,
        }
    }

    #[test]
    fn tip_comparison_prefers_chainwork_over_height() {
        let local = tip(100, [0, 0, 0, 0, 0, 0, 0, 20], 2);
        let remote = tip(90, [0, 0, 0, 0, 0, 0, 0, 21], 3);

        assert!(is_remote_tip_better(&local, &remote));
    }

    #[test]
    fn tip_comparison_rejects_weaker_bootstrap_peer() {
        let local = tip(249, [0, 0, 0, 0, 0, 0, 0, 25], 2);
        let remote = tip(242, [0, 0, 0, 0, 0, 0, 0, 24], 3);

        assert!(!is_remote_tip_better(&local, &remote));
    }

    #[test]
    fn tip_comparison_uses_lower_hash_as_equal_work_tiebreaker() {
        let local = tip(100, [0, 0, 0, 0, 0, 0, 0, 20], 9);
        let remote = tip(101, [0, 0, 0, 0, 0, 0, 0, 20], 1);

        assert!(is_remote_tip_better(&local, &remote));
    }
}
