//! Opt-in devnet transport. Its protocol is separate from the legacy TCP wire format.

use super::inbound_budget::{InboundBudget, Traffic};
use super::litep2p_peers::{self, Endpoint as PeerEndpoint, PeerBook};
use super::mempool::read_mempool;
use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use litep2p::{
    Litep2p, Litep2pEvent, PeerId,
    config::ConfigBuilder,
    crypto::ed25519::Keypair,
    protocol::{
        notification::{
            ConfigBuilder as NotificationConfigBuilder, NotificationEvent, ValidationResult,
        },
        request_response::{
            ConfigBuilder as RequestConfigBuilder, DialOptions, RequestResponseEvent,
        },
    },
    transport::{ConnectionLimitsConfig, tcp::config::Config as TcpConfig},
    types::{RequestId, protocol::ProtocolName},
};

use super::{
    BlockHash, EXPECTED_GENESIS_HASH, Handshake, HeaderSyncResult, Height, MAX_STORED_BLOCK_SIZE,
    MAX_STORED_TRANSACTION_SIZE, Work, block_bytes, canonical_bytes, canonical_decode,
    chain_spec_hash, compare_chain_tips, new_pow_memory,
};
use super::{
    chain_sync::{
        apply_verified_branch_stream, decode_locator, encode_locator, ledger_header_locator,
        ledger_header_state_at_height, map_peer_header_error,
    },
    config::database_path,
    gossip::accept_relayed_block,
    mempool::accept_relayed_transaction,
    protocol::validate_handshake,
    state::{
        cached_canonical_block_bytes, cached_handshake, load_or_initialize,
        load_or_initialize_header_snapshot,
    },
};
use crate::sync::{HeaderChainChunk, MAX_HEADER_CHAIN_CHUNK_HEADERS, decode_header_chain_chunk};
use kernel::{
    consensus::{
        HeaderAtHeight, HeaderValidationState, advance_header_validation_state_with_memory,
    },
    crypto::PoWMemory,
};

const REQUEST_PROTOCOL: &str = "/xparq/devnet/blocks/2";
const NOTIFY_PROTOCOL: &str = "/xparq/devnet/announce/2";
const REQUEST_TIP: u8 = 1;
const REQUEST_BLOCK: u8 = 2;
const REQUEST_HEADERS: u8 = 4;
const RESPONSE_HEADERS: u8 = 4;
const RESPONSE_COMPLETE: u8 = 5;
const ANNOUNCE_BLOCK: u8 = 1;
const ANNOUNCE_TRANSACTION: u8 = 2;
const ANNOUNCE_PEERS: u8 = 3;
const IDENTITY_KEY: &str = "litep2p-devnet-identity";
const MAX_ACTIVE_HEADER_SYNCS: usize = 1;
// Local transport budgets, not consensus limits.
const MAX_SYNC_HEADERS: usize = super::MAX_SYNC_HEADERS;
const MAX_ACCEPTED_PEERS: usize = 32;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const SESSION_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
const SYNC_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const RETRY_COOLDOWN: Duration = Duration::from_secs(30);
// Match the inbound request refill rate without blocking the network event loop.
pub(super) const SYNC_REQUEST_INTERVAL: Duration = Duration::from_millis(125);

// Retry history survives reconnects, but is bounded and expires locally.
const MAX_RETRY_PEERS: usize = MAX_ACCEPTED_PEERS * 2;
const RETRY_HISTORY: Duration = Duration::from_secs(60 * 60);
const MAX_RETRY_COOLDOWN: Duration = Duration::from_secs(30 * 60);

#[derive(Default)]
struct SyncBackoff(HashMap<PeerId, RetryState>);

struct RetryState {
    failures: u32,
    deadline: Instant,
    expires: Instant,
}

impl SyncBackoff {
    fn prune(&mut self, now: Instant) {
        self.0.retain(|_, state| state.expires > now);
    }

    fn blocked(&self, peer: PeerId, now: Instant) -> bool {
        self.0.get(&peer).is_some_and(|state| state.deadline > now)
    }

    fn fail(&mut self, peer: PeerId, now: Instant) {
        self.prune(now);
        if !self.0.contains_key(&peer)
            && self.0.len() >= MAX_RETRY_PEERS
            && let Some(oldest) = self
                .0
                .iter()
                .min_by_key(|(_, state)| state.expires)
                .map(|(&peer, _)| peer)
        {
            self.0.remove(&oldest);
        }
        let failures = self
            .0
            .get(&peer)
            .map_or(1, |state| state.failures.saturating_add(1));
        let duration = RETRY_COOLDOWN
            .saturating_mul(1_u32 << failures.saturating_sub(1).min(6))
            .min(MAX_RETRY_COOLDOWN);
        self.0.insert(
            peer,
            RetryState {
                failures,
                deadline: now + duration,
                expires: now + duration + RETRY_HISTORY,
            },
        );
    }

    fn succeeded(&mut self, peer: PeerId) {
        self.0.remove(&peer);
    }
}

#[derive(Debug, Clone, Copy)]
enum PendingKind {
    Tip,
    Headers,
    Block(usize),
}

struct DialAttempt {
    endpoint: PeerEndpoint,
    started: Instant,
    address: Option<String>,
}

fn connected_dial(
    peer: PeerId,
    outbound: bool,
    address: &str,
    dialing: &mut HashMap<PeerId, DialAttempt>,
) -> Option<PeerEndpoint> {
    let attempt = dialing.remove(&peer)?;
    // TCP reports its numeric endpoint without the /p2p identity suffix.
    // The authenticated peer ID is already the map key, so compare the socket
    // portion while retaining the explicit outbound-direction check.
    (outbound
        && attempt
            .address
            .as_deref()
            .and_then(|value| value.split("/p2p/").next())
            == Some(address))
    .then_some(attempt.endpoint)
}

fn failed_dial(
    address: &str,
    dialing: &mut HashMap<PeerId, DialAttempt>,
    book: &mut PeerBook,
    now: Instant,
) {
    let peer = dialing
        .iter()
        .find_map(|(&peer, attempt)| (attempt.address.as_deref() == Some(address)).then_some(peer));
    if let Some(peer) = peer
        && let Some(attempt) = dialing.remove(&peer)
    {
        book.failed(&attempt.endpoint, now);
    }
}

struct PeerSync {
    claim: Handshake,
    ledger: Arc<super::Ledger>,
    checkpoints: Arc<Vec<super::state::HeaderStateCheckpoint>>,
    local_work: Work,
    local_weight: u64,
    minimums: super::chain_minimums::ChainMinimums,
    local_locator: Vec<([u8; 32], Height)>,
    validation: Option<HeaderValidationState>,
    ancestor: Option<(Height, BlockHash)>,
    headers: Vec<HeaderAtHeight>,
    stage: Option<super::sync_stage::DiskStage>,
    started: Instant,
    progressed: Instant,
    pow_memory: Option<PoWMemory>,
}

impl PeerSync {
    fn new(database: &Path, claim: Handshake) -> Result<Self, String> {
        let (ledger, checkpoints, local_work, local_weight) =
            load_or_initialize_header_snapshot(database)?;
        let local_locator = ledger_header_locator(&ledger)?;
        Ok(Self {
            claim,
            ledger,
            checkpoints,
            local_work,
            local_weight,
            minimums: super::chain_minimums::configured(database)?,
            local_locator,
            validation: None,
            ancestor: None,
            headers: Vec::new(),
            stage: None,
            started: Instant::now(),
            progressed: Instant::now(),
            pow_memory: None,
        })
    }

    fn locator_request(&self) -> Result<Vec<u8>, String> {
        let mut request = vec![REQUEST_HEADERS];
        let locator = if let Some(validation) = &self.validation {
            vec![
                validation
                    .header
                    .hash()
                    .map_err(|error| error.to_string())?
                    .0,
                EXPECTED_GENESIS_HASH.0,
            ]
        } else {
            self.local_locator.iter().map(|(hash, _)| *hash).collect()
        };
        request.extend_from_slice(&encode_locator(&locator)?);
        Ok(request)
    }

    fn ancestor_state(&self, hash: [u8; 32]) -> Result<HeaderValidationState, String> {
        let height = self
            .local_locator
            .iter()
            .find_map(|(candidate, height)| (*candidate == hash).then_some(*height))
            .ok_or("peer ancestor is not in the local locator")?;
        ledger_header_state_at_height(&self.ledger, &self.checkpoints, height)
    }

    fn accept_headers(&mut self, response: &[u8]) -> Result<bool, String> {
        let (&kind, body) = response.split_first().ok_or("empty header response")?;
        let ancestor: [u8; 32] = body
            .get(..32)
            .ok_or("header response has no ancestor")?
            .try_into()
            .map_err(|_| "invalid ancestor hash")?;
        if kind == RESPONSE_COMPLETE {
            if body.len() != 32 {
                return Err("invalid header completion length".into());
            }
            let state = match &self.validation {
                Some(state) => state.clone(),
                None => self.ancestor_state(ancestor)?,
            };
            let tip_hash = state.header.hash().map_err(|error| error.to_string())?;
            if tip_hash.0 != ancestor
                || tip_hash.0 != self.claim.tip_hash
                || state.height != self.claim.tip_height
                || state.cumulative_work.to_be_limbs() != self.claim.cumulative_work
                || state.cumulative_weight != self.claim.cumulative_weight
            {
                return Err("peer claim does not match verified header tip".into());
            }
            if self.ancestor.is_none() {
                self.ancestor = Some((state.height, tip_hash));
            }
            self.validation = Some(state);
            return Ok(true);
        }
        if kind != RESPONSE_HEADERS {
            return Err("unexpected header response".into());
        }
        let chunk = decode_header_chain_chunk(&body[32..]).map_err(|error| error.to_string())?;
        // Freeze this download at the advertised tip even if the peer mines
        // additional blocks while serving headers. Later tips use another session.
        let headers = chunk
            .headers
            .into_iter()
            .take_while(|header| header.height <= self.claim.tip_height)
            .collect::<Vec<_>>();
        if headers.is_empty() {
            return Err("peer did not supply headers for its claimed tip".into());
        }
        if self.headers.len().saturating_add(headers.len()) > MAX_SYNC_HEADERS {
            return Err("header synchronization exceeds session limit".into());
        }
        let current = match &self.validation {
            Some(current) => {
                if current.header.hash().map_err(|error| error.to_string())?.0 != ancestor {
                    return Err("peer changed header ancestor during sync".into());
                }
                current.clone()
            }
            None => self.ancestor_state(ancestor)?,
        };
        if self.ancestor.is_none() {
            self.ancestor = Some((current.height, BlockHash(ancestor)));
        }
        let advanced = advance_header_validation_state_with_memory(
            &current,
            &headers,
            self.pow_memory.get_or_insert_with(new_pow_memory),
        )
        .map_err(map_peer_header_error)?;
        let complete = advanced.height == self.claim.tip_height;
        if complete {
            self.check_claim(&advanced)?;
        }
        self.headers.extend(headers);
        self.progressed = Instant::now();
        self.validation = Some(advanced);
        Ok(complete)
    }

    fn check_claim(&self, state: &HeaderValidationState) -> Result<(), String> {
        if state.header.hash().map_err(|error| error.to_string())?.0 != self.claim.tip_hash
            || state.height != self.claim.tip_height
            || state.cumulative_work.to_be_limbs() != self.claim.cumulative_work
            || state.cumulative_weight != self.claim.cumulative_weight
        {
            return Err("peer claim does not match verified header tip".into());
        }
        Ok(())
    }

    fn preferred(&self) -> Result<bool, String> {
        let state = self
            .validation
            .as_ref()
            .ok_or("missing verified header state")?;
        let local_hash = self.ledger.tip_hash().ok_or("local chain has no tip")?;
        Ok(self
            .minimums
            .allows(state.cumulative_work, state.cumulative_weight)
            && compare_chain_tips(
                state.cumulative_work,
                state.cumulative_weight,
                state.header.hash().map_err(|error| error.to_string())?,
                self.local_work,
                self.local_weight,
                local_hash,
            )
            .is_gt())
    }

    fn into_result(self) -> Result<(HeaderSyncResult, super::sync_stage::DiskStage), String> {
        let state = self.validation.ok_or("missing verified header state")?;
        let (ancestor_height, ancestor_hash) = self.ancestor.ok_or("missing common ancestor")?;
        Ok((
            HeaderSyncResult {
                ancestor_height,
                ancestor_hash,
                headers: self.headers,
                peer_work: state.cumulative_work,
                peer_weight: state.cumulative_weight,
                preferred: true,
            },
            self.stage.ok_or("missing completed staging database")?,
        ))
    }
}

fn multiaddr(address: SocketAddr) -> Result<litep2p::types::multiaddr::Multiaddr, String> {
    let family = match address.ip() {
        IpAddr::V4(_) => "ip4",
        IpAddr::V6(_) => "ip6",
    };
    format!("/{family}/{}/tcp/{}", address.ip(), address.port())
        .parse()
        .map_err(|error| format!("invalid P2P address: {error}"))
}

fn chain_identity() -> Result<Vec<u8>, String> {
    let mut identity = Vec::with_capacity(64);
    identity.extend_from_slice(&EXPECTED_GENESIS_HASH.0);
    identity.extend_from_slice(&chain_spec_hash().map_err(|error| error.to_string())?.0);
    Ok(identity)
}

fn load_identity(database: &Path) -> Result<Keypair, String> {
    let mut bytes = match crate::storage::auxiliary_get(database, IDENTITY_KEY)? {
        Some(bytes) => bytes,
        None => {
            let generated = Keypair::generate();
            crate::storage::auxiliary_get_or_insert(database, IDENTITY_KEY, &generated.to_bytes())?
        }
    };
    Keypair::try_from_bytes(&mut bytes)
        .map_err(|error| format!("invalid stored litep2p identity: {error}"))
}

fn local_tip(database: &Path) -> Result<[u8; 32], String> {
    Ok(cached_handshake(database)?.tip_hash)
}

fn valid_request_shape(request: &[u8]) -> bool {
    if request.len() > super::request_queue::MAX_REQUEST_BYTES {
        return false;
    }
    match request {
        [REQUEST_TIP] => true,
        [REQUEST_BLOCK, hash @ ..] => hash.len() == 32,
        [REQUEST_HEADERS, locator @ ..] => decode_locator(locator).is_ok(),
        _ => false,
    }
}

fn answer(database: &Path, request: &[u8]) -> Result<Vec<u8>, String> {
    match request {
        [REQUEST_TIP] => {
            let mut response = vec![REQUEST_TIP];
            response.extend_from_slice(
                &canonical_bytes(&cached_handshake(database)?)
                    .map_err(|error| error.to_string())?,
            );
            Ok(response)
        }
        [REQUEST_BLOCK, hash @ ..] if hash.len() == 32 => {
            let hash: [u8; 32] = hash.try_into().map_err(|_| "invalid block hash")?;
            let Some(block) = cached_canonical_block_bytes(database, hash)? else {
                return Ok(vec![0]);
            };
            let mut response = vec![REQUEST_BLOCK];
            response.extend_from_slice(&block);
            Ok(response)
        }
        [REQUEST_HEADERS, locator @ ..] => answer_headers(database, locator),
        _ => Err("unknown litep2p request".into()),
    }
}

fn answer_headers(database: &Path, locator: &[u8]) -> Result<Vec<u8>, String> {
    let locator = decode_locator(locator)?;
    let ledger = load_or_initialize(database)?;
    let mut height = ledger.tip_height().ok_or("canonical chain has no tip")?;
    let (ancestor_height, ancestor_hash) = loop {
        let block = ledger
            .chain
            .header(&height)
            .ok_or("canonical block is missing")?;
        let hash = block.hash().map_err(|error| error.to_string())?.0;
        if locator.contains(&hash) {
            break (height, hash);
        }
        height = Height(height.0.checked_sub(1).ok_or("no common ancestor")?);
    };
    let mut extension = Vec::with_capacity(MAX_HEADER_CHAIN_CHUNK_HEADERS);
    let mut next = ancestor_height.0.checked_add(1);
    while let Some(value) = next {
        if value > ledger.tip_height().ok_or("canonical chain has no tip")?.0
            || extension.len() >= MAX_HEADER_CHAIN_CHUNK_HEADERS
        {
            break;
        }
        let height = Height(value);
        let block = ledger
            .chain
            .header(&height)
            .ok_or("canonical block is missing")?;
        extension.push(HeaderAtHeight::new(height, block.clone()));
        next = value.checked_add(1);
    }
    let mut response = vec![if extension.is_empty() {
        RESPONSE_COMPLETE
    } else {
        RESPONSE_HEADERS
    }];
    response.extend_from_slice(&ancestor_hash);
    if !extension.is_empty() {
        response.extend_from_slice(
            &canonical_bytes(&HeaderChainChunk::new(extension).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?,
        );
    }
    Ok(response)
}

fn request_block(hash: [u8; 32]) -> Vec<u8> {
    let mut request = vec![REQUEST_BLOCK];
    request.extend_from_slice(&hash);
    request
}

fn process_response(
    database: &Path,
    peer: PeerId,
    kind: PendingKind,
    response: &[u8],
    sessions: &mut HashMap<PeerId, PeerSync>,
    staging_bytes: u64,
) -> Result<Option<(PendingKind, Vec<u8>)>, String> {
    match kind {
        PendingKind::Tip => {
            if response.first() != Some(&REQUEST_TIP) {
                return Err("unexpected tip response".into());
            }
            if sessions.len() >= MAX_ACTIVE_HEADER_SYNCS && !sessions.contains_key(&peer) {
                return Ok(None);
            }
            let claim: Handshake = canonical_decode(&response[1..])
                .map_err(|error| format!("decode peer tip: {error}"))?;
            validate_handshake(&claim)?;
            if !super::chain_minimums::allows(
                database,
                Work::from_be_limbs(claim.cumulative_work),
                claim.cumulative_weight,
            )? {
                return Ok(None);
            }
            let session = PeerSync::new(database, claim)?;
            let local_hash = session.ledger.tip_hash().ok_or("local chain has no tip")?;
            let claimed_work = Work::from_be_limbs(session.claim.cumulative_work);
            if !compare_chain_tips(
                claimed_work,
                session.claim.cumulative_weight,
                BlockHash(session.claim.tip_hash),
                session.local_work,
                session.local_weight,
                local_hash,
            )
            .is_gt()
            {
                return Ok(None);
            }
            println!(
                "litep2p: peer={peer} claimed_height={}",
                session.claim.tip_height.0
            );
            let request = session.locator_request()?;
            sessions.insert(peer, session);
            Ok(Some((PendingKind::Headers, request)))
        }
        PendingKind::Headers => {
            let session = sessions
                .get_mut(&peer)
                .ok_or("missing header sync session")?;
            if !session.accept_headers(response)? {
                return Ok(Some((PendingKind::Headers, session.locator_request()?)));
            }
            if !session.preferred()? {
                sessions.remove(&peer);
                return Ok(None);
            }
            if session.headers.is_empty() {
                sessions.remove(&peer);
                return Ok(None);
            }
            let branch = canonical_bytes(&(
                chain_identity()?,
                session.ancestor.ok_or("missing common ancestor")?.1,
            ))
            .map_err(|error| error.to_string())?;
            let stage = super::sync_stage::DiskStage::open(
                database,
                &branch,
                &session.headers,
                staging_bytes,
            )?;
            println!(
                "litep2p: peer={peer} staged_blocks={} staged_bytes={}",
                stage.count, stage.bytes
            );
            session.progressed = Instant::now();
            session.stage = Some(stage);
            finish_or_request(database, peer, sessions)
        }
        PendingKind::Block(index) => {
            let session = sessions
                .get_mut(&peer)
                .ok_or("missing block sync session")?;
            let stage = session
                .stage
                .as_mut()
                .ok_or("missing block staging database")?;
            if index != stage.count {
                return Err("unexpected block sequence".into());
            }
            let expected = session.headers.get(index).ok_or("unexpected block index")?;
            if response.first() != Some(&REQUEST_BLOCK) {
                return Err("unexpected block response".into());
            }
            stage.append(&response[1..], expected)?;
            session.progressed = Instant::now();
            if stage.count == 1 {
                println!("litep2p: peer={peer} downloaded_blocks=1");
            }
            finish_or_request(database, peer, sessions)
        }
    }
}

fn finish_or_request(
    database: &Path,
    peer: PeerId,
    sessions: &mut HashMap<PeerId, PeerSync>,
) -> Result<Option<(PendingKind, Vec<u8>)>, String> {
    let session = sessions.get(&peer).ok_or("missing sync session")?;
    let stage = session
        .stage
        .as_ref()
        .ok_or("missing block staging database")?;
    if let Some(expected) = session.headers.get(stage.count) {
        return Ok(Some((
            PendingKind::Block(stage.count),
            request_block(expected.hash().map_err(|error| error.to_string())?.0),
        )));
    }
    let session = sessions
        .remove(&peer)
        .ok_or("missing completed sync session")?;
    let (sync, mut stage) = session.into_result()?;
    let applied = apply_verified_branch_stream(
        database,
        sync,
        (0..stage.count).map(|index| stage.read(index)),
    )?;
    if let Err(error) = stage.clear() {
        eprintln!("litep2p: applied branch but staging cleanup failed: {error}");
    }
    println!("litep2p: peer={peer} applied_blocks={applied}");
    Ok(None)
}

fn clear_sync(
    peer: PeerId,
    pending: &mut HashMap<RequestId, (PeerId, PendingKind)>,
    sessions: &mut HashMap<PeerId, PeerSync>,
) {
    pending.retain(|_, (owner, _)| *owner != peer);
    sessions.remove(&peer);
}

fn expire_sessions(
    now: Instant,
    pending: &mut HashMap<RequestId, (PeerId, PendingKind)>,
    sessions: &mut HashMap<PeerId, PeerSync>,
    cooldown: &mut SyncBackoff,
) {
    let expired = sessions
        .iter()
        .filter_map(|(&peer, session)| {
            (now.saturating_duration_since(session.started) >= SESSION_TIMEOUT
                || now.saturating_duration_since(session.progressed) >= SYNC_IDLE_TIMEOUT)
                .then_some(peer)
        })
        .collect::<Vec<_>>();
    for peer in expired {
        eprintln!("litep2p: sync session expired peer={peer}");
        clear_sync(peer, pending, sessions);
        cooldown.fail(peer, now);
    }
}

/// Poll tips serially in arrival order so response speed cannot choose every session.
fn next_sync_peer(
    peers: &mut VecDeque<PeerId>,
    accepted: &HashSet<PeerId>,
    cooldown: &SyncBackoff,
    now: Instant,
) -> Option<PeerId> {
    for _ in 0..peers.len() {
        let peer = peers.pop_front()?;
        if !accepted.contains(&peer) {
            continue;
        }
        peers.push_back(peer);
        if !cooldown.blocked(peer, now) {
            return Some(peer);
        }
    }
    None
}

fn can_request(peer: PeerId, pending: &HashMap<RequestId, (PeerId, PendingKind)>) -> bool {
    pending.len() < MAX_ACCEPTED_PEERS && !pending.values().any(|(owner, _)| *owner == peer)
}

pub(super) fn run(path: Option<&str>, listen: &str, peers: &[String]) -> Result<(), String> {
    run_database(
        database_path(path),
        listen,
        peers,
        super::sync_stage::DEFAULT_STAGING_BYTES,
        None,
        false,
    )
}

pub(super) fn run_database(
    database: PathBuf,
    listen: &str,
    peers: &[String],
    staging_bytes: u64,
    advertise: Option<super::PeerAddress>,
    private_discovery: bool,
) -> Result<(), String> {
    load_or_initialize(&database)?;
    let listen: SocketAddr = listen
        .parse()
        .map_err(|_| "litep2p listen address must be numeric")?;
    let advertise = advertise.or_else(|| {
        (private_discovery || super::is_admissible_discovered_peer(&listen))
            .then_some(super::PeerAddress::Ip(listen))
    });
    let listen = multiaddr(listen)?;
    if peers.len() > MAX_ACCEPTED_PEERS / 2 {
        return Err("litep2p supports at most 16 configured outbound peers".into());
    }
    let book = PeerBook::load(&database, peers, private_discovery, Instant::now())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("start litep2p runtime: {error}"))?;
    runtime.block_on(run_async(database, listen, book, staging_bytes, advertise))
}

async fn run_async(
    database: PathBuf,
    listen: litep2p::types::multiaddr::Multiaddr,
    mut book: PeerBook,
    staging_bytes: u64,
    advertise: Option<super::PeerAddress>,
) -> Result<(), String> {
    let identity = chain_identity()?;
    let keypair = load_identity(&database)?;
    let (request_config, mut requests) =
        RequestConfigBuilder::new(ProtocolName::from(REQUEST_PROTOCOL))
            .with_max_size(MAX_STORED_BLOCK_SIZE + 1)
            .with_timeout(REQUEST_TIMEOUT)
            .with_max_concurrent_inbound_requests(8)
            .with_max_pending_inbound_requests(32)
            .with_max_inbound_requests_per_peer(2)
            .with_inbound_timeout(Duration::from_secs(5))
            .with_max_inbound_request_size(super::request_queue::MAX_REQUEST_BYTES)
            .build();
    let (notification_config, mut notifications) =
        NotificationConfigBuilder::new(ProtocolName::from(NOTIFY_PROTOCOL))
            .with_max_size(MAX_STORED_BLOCK_SIZE + 1)
            .with_max_handshake_size(64)
            .with_auto_accept_inbound(false)
            .with_handshake(identity.clone())
            .build();
    let config = ConfigBuilder::new()
        .with_keypair(keypair)
        .with_max_parallel_dials(4)
        .with_connection_limits(
            ConnectionLimitsConfig::default()
                .max_incoming_connections(Some(16))
                .max_outgoing_connections(Some(16)),
        )
        .with_tcp(TcpConfig {
            listen_addresses: vec![listen],
            max_pending_connections: 8,
            connection_open_timeout: Duration::from_secs(5),
            substream_open_timeout: Duration::from_secs(5),
            ..Default::default()
        })
        .with_request_response_protocol(request_config)
        .with_notification_protocol(notification_config)
        .build();
    let mut network = Litep2p::new(config).map_err(|error| error.to_string())?;
    if network.listen_addresses().next().is_none() {
        return Err("litep2p did not bind the requested listen address".into());
    }
    println!(
        "litep2p: peer={} listen={:?}",
        network.local_peer_id(),
        network.listen_addresses().collect::<Vec<_>>()
    );
    let own = advertise.and_then(|address| {
        PeerEndpoint::parse(&format!("{address}@{}", network.local_peer_id())).ok()
    });
    let mut connected = HashSet::<PeerId>::new();
    let mut dialing = HashMap::<PeerId, DialAttempt>::new();
    let mut successful_dials = HashMap::<PeerId, PeerEndpoint>::new();
    let mut resolutions = FuturesUnordered::<
        futures::future::BoxFuture<'static, (PeerEndpoint, Result<Vec<SocketAddr>, String>)>,
    >::new();
    let mut discovery_tick = tokio::time::interval(Duration::from_secs(30));

    let mut inbound = InboundBudget::default();
    let mut egress = super::response_budget::ResponseBudget::default();
    let mut serving = super::request_queue::RequestQueue::default();
    let mut serve_tick = tokio::time::interval(Duration::from_micros(31_250));
    serve_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut accepted = HashSet::<PeerId>::new();
    let mut sync_peers = VecDeque::new();
    let mut pending = HashMap::<RequestId, (PeerId, PendingKind)>::new();
    let mut deferred = HashMap::<PeerId, (Instant, PendingKind, Vec<u8>)>::new();
    let mut sessions = HashMap::<PeerId, PeerSync>::new();
    let mut cooldown = SyncBackoff::default();
    let mut announced_transactions = HashSet::<[u8; 32]>::new();
    let mut last_announced = local_tip(&database)?;
    let mut tick = tokio::time::interval(Duration::from_secs(3));
    let mut redial = tokio::time::interval(Duration::from_secs(10));
    let mut request_tick = tokio::time::interval(Duration::from_millis(25));
    loop {
        tokio::select! {
            event = network.next_event() => match event {
                Some(Litep2pEvent::ConnectionEstablished { peer, endpoint }) => {
                    connected.insert(peer);
                    if let Some(dialed) = connected_dial(peer, !endpoint.is_listener(), &endpoint.address().to_string(), &mut dialing) { successful_dials.insert(peer, dialed); }
                    println!("litep2p: connected peer={peer}");
                    if let Err(error) = notifications.open_substream(peer).await {
                        eprintln!("litep2p: open announcement stream: {error}");
                    }
                }
                Some(Litep2pEvent::ConnectionClosed { peer, .. }) => {
                    connected.remove(&peer);
                    for id in serving.remove(peer) { requests.reject_request(id); }
                    if let Some(attempt) = dialing.remove(&peer) { book.failed(&attempt.endpoint, Instant::now()); }
                    successful_dials.remove(&peer);
                    accepted.remove(&peer);
                    sync_peers.retain(|candidate| *candidate != peer);
                    deferred.remove(&peer);
                    clear_sync(peer, &mut pending, &mut sessions);
                }
                Some(Litep2pEvent::DialFailure { address, error }) => { failed_dial(&address.to_string(), &mut dialing, &mut book, Instant::now()); eprintln!("litep2p: dial {address}: {error}"); },
                Some(Litep2pEvent::ListDialFailures { errors }) => { for (address, _) in &errors { failed_dial(&address.to_string(), &mut dialing, &mut book, Instant::now()); } eprintln!("litep2p: dial failures: {errors:?}"); },
                None => return Err("litep2p event stream closed".into()),
            },
            event = notifications.next() => match event {
                Some(NotificationEvent::ValidateSubstream { peer, handshake, .. }) => {
                    notifications.send_validation_result(peer, if handshake == identity && (accepted.contains(&peer) || accepted.len() < MAX_ACCEPTED_PEERS) { ValidationResult::Accept } else { ValidationResult::Reject });
                }
                Some(NotificationEvent::NotificationStreamOpened { peer, handshake, .. }) => {
                    if handshake == identity && (accepted.contains(&peer) || accepted.len() < MAX_ACCEPTED_PEERS) {
                        if accepted.insert(peer) { sync_peers.push_back(peer); }
                        println!("litep2p: chain accepted peer={peer}");
                        if let Some(endpoint) = successful_dials.get(&peer) {
                            book.succeeded(endpoint, Instant::now());
                            match book.save(&database) {
                                Ok(()) => println!("litep2p: peer store saved endpoint={}", endpoint.key()),
                                Err(error) => eprintln!("litep2p: save peer store: {error}"),
                            }
                        }
                        if let Ok(mut message) = book.relay(own.as_ref(), *network.local_peer_id()) {
                            message.insert(0, ANNOUNCE_PEERS);
                            let _ = notifications.send_sync_notification(peer, message);
                        }

                        for transaction in read_mempool(&database).unwrap_or_default().into_iter().take(256) {
                            let Ok(transaction) = canonical_bytes(&transaction) else { continue; };
                            if transaction.len() <= MAX_STORED_TRANSACTION_SIZE {
                                let mut message = vec![ANNOUNCE_TRANSACTION];
                                message.extend_from_slice(&transaction);
                                let _ = notifications.send_sync_notification(peer, message);
                            }
                        }

                    } else {
                        eprintln!("litep2p: rejected peer {peer}: chain identity mismatch");
                        for id in serving.remove(peer) { requests.reject_request(id); }
                        accepted.remove(&peer);
                        sync_peers.retain(|candidate| *candidate != peer);
                        deferred.remove(&peer);
                        clear_sync(peer, &mut pending, &mut sessions);
                        notifications.close_substream(peer).await;
                    }
                }
                Some(NotificationEvent::NotificationStreamClosed { peer }) => {
                    for id in serving.remove(peer) { requests.reject_request(id); }
                    accepted.remove(&peer);
                    sync_peers.retain(|candidate| *candidate != peer);
                    deferred.remove(&peer);
                    clear_sync(peer, &mut pending, &mut sessions);
                }
                Some(NotificationEvent::NotificationReceived { peer, notification }) if accepted.contains(&peer) => {
                    let traffic = match notification.first().copied() {
                        Some(ANNOUNCE_BLOCK) => Traffic::Block,
                        Some(ANNOUNCE_TRANSACTION) => Traffic::Transaction,
                        Some(ANNOUNCE_PEERS) => Traffic::Invalid,
                        _ => Traffic::Invalid,
                    };
                    // Admission precedes decoding, consensus checks and rejection logs.
                    if !inbound.admit(peer, traffic, notification.len(), Instant::now()) { continue; }
                    match notification.first().copied() {
                        Some(ANNOUNCE_PEERS) if notification.len() <= litep2p_peers::MAX_MESSAGE + 1 => {
                            match litep2p_peers::decode(&notification[1..]) {
                                Ok(endpoints) => {
                                    book.prune(litep2p_peers::now_unix());
                                    for endpoint in endpoints {
                                        if endpoint.peer != *network.local_peer_id() && book.insert(endpoint.clone(), false, litep2p_peers::now_unix(), Instant::now()) {
                                            println!("litep2p: discovered endpoint={}", endpoint.key());
                                        }
                                    }
                                }
                                Err(error) => eprintln!("litep2p: invalid peer discovery from {peer}: {error}"),
                            }
                        }
                        Some(ANNOUNCE_BLOCK) if notification.len() <= MAX_STORED_BLOCK_SIZE + 1 => {
                            if let Err(error) = accept_relayed_block(&database, &notification[1..]) {
                                eprintln!("litep2p: block from {peer} rejected: {error}");
                            }
                        }
                        Some(ANNOUNCE_TRANSACTION) if notification.len() <= MAX_STORED_TRANSACTION_SIZE + 1 => {
                            if let Err(error) = accept_relayed_transaction(&database, &notification[1..]) {
                                eprintln!("litep2p: transaction from {peer} rejected: {error}");
                            }
                        }
                        _ => eprintln!("litep2p: invalid announcement from {peer}"),
                    }
                }
                Some(_) => {},
                None => return Err("litep2p notification stream closed".into()),
            },
            event = requests.next() => match event {
                Some(RequestResponseEvent::RequestReceived { peer, request_id, request, .. }) => {
                    let now = Instant::now();
                    if accepted.contains(&peer) && valid_request_shape(&request)
                        && serving.can_push(peer, request.len())
                        && inbound.admit_request_enqueue(peer, request.len(), now) {
                        serving.push(peer, request_id, request, now);
                    } else { requests.reject_request(request_id); }
                }
                Some(RequestResponseEvent::ResponseReceived { peer, request_id, response, .. }) => {
                    if let Some(&(expected_peer, kind)) = pending.get(&request_id) {
                        if expected_peer != peer || !accepted.contains(&peer) { continue; }
                        pending.remove(&request_id);
                        let had_session = sessions.contains_key(&peer);
                        let next = match process_response(&database, peer, kind, &response, &mut sessions, staging_bytes) {
                            Ok(next) => {
                                if had_session && next.is_none() && !sessions.contains_key(&peer) { cooldown.succeeded(peer); }
                                next
                            },
                            Err(error) => {
                                eprintln!("litep2p: peer {peer} synchronization rejected: {error}");
                                clear_sync(peer, &mut pending, &mut sessions);
                                cooldown.fail(peer, Instant::now());
                                None
                            }
                        };
                        if let Some((kind, payload)) = next {
                            deferred.insert(peer, (Instant::now() + SYNC_REQUEST_INTERVAL, kind, payload));
                        }

                    }
                }
                Some(RequestResponseEvent::RequestFailed { peer, request_id, error, .. }) => {
                    if pending.get(&request_id).is_some_and(|(owner, _)| *owner == peer) {
                        clear_sync(peer, &mut pending, &mut sessions);
                        if accepted.contains(&peer) {
                            cooldown.fail(peer, Instant::now());
                        }
                    }
                    eprintln!("litep2p: request failed: {error:?}");
                }
                None => return Err("litep2p request stream closed".into()),
            },
            _ = tick.tick() => {
                let now = Instant::now();
                expire_sessions(now, &mut pending, &mut sessions, &mut cooldown);
                cooldown.prune(now);
                inbound.prune(now);
                egress.prune(now);
                deferred.retain(|peer, _| accepted.contains(peer) && sessions.contains_key(peer));
                let tip = local_tip(&database)?;
                if sessions.is_empty() && pending.is_empty() && deferred.is_empty()
                    && let Some(peer) = next_sync_peer(&mut sync_peers, &accepted, &cooldown, now)
                    && let Ok(id) = requests.try_send_request(peer, vec![REQUEST_TIP], DialOptions::Reject) {
                    pending.insert(id, (peer, PendingKind::Tip));
                }
                if tip != last_announced {
                    let ledger = load_or_initialize(&database)?;
                    if let Some(block) = ledger.tip_height().and_then(|height| ledger.chain.block(&height)) {
                        let mut message = vec![ANNOUNCE_BLOCK];
                        message.extend_from_slice(&block_bytes(block).map_err(|error| error.to_string())?);
                        for &peer in &accepted { let _ = notifications.send_sync_notification(peer, message.clone()); }
                    }
                    last_announced = tip;
                }
                for transaction in read_mempool(&database)?.into_iter().take(256) {
                    let transaction = canonical_bytes(&transaction).map_err(|error| error.to_string())?;
                    if transaction.len() > MAX_STORED_TRANSACTION_SIZE { continue; }
                    let id = kernel::crypto::hash_bytes(&transaction).0;
                    if !announced_transactions.insert(id) { continue; }
                    let mut message = vec![ANNOUNCE_TRANSACTION];
                    message.extend_from_slice(&transaction);
                    for &peer in &accepted { let _ = notifications.send_sync_notification(peer, message.clone()); }
                }
                if announced_transactions.len() > 1024 { announced_transactions.clear(); }
            },
            _ = serve_tick.tick() => {
                let now = Instant::now();
                for id in serving.expire(now) { requests.reject_request(id); }
                if let Some(bytes) = serving.next_size()
                    && inbound.admit_request_work(bytes, now)
                    && let Some(request) = serving.pop() {
                    if accepted.contains(&request.peer) {
                        let response = answer(&database, &request.bytes).unwrap_or_else(|_| vec![0]);
                        let class = if request.bytes.first() == Some(&REQUEST_BLOCK) {
                            super::response_budget::ResponseClass::Block
                        } else { super::response_budget::ResponseClass::Control };
                        if egress.admit(request.peer, class, response.len(), Instant::now()) {
                            requests.send_response(request.id, response);
                        } else { requests.reject_request(request.id); }
                    } else { requests.reject_request(request.id); }
                }
            },
            _ = request_tick.tick() => {
                let now = Instant::now();
                let ready = deferred.iter().filter_map(|(&peer, (deadline, _, _))| (*deadline <= now).then_some(peer)).collect::<Vec<_>>();
                for peer in ready {
                    let Some((_, kind, payload)) = deferred.remove(&peer) else { continue; };
                    if !accepted.contains(&peer) || !sessions.contains_key(&peer) || cooldown.blocked(peer, now) { continue; }
                    if can_request(peer, &pending)
                        && let Ok(id) = requests.try_send_request(peer, payload, DialOptions::Reject) {
                        pending.insert(id, (peer, kind));
                    } else {
                        clear_sync(peer, &mut pending, &mut sessions);
                        cooldown.fail(peer, now);
                    }
                }
            },
            resolution = resolutions.next(), if !resolutions.is_empty() => {
                if let Some((endpoint, result)) = resolution {
                    if !dialing.get(&endpoint.peer).is_some_and(|attempt| attempt.endpoint == endpoint) { continue; }
                    match result {
                        Ok(mut addresses) => {
                            let offset = book.dial_offset(&endpoint) % addresses.len();
                            addresses.rotate_left(offset);
                            let mut queued = false;
                            for address in addresses {
                                let address: litep2p::types::multiaddr::Multiaddr = format!("{}/p2p/{}", multiaddr(address)?, endpoint.peer).parse().map_err(|error| format!("resolved litep2p address: {error}"))?;
                                let key = address.to_string();
                                match network.dial_address(address).await {
                                    Ok(()) => { if let Some(attempt) = dialing.get_mut(&endpoint.peer) { attempt.address = Some(key); } queued = true; break; }
                                    Err(error) => eprintln!("litep2p: dial queue rejected endpoint={} address={key}: {error}", endpoint.key()),
                                }
                            }
                            if !queued { dialing.remove(&endpoint.peer); book.failed(&endpoint, Instant::now()); }
                        }
                        Err(error) => {
                            dialing.remove(&endpoint.peer); book.failed(&endpoint, Instant::now());
                            eprintln!("litep2p: resolve {}: {error}", endpoint.key());
                        }
                    }
                }
            },
            _ = discovery_tick.tick() => {
                book.prune(litep2p_peers::now_unix());
                if let Ok(mut message) = book.relay(own.as_ref(), *network.local_peer_id()) {
                    message.insert(0, ANNOUNCE_PEERS);
                    for &peer in &accepted { let _ = notifications.send_sync_notification(peer, message.clone()); }
                }
            },
            _ = redial.tick() => {
                let now = Instant::now();
                let expired = dialing.iter().filter_map(|(&peer, attempt)| (now.saturating_duration_since(attempt.started) >= Duration::from_secs(20)).then_some(peer)).collect::<Vec<_>>();
                for peer in expired { if let Some(attempt) = dialing.remove(&peer) { book.failed(&attempt.endpoint, now); } }
                book.prune(litep2p_peers::now_unix());
                let busy = dialing.keys().copied().collect();
                let capacity = 4_usize.saturating_sub(dialing.len()).min(4_usize.saturating_sub(resolutions.len())).min(16_usize.saturating_sub(connected.len() + dialing.len()));
                for endpoint in book.candidates(&connected, &busy, *network.local_peer_id(), now).into_iter().filter(|endpoint| !cooldown.blocked(endpoint.peer, now)).take(capacity) {
                    let public_only = !book.private_discovery && !book.records[&endpoint.key()].trusted;
                    dialing.insert(endpoint.peer, DialAttempt { endpoint: endpoint.clone(), started: now, address: None });
                    resolutions.push(async move { let result = litep2p_peers::resolve(&endpoint, public_only).await; (endpoint, result) }.boxed());
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_shape_gate_admits_supported_frames_and_rejects_malformed_locators() {
        assert!(valid_request_shape(&[REQUEST_TIP]));
        let mut block = vec![REQUEST_BLOCK];
        block.extend_from_slice(&[7; 32]);
        assert!(valid_request_shape(&block));
        block.push(0);
        assert!(!valid_request_shape(&block));
        let mut headers = vec![REQUEST_HEADERS];
        headers.extend_from_slice(&encode_locator(&[[8; 32]]).unwrap());
        assert!(valid_request_shape(&headers));
        let mut maximum = vec![REQUEST_HEADERS];
        maximum.extend_from_slice(
            &encode_locator(&vec![[8; 32]; super::super::MAX_LOCATOR_HASHES]).unwrap(),
        );
        assert_eq!(
            maximum.len(),
            super::super::request_queue::MAX_REQUEST_BYTES
        );
        assert!(valid_request_shape(&maximum));
        maximum.push(0);
        assert!(!valid_request_shape(&maximum));
        headers.pop();
        assert!(!valid_request_shape(&headers));
        assert!(!valid_request_shape(&[]));
        assert!(!valid_request_shape(&[255]));
        assert!(!valid_request_shape(&vec![
            REQUEST_TIP;
            super::super::request_queue::MAX_REQUEST_BYTES
                + 1
        ]));
    }

    struct Database(PathBuf);
    impl Database {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                    "xparq-litep2p-unit-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                )))
        }
        fn session(&self) -> PeerSync {
            load_or_initialize(&self.0).unwrap();
            PeerSync::new(&self.0, cached_handshake(&self.0).unwrap()).unwrap()
        }
    }
    impl Drop for Database {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn oversized_header_sessions_and_out_of_order_blocks_are_rejected() {
        let database = Database::new();
        let mut session = database.session();
        let block = session.ledger.chain.block(&Height(0)).unwrap().clone();
        let header = HeaderAtHeight::new(Height(0), block.header.clone());
        session.headers = vec![header.clone(); MAX_SYNC_HEADERS];
        let mut response = vec![RESPONSE_HEADERS];
        response.extend_from_slice(&block.hash().unwrap().0);
        response.extend(canonical_bytes(&HeaderChainChunk::new(vec![header]).unwrap()).unwrap());
        assert!(
            session
                .accept_headers(&response)
                .unwrap_err()
                .contains("session limit")
        );
        session.stage = Some(
            super::super::sync_stage::DiskStage::open(&database.0, b"sequence-test", &[], 4096)
                .unwrap(),
        );
        let peer = PeerId::random();
        let mut sessions = HashMap::from([(peer, session)]);
        assert!(
            process_response(
                &database.0,
                peer,
                PendingKind::Block(1),
                &[],
                &mut sessions,
                super::super::sync_stage::DEFAULT_STAGING_BYTES
            )
            .unwrap_err()
            .contains("sequence")
        );
        assert!(sessions[&peer].stage.as_ref().unwrap().count == 0);
    }

    #[test]
    fn header_sync_finishes_at_the_advertised_tip_while_the_peer_keeps_mining() {
        use super::super::mining::{MiningAttempt, mine_block_database};
        let source = Database::new();
        source.session();
        let receiver = Database::new();
        receiver.session();
        let miner = super::super::ProgramId([71; kernel::crypto::PROGRAM_ID_SIZE]);
        let mut memory = new_pow_memory();
        assert!(matches!(
            mine_block_database(&source.0, miner, 0, 1000, &mut memory).unwrap(),
            MiningAttempt::Mined
        ));
        let claim = cached_handshake(&source.0).unwrap();
        assert!(matches!(
            mine_block_database(&source.0, miner, 0, 1000, &mut memory).unwrap(),
            MiningAttempt::Mined
        ));
        let ledger = load_or_initialize(&source.0).unwrap();
        let headers = (1..=2)
            .map(|height| {
                HeaderAtHeight::new(
                    Height(height),
                    ledger.chain.block(&Height(height)).unwrap().header.clone(),
                )
            })
            .collect();
        let mut response = vec![RESPONSE_HEADERS];
        response.extend_from_slice(&EXPECTED_GENESIS_HASH.0);
        response.extend(canonical_bytes(&HeaderChainChunk::new(headers).unwrap()).unwrap());
        let mut session = PeerSync::new(&receiver.0, claim).unwrap();
        assert!(session.accept_headers(&response).unwrap());
        assert_eq!(session.headers.len(), 1);
        assert_eq!(session.validation.as_ref().unwrap().height, Height(1));
        assert!(session.preferred().unwrap());
    }

    #[test]
    fn chain_minimums_filter_litep2p_claims_before_allocating_a_header_session() {
        use super::super::chain_minimums::{ChainMinimums, configure};
        let database = Database::new();
        database.session();
        configure(
            &database.0,
            ChainMinimums {
                work: Work::pow2(70),
                weight: 100,
            },
        )
        .unwrap();
        let original = cached_handshake(&database.0).unwrap();
        for (work, weight) in [(Work::pow2(69), u64::MAX), (Work::MAX, 99)] {
            let mut claim = original.clone();
            claim.cumulative_work = work.to_be_limbs();
            claim.cumulative_weight = weight;
            let mut response = vec![REQUEST_TIP];
            response.extend(canonical_bytes(&claim).unwrap());
            let mut sessions = HashMap::new();
            assert!(
                process_response(
                    &database.0,
                    PeerId::random(),
                    PendingKind::Tip,
                    &response,
                    &mut sessions,
                    super::super::sync_stage::DEFAULT_STAGING_BYTES
                )
                .unwrap()
                .is_none()
            );
            assert!(sessions.is_empty());
        }
    }

    #[test]
    fn incoming_connections_cannot_promote_unverified_advertised_endpoints() {
        let now = Instant::now();
        let peer = PeerId::random();
        let endpoint = PeerEndpoint::parse(&format!("localhost:1234@{peer}")).unwrap();
        let mut dialing = HashMap::from([(
            peer,
            DialAttempt {
                endpoint: endpoint.clone(),
                started: now,
                address: None,
            },
        )]);
        assert!(connected_dial(peer, false, "incoming", &mut dialing).is_none());
        dialing.insert(
            peer,
            DialAttempt {
                endpoint: endpoint.clone(),
                started: now,
                address: Some("verified-address".into()),
            },
        );
        assert!(connected_dial(peer, true, "different-address", &mut dialing).is_none());
        dialing.insert(
            peer,
            DialAttempt {
                endpoint: endpoint.clone(),
                started: now,
                address: Some("verified-address".into()),
            },
        );
        assert_eq!(
            connected_dial(peer, true, "verified-address", &mut dialing),
            Some(endpoint.clone())
        );
        dialing.insert(
            peer,
            DialAttempt {
                endpoint: endpoint.clone(),
                started: now,
                address: Some(format!("/ip4/127.0.0.1/tcp/1234/p2p/{peer}")),
            },
        );
        assert_eq!(
            connected_dial(peer, true, "/ip4/127.0.0.1/tcp/1234", &mut dialing),
            Some(endpoint)
        );
    }

    #[test]
    fn stale_dial_failure_does_not_remove_a_new_address_attempt() {
        let now = Instant::now();
        let peer = PeerId::random();
        let endpoint = PeerEndpoint::parse(&format!("localhost:1234@{peer}")).unwrap();
        let mut book = PeerBook::default();
        book.insert(endpoint.clone(), true, litep2p_peers::now_unix(), now);
        let mut dialing = HashMap::from([(
            peer,
            DialAttempt {
                endpoint: endpoint.clone(),
                started: now,
                address: Some("new-address".into()),
            },
        )]);
        failed_dial("old-address", &mut dialing, &mut book, now);
        assert_eq!(dialing.len(), 1);
        assert_eq!(book.dial_offset(&endpoint), 0);
        failed_dial("new-address", &mut dialing, &mut book, now);
        assert!(dialing.is_empty());
        assert_eq!(book.dial_offset(&endpoint), 1);
    }

    #[test]
    fn failed_peer_cleanup_removes_only_its_requests_and_session() {
        let database = Database::new();
        let peer = PeerId::random();
        let other = PeerId::random();
        let mut sessions = HashMap::from([(peer, database.session())]);
        let mut pending = HashMap::from([
            (RequestId::from(1_usize), (peer, PendingKind::Headers)),
            (RequestId::from(2_usize), (other, PendingKind::Tip)),
        ]);
        assert!(!can_request(peer, &pending));
        clear_sync(peer, &mut pending, &mut sessions);
        assert!(sessions.is_empty());
        assert_eq!(pending.len(), 1);
        assert!(can_request(peer, &pending));
        assert!(!can_request(other, &pending));
    }

    #[test]
    fn retry_backoff_survives_disconnect_and_caps_repeated_failures() {
        let database = Database::new();
        let peer = PeerId::random();
        let now = Instant::now();
        let mut backoff = SyncBackoff::default();
        backoff.fail(peer, now);
        let mut sessions = HashMap::from([(peer, database.session())]);
        let mut pending = HashMap::from([(RequestId::from(1_usize), (peer, PendingKind::Headers))]);
        clear_sync(peer, &mut pending, &mut sessions);
        assert!(backoff.blocked(peer, now + Duration::from_secs(29)));
        assert!(!backoff.blocked(peer, now + Duration::from_secs(30)));
        backoff.fail(peer, now + Duration::from_secs(30));
        assert_eq!(backoff.0[&peer].deadline, now + Duration::from_secs(90));
        for _ in 0..100 {
            backoff.fail(peer, now);
        }
        assert_eq!(backoff.0[&peer].deadline, now + MAX_RETRY_COOLDOWN);
        backoff.succeeded(peer);
        assert!(!backoff.blocked(peer, now));
        backoff.fail(peer, now);
        assert_eq!(backoff.0[&peer].failures, 1);
    }

    #[test]
    fn retry_history_is_bounded_expires_and_does_not_punish_other_peers() {
        let now = Instant::now();
        let mut backoff = SyncBackoff::default();
        let healthy = PeerId::random();
        for _ in 0..MAX_RETRY_PEERS + 10 {
            backoff.fail(PeerId::random(), now);
        }
        assert_eq!(backoff.0.len(), MAX_RETRY_PEERS);
        assert!(!backoff.blocked(healthy, now));
        backoff.prune(now + RETRY_HISTORY + MAX_RETRY_COOLDOWN);
        assert!(backoff.0.is_empty());
    }

    #[test]
    fn idle_timeout_uses_verified_progress_and_releases_the_slot() {
        let database = Database::new();
        let peer = PeerId::random();
        let mut session = database.session();
        let started = session.started;
        session.progressed = started + Duration::from_secs(30);
        let mut sessions = HashMap::from([(peer, session)]);
        let mut pending = HashMap::from([(RequestId::from(1_usize), (peer, PendingKind::Headers))]);
        let mut cooldown = SyncBackoff::default();
        expire_sessions(
            started + Duration::from_secs(89),
            &mut pending,
            &mut sessions,
            &mut cooldown,
        );
        assert_eq!(sessions.len(), 1);
        expire_sessions(
            started + Duration::from_secs(90),
            &mut pending,
            &mut sessions,
            &mut cooldown,
        );
        assert!(sessions.is_empty() && pending.is_empty());
        assert!(cooldown.blocked(peer, started + Duration::from_secs(90)));
    }

    #[test]
    fn peer_rotation_is_fifo_skips_cooldown_and_removes_closed_peers() {
        let now = Instant::now();
        let a = PeerId::random();
        let b = PeerId::random();
        let c = PeerId::random();
        let accepted = HashSet::from([a, b]);
        let mut queue = VecDeque::from([a, b, c]);
        let mut cooldown = SyncBackoff::default();
        assert_eq!(
            next_sync_peer(&mut queue, &accepted, &cooldown, now),
            Some(a)
        );
        assert_eq!(
            next_sync_peer(&mut queue, &accepted, &cooldown, now),
            Some(b)
        );
        cooldown.fail(a, now);
        assert_eq!(
            next_sync_peer(&mut queue, &accepted, &cooldown, now),
            Some(b)
        );
        assert!(!queue.contains(&c));
        cooldown.fail(b, now);
        assert_eq!(next_sync_peer(&mut queue, &accepted, &cooldown, now), None);
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn session_deadline_is_absolute_and_releases_the_slot() {
        let database = Database::new();
        let peer = PeerId::random();
        let mut session = database.session();
        let started = session.started;
        session.progressed = started + SESSION_TIMEOUT;
        let mut sessions = HashMap::from([(peer, session)]);
        let mut pending = HashMap::from([(RequestId::from(1_usize), (peer, PendingKind::Headers))]);
        let mut cooldown = SyncBackoff::default();
        expire_sessions(
            started + SESSION_TIMEOUT - Duration::from_nanos(1),
            &mut pending,
            &mut sessions,
            &mut cooldown,
        );
        assert_eq!(sessions.len(), 1);
        expire_sessions(
            started + SESSION_TIMEOUT,
            &mut pending,
            &mut sessions,
            &mut cooldown,
        );
        assert!(sessions.is_empty() && pending.is_empty());
        assert_eq!(
            cooldown.0[&peer].deadline,
            started + SESSION_TIMEOUT + RETRY_COOLDOWN
        );
        for id in 0..MAX_ACCEPTED_PEERS {
            pending.insert(RequestId::from(id), (PeerId::random(), PendingKind::Tip));
        }
        assert!(!can_request(peer, &pending));
    }
}
