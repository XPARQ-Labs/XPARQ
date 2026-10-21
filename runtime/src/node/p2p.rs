use std::{
    collections::{BTreeMap, VecDeque},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, ToSocketAddrs},
    sync::{Condvar, Mutex, mpsc},
    time::{Duration, Instant},
};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener as TokioTcpListener;

use super::*;
use super::{chain_sync::*, config::*, gossip::*, mempool::*, protocol::*, state::*, util::*};

pub(super) struct SyncGate {
    active: Mutex<usize>,
    available: Condvar,
    limit: usize,
}

impl SyncGate {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            active: Mutex::new(0),
            available: Condvar::new(),
            limit: limit.max(1),
        }
    }

    fn acquire(&self) -> Result<SyncPermit<'_>, String> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| "peer sync gate lock is poisoned")?;
        while *active >= self.limit {
            active = self
                .available
                .wait(active)
                .map_err(|_| "peer sync gate lock is poisoned")?;
        }
        *active += 1;
        Ok(SyncPermit { gate: self })
    }
}

struct SyncPermit<'a> {
    gate: &'a SyncGate,
}

impl Drop for SyncPermit<'_> {
    fn drop(&mut self) {
        let mut active = self
            .gate
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *active = active.saturating_sub(1);
        self.gate.available.notify_one();
    }
}

pub(super) const MAX_CONCURRENT_SYNC_SESSIONS: usize = 2;

pub(super) fn serve_p2p(path: Option<&str>, listen: &str) -> Result<(), String> {
    let database = database_path(path);
    load_or_initialize(&database)?;
    serve_p2p_database(database, listen)
}

pub(super) fn serve_p2p_database(database: PathBuf, listen: &str) -> Result<(), String> {
    let listeners = bind_p2p_listeners(listen).map_err(|error| format!("bind P2P: {error}"))?;
    let bound = listeners
        .iter()
        .filter_map(|listener| listener.local_addr().ok())
        .map(|address| address.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    println!("p2p: {bound}");
    let active = Arc::new(AtomicUsize::new(0));
    let active_by_ip = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    let rejected_until = Arc::new(Mutex::new(BTreeMap::<IpAddr, (u32, Instant)>::new()));
    let (sender, receiver) = mpsc::channel();
    let accept_sender = sender.clone();
    thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                let _ = accept_sender.send(Err(io::Error::other(format!(
                    "create P2P runtime: {error}"
                ))));
                return;
            }
        };
        runtime.block_on(async move {
            let listeners = match listeners
                .into_iter()
                .map(TokioTcpListener::from_std)
                .collect::<io::Result<Vec<_>>>()
            {
                Ok(listeners) => listeners,
                Err(error) => {
                    let _ = accept_sender.send(Err(error));
                    return;
                }
            };
            for listener in listeners {
                let sender = accept_sender.clone();
                tokio::spawn(async move {
                    loop {
                        let accepted = listener
                            .accept()
                            .await
                            .and_then(|(stream, _)| stream.into_std());
                        if sender.send(accepted).is_err() {
                            break;
                        }
                    }
                });
            }
            std::future::pending::<()>().await;
        });
    });
    drop(sender);
    for connection in receiver {
        match connection {
            Ok(stream) => {
                if let Err(error) = configure_p2p_stream(&stream) {
                    super::mining::log_node(format!(
                        "node: configure inbound peer stream: {error}"
                    ));
                    continue;
                }
                if active.fetch_add(1, Ordering::AcqRel) >= MAX_INBOUND_CONNECTIONS {
                    active.fetch_sub(1, Ordering::AcqRel);
                    super::mining::log_node("node: inbound peer limit reached");
                    continue;
                }
                let peer_ip = stream
                    .peer_addr()
                    .ok()
                    .map(|address| rate_limit_key(address.ip()));
                if let Some(ip) = peer_ip {
                    let now = Instant::now();
                    if let Ok(mut rejected) = rejected_until.lock() {
                        rejected.retain(|_, (_, until)| *until > now);
                        if rejected.get(&ip).is_some_and(|(_, until)| *until > now) {
                            active.fetch_sub(1, Ordering::AcqRel);
                            super::mining::log_node(format!(
                                "node: inbound peer temporarily suppressed address={ip}"
                            ));
                            continue;
                        }
                    }
                }
                if let Some(ip) = peer_ip {
                    let mut by_ip = active_by_ip
                        .lock()
                        .map_err(|_| "inbound peer counter lock is poisoned")?;
                    let count = by_ip.entry(ip).or_insert(0_usize);
                    if *count >= MAX_INBOUND_CONNECTIONS_PER_IP {
                        active.fetch_sub(1, Ordering::AcqRel);
                        super::mining::log_node(format!(
                            "node: inbound per-IP limit reached address={ip}"
                        ));
                        continue;
                    }
                    *count += 1;
                }
                let database = database.clone();
                let active = Arc::clone(&active);
                let active_by_ip = Arc::clone(&active_by_ip);
                let rejected_until = Arc::clone(&rejected_until);
                thread::spawn(move || {
                    let should_cooldown = handle_inbound_peer(&database, stream);
                    if should_cooldown
                        && let Some(ip) = peer_ip
                        && let Ok(mut cooldowns) = rejected_until.lock()
                    {
                        let failures = cooldowns
                            .get(&ip)
                            .map_or(1, |(failures, _)| failures.saturating_add(1));
                        let exponent = failures.min(8);
                        let delay = Duration::from_secs((10_u64 << exponent).min(1_800));
                        cooldowns.insert(ip, (failures, Instant::now() + delay));
                    }
                    active.fetch_sub(1, Ordering::AcqRel);
                    if let Some(ip) = peer_ip
                        && let Ok(mut by_ip) = active_by_ip.lock()
                        && let Some(count) = by_ip.get_mut(&ip)
                    {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            by_ip.remove(&ip);
                        }
                    }
                });
            }
            Err(error) => super::mining::log_node(format!("node: accept P2P connection: {error}")),
        }
    }
    Ok(())
}

fn bind_p2p_listeners(listen: &str) -> io::Result<Vec<TcpListener>> {
    let requested: SocketAddr = listen.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "P2P listen address must be an IP socket address",
        )
    })?;
    let listeners = if requested.ip().is_unspecified() {
        let port = requested.port();
        let v6_listener = bind_v6_only(port);
        match v6_listener {
            Ok(v6_listener) => {
                let port = v6_listener.local_addr()?.port();
                let v4_listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))?;
                vec![v6_listener, v4_listener]
            }
            Err(error) if can_fall_back_to_separate_families(&error) => {
                vec![TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))?]
            }
            Err(error) => return Err(error),
        }
    } else {
        vec![TcpListener::bind(requested)?]
    };
    for listener in &listeners {
        listener.set_nonblocking(true)?;
    }
    Ok(listeners)
}

fn bind_v6_only(port: u16) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    socket.listen(1024)?;
    Ok(socket.into())
}

fn can_fall_back_to_separate_families(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::AddrNotAvailable | io::ErrorKind::Unsupported | io::ErrorKind::InvalidInput
    )
}

pub(super) fn handle_inbound_peer(database: &Path, mut stream: TcpStream) -> bool {
    let address = stream
        .peer_addr()
        .map_or_else(|_| "unknown".into(), |value| value.to_string());
    match exchange_handshake(database, &mut stream).and_then(|exchange| {
        let outcome = serve_peer_requests(database, &mut stream, &exchange.session_ledger)?;
        if let PeerSessionOutcome::ReverseSync(inventory) = outcome {
            let peer = handshake_from_inventory(&exchange.peer, &inventory);
            let sync = synchronize_headers(database, &mut stream, &peer)?;
            if sync.preferred {
                synchronize_blocks(database, &mut stream, sync)?;
            }
            write_frame(&mut stream, &[SYNC_COMPLETE_MESSAGE])?;
        }
        Ok(exchange.peer)
    }) {
        Ok(peer) => {
            super::mining::log_node(format!(
                "peer served address={address} height={} tip={} work={}",
                peer.tip_height.0,
                hex::encode(peer.tip_hash),
                format_work(peer.cumulative_work),
            ));
            false
        }
        Err(error) => {
            let rejected = inbound_error_is_protocol_violation(&error);
            if rejected {
                super::mining::log_node(format!(
                    "node: peer rejected address={address} reason={error}"
                ));
            } else {
                super::mining::log_node(format!(
                    "node: peer disconnected address={address} reason={error}"
                ));
            }
            rejected
        }
    }
}

fn inbound_error_is_protocol_violation(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    if [
        "failed to fill whole buffer",
        "unexpected eof",
        "connection reset",
        "connection aborted",
        "connection was aborted",
        "broken pipe",
        "forcibly closed",
        "timed out",
        "operation timed out",
        "resource temporarily unavailable",
        "would block",
        "network is unreachable",
        "host is unreachable",
        "no route to host",
    ]
    .iter()
    .any(|marker| error.contains(marker))
    {
        return false;
    }

    [
        "invalid",
        "unsupported ",
        "does not match",
        "mismatch",
        "exceeded",
        "outside allowed range",
        "exceeds ",
        "unexpected ",
        "decode ",
        "expected get-headers message",
        "missing locator count",
        "peer locator has no canonical common ancestor",
    ]
    .iter()
    .any(|marker| error.contains(marker))
}

pub(super) fn run_network(
    path: Option<&str>,
    listen: &str,
    peers: &[String],
) -> Result<(), String> {
    let database = database_path(path);
    load_or_initialize(&database)?;
    let sync_gate = Arc::new(SyncGate::new(MAX_CONCURRENT_SYNC_SESSIONS));
    start_peer_supervisor(database.clone(), peers.to_vec(), sync_gate);
    println!("outbound_peers: {}", peers.len());
    serve_p2p_database(database, listen)
}

pub(super) fn start_peer_supervisor(
    database: PathBuf,
    configured: Vec<String>,
    sync_gate: Arc<SyncGate>,
) {
    let configured: Vec<_> = configured
        .into_iter()
        .map(|endpoint| {
            endpoint
                .parse::<PeerAddress>()
                .map(|address| address.to_string())
                .unwrap_or(endpoint)
        })
        .collect();
    thread::spawn(move || {
        let mut active = BTreeSet::new();
        let mut retry = BTreeMap::new();
        let (events, completed) = mpsc::channel();
        let mut pending_events = VecDeque::new();
        let mut dialing = 0_usize;
        loop {
            while let Some((peer, outcome)) = pending_events
                .pop_front()
                .or_else(|| completed.try_recv().ok())
            {
                match outcome {
                    None => dialing -= 1,
                    Some((failures, delay)) => {
                        active.remove(&peer);
                        retry.insert(peer, (failures, Instant::now() + delay));
                    }
                }
            }
            let mut candidates = configured.clone();
            match PeerStore::load(&database) {
                Ok(store) => {
                    candidates.extend(store.addresses().into_iter().map(|peer| peer.to_string()))
                }
                Err(error) => super::mining::log_node(format!("node: load peer store: {error}")),
            }
            retry.retain(|peer, (_, until)| {
                active.contains(peer) || candidates.contains(peer) || *until > Instant::now()
            });
            let selected = select_outbound_candidates(&candidates, &active, &retry, dialing);
            for peer in selected {
                active.insert(peer.clone());
                dialing += 1;
                let database = database.clone();
                let sync_gate = Arc::clone(&sync_gate);
                let events = events.clone();
                let public_only = !configured.contains(&peer);
                let mut consecutive_failures: u32 =
                    retry.get(&peer).map_or(0, |(failures, _)| *failures);
                thread::spawn(move || {
                    let sync_started = Instant::now();
                    let result = match sync_gate.acquire() {
                        Ok(_permit) => {
                            let dialed =
                                dial_peer_database_with_policy(&database, &peer, public_only);
                            let _ = events.send((peer.clone(), None));
                            dialed.and_then(|connection| {
                                synchronize_peer_database(&database, &peer, connection)
                            })
                        }
                        Err(error) => {
                            let _ = events.send((peer.clone(), None));
                            Err(error)
                        }
                    };
                    if let Err(error) = &result {
                        super::mining::log_node(format!(
                            "p2p_sync_failed: peer={peer} elapsed_ms={:.3} reason={error}",
                            sync_started.elapsed().as_secs_f64() * 1_000.0,
                        ));
                    }
                    let reconnect_after = match result {
                        Ok(mut connection) => {
                            consecutive_failures = 0;
                            let gossip = gossip_outbound_session(
                                &database,
                                &mut connection.stream,
                                &connection.handshake,
                            );
                            match gossip {
                                Ok(()) => RECONNECT_INTERVAL,
                                Err(error) if error.starts_with(GOSSIP_RESYNC_PREFIX) => {
                                    super::mining::log_node(format!(
                                        "node: peer={peer} requires header resync"
                                    ));
                                    Duration::ZERO
                                }
                                Err(error) => {
                                    consecutive_failures = consecutive_failures.saturating_add(1);
                                    let malicious = gossip_error_is_malicious(&error);
                                    if let Ok(address) = peer.parse() {
                                        let _ = record_peer_failure(&database, address, malicious);
                                    }
                                    let cooldown = if malicious {
                                        INVALID_POW_COOLDOWN
                                    } else {
                                        reconnect_delay_for_error(
                                            &error,
                                            consecutive_failures,
                                            &peer,
                                        )
                                    };
                                    super::mining::log_node(format!(
                                        "node: peer={peer} gossip session failed: {error} reconnect_after_secs={}",
                                        cooldown.as_secs()
                                    ));
                                    cooldown
                                }
                            }
                        }
                        Err(error) => {
                            consecutive_failures = consecutive_failures.saturating_add(1);
                            let malicious = error.starts_with(INVALID_POW_ERROR_PREFIX);
                            if let Ok(address) = peer.parse() {
                                let _ = record_peer_failure(&database, address, malicious);
                            }
                            let cooldown =
                                reconnect_delay_for_error(&error, consecutive_failures, &peer);
                            super::mining::log_node(format!(
                                "node: outbound peer={peer} sync failed: {error} reconnect_after_secs={}",
                                cooldown.as_secs()
                            ));
                            cooldown
                        }
                    };
                    let _ = events.send((peer, Some((consecutive_failures, reconnect_after))));
                });
            }
            if let Ok(event) = completed.recv_timeout(Duration::from_secs(1)) {
                pending_events.push_back(event);
            }
        }
    });
}

fn select_outbound_candidates(
    candidates: &[String],
    active: &BTreeSet<String>,
    retry: &BTreeMap<String, (u32, Instant)>,
    dialing: usize,
) -> Vec<String> {
    let slots = MAX_OUTBOUND_CONNECTIONS
        .saturating_sub(active.len())
        .min(MAX_CONCURRENT_DIALS.saturating_sub(dialing));
    let now = Instant::now();
    let mut seen = BTreeSet::new();
    candidates
        .iter()
        .filter(|peer| {
            !active.contains(*peer)
                && !retry.get(*peer).is_some_and(|(_, until)| *until > now)
                && seen.insert((*peer).clone())
        })
        .take(slots)
        .cloned()
        .collect()
}

pub(super) fn connect_peer(path: Option<&str>, peer: &str) -> Result<(), String> {
    let database = database_path(path);
    let mut connection = connect_peer_database(&database, peer)?;
    write_frame(&mut connection.stream, &[SYNC_COMPLETE_MESSAGE])
}

pub(super) fn connect_peer_database(database: &Path, peer: &str) -> Result<ConnectedPeer, String> {
    let connection = dial_peer_database(database, peer)?;
    synchronize_peer_database(database, peer, connection)
}

#[cfg(test)]
fn connect_with_timeout(peer: &str, timeout: Duration) -> Result<TcpStream, String> {
    connect_with_policy(peer, timeout, false)
}

fn connect_with_policy(
    peer: &str,
    timeout: Duration,
    public_only: bool,
) -> Result<TcpStream, String> {
    // Resolve on every attempt so DDNS changes are picked up on reconnect.
    // The system resolver has its own timeout; this budget covers TCP dialing.
    let addresses = peer
        .to_socket_addrs()
        .map_err(|error| format!("resolve peer: {error}"))?;
    let addresses: Vec<_> = interleave(addresses.collect())
        .into_iter()
        .filter(|address| !public_only || is_admissible_discovered_peer(address))
        .collect();
    if addresses.is_empty() {
        return Err("peer resolved to no admissible addresses".into());
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("create peer dial runtime: {error}"))?;
    let stream = runtime
        .block_on(async move {
            let deadline = tokio::time::Instant::now() + timeout;
            let mut attempts = tokio::task::JoinSet::new();
            for (index, address) in addresses.into_iter().enumerate() {
                attempts.spawn(async move {
                    if index != 0 {
                        tokio::time::sleep(Duration::from_millis(250 * index as u64)).await;
                    }
                    tokio::time::timeout_at(deadline, tokio::net::TcpStream::connect(address))
                        .await
                        .map_err(|_| "dial timeout".to_string())?
                        .map_err(|error| error.to_string())
                });
            }
            let mut last_error = "dial timeout".to_string();
            while let Some(result) = attempts.join_next().await {
                match result {
                    Ok(Ok(stream)) => {
                        attempts.abort_all();
                        return stream.into_std().map_err(|error| error.to_string());
                    }
                    Ok(Err(error)) => last_error = error,
                    Err(error) => last_error = error.to_string(),
                }
            }
            Err(last_error)
        })
        .map_err(|error| format!("connect peer: {error}"))?;
    configure_p2p_stream(&stream).map_err(|error| format!("configure peer stream: {error}"))?;
    Ok(stream)
}

const P2P_SESSION_TIMEOUT: Duration = Duration::from_secs(60);

fn configure_p2p_stream(stream: &TcpStream) -> io::Result<()> {
    // Both inbound and outbound streams arrive here through Tokio's
    // `into_std`, which deliberately leaves the std stream nonblocking.
    // The P2P protocol below uses blocking `read_exact`/`write_all` with
    // socket timeouts, so restore blocking mode before handing it off.
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(P2P_SESSION_TIMEOUT))?;
    stream.set_write_timeout(Some(P2P_SESSION_TIMEOUT))
}

fn interleave(addresses: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let (v6, v4): (Vec<_>, Vec<_>) = addresses.into_iter().partition(SocketAddr::is_ipv6);
    let (mut v6, mut v4) = (v6.into_iter(), v4.into_iter());
    let mut output = Vec::new();
    loop {
        let (next_v6, next_v4) = (v6.next(), v4.next());
        if next_v6.is_none() && next_v4.is_none() {
            return output;
        }
        output.extend(next_v6);
        output.extend(next_v4);
    }
}

fn dial_peer_database(database: &Path, peer: &str) -> Result<ConnectedPeer, String> {
    dial_peer_database_with_policy(database, peer, false)
}

fn dial_peer_database_with_policy(
    database: &Path,
    peer: &str,
    public_only: bool,
) -> Result<ConnectedPeer, String> {
    load_or_initialize(database)?;
    let dial_started = Instant::now();
    let mut stream = connect_with_policy(peer, DIAL_TIMEOUT, public_only)?;
    let dial_time = dial_started.elapsed();
    let handshake_started = Instant::now();
    let handshake = exchange_handshake(database, &mut stream)?.peer;
    super::mining::log_node(format!(
        "p2p_handshake: peer={peer} dial_ms={:.3} handshake_ms={:.3} height={}",
        dial_time.as_secs_f64() * 1_000.0,
        handshake_started.elapsed().as_secs_f64() * 1_000.0,
        handshake.tip_height.0,
    ));
    Ok(ConnectedPeer { handshake, stream })
}

fn synchronize_peer_database(
    database: &Path,
    peer: &str,
    connection: ConnectedPeer,
) -> Result<ConnectedPeer, String> {
    let started = Instant::now();
    let ConnectedPeer {
        handshake,
        mut stream,
    } = connection;
    let connected_address = stream.peer_addr().ok();
    // TCP's initial request phase requires a locator. Close an ineligible
    // outbound session before entering it, rather than sending block/discovery
    // requests to a peer that is still waiting for headers.
    if !super::chain_minimums::allows(
        database,
        Work::from_be_limbs(handshake.cumulative_work),
        handshake.cumulative_weight,
    )? {
        return Err("peer chain is below configured work/weight minimums".into());
    }
    let header_started = Instant::now();
    let sync = synchronize_headers(database, &mut stream, &handshake)?;
    let verified = sync.headers.len();
    let preferred = sync.preferred;
    super::mining::log_node(format!(
        "p2p_sync_headers: peer={peer} verified={verified} preferred={preferred} elapsed_ms={:.3}",
        header_started.elapsed().as_secs_f64() * 1_000.0,
    ));
    let block_started = Instant::now();
    let applied = if preferred {
        synchronize_blocks(database, &mut stream, sync)?
    } else {
        0
    };
    super::mining::log_node(format!(
        "p2p_sync_blocks: peer={peer} applied={applied} elapsed_ms={:.3}",
        block_started.elapsed().as_secs_f64() * 1_000.0,
    ));
    let discovered = if handshake.capabilities & CAPABILITY_PEER_DISCOVERY != 0 {
        request_discovered_peers(&mut stream)?
    } else {
        Vec::new()
    };
    if handshake.capabilities & CAPABILITY_RELAY != 0 {
        let local = cached_handshake(database)?;
        let same_tip = local.tip_hash == handshake.tip_hash;
        let extended_peer = relay_next_block(
            database,
            &mut stream,
            handshake.tip_height,
            handshake.tip_hash,
            handshake.capabilities & CAPABILITY_COMPACT_BLOCK_RELAY_V2 != 0,
        )?;
        if same_tip || extended_peer {
            relay_mempool(database, &mut stream)?;
        }
    }
    if let Ok(endpoint) = peer.parse::<PeerAddress>() {
        // Preserve DNS identity rather than pinning its transient resolved IP.
        record_peer_success(database, endpoint)?;
    } else if let Some(address) = connected_address {
        record_peer_success(database, address.into())?;
    }
    record_discovered_peers(database, discovered)?;
    if handshake.capabilities & CAPABILITY_PEER_RELAY != 0 {
        announce_peer_addresses(database, &mut stream)?;
    }
    super::mining::log_node(format!(
        "peer accepted address={peer} height={} tip={} work={} verified_headers={verified} preferred={preferred} applied_blocks={applied}",
        handshake.tip_height.0,
        hex::encode(handshake.tip_hash),
        format_work(handshake.cumulative_work),
    ));
    super::mining::log_node(format!(
        "p2p_sync_complete: peer={peer} verified_headers={verified} applied_blocks={applied} elapsed_ms={:.3}",
        started.elapsed().as_secs_f64() * 1_000.0,
    ));
    Ok(ConnectedPeer { handshake, stream })
}

pub(super) fn serve_peer_requests(
    database: &Path,
    stream: &mut TcpStream,
    session_ledger: &Ledger,
) -> Result<PeerSessionOutcome, String> {
    let tip_height = session_ledger
        .tip_height()
        .ok_or("canonical chain has no tip")?;

    serve_peer_requests_through(database, stream, session_ledger, tip_height)
}

pub(super) fn serve_peer_requests_through(
    database: &Path,
    stream: &mut TcpStream,
    session_ledger: &Ledger,
    tip_height: Height,
) -> Result<PeerSessionOutcome, String> {
    serve_header_requests(stream, session_ledger, tip_height)?;
    serve_block_requests(database, stream)
}

pub(super) fn serve_header_requests(
    stream: &mut TcpStream,
    ledger: &Ledger,
    tip_height: Height,
) -> Result<(), String> {
    let mut requests = 0_usize;

    loop {
        requests += 1;

        if requests > MAX_HEADER_REQUESTS_PER_SESSION {
            return Err("peer exceeded the header request limit".into());
        }

        let request = read_frame(stream, 2 + MAX_LOCATOR_HASHES * 32)?;
        let locator = decode_locator(&request)?;
        let mut height = tip_height;
        let (ancestor_height, ancestor_hash) = loop {
            let block = ledger
                .chain
                .header(&height)
                .ok_or("canonical block is missing")?;

            let hash = block.hash().map_err(|error| error.to_string())?.0;

            if locator.contains(&hash) {
                break (height, hash);
            }

            let Some(previous) = height.0.checked_sub(1) else {
                return Err("peer locator has no canonical common ancestor".into());
            };

            height = Height(previous);
        };

        let mut extension = Vec::with_capacity(MAX_HEADER_CHAIN_CHUNK_HEADERS);

        let mut next_height = ancestor_height.0.checked_add(1);

        while let Some(value) = next_height {
            if value > tip_height.0 || extension.len() >= MAX_HEADER_CHAIN_CHUNK_HEADERS {
                break;
            }

            let height = Height(value);

            let block = ledger
                .chain
                .header(&height)
                .ok_or("canonical block is missing")?;

            extension.push(kernel::consensus::HeaderAtHeight::new(
                height,
                block.clone(),
            ));

            next_height = value.checked_add(1);
        }

        if extension.is_empty() {
            let mut response = Vec::with_capacity(33);
            response.push(HEADERS_COMPLETE_MESSAGE);
            response.extend_from_slice(&ancestor_hash);
            write_frame(stream, &response)?;
            return Ok(());
        }

        let chunk = HeaderChainChunk::new(extension).map_err(|error| error.to_string())?;

        let chunk = canonical_bytes(&chunk).map_err(|error| error.to_string())?;

        let mut response = Vec::with_capacity(33 + chunk.len());
        response.push(HEADERS_MESSAGE);
        response.extend_from_slice(&ancestor_hash);
        response.extend_from_slice(&chunk);

        write_frame(stream, &response)?;
    }
}

pub(super) fn serve_block_requests(
    database: &Path,
    stream: &mut TcpStream,
) -> Result<PeerSessionOutcome, String> {
    let mut block_requests = 0_usize;
    let mut last_discovery_request = None;
    let mut last_peer_announcement = None;
    let mut last_peers_announcement = None;
    let mut relayed_transactions = 0_usize;
    let mut relayed_blocks = 0_usize;
    let mut transaction_requests = 0_usize;
    let mut last_tip_announcement = None;
    loop {
        let request = read_block_session_frame(stream)?;
        let (&message, body) = request.split_first().ok_or("empty block request")?;
        match message {
            SYNC_COMPLETE_MESSAGE if body.is_empty() => return Ok(PeerSessionOutcome::Complete),
            GET_PEERS_MESSAGE if body.is_empty() => {
                let now = Instant::now();
                if last_discovery_request.is_some_and(|last: Instant| {
                    now.duration_since(last) < PEER_RELAY_REFRESH_INTERVAL
                }) {
                    return Err("peer exceeded the discovery request rate limit".into());
                }
                last_discovery_request = Some(now);
                let peers = relay_address_list(database)?;
                let encoded = encode_discovery_addresses(peers)?;
                let mut response = Vec::with_capacity(1 + encoded.len());
                response.push(PEERS_MESSAGE);
                response.extend_from_slice(&encoded);
                write_frame(stream, &response)?;
                continue;
            }
            ANNOUNCE_PEER_MESSAGE => {
                if let Err(error) = check_peer_announcement_rate_limit(
                    &mut last_peer_announcement,
                    "peer endpoint announcement",
                ) {
                    write_relay_result(stream, Err(error.clone()))?;
                    return Err(error);
                }
                let addresses = match decode_peer_addresses(body, MAX_PEER_ANNOUNCEMENT_ENDPOINTS) {
                    Ok(addresses) => addresses,
                    Err(error) => {
                        write_relay_result(stream, Err(error.clone()))?;
                        return Err(format!("invalid peer endpoint announcement: {error}"));
                    }
                };
                let result = record_announced_peers(database, addresses);
                let rejection = result.as_ref().err().cloned();
                write_relay_result(stream, result)?;
                if let Some(error) = rejection {
                    return Err(error);
                }
                continue;
            }
            ANNOUNCE_PEERS_MESSAGE => {
                if let Err(error) = check_peer_announcement_rate_limit(
                    &mut last_peers_announcement,
                    "peer list announcement",
                ) {
                    write_relay_result(stream, Err(error.clone()))?;
                    return Err(error);
                }
                let addresses = match decode_peer_addresses(body, MAX_PEER_ANNOUNCEMENT_ENDPOINTS) {
                    Ok(addresses) => addresses,
                    Err(error) => {
                        write_relay_result(stream, Err(error.clone()))?;
                        return Err(format!("invalid peer list announcement: {error}"));
                    }
                };
                let result = record_discovered_peers(database, addresses);
                let rejection = result.as_ref().err().cloned();
                write_relay_result(stream, result)?;
                if let Some(error) = rejection {
                    return Err(error);
                }
                continue;
            }
            ANNOUNCE_TIP_MESSAGE => {
                let now = Instant::now();
                if last_tip_announcement
                    .is_some_and(|last: Instant| now.duration_since(last) < GOSSIP_HEARTBEAT / 4)
                {
                    return Err("peer exceeded the tip announcement rate limit".into());
                }
                last_tip_announcement = Some(now);
                let _: TipAnnouncement = canonical_decode(body)
                    .map_err(|error| format!("invalid tip announcement: {error}"))?;
                let local_tip = gossip_tip(database)?;
                let encoded = canonical_bytes(&local_tip).map_err(|error| error.to_string())?;
                let mut response = Vec::with_capacity(1 + encoded.len());
                response.push(ANNOUNCE_TIP_MESSAGE);
                response.extend_from_slice(&encoded);
                write_frame(stream, &response)?;
                continue;
            }
            INVENTORY_MESSAGE => {
                let peer_inventory = decode_gossip_inventory(body)?;
                relayed_transactions = 0;
                relayed_blocks = 0;
                transaction_requests = 0;
                let inventory = gossip_inventory(database)?;
                let encoded = canonical_bytes(&inventory).map_err(|error| error.to_string())?;
                if encoded.len() > MAX_GOSSIP_INVENTORY_SIZE {
                    return Err("local gossip inventory exceeds size limit".into());
                }
                let mut response = Vec::with_capacity(1 + encoded.len());
                response.push(INVENTORY_MESSAGE);
                response.extend_from_slice(&encoded);
                write_frame(stream, &response)?;
                if super::chain_minimums::allows(
                    database,
                    Work::from_be_limbs(peer_inventory.cumulative_work),
                    peer_inventory.cumulative_weight,
                )? && inventory_preferred(&peer_inventory, &inventory)
                {
                    return Ok(PeerSessionOutcome::ReverseSync(peer_inventory));
                }
                continue;
            }
            GET_TRANSACTION_MESSAGE if body.len() == 32 => {
                transaction_requests += 1;
                if transaction_requests > MAX_RELAY_ITEMS_PER_SESSION {
                    return Err("peer exceeded the transaction request limit".into());
                }
                let requested: [u8; 32] =
                    body.try_into().map_err(|_| "invalid requested Tx Hash")?;
                let transaction = read_mempool(database)?
                    .into_iter()
                    .find(|transaction| transaction.id().ok() == Some(requested))
                    .ok_or("requested transaction is not in the mempool")?;
                let encoded = canonical_bytes(&transaction).map_err(|error| error.to_string())?;
                let mut response = Vec::with_capacity(1 + encoded.len());
                response.push(TRANSACTION_MESSAGE);
                response.extend_from_slice(&encoded);
                write_frame(stream, &response)?;
                continue;
            }
            SUBMIT_TRANSACTION_MESSAGE => {
                relayed_transactions += 1;
                if relayed_transactions > MAX_RELAY_ITEMS_PER_SESSION {
                    return Err("peer exceeded the transaction relay limit".into());
                }
                let result = accept_relayed_transaction(database, body);
                let rejection = result.as_ref().err().cloned();
                write_relay_result(stream, result)?;
                if let Some(error) = rejection {
                    return Err(format!("invalid relayed transaction: {error}"));
                }
                continue;
            }
            SUBMIT_BLOCK_MESSAGE => {
                relayed_blocks += 1;
                if relayed_blocks > MAX_RELAYED_BLOCKS_PER_SESSION {
                    return Err("peer exceeded the block relay limit".into());
                }
                let result = accept_relayed_block(database, body);
                let rejection = result.as_ref().err().cloned();
                write_relay_result(stream, result)?;
                if let Some(error) = rejection {
                    return if error.starts_with(GOSSIP_RESYNC_PREFIX) {
                        Err(error)
                    } else {
                        Err(format!("invalid relayed block: {error}"))
                    };
                }
                continue;
            }
            COMPACT_BLOCK_MESSAGE => {
                relayed_blocks += 1;
                if relayed_blocks > MAX_RELAYED_BLOCKS_PER_SESSION {
                    return Err("peer exceeded the block relay limit".into());
                }
                let result = accept_compact_block(database, stream, body);
                let rejection = result.as_ref().err().cloned();
                write_relay_result(stream, result)?;
                if let Some(error) = rejection {
                    return if error.starts_with(GOSSIP_RESYNC_PREFIX) {
                        Err(error)
                    } else {
                        Err(format!("invalid compact relayed block: {error}"))
                    };
                }
                continue;
            }
            GET_BLOCK_MESSAGE if body.len() == 32 => {
                block_requests += 1;
                if block_requests > MAX_SYNC_HEADERS {
                    return Err("peer exceeded the block request limit".into());
                }
            }
            GET_COMPACT_BLOCK_MESSAGE if body.len() == 32 => {
                block_requests += 1;
                if block_requests > MAX_SYNC_HEADERS {
                    return Err("peer exceeded the block request limit".into());
                }
                let requested: [u8; 32] = body
                    .try_into()
                    .map_err(|_| "invalid requested block hash")?;
                let encoded = cached_canonical_block_bytes(database, requested)?
                    .ok_or("requested compact block is not canonical")?;
                let block = decode_block(&encoded)
                    .map_err(|error| format!("decode requested compact block: {error}"))?;
                relay_compact_block(stream, &block)?;
                continue;
            }
            _ => return Err("invalid block-session message".into()),
        }
        let requested: [u8; 32] = body
            .try_into()
            .map_err(|_| "invalid requested block hash")?;
        let encoded = cached_canonical_block_bytes(database, requested)?
            .ok_or("requested block is not canonical")?;

        let mut response = Vec::with_capacity(1 + encoded.len());
        response.push(BLOCK_MESSAGE);
        response.extend_from_slice(&encoded);
        write_frame(stream, &response)?;
    }
}

fn encode_discovery_addresses(mut peers: Vec<String>) -> Result<Vec<u8>, String> {
    peers.truncate(MAX_DISCOVERED_PEERS);
    let addresses = peers
        .iter()
        .filter_map(|peer| peer.parse::<SocketAddr>().ok())
        .collect::<Vec<_>>();
    let mut encoded = encode_peer_endpoints(&addresses, MAX_DISCOVERED_PEERS);
    while encoded.len() > MAX_PEERS_RESPONSE_SIZE && !addresses.is_empty() {
        let shortened = &addresses[..addresses.len() - 1];
        encoded = encode_peer_endpoints(shortened, MAX_DISCOVERED_PEERS);
        if shortened.is_empty() {
            break;
        }
    }
    Ok(encoded)
}

pub(super) fn record_discovered_peers(
    database: &Path,
    addresses: impl IntoIterator<Item = PeerAddress>,
) -> Result<(), String> {
    let _guard = peer_store_lock()?
        .lock()
        .map_err(|_| "peer store lock is poisoned")?;
    let mut store = PeerStore::load(database)?;
    let local = advertised_peer_addresses()?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut changed = false;
    for address in addresses {
        if local.contains(&address.to_string()) {
            continue;
        }
        changed |= store.insert_discovered(address);
    }
    if changed {
        store.save(database)?;
    }
    Ok(())
}

fn record_announced_peers(
    database: &Path,
    addresses: impl IntoIterator<Item = PeerAddress>,
) -> Result<(), String> {
    let _guard = peer_store_lock()?
        .lock()
        .map_err(|_| "peer store lock is poisoned")?;
    let mut store = PeerStore::load(database)?;
    let local = advertised_peer_addresses()?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut changed = false;
    for address in addresses {
        if local.contains(&address.to_string()) {
            continue;
        }
        changed |= store.insert_announced(address);
    }
    if changed {
        store.save(database)?;
    }
    Ok(())
}

fn relay_address_list(database: &Path) -> Result<Vec<String>, String> {
    let mut addresses = PeerStore::load(database)?.relay_candidates();
    addresses.extend(advertised_peer_addresses()?);
    let mut unique = BTreeSet::new();
    Ok(addresses
        .into_iter()
        .filter_map(|address| address.parse::<PeerAddress>().ok())
        .filter(PeerAddress::is_admissible)
        .filter(|address| unique.insert(address.clone()))
        .map(|address| address.to_string())
        .collect())
}

pub(super) fn announce_peer_addresses(
    database: &Path,
    stream: &mut TcpStream,
) -> Result<(), String> {
    let local = advertised_peer_addresses()?
        .into_iter()
        .filter_map(|address| address.parse::<PeerAddress>().ok())
        .filter(PeerAddress::is_admissible)
        .map(|address| address.to_string())
        .collect::<BTreeSet<_>>();
    if !local.is_empty() {
        let encoded = encode_peer_announcement_addresses(local.iter().cloned().collect())?;
        let mut message = Vec::with_capacity(1 + encoded.len());
        message.push(ANNOUNCE_PEER_MESSAGE);
        message.extend_from_slice(&encoded);
        write_frame(stream, &message)?;
        read_relay_result(stream)?;
    }

    let mut peers = PeerStore::load(database)?
        .relay_candidates()
        .into_iter()
        .filter_map(|address| address.parse::<PeerAddress>().ok())
        .filter(PeerAddress::is_admissible)
        .map(|address| address.to_string())
        .filter(|address| !local.contains(address))
        .collect::<Vec<_>>();
    peers.truncate(MAX_PEER_ANNOUNCEMENT_ENDPOINTS);
    if !peers.is_empty() {
        let encoded = encode_peer_announcement_addresses(peers)?;
        let mut message = Vec::with_capacity(1 + encoded.len());
        message.push(ANNOUNCE_PEERS_MESSAGE);
        message.extend_from_slice(&encoded);
        write_frame(stream, &message)?;
        read_relay_result(stream)?;
    }
    Ok(())
}

pub(super) fn refresh_peer_addresses(
    database: &Path,
    stream: &mut TcpStream,
    peer: &Handshake,
) -> Result<(), String> {
    if peer.capabilities & CAPABILITY_PEER_DISCOVERY != 0 {
        let discovered = request_discovered_peers(stream)?;
        record_discovered_peers(database, discovered)?;
    }
    announce_peer_addresses(database, stream)
}

fn encode_peer_announcement_addresses(mut peers: Vec<String>) -> Result<Vec<u8>, String> {
    peers.truncate(MAX_PEER_ANNOUNCEMENT_ENDPOINTS);
    let addresses = peers
        .iter()
        .filter_map(|peer| peer.parse::<SocketAddr>().ok())
        .collect::<Vec<_>>();
    Ok(encode_peer_endpoints(
        &addresses,
        MAX_PEER_ANNOUNCEMENT_ENDPOINTS,
    ))
}

fn check_peer_announcement_rate_limit(
    last: &mut Option<Instant>,
    label: &str,
) -> Result<(), String> {
    let now = Instant::now();
    if last.is_some_and(|previous| now.duration_since(previous) < PEER_RELAY_REFRESH_INTERVAL) {
        return Err(format!("peer exceeded the {label} rate limit"));
    }
    *last = Some(now);
    Ok(())
}

pub(super) fn record_peer_success(database: &Path, address: PeerAddress) -> Result<(), String> {
    let _guard = peer_store_lock()?
        .lock()
        .map_err(|_| "peer store lock is poisoned")?;
    let mut store = PeerStore::load(database)?;
    store.record_success(address);
    store.save(database)
}

pub(super) fn record_peer_failure(
    database: &Path,
    address: PeerAddress,
    malicious: bool,
) -> Result<(), String> {
    let _guard = peer_store_lock()?
        .lock()
        .map_err(|_| "peer store lock is poisoned")?;
    let mut store = PeerStore::load(database)?;
    store.record_failure(address, malicious);
    store.save(database)
}

pub(super) fn peer_store_lock() -> Result<&'static Mutex<()>, String> {
    Ok(PEER_STORE_LOCK.get_or_init(|| Mutex::new(())))
}

#[cfg(test)]
mod connection_tests {
    use super::*;

    #[test]
    fn outbound_slots_skip_duplicates_active_and_cooling_peers() {
        let candidates: Vec<String> = ["active", "cooling", "ready", "ready", "other", "extra"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let mut active = BTreeSet::from(["active".to_string()]);
        let retry = BTreeMap::from([(
            "cooling".to_string(),
            (1, Instant::now() + Duration::from_secs(60)),
        )]);
        assert_eq!(
            select_outbound_candidates(&candidates, &active, &retry, 0),
            ["ready", "other"]
        );
        assert_eq!(
            select_outbound_candidates(&candidates, &active, &retry, 1),
            ["ready"]
        );
        assert!(
            select_outbound_candidates(&candidates, &active, &retry, MAX_CONCURRENT_DIALS)
                .is_empty()
        );
        for i in 1..MAX_OUTBOUND_CONNECTIONS {
            active.insert(format!("connected-{i}"));
        }
        assert!(select_outbound_candidates(&candidates, &active, &retry, 0).is_empty());
        active.remove("connected-1");
        assert_eq!(
            select_outbound_candidates(&candidates, &active, &retry, 0),
            ["ready"]
        );
    }

    #[test]
    fn discovered_dns_cannot_dial_private_resolved_addresses() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("localhost:{}", listener.local_addr().unwrap().port());
        assert!(connect_with_policy(&endpoint, Duration::from_secs(1), true).is_err());
        assert!(connect_with_policy(&endpoint, Duration::from_secs(1), false).is_ok());
    }

    #[test]
    fn long_dns_names_do_not_exceed_discovery_frame_budget() {
        let name = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        let endpoint = format!("{name}:6677");
        assert!(endpoint.parse::<PeerAddress>().unwrap().is_admissible());
        let encoded = encode_discovery_addresses(vec![endpoint; MAX_DISCOVERED_PEERS]).unwrap();
        assert!(encoded.len() <= MAX_PEERS_RESPONSE_SIZE);
        assert_eq!(u16::from_be_bytes(encoded[..2].try_into().unwrap()), 0);
    }

    #[test]
    fn peer_exchange_binary_codec_round_trips_ipv6() {
        let endpoint = "[2001:4860:4860::8888]:6677";
        let encoded = encode_discovery_addresses(vec![endpoint.to_string()]).unwrap();
        let decoded = decode_peer_addresses(&encoded, MAX_DISCOVERED_PEERS).unwrap();
        assert_eq!(decoded, vec![endpoint.parse::<PeerAddress>().unwrap()]);
    }

    #[test]
    fn zero_dial_budget_does_not_connect() {
        assert!(
            connect_with_timeout("[::1]:6677", Duration::ZERO)
                .unwrap_err()
                .contains("dial timeout")
        );
    }

    #[test]
    fn dial_accepts_ipv4_ipv6_and_hostname() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let listener = TcpListener::bind(bind).unwrap();
            let address = listener.local_addr().unwrap();
            let stream =
                connect_with_timeout(&address.to_string(), Duration::from_secs(2)).unwrap();
            assert_eq!(stream.peer_addr().unwrap(), address);
            let _ = listener.accept().unwrap();
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stream = connect_with_timeout(
            &format!("localhost:{}", address.port()),
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), address);
    }

    #[test]
    fn interleave_alternates_address_families_and_keeps_order() {
        let addresses = [
            "192.0.2.1:1",
            "[2001:db8::1]:2",
            "192.0.2.2:3",
            "[2001:db8::2]:4",
            "192.0.2.3:5",
        ]
        .map(|address| address.parse().unwrap());
        let ordered = interleave(addresses.to_vec());
        assert_eq!(
            ordered,
            [
                addresses[1],
                addresses[0],
                addresses[3],
                addresses[2],
                addresses[4]
            ]
        );
        assert!(
            ordered[..4]
                .windows(2)
                .all(|pair| pair[0].is_ipv6() != pair[1].is_ipv6())
        );
    }

    #[test]
    fn p2p_stream_enables_nodelay_and_bounded_session_timeouts() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        configure_p2p_stream(&stream).unwrap();
        assert!(stream.nodelay().unwrap());
        assert_eq!(stream.read_timeout().unwrap(), Some(P2P_SESSION_TIMEOUT));
        assert_eq!(stream.write_timeout().unwrap(), Some(P2P_SESSION_TIMEOUT));
    }
}
