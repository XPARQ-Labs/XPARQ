#![cfg_attr(test, allow(dead_code))]

mod command;
mod gateway;
mod grpc;
mod log;
mod mining;
mod nat;
mod p2p;
mod rpc;
mod runtime;
mod snapshot;

use axum::{
    Json, Router,
    body::Body,
    extract::{Path as AxumPath, Query, State},
    http::{Request, StatusCode, header},
    middleware::{self, Next},
    response::{
        IntoResponse, Sse,
        sse::{Event as SseEvent, KeepAlive},
    },
    routing::{get, post},
};
use command::config::{
    CONFIG_FILE_ENV, DEFAULT_CONFIG_FILE, RunConfig, current_network,
    dedupe as dedupe_socket_addrs, format_socket_addrs, parse as parse_run_config,
    write_default as write_default_run_config,
};
use command::display::{
    format_difficulty, format_hash, print_help, print_network_info, print_version, short_hash,
};
use command::parse::{
    address as parse_address, address_string as parse_address_string, hash_hex as parse_hash_hex,
    signed_protocol_transaction as signed_protocol_transaction_from_hex,
    signed_qcash_transaction as signed_qcash_transaction_from_hex,
    signed_transaction as signed_transaction_from_hex,
};
use futures_util::stream;
use gateway::{heartbeat_peer, register_peer, request_gateway_peers};
use log::{MiningStatus, block_announced, mining_status};
use mining::{MiningStats, mine_once as mine_once_unlocked};
use p2p::gossip::broadcast_to_peers;
use p2p::{
    PeerConnection, PeerPoll, PeerState, dedupe_peers, download_authenticated_snapshot,
    load_peers_file, poll_peer_connection, request_peers_connection, save_peer_states_file,
    sync_from_peers_parallel, sync_mempool_connection,
};
use rpc::api::{LogCounters, RpcMetrics, RpcServerConfig, RpcState, start_rpc_servers};
use runtime::mempool::MempoolConfig;
use runtime::miner::prepare_candidate_block;
use runtime::network::{CompactBlock, InventoryItem, NetworkMessage};
use runtime::node::Node;
use runtime::params::{
    CHAIN_ID, CHAIN_NAME, COIN_NAME, MAX_BLOCK_TXS, NETWORK_MAGIC, PROTOCOL_STAGE,
    PROTOCOL_VERSION, SIGNATURE_SCHEME, STORAGE_VERSION,
};
use runtime::recovery::{RollbackIssue, RollbackIssueId, RollbackRecoveryStatus};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::env;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::process::ExitCode;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use xparq::block::{Block, Height};
use xparq::codec::{block_bytes, decode_block, transaction_bytes};
use xparq::consensus::{Consensus, DIFFICULTY_ALGORITHM, DIFFICULTY_START};
use xparq::crypto::{Address, BlockHash, TransactionHash, address_from_string, address_to_string};
use xparq::event::{EventId, ProtocolEvent, ProtocolEventKind};
use xparq::genesis::CURRENT_CHAIN_PARAMS;
use xparq::ledger::{
    ACCOUNT_STATE_PROOF_BUNDLE_VERSION, AccountNonMembershipProofBundle, AccountStateProofBundle,
    BLOCK_REWARD_MATURITY, CONFIRMATION_DEPTH, FINALITY_DEPTH, QCashStateProofBundle,
    canonical_transaction_lifecycle,
};
use xparq::transaction::{SignedProtocolTransaction, Transfer as Transaction};
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "mainnet")]
const DEFAULT_NODE_DB: &str = "./data/mainnet";
#[cfg(feature = "testnet")]
const DEFAULT_NODE_DB: &str = "./data/testnet";
#[cfg(feature = "devnet")]
const DEFAULT_NODE_DB: &str = "./data/devnet";
const DEFAULT_WALLET_CANDIDATES: &[&str] = &["../wallet.json", "wallet.json"];
const MAX_PEER_FAILURES: u32 = 8;
const ACTIVITY_LOG_INTERVAL: Duration = Duration::from_secs(60);
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

fn main() -> ExitCode {
    if let Err(error) = ctrlc::set_handler(|| {
        SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
    }) {
        eprintln!("warning: failed to install shutdown signal handler: {error}");
    }
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        args = default_run_args();
    }
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(mut args: Vec<String>) -> Result<(), String> {
    let result = match args.first().map(String::as_str) {
        None => {
            print_help();
            Ok(())
        }
        Some("-h") | Some("--help") | Some("help") => {
            print_help();
            Ok(())
        }
        Some("-V") | Some("--version") | Some("version") => {
            print_version();
            Ok(())
        }
        Some("mine") => run_mine_shortcut(&args[1..]),
        Some("node") => node_command(&args[1..]),
        Some(command) => Err(format!(
            "unknown command `{command}`. Try `xparq-node --help`."
        )),
    };
    args.zeroize();
    result
}

fn default_run_args() -> Vec<String> {
    let Some(wallet_path) = default_wallet_path() else {
        return vec!["node".to_string(), "run".to_string()];
    };
    vec![
        "node".to_string(),
        "run".to_string(),
        "--wallet".to_string(),
        wallet_path,
        "--mine".to_string(),
    ]
}

fn default_wallet_path() -> Option<String> {
    DEFAULT_WALLET_CANDIDATES
        .iter()
        .copied()
        .find(|path| fs::metadata(path).is_ok())
        .map(str::to_string)
}

fn run_mine_shortcut(args: &[String]) -> Result<(), String> {
    if let Some(run_args) = mine_config_args(args) {
        return run_node(&run_args);
    }

    let wallet_path = args
        .first()
        .cloned()
        .or_else(default_wallet_path)
        .ok_or_else(|| {
            "mining wallet not found; create one with `wallet new wallet.json`".to_string()
        })?;
    let db_path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| DEFAULT_NODE_DB.to_string());
    run_node(&[
        db_path,
        "--wallet".to_string(),
        wallet_path,
        "--mine".to_string(),
    ])
}

fn mine_config_args(args: &[String]) -> Option<Vec<String>> {
    if !args.is_empty() && !args.first()?.starts_with('-') {
        return None;
    }
    let mut run_args = args.to_vec();
    run_args.push("--mine".to_string());
    Some(run_args)
}

fn node_command(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("init") => {
            let path = args.get(1).map(String::as_str).unwrap_or(DEFAULT_NODE_DB);
            let miner_address = parse_address(args.get(2)).unwrap_or(Address([9; 20]));
            if args.get(3).is_some() {
                return Err(
                    "premine address is fixed by protocol and cannot be overridden".to_string(),
                );
            }
            let node = open_node(path, miner_address)?;

            println!("database: {path}");
            println!("tip_height: {:?}", node.tip_height());
            println!("tip_hash: {}", format_hash(node.tip_hash()));
            println!("miner_address: {}", address_to_string(&miner_address));
            println!("genesis: chain-spec anchored");
            Ok(())
        }
        Some("run") => run_node(&args[1..]),
        Some("snapshot") => snapshot_command(&args[1..]),
        Some("db") => command::database::run(&args[1..], DEFAULT_NODE_DB),
        Some("config") => node_config_command(&args[1..]),
        Some("info") => {
            print_network_info();
            Ok(())
        }
        _ => Err("usage: xparq-node node <info|init|config|run|db> [options]".to_string()),
    }
}

fn snapshot_command(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("export") => {
            let database = args
                .get(1)
                .ok_or("usage: xparq-node node snapshot export <database> <bundle>")?;
            let output = args
                .get(2)
                .ok_or("usage: xparq-node node snapshot export <database> <bundle>")?;
            let node = open_node(database, Address([9; 20]))?;
            snapshot::export_to_file(&node.ledger, output)?;
            println!(
                "authenticated snapshot exported: height={} tip={} file={output}",
                node.tip_height().unwrap_or(Height(0)).0,
                format_hash(node.tip_hash())
            );
            Ok(())
        }
        Some("import") => {
            let database = args
                .get(1)
                .ok_or("usage: xparq-node node snapshot import <database> <bundle>")?;
            let bundle = args
                .get(2)
                .ok_or("usage: xparq-node node snapshot import <database> <bundle>")?;
            let (height, hash, work) = snapshot::import_file_atomic(database, bundle)?;
            println!(
                "authenticated snapshot activated: height={} tip={} work={:016x?} database={database}",
                height.0,
                hex::encode(hash.0),
                work.to_be_limbs()
            );
            Ok(())
        }
        _ => Err("usage: xparq-node node snapshot <export|import> <database> <bundle>".to_string()),
    }
}

fn open_node(path: &str, miner_address: Address) -> Result<Node, String> {
    let _ = miner_address;
    Node::init_or_load(path, Consensus::with_default_config()).map_err(|error| {
        let error = error.to_string();
        if error.contains("stored block failed validation") {
            format!(
                "failed to open node storage: {error}. Existing data was created under a different protocol/genesis identity; reset this local node database with `rm -rf {path}`"
            )
        } else {
            format!("failed to open node storage: {error}")
        }
    })
}

fn node_config_command(args: &[String]) -> Result<(), String> {
    let environment_path = env::var(CONFIG_FILE_ENV).ok();
    let path = args
        .first()
        .map(String::as_str)
        .or(environment_path.as_deref())
        .unwrap_or(DEFAULT_CONFIG_FILE);
    write_default_run_config(path)?;
    println!("node config written: {path}");
    println!("edit miner_address/public_addr as needed, then run: ./xparq-node mine");
    Ok(())
}

fn print_core_startup_info() {
    println!(
        "[INFO] core network={} chain={} chain_id={} coin={} stage={} signature={} protocol={} storage={} magic={}",
        current_network(),
        CHAIN_NAME,
        CHAIN_ID,
        COIN_NAME,
        PROTOCOL_STAGE,
        SIGNATURE_SCHEME,
        PROTOCOL_VERSION,
        STORAGE_VERSION,
        hex::encode(NETWORK_MAGIC)
    );
    println!(
        "[INFO] consensus confirmation={} finality={} reward_maturity={} difficulty_start={} difficulty_algorithm={}",
        CONFIRMATION_DEPTH,
        FINALITY_DEPTH,
        BLOCK_REWARD_MATURITY,
        DIFFICULTY_START,
        DIFFICULTY_ALGORITHM
    );
}

fn validate_rpc_security(config: &RunConfig) -> Result<(), String> {
    if config.rpc_tls_cert.is_some() != config.rpc_tls_key.is_some() {
        return Err("RPC TLS requires both --rpc-tls-cert and --rpc-tls-key".to_string());
    }
    if !config.rpc_addr.ip().is_loopback() && config.rpc_tls_cert.is_none() {
        return Err(format!(
            "public RPC listener {} is non-loopback and requires TLS",
            config.rpc_addr
        ));
    }
    if let Some(admin_addr) = config.rpc_admin_addr {
        let token = config
            .rpc_admin_token
            .as_ref()
            .ok_or("RPC admin listener requires --rpc-admin-token")?;
        if token.len() < 32 {
            return Err("RPC admin token must contain at least 32 characters".to_string());
        }
        if !admin_addr.ip().is_loopback() && config.rpc_tls_cert.is_none() {
            return Err(format!(
                "admin RPC listener {admin_addr} is non-loopback and requires TLS"
            ));
        }
    }
    Ok(())
}

fn run_node(args: &[String]) -> Result<(), String> {
    let startup_started = Instant::now();
    let mut config = parse_run_config(args)?;
    validate_mining_config(&config)?;
    print_core_startup_info();
    println!(
        "[STARTUP] configuration loaded db={} mining={} peers={} elapsed={}ms",
        config.db_path,
        config.mine,
        config.peers.len(),
        startup_started.elapsed().as_millis()
    );
    validate_rpc_security(&config)?;
    if let Some(path) = &config.peers_file {
        config.peers.extend(load_peers_file(path)?);
    }
    for seed in &config.dns_seeds {
        match resolve_dns_seed(seed, config.listen_addrs[0].port()) {
            Ok(mut addrs) => {
                println!("[DISCOVERY] dns_seed seed={seed} peers={}", addrs.len());
                config.peers.append(&mut addrs);
            }
            Err(error) => eprintln!("[DISCOVERY] dns_seed_failed seed={seed} error=\"{error}\""),
        }
    }
    dedupe_peers(&mut config.peers);
    if config.peers.len() > config.max_peers {
        config.peers.truncate(config.max_peers);
    }
    if config.listen_addrs.is_empty() {
        return Err("at least one --listen address is required".to_string());
    }
    dedupe_socket_addrs(&mut config.listen_addrs);
    dedupe_socket_addrs(&mut config.public_addrs);

    if config.fast_sync && !Path::new(&config.db_path).exists() {
        println!(
            "[FASTSYNC] discovering authenticated header chains from {} peer(s)",
            config.peers.len()
        );
        let download = download_authenticated_snapshot(&config.peers)?;
        let bundle = snapshot::FastSyncBundle {
            version: snapshot::FAST_SYNC_BUNDLE_VERSION,
            headers: download.headers,
            snapshot: download.snapshot,
        }
        .encode()?;
        let (height, hash, work) = snapshot::import_bytes_atomic(&config.db_path, &bundle)?;
        println!(
            "[FASTSYNC] activated peer={} height={} tip={} work={:016x?}",
            download.peer,
            height.0,
            hex::encode(hash.0),
            work.to_be_limbs()
        );
    } else if config.fast_sync {
        println!(
            "[FASTSYNC] skipped: database path already exists ({})",
            config.db_path
        );
    }

    let database_started = Instant::now();
    println!(
        "[STARTUP] opening database={} action=validate_and_restore",
        config.db_path
    );
    let mut node = open_node(&config.db_path, config.miner_address)?;
    println!(
        "[STARTUP] database ready height={} tip={} elapsed={}ms",
        node.tip_height().unwrap_or(Height(0)).0,
        short_hash(node.tip_hash()),
        database_started.elapsed().as_millis()
    );
    node.mempool = runtime::mempool::Mempool::with_config(MempoolConfig {
        min_relay_fee: config.min_relay_fee,
        market_fee: config.market_fee,
        low_fee_ttl_secs: config.low_fee_expiry.as_secs(),
        transaction_ttl_secs: config.mempool_expiry.as_secs(),
        ..MempoolConfig::default()
    });
    node.next_difficulty()
        .map_err(|error| format!("failed to calculate next difficulty: {error}"))?;

    let bound_addrs = config.listen_addrs.clone();
    println!(
        "[STARTUP] binding network p2p={} rpc={}",
        format_socket_addrs(&config.listen_addrs),
        config.rpc_addr
    );
    if config.nat_traversal {
        let lease = config.nat_lease;
        for local_addr in bound_addrs.clone() {
            match nat::map_tcp_listener(local_addr, lease) {
                Ok(mapping) => {
                    println!(
                        "[NAT] mapped protocol=tcp local={} public={} lease={}s",
                        mapping.local_addr,
                        mapping.public_addr,
                        mapping.lease.as_secs()
                    );
                    config.public_addrs.push(mapping.public_addr);
                }
                Err(error) => {
                    eprintln!("[NAT] mapping_failed local={local_addr} error=\"{error}\"")
                }
            }
        }
        dedupe_socket_addrs(&mut config.public_addrs);
    }
    for public_addr in &config.public_addrs {
        println!("[P2P] advertised_addr={public_addr}");
    }

    let peers = Arc::new(Mutex::new(
        config
            .peers
            .iter()
            .copied()
            .map(|peer| (peer, PeerState::new(peer)))
            .collect::<HashMap<_, _>>(),
    ));
    let peer_connections = Arc::new(Mutex::new(HashMap::new()));
    let inbound_connections = Arc::new(Mutex::new(HashMap::new()));
    let log_counters = Arc::new(LogCounters::default());
    let mining_stats = Arc::new(MiningStats::default());
    let rpc_metrics = Arc::new(RpcMetrics::default());
    let node = Arc::new(Mutex::new(node));
    let p2p_swarm = p2p::swarm::start(
        &config.listen_addrs,
        &config.peers,
        &config.public_addrs,
        Path::new(&config.db_path).join("p2p-identity.key"),
        node.clone(),
        peers.clone(),
    )?;

    {
        let node = node
            .lock()
            .map_err(|_| "node state lock poisoned".to_string())?;
        println!(
            "[OK] preflight height={} tip={} difficulty={} mempool={} mining={}",
            node.tip_height().unwrap_or(Height(0)).0,
            short_hash(node.tip_hash()),
            format_difficulty(node.next_difficulty()),
            node.mempool.len(),
            config.mine
        );
        println!(
            "[NODE] db={} p2p={} rpc={} height={} tip={} difficulty={} peers={} mining={} relay_fee={} market_fee={} dynamic_fee={} miner_fee={} low_fee_retention={}s mempool_retention={}s",
            config.db_path,
            format_socket_addrs(&bound_addrs),
            config.rpc_addr,
            node.tip_height().unwrap_or(Height(0)).0,
            short_hash(node.tip_hash()),
            format_difficulty(node.next_difficulty()),
            config.peers.len(),
            config.mine,
            config.min_relay_fee,
            config.market_fee,
            node.mempool.dynamic_market_fee_rate(),
            config
                .miner_min_fee_rate
                .map(|rate| rate.to_string())
                .unwrap_or_else(|| "dynamic".to_string()),
            config.low_fee_expiry.as_secs(),
            config.mempool_expiry.as_secs()
        );
    }
    if !config.mine {
        println!("[HINT] mining=off set mine=true and wallet=wallet.json in config.json");
    }

    println!(
        "[STARTUP] services starting elapsed={}ms",
        startup_started.elapsed().as_millis()
    );

    let _rpc = start_rpc_servers(
        RpcState {
            node: node.clone(),
            peers: peers.clone(),
            peer_connections: peer_connections.clone(),
            inbound_connections: inbound_connections.clone(),
            mining: config.mine,
            log_counters: log_counters.clone(),
            mining_stats: mining_stats.clone(),
            metrics: rpc_metrics,
            db_path: config.db_path.clone(),
        },
        RpcServerConfig {
            public_addr: config.rpc_addr,
            admin_addr: config.rpc_admin_addr,
            admin_token: config
                .rpc_admin_token
                .as_ref()
                .map(|token| Arc::new(Zeroizing::new(token.to_string()))),
            tls_cert: config.rpc_tls_cert.clone(),
            tls_key: config.rpc_tls_key.clone(),
            cors_origins: config.rpc_cors_origins.clone(),
            max_body_bytes: config.rpc_max_body_bytes,
            timeout: config.rpc_timeout,
            max_concurrent_requests: config.rpc_max_concurrent_requests,
            max_connections: config.rpc_max_connections,
            rate_limit_per_second: config.rpc_rate_limit_per_second,
            rate_limit_burst: config.rpc_rate_limit_burst,
        },
    )?;
    let _grpc = config.grpc_addr.map(|addr| {
        grpc::start_grpc_server(
            addr,
            node.clone(),
            peers.clone(),
            peer_connections.clone(),
            config.mine,
            config.min_relay_fee,
            config.market_fee,
        )
    });
    println!(
        "[OK] node active rpc={} p2p={} mining={} startup={}ms",
        config.rpc_addr,
        format_socket_addrs(&bound_addrs),
        config.mine,
        startup_started.elapsed().as_millis()
    );

    let mut last_network = Instant::now()
        .checked_sub(ACTIVITY_LOG_INTERVAL)
        .unwrap_or_else(Instant::now);
    let mut last_gateway = Instant::now()
        .checked_sub(config.gateway_heartbeat)
        .unwrap_or_else(Instant::now);
    while !SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
        service_network_once(
            &node,
            &config,
            &peers,
            &peer_connections,
            &inbound_connections,
        );
        service_gateway_once(
            &node,
            &config,
            &peers,
            &mut last_gateway,
            bound_addrs.first().copied(),
        );
        if config.mine {
            if let Some(block) =
                mine_once_unlocked(&node, &config, &mining_stats, &SHUTDOWN_REQUESTED)?
            {
                let block_hash = block.hash().map_err(|error| error.to_string())?;
                let announcement = CompactBlock::from_block(&block)
                    .map(NetworkMessage::CompactBlock)
                    .unwrap_or_else(|error| {
                        eprintln!(
                            "[P2P] compact_block_build_failed hash={} error=\"{}\" fallback=inventory",
                            hex::encode(block_hash.0),
                            error
                        );
                        NetworkMessage::Inventory(vec![InventoryItem::Block(block_hash)])
                    });
                let report = broadcast_to_peers(
                    &peers,
                    &peer_connections,
                    &inbound_connections,
                    announcement,
                );
                block_announced(
                    block.height().0,
                    block_hash,
                    report.attempted,
                    report.sent,
                    report.failed,
                );
            }
            if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
                break;
            }
        }
        if last_network.elapsed() >= ACTIVITY_LOG_INTERVAL {
            last_network = Instant::now();
            let node = node
                .lock()
                .map_err(|_| "node state lock poisoned".to_string())?;
            mining_status(MiningStatus {
                height: node.tip_height().unwrap_or(Height(0)).0,
                tip: node.tip_hash(),
                difficulty: format_difficulty(node.next_difficulty()),
                peers: peers.lock().map(|peers| peers.len()).unwrap_or_default(),
                outbound: peer_connections
                    .lock()
                    .map(|connections| connections.len())
                    .unwrap_or_default(),
                inbound: inbound_connections
                    .lock()
                    .map(|connections| connections.len())
                    .unwrap_or_default(),
                hashrate_hps: mining_stats
                    .last_hashrate_hps
                    .load(std::sync::atomic::Ordering::Relaxed),
                accepted_tx: log_counters
                    .accepted_tx_total
                    .load(std::sync::atomic::Ordering::Relaxed),
                broadcast_tx: log_counters
                    .broadcast_tx_total
                    .load(std::sync::atomic::Ordering::Relaxed),
            });
        }
        if !config.mine || config.mine_attempts != 0 {
            interruptible_sleep(config.mine_interval);
        }
    }
    if let Ok(connections) = peer_connections.lock() {
        for connection in connections.values() {
            connection.shutdown();
        }
    }
    if let Ok(connections) = inbound_connections.lock() {
        for connection in connections.values() {
            connection.shutdown();
        }
    }
    p2p_swarm.shutdown();
    println!("[OK] shutdown complete");
    Ok(())
}

fn validate_mining_config(config: &RunConfig) -> Result<(), String> {
    if config.mine && !config.miner_configured {
        return Err(
            "mining requires `wallet` or `miner_address` in config.json, or --wallet/--miner"
                .to_string(),
        );
    }
    Ok(())
}

fn interruptible_sleep(duration: Duration) {
    let deadline = Instant::now()
        .checked_add(duration)
        .unwrap_or_else(Instant::now);
    while !SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        thread::sleep((deadline - now).min(Duration::from_millis(100)));
    }
}

fn service_network_once(
    node: &Arc<Mutex<Node>>,
    config: &RunConfig,
    peers: &Arc<Mutex<HashMap<SocketAddr, PeerState>>>,
    peer_connections: &Arc<Mutex<HashMap<SocketAddr, PeerConnection>>>,
    inbound_connections: &Arc<Mutex<HashMap<SocketAddr, PeerConnection>>>,
) {
    if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
        return;
    }
    let self_addrs = config
        .public_addrs
        .iter()
        .copied()
        .chain(config.listen_addrs.iter().copied())
        .collect::<Vec<_>>();
    let addrs = match peers.lock() {
        Ok(mut peers) => {
            for addr in &self_addrs {
                if peers.remove(addr).is_some() {
                    println!("[P2P] removed_self_peer peer={addr}");
                }
            }
            let mut candidates = peers
                .values()
                .filter(|peer| !peer.is_banned())
                .cloned()
                .collect::<Vec<_>>();
            candidates.sort_by_key(|peer| {
                (
                    peer.score,
                    peer.latency
                        .map(|latency| latency.as_millis() as u64)
                        .unwrap_or(u64::MAX),
                    peer.failures,
                )
            });
            candidates
                .into_iter()
                .take(config.max_peers)
                .map(|peer| peer.addr)
                .collect::<Vec<_>>()
        }
        Err(_) => return,
    };
    let has_outbound = peer_connections
        .lock()
        .map(|connections| !connections.is_empty())
        .unwrap_or(false);
    if !addrs.is_empty() && !has_outbound {
        if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
            return;
        }
        let sync_window = addrs
            .iter()
            .filter_map(|addr| peers.lock().ok()?.get(addr).map(|peer| peer.sync_window))
            .max()
            .unwrap_or(64);
        match sync_from_peers_parallel(addrs.clone(), node, &config.public_addrs, sync_window) {
            Ok(report) => {
                if report.applied_blocks > 0 {
                    println!(
                        "[SYNC] remote_tip={} applied={} peers={}",
                        report.remote_tip.0, report.applied_blocks, report.used_peers
                    );
                }
                if let Ok(mut peers) = peers.lock() {
                    for addr in report.used_peer_addrs {
                        if let Some(peer) = peers.get_mut(&addr) {
                            peer.mark_synced(report.remote_tip, report.applied_blocks);
                        }
                    }
                    for addr in report.failed_peer_addrs {
                        if let Some(peer) = peers.get_mut(&addr) {
                            peer.mark_failed();
                        }
                    }
                }
            }
            Err(error) => eprintln!("[SYNC] failed error=\"{error}\""),
        }
    }

    for addr in addrs {
        if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
            break;
        }
        let should_connect = {
            let peers = match peers.lock() {
                Ok(peers) => peers,
                Err(_) => return,
            };
            let connected = peer_connections
                .lock()
                .map(|connections| connections.contains_key(&addr))
                .unwrap_or(false);
            !connected
                && peers
                    .get(&addr)
                    .map(|peer| !peer.is_banned() && Instant::now() >= peer.next_attempt)
                    .unwrap_or(false)
        };
        if should_connect {
            match PeerConnection::connect(addr) {
                Ok(connection) => {
                    if let Ok(mut inbound) = inbound_connections.lock()
                        && inbound.remove(&addr).is_some()
                    {
                        println!("[P2P] outbound_deduped peer={addr} reason=\"inbound_exists\"");
                    }
                    if let Ok(mut connections) = peer_connections.lock() {
                        connections.insert(addr, connection);
                    }
                }
                Err(error) => {
                    eprintln!("[P2P] connect_failed peer={addr} error=\"{error}\"");
                    if let Ok(mut peers) = peers.lock()
                        && let Some(peer) = peers.get_mut(&addr)
                    {
                        peer.mark_failed();
                        if peer.is_banned() {
                            eprintln!(
                                "[P2P] peer_banned peer={addr} score={} failures={}",
                                peer.score, peer.failures
                            );
                        }
                    }
                }
            }
        }

        let mut connection = match peer_connections
            .lock()
            .ok()
            .and_then(|mut connections| connections.remove(&addr))
        {
            Some(connection) => connection,
            None => continue,
        };
        let sync_window = peers
            .lock()
            .ok()
            .and_then(|peers| peers.get(&addr).map(|peer| peer.sync_window))
            .unwrap_or(64);
        let result = poll_peer_connection(&mut connection, node, &config.public_addrs, sync_window)
            .inspect(|_poll| {
                let _ = sync_mempool_connection(&mut connection, node);
                let discovered = request_peers_connection(&mut connection).unwrap_or_default();
                if let Ok(mut peers) = peers.lock() {
                    for info in discovered {
                        if let Ok(addr) = info.address.parse::<SocketAddr>() {
                            if config.public_addrs.contains(&addr)
                                || config.listen_addrs.contains(&addr)
                            {
                                continue;
                            }
                            peers.entry(addr).or_insert_with(|| PeerState::new(addr));
                        }
                    }
                }
            });
        match result {
            Ok(PeerPoll::Idle {
                remote_tip,
                latency,
            }) => {
                if let Ok(mut peers) = peers.lock()
                    && let Some(peer) = peers.get_mut(&addr)
                {
                    peer.set_latency(latency);
                    peer.mark_ok(Some(remote_tip));
                }
                if let Ok(mut connections) = peer_connections.lock() {
                    connections.insert(addr, connection);
                }
            }
            Ok(PeerPoll::Synced {
                remote_tip,
                synced_blocks,
                latency,
            }) => {
                if let Ok(mut peers) = peers.lock()
                    && let Some(peer) = peers.get_mut(&addr)
                {
                    peer.set_latency(latency);
                    peer.mark_synced(remote_tip, synced_blocks);
                }
                if let Ok(mut connections) = peer_connections.lock() {
                    connections.insert(addr, connection);
                }
            }
            Err(error) => {
                eprintln!("[P2P] poll_failed peer={addr} error=\"{error}\"");
                if let Ok(mut peers) = peers.lock()
                    && let Some(peer) = peers.get_mut(&addr)
                {
                    peer.mark_failed();
                    if peer.failures > MAX_PEER_FAILURES {
                        peers.remove(&addr);
                    } else if peer.is_banned() {
                        eprintln!(
                            "[P2P] peer_banned peer={addr} score={} failures={}",
                            peer.score, peer.failures
                        );
                    }
                }
            }
        }
    }

    if let Some(path) = &config.peers_file
        && let Ok(peers) = peers.lock()
    {
        let _ = save_peer_states_file(path, peers.values().cloned().collect());
    }
}

fn resolve_dns_seed(seed: &str, default_port: u16) -> Result<Vec<SocketAddr>, String> {
    let target = if seed.contains(':') {
        seed.to_string()
    } else {
        format!("{seed}:{default_port}")
    };
    target
        .to_socket_addrs()
        .map(|addrs| addrs.collect::<Vec<_>>())
        .map_err(|error| format!("failed to resolve DNS seed `{seed}`: {error}"))
}

fn service_gateway_once(
    node: &Arc<Mutex<Node>>,
    config: &RunConfig,
    peers: &Arc<Mutex<HashMap<SocketAddr, PeerState>>>,
    last_gateway: &mut Instant,
    public_fallback: Option<SocketAddr>,
) {
    let Some(gateway_url) = config.gateway_url.as_deref() else {
        return;
    };
    if last_gateway.elapsed() < config.gateway_heartbeat {
        return;
    }
    *last_gateway = Instant::now();
    let public_addr = config
        .public_addrs
        .first()
        .copied()
        .or(public_fallback)
        .unwrap_or(config.rpc_addr);
    let (height, tip_hash) = match node.lock() {
        Ok(node) => (
            node.tip_height().map(|height| height.0),
            node.tip_hash().map(|hash| hex::encode(hash.0)),
        ),
        Err(_) => (None, None),
    };
    let _ = register_peer(gateway_url, public_addr, height, tip_hash.clone());
    let _ = heartbeat_peer(gateway_url, public_addr, height, tip_hash);
    match request_gateway_peers(gateway_url, config.max_peers, Some(public_addr)) {
        Ok(discovered) => {
            if let Ok(mut peers) = peers.lock() {
                for info in discovered {
                    if let Ok(addr) = info.address.parse::<SocketAddr>() {
                        peers.entry(addr).or_insert_with(|| PeerState::new(addr));
                    }
                }
            }
        }
        Err(error) => eprintln!("[GATEWAY] peer_request_failed error=\"{error}\""),
    }
}

fn unix_timestamp() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before unix epoch".to_string())
}

#[cfg(test)]
mod test;
