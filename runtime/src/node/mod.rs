use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, OnceLock, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use crate::peer::{
    MAX_DISCOVERED_PEERS, PeerAddress, PeerStore, is_admissible_discovered_peer, rate_limit_key,
};
use crate::sync::{
    HeaderChainChunk, MAX_HEADER_CHAIN_CHUNK_HEADERS, MAX_HEADER_CHAIN_CHUNK_SIZE,
    decode_header_chain_chunk,
};
use borsh::{BorshDeserialize, BorshSerialize};
use kernel::{
    block::{Block, Emission},
    codec::{block_bytes, decode_block},
    common::{Height, Nonce},
    consensus::{
        Work, apply_block, compare_chain_tips, expected_emission_for_height,
        expected_next_difficulty, new_pow_memory,
    },
    crypto::{
        BlockHash, PoWMemory, ProgramId, canonical_bytes, canonical_decode, program_id_from_string,
    },
    genesis::{EXPECTED_GENESIS_HASH, chain_spec_hash, genesis_block},
    ledger::Ledger,
    monetary::coin::{CoinOutput, Zeno},
    operation::BlockOperation,
    program::{AuthorizedProgramEnvelope, ProgramEnvelope as Transaction},
};

mod admission;
const NODE_ID_FILE: &str = "node-id";
const MAX_STORED_BLOCK_SIZE: usize = kernel::block::MAX_BLOCK_SIZE + 1024;
const MAX_STORED_TRANSACTION_SIZE: usize = kernel::program::MAX_PROGRAM_INVOCATION_SIZE;
const MAX_STORED_MEMPOOL_SIZE: u64 = 64 * 1024 * 1024;
const MAX_RPC_HEADER_SIZE: usize = 16 * 1024;
const MAX_RPC_CONNECTIONS: usize = 8;
const MAX_RPC_CONNECTIONS_PER_IP: usize = 4;
const MAX_ACCOUNT_UTXOS_PER_PAGE: usize = 1_000;
const RPC_TIMEOUT: Duration = Duration::from_secs(10);
const OPENAPI_JSON: &[u8] = include_bytes!("../../../docs/openapi.json");
const API_DOCS_HTML: &[u8] = br#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>kernel RPC API</title>
</head>
<body>
  <script id="api-reference" data-url="/openapi.json"></script>
  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
</body>
</html>
"#;
const P2P_MAGIC: [u8; 8] = *b"XPQP2P01";
const P2P_PROTOCOL_VERSION: u32 = 1;
const CAPABILITY_PEER_DISCOVERY: u64 = 1 << 0;
const CAPABILITY_RELAY: u64 = 1 << 1;
const CAPABILITY_PEER_RELAY: u64 = 1 << 2;
const CAPABILITY_COMPACT_BLOCK_RELAY_V2: u64 = 1 << 4;
const LOCAL_CAPABILITIES: u64 = CAPABILITY_PEER_DISCOVERY
    | CAPABILITY_RELAY
    | CAPABILITY_PEER_RELAY
    | CAPABILITY_COMPACT_BLOCK_RELAY_V2;
const MAX_HANDSHAKE_SIZE: usize = 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_LOCATOR_HASHES: usize = 64;
const MAX_SYNC_HEADERS: usize = 100_000;
const GET_HEADERS_MESSAGE: u8 = 1;
const HEADERS_MESSAGE: u8 = 2;
const HEADERS_COMPLETE_MESSAGE: u8 = 3;
const GET_BLOCK_MESSAGE: u8 = 4;
const BLOCK_MESSAGE: u8 = 5;
const SYNC_COMPLETE_MESSAGE: u8 = 6;
const GET_PEERS_MESSAGE: u8 = 7;
const PEERS_MESSAGE: u8 = 8;
const SUBMIT_TRANSACTION_MESSAGE: u8 = 9;
const SUBMIT_BLOCK_MESSAGE: u8 = 10;
const ACCEPTED_MESSAGE: u8 = 11;
const REJECTED_MESSAGE: u8 = 12;
const INVENTORY_MESSAGE: u8 = 13;
const GET_TRANSACTION_MESSAGE: u8 = 14;
const TRANSACTION_MESSAGE: u8 = 15;
const ANNOUNCE_PEER_MESSAGE: u8 = 16;
const ANNOUNCE_PEERS_MESSAGE: u8 = 17;
const COMPACT_BLOCK_MESSAGE: u8 = 18;
const GET_BLOCK_OPERATIONS_MESSAGE: u8 = 19;
const BLOCK_OPERATIONS_MESSAGE: u8 = 20;
const GET_COMPACT_BLOCK_MESSAGE: u8 = 21;
const ANNOUNCE_TIP_MESSAGE: u8 = 22;
const MAX_PEERS_RESPONSE_SIZE: usize = 16 * 1024;
const MAX_PEER_ANNOUNCEMENT_ENDPOINTS: usize = 32;
const PEER_RELAY_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
const MAX_RELAY_ITEMS_PER_SESSION: usize = 256;
const MAX_RELAYED_BLOCKS_PER_SESSION: usize = 4;
const MAX_HEADER_REQUESTS_PER_SESSION: usize =
    MAX_SYNC_HEADERS.div_ceil(MAX_HEADER_CHAIN_CHUNK_HEADERS) + 1;
const MAX_GOSSIP_INVENTORY_ITEMS: usize = 1_024;
const MAX_MEMPOOL_TRANSACTIONS: usize = MAX_GOSSIP_INVENTORY_ITEMS;
const MIN_RELAY_FEE_ZENO_PER_BYTE: u64 = 8;
const MAX_GOSSIP_INVENTORY_SIZE: usize = 64 * 1024;
const GOSSIP_HEARTBEAT: Duration = Duration::from_millis(200);
const GOSSIP_FULL_INVENTORY_INTERVAL: Duration = Duration::from_secs(2);
const MAX_OUTBOUND_CONNECTIONS: usize = 8;
const MAX_CONCURRENT_DIALS: usize = 2;
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_INBOUND_CONNECTIONS: usize = 64;
const MAX_INBOUND_CONNECTIONS_PER_IP: usize = 4;
const RECONNECT_INTERVAL: Duration = Duration::from_secs(10);
const INVALID_POW_COOLDOWN: Duration = Duration::from_secs(10 * 60);
const INVALID_POW_ERROR_PREFIX: &str = "peer-invalid-pow:";
const GOSSIP_RESYNC_PREFIX: &str = "gossip-resync:";
const DEFAULT_NAT_LEASE: Duration = Duration::from_secs(3_600);

#[derive(Clone)]
struct HeaderSyncResult {
    ancestor_height: Height,
    ancestor_hash: BlockHash,
    headers: Vec<kernel::consensus::HeaderAtHeight>,
    peer_work: Work,
    peer_weight: u64,
    preferred: bool,
}

#[derive(Clone)]
struct CachedLedger {
    database: PathBuf,
    ledger: Arc<Ledger>,
    header_checkpoints: Arc<Vec<state::HeaderStateCheckpoint>>,
    cumulative_work: Work,
    cumulative_weight: u64,
}

static LEDGER_CACHE: OnceLock<RwLock<Option<CachedLedger>>> = OnceLock::new();
static ADVERTISED_PEER: OnceLock<RwLock<Option<config::PublicAdvertisement>>> = OnceLock::new();
static STATE_MUTATION_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static PEER_STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static GOSSIP_NOTIFIER: OnceLock<(Mutex<u64>, Condvar)> = OnceLock::new();

struct RunConfig {
    database: PathBuf,
    p2p_listen: String,
    rpc_listen: String,
    peers: Vec<String>,
    miner: Option<ProgramId>,
    public_addr: Option<PeerAddress>,
    nat_traversal: bool,
    chain_minimums: chain_minimums::ChainMinimums,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
struct Handshake {
    magic: [u8; 8],
    protocol_version: u32,
    node_id: [u8; 32],
    genesis_hash: [u8; 32],
    chain_spec_hash: [u8; 32],
    capabilities: u64,
    tip_height: Height,
    tip_hash: [u8; 32],
    cumulative_work: [u64; 8],
    cumulative_weight: u64,
}

struct ConnectedPeer {
    handshake: Handshake,
    stream: TcpStream,
}

struct HandshakeExchange {
    peer: Handshake,
    session_ledger: Arc<Ledger>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
struct CompactBlock {
    block_hash: [u8; 32],
    header: kernel::block::Header,
    height: Height,
    emission: Option<Emission>,
    salt: u64,
    short_ids: Vec<[u8; 6]>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
struct MissingBlockOperations {
    block_hash: [u8; 32],
    indices: Vec<u32>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
struct RequestedBlockOperations {
    block_hash: [u8; 32],
    operations: Vec<(u32, BlockOperation)>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
struct GossipInventory {
    tip_height: Height,
    tip_hash: [u8; 32],
    cumulative_work: [u64; 8],
    cumulative_weight: u64,
    hash: Vec<[u8; 32]>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
struct TipAnnouncement {
    tip_height: Height,
    tip_hash: [u8; 32],
    cumulative_work: [u64; 8],
    cumulative_weight: u64,
}

enum PeerSessionOutcome {
    Complete,
    ReverseSync(GossipInventory),
}

#[derive(Debug)]
struct HttpRequest {
    headers: String,
    body: Vec<u8>,
}

mod chain_minimums;
mod chain_sync;
mod config;
mod explorer;
mod gossip;
mod index;
mod journal;
mod mempool;
mod mining;
mod p2p;
mod protocol;
mod recovery;
mod rpc;
mod state;
mod util;

pub fn run(args: Vec<String>) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None => run_automatic(&[]),
        Some("run") => run_automatic(&args[1..]),
        Some("info") => config::print_network_info(),
        Some("peers") => {
            if args.len() > 2 {
                return Err("usage: node peers [data-dir]".into());
            }
            print_stored_peers(args.get(1).map(String::as_str))
        }
        Some("check") => {
            let mut path = None;
            let mut full = false;
            for argument in &args[1..] {
                match argument.as_str() {
                    "--full" => full = true,
                    value if value.starts_with("--") => {
                        return Err(format!("unknown check option: {value}"));
                    }
                    value if path.is_none() => path = Some(value),
                    _ => return Err("usage: node check [database] [--full]".into()),
                }
            }
            state::check_database(path, full)
        }
        Some("submit-block") => state::submit_block(
            args.get(1).map(String::as_str),
            args.get(2).ok_or("missing block hex")?,
        ),
        Some("mine-block") => mining::mine_one_block(
            args.get(1).map(String::as_str),
            args.get(2).ok_or("missing miner program ID")?,
        ),
        Some("submit-transaction") => mempool::submit_transaction(
            args.get(1).map(String::as_str),
            args.get(2).ok_or("missing transaction hex")?,
        ),
        Some("submit-deploy") => mempool::submit_deploy(
            args.get(1).map(String::as_str),
            args.get(2).ok_or("missing deploy hex")?,
        ),
        Some("mempool") => mempool::print_mempool(args.get(1).map(String::as_str)),
        Some("program-account") => explorer::print_account(
            args.get(1).map(String::as_str),
            args.get(2).ok_or("missing account program ID")?,
        ),
        Some("rpc") => rpc::serve_rpc(
            args.get(1).map(String::as_str),
            args.get(2).map_or("127.0.0.1:6666", String::as_str),
        ),
        Some("p2p-listen") => p2p::serve_p2p(
            args.get(1).map(String::as_str),
            args.get(2).map_or("0.0.0.0:6677", String::as_str),
        ),
        Some("network") => p2p::run_network(
            args.get(1).map(String::as_str),
            args.get(2)
                .map_or(config::default_p2p_listen(), String::as_str),
            args.get(3..).unwrap_or(&[]),
        ),
        Some("peer") => p2p::connect_peer(
            args.get(1).map(String::as_str),
            args.get(2).ok_or("missing peer address")?,
        ),
        Some("version") | Some("--version") | Some("-V") => {
            println!("node {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("help") | Some("--help") | Some("-h") => {
            config::print_help();
            Ok(())
        }
        Some(command) => Err(format!("unknown command `{command}`")),
    }
}

fn print_stored_peers(path: Option<&str>) -> Result<(), String> {
    let database = config::database_path(path);
    let mut found = false;

    if let Some(bytes) = crate::storage::auxiliary_get(&database, "peers")? {
        let decoded: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("decode peer store: {error}"))?;
        let peers = decoded
            .get("peers")
            .and_then(serde_json::Value::as_array)
            .ok_or("invalid peer store: expected peers array")?;
        println!("P2P peers ({}):", peers.len());
        for peer in peers {
            let address = peer
                .get("address")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let successes = peer
                .get("successes")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let failures = peer
                .get("failures")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            println!("  {address} successes={successes} failures={failures}");
        }
        found = true;
    } else if let Ok(bytes) = std::fs::read(database.join("peers.json")) {
        let decoded: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("decode peer JSON export: {error}"))?;
        let peers = decoded
            .get("peers")
            .and_then(serde_json::Value::as_array)
            .ok_or("invalid peer JSON export: expected peers array")?;
        println!("P2P peers ({}):", peers.len());
        for peer in peers {
            let address = peer
                .get("address")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let successes = peer
                .get("successes")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let failures = peer
                .get("failures")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            println!("  {address} successes={successes} failures={failures}");
        }
        found = true;
    }

    if !found {
        println!("no stored peers in {}", database.display());
    }
    Ok(())
}

fn run_automatic(args: &[String]) -> Result<(), String> {
    let config = RunConfig::parse(args)?;
    state::load_or_initialize(&config.database)?;
    chain_minimums::configure(&config.database, config.chain_minimums)?;
    println!(
        "chain_minimums: work={} weight={}",
        util::format_work(config.chain_minimums.work.to_be_limbs()),
        config.chain_minimums.weight
    );
    config::configure_public_address(&config)?;
    let sync_lock = Arc::new(Mutex::new(()));

    let rpc_database = config.database.clone();
    let rpc_listen = config.rpc_listen.clone();
    thread::spawn(move || {
        if let Err(error) = rpc::serve_rpc_database(rpc_database, &rpc_listen) {
            eprintln!("node: RPC stopped: {error}");
        }
    });

    p2p::start_peer_supervisor(
        config.database.clone(),
        config.peers.clone(),
        Arc::clone(&sync_lock),
    );

    if let Some(miner) = config.miner {
        let database = config.database.clone();
        thread::spawn(move || mining::mining_loop(database, miner));
    }

    println!("database: {}", config.database.display());
    println!("rpc: http://{}", config.rpc_listen);
    println!("outbound_peers: {}", config.peers.len());
    if config.miner.is_some() {
        println!("mining: enabled on the local canonical tip");
    } else {
        println!("mining: disabled");
    }
    p2p::serve_p2p_database(config.database, &config.p2p_listen)
}

#[cfg(test)]
mod tests;
