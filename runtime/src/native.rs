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

use crate::peer::{MAX_DISCOVERED_PEERS, PeerStore, is_admissible_discovered_peer};
use crate::sync::{
    HeaderChainChunk, MAX_HEADER_CHAIN_CHUNK_HEADERS, MAX_HEADER_CHAIN_CHUNK_SIZE,
    decode_header_chain_chunk,
};
use borsh::{BorshDeserialize, BorshSerialize};
use xparq::{
    block::{Block, Emission, Height, Nonce},
    codec::{block_bytes, decode_block},
    coin::Amount,
    common::{canonical_bytes, canonical_decode},
    consensus::{
        ReorgPlan, Work, apply_block, compare_chain_tips, expected_emission_for_height,
        expected_next_difficulty, new_pow_memory, validate_transaction,
    },
    crypto::{Address, BlockHash, StateRoot, address_from_string},
    genesis::{EXPECTED_GENESIS_HASH, chain_spec_hash, genesis_block},
    ledger::Ledger,
    transaction::{AuthorizedTransaction, OutputTarget, SpendOutput},
};

const NODE_ID_FILE: &str = "node-id";
const MAX_STORED_BLOCK_SIZE: usize = xparq::block::MAX_BLOCK_WEIGHT + 1024;
const MAX_STORED_TRANSACTION_SIZE: usize = xparq::block::MAX_BLOCK_WEIGHT;
const MAX_STORED_MEMPOOL_SIZE: u64 = 64 * 1024 * 1024;
const MAX_RPC_HEADER_SIZE: usize = 16 * 1024;
const MAX_ACCOUNT_UTXOS_PER_PAGE: usize = 1_000;
const RPC_TIMEOUT: Duration = Duration::from_secs(10);
const OPENAPI_JSON: &[u8] = include_bytes!("../../docs/openapi.json");
const API_DOCS_HTML: &[u8] = br#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>XPARQ Node RPC API</title>
</head>
<body>
  <script id="api-reference" data-url="/openapi.json"></script>
  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
</body>
</html>
"#;
const P2P_MAGIC: [u8; 8] = *b"XPQP2P01";
const P2P_PROTOCOL_VERSION: u32 = 6;
const CAPABILITY_PEER_DISCOVERY: u64 = 1 << 0;
const CAPABILITY_RELAY: u64 = 1 << 1;
const LOCAL_CAPABILITIES: u64 = CAPABILITY_PEER_DISCOVERY | CAPABILITY_RELAY;
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
const MAX_PEERS_RESPONSE_SIZE: usize = 16 * 1024;
const MAX_RELAY_ITEMS_PER_SESSION: usize = 256;
const MAX_RELAYED_BLOCKS_PER_SESSION: usize = 4;
const MAX_HEADER_REQUESTS_PER_SESSION: usize =
    MAX_SYNC_HEADERS.div_ceil(MAX_HEADER_CHAIN_CHUNK_HEADERS) + 1;
const MAX_GOSSIP_INVENTORY_ITEMS: usize = 1_024;
const MAX_MEMPOOL_TRANSACTIONS: usize = MAX_GOSSIP_INVENTORY_ITEMS;
const MIN_RELAY_FEE_ESCA_PER_BYTE: u64 = 1;
const MAX_GOSSIP_INVENTORY_SIZE: usize = 64 * 1024;
const GOSSIP_HEARTBEAT: Duration = Duration::from_secs(2);
const MAX_INBOUND_CONNECTIONS: usize = 64;
const MAX_INBOUND_CONNECTIONS_PER_IP: usize = 4;
const RECONNECT_INTERVAL: Duration = Duration::from_secs(10);
const INVALID_POW_COOLDOWN: Duration = Duration::from_secs(10 * 60);
const INVALID_POW_ERROR_PREFIX: &str = "peer-invalid-pow:";
const GOSSIP_RESYNC_PREFIX: &str = "gossip-resync:";
const DEFAULT_NAT_LEASE: Duration = Duration::from_secs(3_600);

struct HeaderSyncResult {
    ancestor_height: Height,
    ancestor_hash: BlockHash,
    headers: Vec<xparq::consensus::HeaderAtHeight>,
    peer_work: Work,
    peer_weight: u128,
    preferred: bool,
}

#[derive(Clone)]
struct CachedLedger {
    database: PathBuf,
    ledger: Ledger,
}

static LEDGER_CACHE: OnceLock<RwLock<Option<CachedLedger>>> = OnceLock::new();
static ADVERTISED_PEER: OnceLock<RwLock<Option<SocketAddr>>> = OnceLock::new();
static STATE_MUTATION_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static PEER_STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static GOSSIP_NOTIFIER: OnceLock<(Mutex<u64>, Condvar)> = OnceLock::new();

struct RunConfig {
    database: PathBuf,
    p2p_listen: String,
    rpc_listen: String,
    peers: Vec<String>,
    miner: Option<Address>,
    public_addr: Option<SocketAddr>,
    nat_traversal: bool,
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
    cumulative_weight: u128,
}

struct ConnectedPeer {
    handshake: Handshake,
    stream: TcpStream,
}

struct HandshakeExchange {
    peer: Handshake,
    local_headers: Vec<(Height, xparq::block::Header)>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
struct GossipInventory {
    tip_height: Height,
    tip_hash: [u8; 32],
    cumulative_work: [u64; 8],
    cumulative_weight: u128,
    transaction_ids: Vec<[u8; 32]>,
}

enum PeerSessionOutcome {
    Complete,
    ReverseSync(GossipInventory),
}

pub fn run(args: Vec<String>) -> Result<(), String> {
    initialize_extensions()?;
    match args.first().map(String::as_str) {
        None => run_automatic(&[]),
        Some("run") => run_automatic(&args[1..]),
        Some("info") => print_network_info(),
        Some("check") => check_database(args.get(1).map(String::as_str)),
        Some("submit-block") => submit_block(
            args.get(1).map(String::as_str),
            args.get(2).ok_or("missing block hex")?,
        ),
        Some("mine-block") => mine_one_block(
            args.get(1).map(String::as_str),
            args.get(2).ok_or("missing miner address")?,
        ),
        Some("submit-transaction") => submit_transaction(
            args.get(1).map(String::as_str),
            args.get(2).ok_or("missing transaction hex")?,
        ),
        Some("mempool") => print_mempool(args.get(1).map(String::as_str)),
        Some("account") => print_account(
            args.get(1).map(String::as_str),
            args.get(2).ok_or("missing account address")?,
        ),
        Some("rpc") => serve_rpc(
            args.get(1).map(String::as_str),
            args.get(2).map_or("127.0.0.1:6666", String::as_str),
        ),
        Some("p2p-listen") => serve_p2p(
            args.get(1).map(String::as_str),
            args.get(2).map_or("0.0.0.0:6677", String::as_str),
        ),
        Some("network") => run_network(
            args.get(1).map(String::as_str),
            args.get(2).map_or(default_p2p_listen(), String::as_str),
            args.get(3..).unwrap_or(&[]),
        ),
        Some("peer") => connect_peer(
            args.get(1).map(String::as_str),
            args.get(2).ok_or("missing peer address")?,
        ),
        Some("version") | Some("--version") | Some("-V") => {
            println!("node {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("help") | Some("--help") | Some("-h") => {
            print_help();
            Ok(())
        }
        Some(command) => Err(format!("unknown command `{command}`")),
    }
}

fn initialize_extensions() -> Result<(), String> {
    let chain = xparq::genesis::chain_context().map_err(|error| error.to_string())?;
    let mut registry = xparq::extension::ExtensionRegistry::new();
    registry
        .register(xparq::extension::asset::AssetExtension::new(
            chain.genesis_hash,
            xparq::extension::asset::ASSET_ACTIVATION_HEIGHT,
        ))
        .map_err(|error| format!("register asset extension: {error:?}"))?;
    xparq::extension::initialize_production_registry(registry)
        .map_err(|error| format!("initialize extension registry: {error:?}"))
}

fn run_automatic(args: &[String]) -> Result<(), String> {
    let config = RunConfig::parse(args)?;
    load_or_initialize(&config.database)?;
    configure_public_address(&config)?;
    let sync_lock = Arc::new(Mutex::new(()));

    let rpc_database = config.database.clone();
    let rpc_listen = config.rpc_listen.clone();
    thread::spawn(move || {
        if let Err(error) = serve_rpc_database(rpc_database, &rpc_listen) {
            eprintln!("node: RPC stopped: {error}");
        }
    });

    start_peer_supervisor(
        config.database.clone(),
        config.peers.clone(),
        Arc::clone(&sync_lock),
    );

    if let Some(miner) = config.miner {
        let database = config.database.clone();
        thread::spawn(move || mining_loop(database, miner));
    }

    println!("database: {}", config.database.display());
    println!("rpc: http://{}", config.rpc_listen);
    println!("outbound_peers: {}", config.peers.len());
    if config.miner.is_some() {
        println!("mining: enabled on the local canonical tip");
    } else {
        println!("mining: disabled");
    }
    serve_p2p_database(config.database, &config.p2p_listen)
}

fn mining_loop(database: PathBuf, miner: Address) {
    let mut next_nonce = 0_u64;
    println!("mining_state: ready");
    loop {
        match mine_block_database(&database, miner, next_nonce, 1_000_000) {
            Ok(MiningAttempt::Mined) => next_nonce = 0,
            Ok(MiningAttempt::Exhausted { next }) => next_nonce = next,
            Err(error) => {
                next_nonce = 0;
                eprintln!("node: mining attempt failed: {error}");
            }
        }
    }
}

impl RunConfig {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut database = PathBuf::from(default_database());
        let mut p2p_listen = default_p2p_listen().to_string();
        let mut rpc_listen = default_rpc_listen().to_string();
        let mut peers = Vec::new();
        let mut miner = None;
        let mut public_addr = None;
        let mut nat_traversal = false;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--data" => {
                    index += 1;
                    database = PathBuf::from(args.get(index).ok_or("missing value for --data")?);
                }
                "--p2p" => {
                    index += 1;
                    p2p_listen = args.get(index).ok_or("missing value for --p2p")?.clone();
                }
                "--rpc" => {
                    index += 1;
                    rpc_listen = args.get(index).ok_or("missing value for --rpc")?.clone();
                }
                "--peer" => {
                    index += 1;
                    peers.push(args.get(index).ok_or("missing value for --peer")?.clone());
                }
                "--miner" => {
                    index += 1;
                    miner = Some(parse_address(
                        args.get(index).ok_or("missing value for --miner")?,
                    )?);
                }
                "--public-addr" => {
                    index += 1;
                    public_addr = Some(
                        args.get(index)
                            .ok_or("missing value for --public-addr")?
                            .parse()
                            .map_err(|_| "invalid --public-addr socket address")?,
                    );
                }
                "--nat-traversal" => nat_traversal = true,
                option => return Err(format!("unknown node run option `{option}`")),
            }
            index += 1;
        }
        Ok(Self {
            database,
            p2p_listen,
            rpc_listen,
            peers,
            miner,
            public_addr,
            nat_traversal,
        })
    }
}

enum MiningAttempt {
    Mined,
    Exhausted { next: u64 },
}

fn mine_block_database(
    database: &Path,
    miner: Address,
    start_nonce: u64,
    attempts: u64,
) -> Result<MiningAttempt, String> {
    let mut ledger = load_or_initialize(database)?;
    let mempool = read_mempool(database)?;
    let transactions = select_block_transactions(&ledger, miner, &mempool)?;
    validate_mempool(&ledger, &transactions)?;
    let mut block = candidate_block(&ledger, miner, transactions.clone())?;
    block
        .validate_structure()
        .map_err(|error| format!("mining candidate is invalid: {error}"))?;
    let height = block.height();
    let mut memory = new_pow_memory();
    let found = crate::miner::mine_range(
        &mut block,
        crate::miner::MiningRange {
            start_nonce,
            attempts,
        },
        &mut memory,
    )
    .map_err(|error| error.to_string())?;
    if found.is_none() {
        return Ok(MiningAttempt::Exhausted {
            next: start_nonce.wrapping_add(attempts),
        });
    }
    let _mutation = state_mutation_lock()?
        .lock()
        .map_err(|_| "state mutation lock is poisoned")?;
    ledger = load_or_initialize(database)?;
    if ledger.tip_hash().map(|hash| hash.0) != Some(block.previous_hash().0) {
        return Err("mined candidate became stale while mining".into());
    }
    apply_block(&mut ledger, block.clone()).map_err(|error| error.to_string())?;
    let included = transactions
        .iter()
        .map(|transaction| transaction.id().map_err(|error| error.to_string()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let remaining = reconcile_mempool(&ledger, read_mempool(database)?, &included);
    persist_block_and_mempool(database, &block, &remaining)?;
    update_ledger_cache(database, &ledger)?;
    notify_gossip();
    println!(
        "mined height={} nonce={} hash={}",
        height.0,
        block.header.nonce.0,
        hex::encode(block.hash().map_err(|error| error.to_string())?.0)
    );
    Ok(MiningAttempt::Mined)
}

fn mine_one_block(path: Option<&str>, miner: &str) -> Result<(), String> {
    let database = database_path(path);
    let miner = parse_address(miner)?;
    let mut next_nonce = 0_u64;
    loop {
        match mine_block_database(&database, miner, next_nonce, 1_000_000)? {
            MiningAttempt::Mined => return Ok(()),
            MiningAttempt::Exhausted { next } => next_nonce = next,
        }
    }
}

fn select_block_transactions(
    ledger: &Ledger,
    miner: Address,
    mempool: &[AuthorizedTransaction],
) -> Result<Vec<AuthorizedTransaction>, String> {
    let mut selected = Vec::new();
    for transaction in mempool {
        let mut candidate = selected.clone();
        candidate.push(transaction.clone());
        let block = candidate_block(ledger, miner, candidate.clone())?;
        if block.weight().map_err(|error| error.to_string())? > xparq::block::MAX_BLOCK_WEIGHT {
            break;
        }
        selected = candidate;
    }
    Ok(selected)
}

fn candidate_block(
    ledger: &Ledger,
    miner: Address,
    transactions: Vec<AuthorizedTransaction>,
) -> Result<Block, String> {
    let height = Height(
        ledger
            .tip_height()
            .map_or(0, |height| height.0.saturating_add(1)),
    );
    let previous = ledger.tip_hash().ok_or("canonical genesis is missing")?;
    let difficulty = expected_next_difficulty(&ledger.chain).map_err(|error| error.to_string())?;
    let parent_emission = if height.0 <= 1 {
        xparq::consensus::initial_block_emission()
    } else {
        ledger
            .chain
            .block(&Height(height.0 - 1))
            .and_then(Block::emission)
            .map(|emission| emission.subsidy)
            .ok_or("parent emission is missing")?
    };
    let subsidy = expected_emission_for_height(height, parent_emission, |height| {
        ledger
            .chain
            .header(&height)
            .map(|header| header.block_weight)
    })
    .map_err(|error| error.to_string())?;
    let extension_root = ledger
        .preview_extension_state_root(&transactions, height)
        .map_err(|error| error.to_string())?;
    let mut block = Block::from_protocol_transactions(
        height,
        previous,
        difficulty,
        Nonce(0),
        Some(Emission::new(miner, subsidy)),
        transactions,
    )
    .map_err(|error| error.to_string())?;
    block.set_state_root(StateRoot(*extension_root.as_bytes()));
    Ok(block)
}

fn submit_transaction(path: Option<&str>, encoded: &str) -> Result<(), String> {
    let database = database_path(path);
    let bytes =
        hex::decode(encoded).map_err(|error| format!("invalid transaction hex: {error}"))?;
    if bytes.is_empty() || bytes.len() > MAX_STORED_TRANSACTION_SIZE {
        return Err("transaction size is outside allowed range".into());
    }
    let transaction: AuthorizedTransaction =
        canonical_decode(&bytes).map_err(|error| format!("invalid transaction: {error}"))?;
    let transaction_id = insert_mempool_transaction(&database, transaction, false)?;
    println!("accepted transaction={}", hex::encode(transaction_id));
    Ok(())
}

fn print_mempool(path: Option<&str>) -> Result<(), String> {
    let database = database_path(path);
    let transactions = read_mempool(&database)?;
    println!("transactions: {}", transactions.len());
    for transaction in transactions {
        println!(
            "{}",
            hex::encode(transaction.id().map_err(|error| error.to_string())?)
        );
    }
    Ok(())
}

fn print_account(path: Option<&str>, address: &str) -> Result<(), String> {
    let database = database_path(path);
    let ledger = load_or_initialize(&database)?;
    let address = parse_address(address)?;
    let response = account_response(&ledger, &read_mempool(&database)?, address, 0)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&response).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn account_response(
    ledger: &Ledger,
    mempool: &[AuthorizedTransaction],
    address: Address,
    utxo_offset: usize,
) -> Result<serde_json::Value, String> {
    let next_height = ledger
        .tip_height()
        .map_or(0, |height| height.0.saturating_add(1));
    let reserved = reserved_coin_inputs(mempool);
    let mut total = Amount::from_esca(0);
    let mut spendable = Amount::from_esca(0);
    let account_utxos = ledger
        .state()
        .coins
        .iter()
        .filter(|utxo| utxo.owner == address)
        .collect::<Vec<_>>();
    for utxo in &account_utxos {
        let is_reserved = reserved.contains(&utxo.coin.id);
        let is_spendable = utxo
            .maturity_height
            .is_none_or(|height| height.0 <= next_height)
            && !is_reserved;
        total = total
            .checked_add(utxo.coin.amount)
            .ok_or("account balance overflow")?;
        if is_spendable {
            spendable = spendable
                .checked_add(utxo.coin.amount)
                .ok_or("account balance overflow")?;
        }
    }
    let utxos = account_utxos
        .iter()
        .skip(utxo_offset)
        .take(MAX_ACCOUNT_UTXOS_PER_PAGE)
        .map(|utxo| {
            let is_reserved = reserved.contains(&utxo.coin.id);
            serde_json::json!({
                "id": utxo.coin.id.to_string(),
                "amount": utxo.coin.amount.as_esca(),
                "maturity_height": utxo.maturity_height.map(|height| height.0),
                "reserved": is_reserved,
            })
        })
        .collect::<Vec<_>>();
    let next_utxo_offset = utxo_offset
        .checked_add(utxos.len())
        .filter(|offset| *offset < account_utxos.len());
    let registered_signature_profile = ledger
        .state()
        .account_keys
        .get_profile(&address)
        .map(|key| key.profile.as_str());
    let assets = account_asset_balances(ledger, address)?;
    Ok(serde_json::json!({
        "address": xparq::crypto::address_to_string(&address),
        "public_key_registered": registered_signature_profile.is_some(),
        "signature_profile": registered_signature_profile,
        "tip_height": ledger.tip_height().map_or(0, |height| height.0),
        "next_height": next_height,
        "total": total.as_esca(),
        "spendable": spendable.as_esca(),
        "assets": assets,
        "utxos": utxos,
        "next_utxo_offset": next_utxo_offset,
    }))
}

fn account_asset_balances(
    ledger: &Ledger,
    address: Address,
) -> Result<Vec<serde_json::Value>, String> {
    let namespace = ledger
        .state()
        .extensions
        .namespace(xparq::extension::asset::asset_extension_id());
    let mut balances = std::collections::BTreeMap::new();
    for (key, value) in namespace.entries() {
        if let Some((asset_id, metadata)) =
            xparq::extension::asset::decode_asset_metadata_entry(key, value)
                .map_err(|error| format!("decode asset metadata: {error:?}"))?
            && metadata.mint_authority == address
        {
            balances.entry(asset_id).or_insert(0_u128);
        }
        let Some((asset_id, owner, balance)) =
            xparq::extension::asset::decode_asset_balance_entry(key, value)
                .map_err(|error| format!("decode asset balance: {error:?}"))?
        else {
            continue;
        };
        if owner != address || balance == 0 {
            continue;
        }
        balances.insert(asset_id, balance);
    }
    let mut response = Vec::with_capacity(balances.len());
    for (asset_id, balance) in balances {
        let metadata = xparq::extension::asset::asset_metadata(&namespace, asset_id)
            .map_err(|error| format!("read asset metadata: {error:?}"))?
            .ok_or("asset balance references missing metadata")?;
        response.push(serde_json::json!({
            "asset_id": asset_id.to_string(),
            "name": metadata.name,
            "symbol": metadata.symbol,
            "decimals": metadata.decimals,
            "balance": balance.to_string(),
        }));
    }
    Ok(response)
}

fn explorer_address_response(
    ledger: &Ledger,
    mempool: &[AuthorizedTransaction],
    address: Address,
    include_emissions: bool,
) -> Result<serde_json::Value, String> {
    let next_height = ledger
        .tip_height()
        .map_or(0, |height| height.0.saturating_add(1));
    let reserved_ids = reserved_coin_inputs(mempool);
    let mut total = Amount::from_esca(0);
    let mut spendable = Amount::from_esca(0);
    let mut immature = Amount::from_esca(0);
    let mut reserved = Amount::from_esca(0);
    for utxo in ledger
        .state()
        .coins
        .iter()
        .filter(|utxo| utxo.owner == address)
    {
        total = total
            .checked_add(utxo.coin.amount)
            .ok_or("explorer balance overflow")?;
        if reserved_ids.contains(&utxo.coin.id) {
            reserved = reserved
                .checked_add(utxo.coin.amount)
                .ok_or("explorer reserved balance overflow")?;
        } else if utxo
            .maturity_height
            .is_none_or(|height| height.0 <= next_height)
        {
            spendable = spendable
                .checked_add(utxo.coin.amount)
                .ok_or("explorer spendable balance overflow")?;
        } else {
            immature = immature
                .checked_add(utxo.coin.amount)
                .ok_or("explorer immature balance overflow")?;
        }
    }

    let mut activities = Vec::new();
    let mut emission_count = 0usize;
    for block in ledger.chain.blocks() {
        let block_hash = hex::encode(block.hash().map_err(|error| error.to_string())?.0);
        if let Some(emission) = block.emission().filter(|emission| emission.to == address) {
            emission_count = emission_count.saturating_add(1);
            if include_emissions {
                activities.push(serde_json::json!({
                    "height": block.height().0,
                    "block_hash": block_hash,
                    "transaction_id": serde_json::Value::Null,
                    "type": "emission",
                    "direction": "in",
                    "amount": emission.subsidy.as_esca(),
                    "size_bytes": serde_json::Value::Null,
                }));
            }
        }
        for transaction in block.transactions() {
            if let Some(activity) = address_transaction_activity(transaction, address, block)? {
                activities.push(activity);
            }
        }
    }
    activities.reverse();

    Ok(serde_json::json!({
        "address": xparq::crypto::address_to_string(&address),
        "tip_height": ledger.tip_height().map_or(0, |height| height.0),
        "balance": {
            "total": total.as_esca(),
            "spendable": spendable.as_esca(),
            "immature": immature.as_esca(),
            "reserved": reserved.as_esca(),
        },
        "activity_count": activities.len(),
        "emission_count": emission_count,
        "activities": activities,
    }))
}

fn address_transaction_activity(
    transaction: &AuthorizedTransaction,
    address: Address,
    block: &Block,
) -> Result<Option<serde_json::Value>, String> {
    let miner = block.miner_address();
    let (sender, outputs, extra_sent) = match transaction {
        AuthorizedTransaction::OnChainSpend(tx) => (
            Some(tx.intent.sender),
            tx.intent.outputs.as_slice(),
            Amount::from_esca(0),
        ),
        AuthorizedTransaction::Withdraw(tx) => (
            Some(tx.intent.sender),
            tx.intent.outputs.as_slice(),
            checked_output_sum(tx.intent.qcash_outputs.iter().map(|output| output.amount))?,
        ),
        AuthorizedTransaction::Redeem(tx) => {
            (None, tx.intent.outputs.as_slice(), Amount::from_esca(0))
        }
        AuthorizedTransaction::Merge(tx) => (
            None,
            tx.intent.miner_output.as_slice(),
            Amount::from_esca(0),
        ),
        AuthorizedTransaction::Split(tx) => (
            None,
            tx.intent.miner_output.as_slice(),
            Amount::from_esca(0),
        ),
        AuthorizedTransaction::Extension(tx) => (
            Some(tx.fee.intent.sender),
            tx.fee.intent.outputs.as_slice(),
            Amount::from_esca(0),
        ),
    };
    let received = checked_output_sum(
        outputs
            .iter()
            .filter(|output| output_recipient(output, miner) == address)
            .map(|output| output.amount),
    )?;
    let (direction, amount) = if sender == Some(address) {
        let external = checked_output_sum(
            outputs
                .iter()
                .filter(|output| output_recipient(output, miner) != address)
                .map(|output| output.amount),
        )?
        .checked_add(extra_sent)
        .ok_or("explorer transaction amount overflow")?;
        (
            if external.as_esca() == 0 {
                "self"
            } else {
                "out"
            },
            external,
        )
    } else if received.as_esca() > 0 {
        ("in", received)
    } else {
        return Ok(None);
    };
    Ok(Some(serde_json::json!({
        "height": block.height().0,
        "block_hash": hex::encode(block.hash().map_err(|error| error.to_string())?.0),
        "transaction_id": hex::encode(transaction.id().map_err(|error| error.to_string())?),
        "type": transaction_kind(transaction),
        "direction": direction,
        "amount": amount.as_esca(),
        "size_bytes": canonical_bytes(transaction).map_err(|error| error.to_string())?.len(),
    })))
}

fn explorer_transaction_response(
    ledger: &Ledger,
    transaction_id: [u8; 32],
) -> Result<serde_json::Value, String> {
    let tip_height = ledger.tip_height().map_or(0, |height| height.0);
    for block in ledger.chain.blocks() {
        for transaction in block.transactions() {
            if transaction.id().map_err(|error| error.to_string())? == transaction_id {
                return Ok(serde_json::json!({
                    "transaction_id": hex::encode(transaction_id),
                    "type": transaction_kind(transaction),
                    "status": "confirmed",
                    "height": block.height().0,
                    "block_hash": hex::encode(block.hash().map_err(|error| error.to_string())?.0),
                    "confirmations": tip_height.saturating_sub(block.height().0).saturating_add(1),
                    "size_bytes": canonical_bytes(transaction).map_err(|error| error.to_string())?.len(),
                    "transaction": transaction_response(transaction, block.miner_address()),
                }));
            }
        }
    }
    Err("transaction was not found in the canonical chain".into())
}

fn transaction_response(transaction: &AuthorizedTransaction, miner: Address) -> serde_json::Value {
    match transaction {
        AuthorizedTransaction::OnChainSpend(tx) => serde_json::json!({
            "sender": xparq::crypto::address_to_string(&tx.intent.sender),
            "outputs": public_outputs_response(&tx.intent.outputs, miner),
        }),
        AuthorizedTransaction::Withdraw(tx) => serde_json::json!({
            "sender": xparq::crypto::address_to_string(&tx.intent.sender),
            "outputs": public_outputs_response(&tx.intent.outputs, miner),
            "qcash_output_count": tx.intent.qcash_outputs.len(),
            "qcash_amount": tx.intent.qcash_outputs.iter().map(|output| output.amount.as_esca()).sum::<u64>(),
        }),
        AuthorizedTransaction::Redeem(tx) => serde_json::json!({
            "outputs": public_outputs_response(&tx.intent.outputs, miner),
            "qcash_input_count": tx.intent.inputs.len(),
            "qcash_output_count": tx.intent.qcash_outputs.len(),
        }),
        AuthorizedTransaction::Merge(tx) => serde_json::json!({
            "qcash_input_count": tx.intent.inputs.len(),
            "qcash_output_count": 1,
            "miner_output": public_outputs_response(tx.intent.miner_output.as_slice(), miner),
        }),
        AuthorizedTransaction::Split(tx) => serde_json::json!({
            "qcash_input_count": 1,
            "qcash_output_count": tx.intent.outputs.len(),
            "miner_output": public_outputs_response(tx.intent.miner_output.as_slice(), miner),
        }),
        AuthorizedTransaction::Extension(tx) => extension_transaction_response(tx, miner),
    }
}

fn extension_transaction_response(
    transaction: &xparq::transaction::AuthorizedExtensionTransaction,
    miner: Address,
) -> serde_json::Value {
    let base = serde_json::json!({
        "extension_id": hex::encode(transaction.call.extension_id().as_bytes()),
        "payload_size": transaction.call.payload().len(),
        "fee_sender": xparq::crypto::address_to_string(&transaction.fee.intent.sender),
        "fee_outputs": public_outputs_response(&transaction.fee.intent.outputs, miner),
    });
    if transaction.call.extension_id() != xparq::extension::asset::asset_extension_id() {
        return base;
    }
    let Ok(call) = xparq::extension::asset::AssetCall::from_extension_call(&transaction.call)
    else {
        return base;
    };
    let mut response = base;
    let object = response
        .as_object_mut()
        .expect("extension response is an object");
    object.insert(
        "asset_id".into(),
        serde_json::json!(call.asset_id().to_string()),
    );
    object.insert(
        "signer".into(),
        serde_json::json!(xparq::crypto::address_to_string(&call.signer)),
    );
    object.insert("nonce".into(), serde_json::json!(call.nonce));
    let action = match call.action {
        xparq::extension::asset::AssetAction::Register {
            name,
            symbol,
            decimals,
            max_supply,
        } => serde_json::json!({
            "type": "register",
            "name": name,
            "symbol": symbol,
            "decimals": decimals,
            "max_supply": max_supply.to_string(),
        }),
        xparq::extension::asset::AssetAction::Mint {
            recipient, amount, ..
        } => serde_json::json!({
            "type": "mint",
            "recipient": xparq::crypto::address_to_string(&recipient),
            "amount": amount.to_string(),
        }),
        xparq::extension::asset::AssetAction::Burn { amount, .. } => serde_json::json!({
            "type": "burn",
            "amount": amount.to_string(),
        }),
        xparq::extension::asset::AssetAction::Transfer {
            recipient, amount, ..
        } => serde_json::json!({
            "type": "transfer",
            "recipient": xparq::crypto::address_to_string(&recipient),
            "amount": amount.to_string(),
        }),
    };
    object.insert("asset_action".into(), action);
    response
}

fn public_outputs_response(outputs: &[SpendOutput], miner: Address) -> Vec<serde_json::Value> {
    outputs
        .iter()
        .map(|output| {
            serde_json::json!({
                "address": xparq::crypto::address_to_string(&output_recipient(output, miner)),
                "amount": output.amount.as_esca(),
                "kind": if matches!(output.target, OutputTarget::BlockMiner) { "miner" } else { "address" },
            })
        })
        .collect()
}

fn output_recipient(output: &SpendOutput, miner: Address) -> Address {
    match output.target {
        OutputTarget::Address(address) => address,
        OutputTarget::BlockMiner => miner,
    }
}

fn checked_output_sum(amounts: impl IntoIterator<Item = Amount>) -> Result<Amount, String> {
    amounts
        .into_iter()
        .try_fold(Amount::from_esca(0), |total, amount| {
            total
                .checked_add(amount)
                .ok_or_else(|| "explorer amount overflow".to_string())
        })
}

fn transaction_kind(transaction: &AuthorizedTransaction) -> &'static str {
    match transaction {
        AuthorizedTransaction::OnChainSpend(_) => "transfer",
        AuthorizedTransaction::Withdraw(_) => "qcash_withdraw",
        AuthorizedTransaction::Redeem(_) => "qcash_redeem",
        AuthorizedTransaction::Merge(_) => "qcash_merge",
        AuthorizedTransaction::Split(_) => "qcash_split",
        AuthorizedTransaction::Extension(_) => "extension",
    }
}

fn parse_transaction_id(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || value.contains(['/', '?', '#']) {
        return Err("transaction ID must be 64 hexadecimal characters".into());
    }
    let bytes = hex::decode(value).map_err(|_| "transaction ID is not valid hexadecimal")?;
    bytes
        .try_into()
        .map_err(|_| "transaction ID must be 32 bytes".to_string())
}

fn serve_rpc(path: Option<&str>, listen: &str) -> Result<(), String> {
    let database = database_path(path);
    serve_rpc_database(database, listen)
}

fn serve_rpc_database(database: PathBuf, listen: &str) -> Result<(), String> {
    load_or_initialize(&database)?;
    let listener = TcpListener::bind(listen).map_err(|error| format!("bind RPC: {error}"))?;
    println!("rpc: http://{listen}");
    for connection in listener.incoming() {
        match connection {
            Ok(mut stream) => {
                if let Err(error) = handle_rpc_connection(&database, &mut stream) {
                    let _ =
                        write_http_response(&mut stream, 400, &serde_json::json!({"error": error}));
                }
            }
            Err(error) => eprintln!("node: accept RPC connection: {error}"),
        }
    }
    Ok(())
}

fn handle_rpc_connection(database: &Path, stream: &mut TcpStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(RPC_TIMEOUT))
        .and_then(|_| stream.set_write_timeout(Some(RPC_TIMEOUT)))
        .map_err(|error| format!("configure RPC timeout: {error}"))?;
    let request = read_http_request(stream)?;
    let request_line = request.headers.lines().next().ok_or("empty RPC request")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("missing RPC method")?;
    let route = parts.next().ok_or("missing RPC route")?;
    if method == "POST" && route == "/transaction" {
        let transaction: AuthorizedTransaction = canonical_decode(&request.body)
            .map_err(|error| format!("invalid submitted transaction: {error}"))?;
        let transaction_id = insert_mempool_transaction(database, transaction, false)?;
        return write_http_response(
            stream,
            200,
            &serde_json::json!({"transaction_id": hex::encode(transaction_id)}),
        );
    }
    if method != "GET" {
        return Err("unsupported RPC method".into());
    }
    if !request.body.is_empty() {
        return Err("GET request body is not allowed".into());
    }
    match route {
        "/openapi.json" => {
            return write_http_bytes(stream, 200, "application/json", OPENAPI_JSON);
        }
        "/docs" | "/docs/" => {
            return write_http_bytes(stream, 200, "text/html; charset=utf-8", API_DOCS_HTML);
        }
        _ => {}
    }
    let ledger = load_or_initialize(database)?;
    let response = match route {
        "/status" => status_response(&ledger)?,
        "/fee-policy" => serde_json::json!({
            "minimum_fee_rate_esca_per_byte": MIN_RELAY_FEE_ESCA_PER_BYTE,
        }),
        "/blocks/latest" => latest_blocks_response(&ledger)?,
        route if route.starts_with("/asset/nonce/") => {
            let address = parse_address(route.trim_start_matches("/asset/nonce/"))?;
            asset_nonce_response(database, &ledger, address)?
        }
        route if route.starts_with("/asset/") => asset_response(&ledger, route)?,
        route if route.starts_with("/block/") => {
            let height = route
                .trim_start_matches("/block/")
                .parse::<u64>()
                .map_err(|_| "invalid block height")?;
            block_response(
                ledger
                    .chain
                    .block(&Height(height))
                    .ok_or("block was not found")?,
            )?
        }
        route if route.starts_with("/account/") => {
            let account_route = route.trim_start_matches("/account/");
            let (address, query) = account_route.split_once('?').unwrap_or((account_route, ""));
            if address.is_empty() || address.contains(['/', '#']) {
                return Err("invalid account route".into());
            }
            let mut utxo_offset = 0;
            if !query.is_empty() {
                let (name, value) = query.split_once('=').ok_or("invalid account query")?;
                if name != "utxo_offset" || value.is_empty() || value.contains('&') {
                    return Err("invalid account query".into());
                }
                utxo_offset = value
                    .parse::<usize>()
                    .map_err(|_| "invalid account UTXO offset")?;
            }
            account_response(
                &ledger,
                &read_mempool(database)?,
                parse_address(address)?,
                utxo_offset,
            )?
        }
        route if route.starts_with("/explorer/address/") => {
            let value = route.trim_start_matches("/explorer/address/");
            let (address, include_emissions) = match value.split_once('?') {
                None => (value, true),
                Some((address, "include_emissions=false")) => (address, false),
                Some(_) => return Err("invalid explorer address query".into()),
            };
            if address.is_empty() || address.contains(['/', '#']) {
                return Err("invalid explorer address route".into());
            }
            explorer_address_response(
                &ledger,
                &read_mempool(database)?,
                parse_address(address)?,
                include_emissions,
            )?
        }
        route if route.starts_with("/explorer/transaction/") => {
            let transaction_id = route.trim_start_matches("/explorer/transaction/");
            explorer_transaction_response(&ledger, parse_transaction_id(transaction_id)?)?
        }
        _ => return Err("unknown RPC route".into()),
    };
    write_http_response(stream, 200, &response)
}

fn asset_nonce_response(
    database: &Path,
    ledger: &Ledger,
    address: Address,
) -> Result<serde_json::Value, String> {
    let mut state = ledger.state().clone();
    let height = Height(
        ledger
            .tip_height()
            .map_or(0, |height| height.0.saturating_add(1)),
    );
    let chain = xparq::genesis::chain_context().map_err(|error| error.to_string())?;
    for transaction in read_mempool(database)? {
        let validated = validate_transaction(transaction, chain, height.0, &state)
            .map_err(|error| format!("validate pending asset nonce: {error}"))?;
        state
            .apply_validated_transaction(&validated, height, Address::ZERO)
            .map_err(|error| format!("apply pending asset nonce: {error}"))?;
    }
    let namespace = state
        .extensions
        .namespace(xparq::extension::asset::asset_extension_id());
    let nonce = xparq::extension::asset::asset_nonce(&namespace, address)
        .map_err(|error| format!("read asset nonce: {error:?}"))?;
    Ok(serde_json::json!({
        "address": xparq::crypto::address_to_string(&address),
        "nonce": nonce,
    }))
}

fn asset_response(ledger: &Ledger, route: &str) -> Result<serde_json::Value, String> {
    let path = route.trim_start_matches("/asset/");
    let parts = path.split('/').collect::<Vec<_>>();
    let asset_id = parts
        .first()
        .ok_or("missing asset id")?
        .parse::<xparq::extension::asset::AssetId>()
        .map_err(|_| "invalid asset id")?;
    let namespace = ledger
        .state()
        .extensions
        .namespace(xparq::extension::asset::asset_extension_id());
    if parts.len() == 1 {
        let metadata = xparq::extension::asset::asset_metadata(&namespace, asset_id)
            .map_err(|error| format!("read asset metadata: {error:?}"))?
            .ok_or("asset was not found")?;
        let supply = xparq::extension::asset::asset_supply(&namespace, asset_id)
            .map_err(|error| format!("read asset supply: {error:?}"))?;
        return Ok(serde_json::json!({
            "asset_id": asset_id.to_string(),
            "name": metadata.name,
            "symbol": metadata.symbol,
            "decimals": metadata.decimals,
            "max_supply": metadata.max_supply.to_string(),
            "supply": supply.to_string(),
            "mint_authority": xparq::crypto::address_to_string(&metadata.mint_authority),
        }));
    }
    if parts.len() == 3 && parts[1] == "balance" {
        let address = parse_address(parts[2])?;
        let balance = xparq::extension::asset::asset_balance(&namespace, asset_id, address)
            .map_err(|error| format!("read asset balance: {error:?}"))?;
        return Ok(serde_json::json!({
            "asset_id": asset_id.to_string(),
            "address": xparq::crypto::address_to_string(&address),
            "balance": balance.to_string(),
        }));
    }
    Err("invalid asset route".into())
}

#[derive(Debug)]
struct HttpRequest {
    headers: String,
    body: Vec<u8>,
}

fn read_http_request(stream: &mut impl Read) -> Result<HttpRequest, String> {
    let mut bytes = Vec::new();
    let header_end = loop {
        if bytes.len() >= MAX_RPC_HEADER_SIZE {
            return Err("RPC headers exceed size limit".into());
        }
        let mut chunk = [0_u8; 1024];
        let length = stream
            .read(&mut chunk)
            .map_err(|error| format!("read RPC: {error}"))?;
        if length == 0 {
            return Err("RPC connection closed before headers completed".into());
        }
        bytes.extend_from_slice(&chunk[..length]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| "RPC headers are not UTF-8")?
        .to_string();
    let mut content_length = None;
    for line in headers.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err("malformed RPC header".into());
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("RPC Transfer-Encoding is not supported".into());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err("duplicate RPC Content-Length".into());
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "invalid RPC Content-Length")?,
            );
        }
    }
    let content_length = content_length.unwrap_or(0);
    if content_length > MAX_STORED_TRANSACTION_SIZE {
        return Err("RPC request body exceeds transaction size limit".into());
    }
    let total = header_end
        .checked_add(content_length)
        .ok_or("RPC request size overflow")?;
    if bytes.len() > total {
        bytes.truncate(total);
    }
    while bytes.len() < total {
        let remaining = total - bytes.len();
        let mut chunk = vec![0_u8; remaining.min(8 * 1024)];
        let length = stream
            .read(&mut chunk)
            .map_err(|error| format!("read RPC body: {error}"))?;
        if length == 0 {
            return Err("RPC body is truncated".into());
        }
        bytes.extend_from_slice(&chunk[..length]);
    }
    Ok(HttpRequest {
        headers,
        body: bytes[header_end..].to_vec(),
    })
}

fn status_response(ledger: &Ledger) -> Result<serde_json::Value, String> {
    let tip_height = ledger.tip_height().ok_or("canonical genesis is missing")?;
    let tip_hash = ledger.tip_hash().ok_or("canonical genesis is missing")?;
    let next_difficulty =
        expected_next_difficulty(&ledger.chain).map_err(|error| error.to_string())?;
    let cumulative_work = ledger
        .chain
        .blocks()
        .filter(|block| !block.is_genesis())
        .fold(xparq::consensus::Work::ZERO, |work, block| {
            work.saturating_add(xparq::consensus::block_work(block.difficulty()))
        });
    let cumulative_weight = ledger
        .chain
        .blocks()
        .filter(|block| !block.is_genesis())
        .fold(0_u128, |total, block| {
            total.saturating_add(u128::from(block.block_weight()))
        });
    Ok(serde_json::json!({
        "tip_height": tip_height.0,
        "next_height": tip_height.0.saturating_add(1),
        "tip_hash": hex::encode(tip_hash.0),
        "next_difficulty": next_difficulty,
        "cumulative_work": format_work(cumulative_work.to_be_limbs()),
        "cumulative_weight": cumulative_weight.to_string(),
    }))
}

fn latest_blocks_response(ledger: &Ledger) -> Result<serde_json::Value, String> {
    let blocks = ledger
        .chain
        .blocks()
        .rev()
        .take(20)
        .map(block_response)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(serde_json::json!({ "blocks": blocks }))
}

fn block_response(block: &Block) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "height": block.height().0,
        "hash": hex::encode(block.hash().map_err(|error| error.to_string())?.0),
        "previous_hash": hex::encode(block.previous_hash().0),
        "difficulty": block.difficulty(),
        "block_weight": block.block_weight(),
        "nonce": block.header.nonce.0,
        "transactions": block.transaction_count(),
        "miner": xparq::crypto::address_to_string(&block.miner_address()),
        "subsidy": block
            .emission()
            .map_or(0, |emission| emission.subsidy.as_esca()),
    }))
}

fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    value: &serde_json::Value,
) -> Result<(), String> {
    let body = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    write_http_bytes(stream, status, "application/json", &body)
}

fn write_http_bytes(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<(), String> {
    let reason = if status == 200 { "OK" } else { "Bad Request" };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n",
        body.len()
    )
    .and_then(|_| stream.write_all(&body))
    .map_err(|error| format!("write RPC: {error}"))
}

fn serve_p2p(path: Option<&str>, listen: &str) -> Result<(), String> {
    let database = database_path(path);
    load_or_initialize(&database)?;
    serve_p2p_database(database, listen)
}

fn serve_p2p_database(database: PathBuf, listen: &str) -> Result<(), String> {
    let listener = TcpListener::bind(listen).map_err(|error| format!("bind P2P: {error}"))?;
    println!("p2p: {listen}");
    let active = Arc::new(AtomicUsize::new(0));
    let active_by_ip = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                if active.fetch_add(1, Ordering::AcqRel) >= MAX_INBOUND_CONNECTIONS {
                    active.fetch_sub(1, Ordering::AcqRel);
                    eprintln!("node: inbound peer limit reached");
                    continue;
                }
                let peer_ip = stream.peer_addr().ok().map(|address| address.ip());
                if let Some(ip) = peer_ip {
                    let mut by_ip = active_by_ip
                        .lock()
                        .map_err(|_| "inbound peer counter lock is poisoned")?;
                    let count = by_ip.entry(ip).or_insert(0_usize);
                    if *count >= MAX_INBOUND_CONNECTIONS_PER_IP {
                        active.fetch_sub(1, Ordering::AcqRel);
                        eprintln!("node: inbound per-IP limit reached address={ip}");
                        continue;
                    }
                    *count += 1;
                }
                let database = database.clone();
                let active = Arc::clone(&active);
                let active_by_ip = Arc::clone(&active_by_ip);
                thread::spawn(move || {
                    handle_inbound_peer(&database, stream);
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
            Err(error) => eprintln!("node: accept P2P connection: {error}"),
        }
    }
    Ok(())
}

fn handle_inbound_peer(database: &Path, mut stream: TcpStream) {
    let address = stream
        .peer_addr()
        .map_or_else(|_| "unknown".into(), |value| value.to_string());
    match exchange_handshake(database, &mut stream).and_then(|exchange| {
        let outcome = serve_peer_requests(database, &mut stream, &exchange.local_headers)?;
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
        Ok(peer) => println!(
            "peer served address={address} height={} tip={} work={}",
            peer.tip_height.0,
            hex::encode(peer.tip_hash),
            format_work(peer.cumulative_work),
        ),
        Err(error) => eprintln!("node: peer rejected address={address} reason={error}"),
    }
}

fn run_network(path: Option<&str>, listen: &str, peers: &[String]) -> Result<(), String> {
    let database = database_path(path);
    load_or_initialize(&database)?;
    let sync_lock = Arc::new(Mutex::new(()));
    start_peer_supervisor(database.clone(), peers.to_vec(), sync_lock);
    println!("outbound_peers: {}", peers.len());
    serve_p2p_database(database, listen)
}

fn start_peer_supervisor(database: PathBuf, configured: Vec<String>, sync_lock: Arc<Mutex<()>>) {
    thread::spawn(move || {
        let mut active = BTreeSet::new();
        loop {
            let mut candidates = configured.clone();
            match PeerStore::load(&database) {
                Ok(store) => {
                    candidates.extend(store.addresses().into_iter().map(|peer| peer.to_string()))
                }
                Err(error) => eprintln!("node: load peer store: {error}"),
            }
            for peer in candidates {
                if !active.insert(peer.clone()) {
                    continue;
                }
                let database = database.clone();
                let sync_lock = Arc::clone(&sync_lock);
                thread::spawn(move || {
                    let mut consecutive_failures = 0_u32;
                    loop {
                        let result = match sync_lock.lock() {
                            Ok(_guard) => connect_peer_database(&database, &peer),
                            Err(_) => Err("outbound sync lock is poisoned".into()),
                        };
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
                                        eprintln!("node: peer={peer} requires header resync");
                                        Duration::from_secs(1)
                                    }
                                    Err(error) => {
                                        consecutive_failures =
                                            consecutive_failures.saturating_add(1);
                                        let malicious = gossip_error_is_malicious(&error);
                                        if let Ok(address) = peer.parse() {
                                            let _ =
                                                record_peer_failure(&database, address, malicious);
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
                                        eprintln!(
                                            "node: peer={peer} gossip session failed: {error} reconnect_after_secs={}",
                                            cooldown.as_secs()
                                        );
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
                                eprintln!(
                                    "node: outbound peer={peer} sync failed: {error} reconnect_after_secs={}",
                                    cooldown.as_secs()
                                );
                                cooldown
                            }
                        };
                        thread::sleep(reconnect_after);
                    }
                });
            }
            thread::sleep(RECONNECT_INTERVAL);
        }
    });
}

fn connect_peer(path: Option<&str>, peer: &str) -> Result<(), String> {
    let database = database_path(path);
    let mut connection = connect_peer_database(&database, peer)?;
    write_frame(&mut connection.stream, &[SYNC_COMPLETE_MESSAGE])
}

fn connect_peer_database(database: &Path, peer: &str) -> Result<ConnectedPeer, String> {
    load_or_initialize(database)?;
    let mut stream = TcpStream::connect(peer).map_err(|error| format!("connect peer: {error}"))?;
    let connected_address = stream.peer_addr().ok();
    let handshake = exchange_handshake(database, &mut stream)?.peer;
    let sync = synchronize_headers(database, &mut stream, &handshake)?;
    let verified = sync.headers.len();
    let preferred = sync.preferred;
    let applied = if preferred {
        synchronize_blocks(database, &mut stream, sync)?
    } else {
        0
    };
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
        )?;
        if same_tip || extended_peer {
            relay_mempool(database, &mut stream)?;
        }
    }
    if let Some(address) = connected_address {
        record_peer_success(database, address)?;
    }
    for address in discovered {
        record_discovered_peer(database, address)?;
    }
    println!(
        "peer accepted address={peer} height={} tip={} work={} verified_headers={verified} preferred={preferred} applied_blocks={applied}",
        handshake.tip_height.0,
        hex::encode(handshake.tip_hash),
        format_work(handshake.cumulative_work),
    );
    Ok(ConnectedPeer { handshake, stream })
}

fn serve_peer_requests(
    database: &Path,
    stream: &mut TcpStream,
    session_headers: &[(Height, xparq::block::Header)],
) -> Result<PeerSessionOutcome, String> {
    serve_header_requests(stream, session_headers)?;
    serve_block_requests(database, stream)
}

fn serve_header_requests(
    stream: &mut TcpStream,
    headers: &[(Height, xparq::block::Header)],
) -> Result<(), String> {
    let mut requests = 0_usize;
    loop {
        requests += 1;
        if requests > MAX_HEADER_REQUESTS_PER_SESSION {
            return Err("peer exceeded the header request limit".into());
        }
        let request = read_frame(stream, 2 + MAX_LOCATOR_HASHES * 32)?;
        let locator = decode_locator(&request)?;
        let ancestor_index = headers
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, (_, header))| {
                let hash = header.hash().ok()?.0;
                locator.contains(&hash).then_some(index)
            })
            .ok_or("peer locator has no canonical common ancestor")?;
        let ancestor_hash = headers[ancestor_index]
            .1
            .hash()
            .map_err(|error| error.to_string())?
            .0;
        let extension = headers
            .iter()
            .skip(ancestor_index + 1)
            .take(MAX_HEADER_CHAIN_CHUNK_HEADERS)
            .map(|(height, header)| xparq::consensus::HeaderAtHeight::new(*height, header.clone()))
            .collect::<Vec<_>>();
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

fn serve_block_requests(
    database: &Path,
    stream: &mut TcpStream,
) -> Result<PeerSessionOutcome, String> {
    let mut block_requests = 0_usize;
    let mut discovery_requests = 0_usize;
    let mut relayed_transactions = 0_usize;
    let mut relayed_blocks = 0_usize;
    let mut transaction_requests = 0_usize;
    loop {
        let request = read_frame(stream, 1 + MAX_STORED_BLOCK_SIZE)?;
        let (&message, body) = request.split_first().ok_or("empty block request")?;
        match message {
            SYNC_COMPLETE_MESSAGE if body.is_empty() => return Ok(PeerSessionOutcome::Complete),
            GET_PEERS_MESSAGE if body.is_empty() => {
                discovery_requests += 1;
                if discovery_requests > 1 {
                    return Err("peer exceeded the discovery request limit".into());
                }
                let mut peers = PeerStore::load(database)?.relay_addresses();
                if let Some(address) = advertised_peer()? {
                    let address = address.to_string();
                    if !peers.contains(&address) {
                        peers.push(address);
                    }
                }
                peers.truncate(MAX_DISCOVERED_PEERS);
                let encoded = canonical_bytes(&peers).map_err(|error| error.to_string())?;
                if encoded.len() > MAX_PEERS_RESPONSE_SIZE {
                    return Err("local peer response exceeds size limit".into());
                }
                let mut response = Vec::with_capacity(1 + encoded.len());
                response.push(PEERS_MESSAGE);
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
                if inventory_preferred(&peer_inventory, &inventory) {
                    return Ok(PeerSessionOutcome::ReverseSync(peer_inventory));
                }
                continue;
            }
            GET_TRANSACTION_MESSAGE if body.len() == 32 => {
                transaction_requests += 1;
                if transaction_requests > MAX_RELAY_ITEMS_PER_SESSION {
                    return Err("peer exceeded the transaction request limit".into());
                }
                let requested: [u8; 32] = body
                    .try_into()
                    .map_err(|_| "invalid requested transaction ID")?;
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
            GET_BLOCK_MESSAGE if body.len() == 32 => {
                block_requests += 1;
                if block_requests > MAX_SYNC_HEADERS {
                    return Err("peer exceeded the block request limit".into());
                }
            }
            _ => return Err("invalid block-session message".into()),
        }
        let requested: [u8; 32] = body
            .try_into()
            .map_err(|_| "invalid requested block hash")?;
        let block = cached_canonical_block(database, requested)?
            .ok_or("requested block is not canonical")?;
        let encoded = block_bytes(&block).map_err(|error| error.to_string())?;
        let mut response = Vec::with_capacity(1 + encoded.len());
        response.push(BLOCK_MESSAGE);
        response.extend_from_slice(&encoded);
        write_frame(stream, &response)?;
    }
}

fn gossip_inventory(database: &Path) -> Result<GossipInventory, String> {
    let ledger = load_or_initialize(database)?;
    let tip_height = ledger.tip_height().ok_or("canonical genesis is missing")?;
    let tip_hash = ledger.tip_hash().ok_or("canonical genesis is missing")?.0;
    let headers = ledger
        .chain
        .chain_headers()
        .into_iter()
        .map(|(height, header)| xparq::consensus::HeaderAtHeight::new(height, header))
        .collect::<Vec<_>>();
    let state = validated_header_state(&headers)?;
    let transactions = read_mempool(database)?;
    let start = transactions
        .len()
        .saturating_sub(MAX_GOSSIP_INVENTORY_ITEMS);
    let transaction_ids = transactions[start..]
        .iter()
        .map(|transaction| transaction.id().map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(GossipInventory {
        tip_height,
        tip_hash,
        cumulative_work: state.cumulative_work.to_be_limbs(),
        cumulative_weight: state.cumulative_weight,
        transaction_ids,
    })
}

fn inventory_preferred(candidate: &GossipInventory, current: &GossipInventory) -> bool {
    compare_chain_tips(
        Work::from_be_limbs(candidate.cumulative_work),
        candidate.cumulative_weight,
        BlockHash(candidate.tip_hash),
        Work::from_be_limbs(current.cumulative_work),
        current.cumulative_weight,
        BlockHash(current.tip_hash),
    )
    .is_gt()
}

fn handshake_from_inventory(handshake: &Handshake, inventory: &GossipInventory) -> Handshake {
    let mut current = handshake.clone();
    current.tip_height = inventory.tip_height;
    current.tip_hash = inventory.tip_hash;
    current.cumulative_work = inventory.cumulative_work;
    current.cumulative_weight = inventory.cumulative_weight;
    current
}

fn decode_gossip_inventory(bytes: &[u8]) -> Result<GossipInventory, String> {
    if bytes.len() > MAX_GOSSIP_INVENTORY_SIZE {
        return Err("gossip inventory exceeds size limit".into());
    }
    let declared = bytes
        .get(120..124)
        .and_then(|count| count.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or("gossip inventory is truncated")? as usize;
    if declared > MAX_GOSSIP_INVENTORY_ITEMS {
        return Err("gossip inventory item count exceeds limit".into());
    }
    let inventory: GossipInventory =
        canonical_decode(bytes).map_err(|error| format!("decode gossip inventory: {error}"))?;
    if inventory.transaction_ids.len() > MAX_GOSSIP_INVENTORY_ITEMS {
        return Err("gossip inventory item count exceeds limit".into());
    }
    Ok(inventory)
}

fn request_discovered_peers(stream: &mut TcpStream) -> Result<Vec<SocketAddr>, String> {
    write_frame(stream, &[GET_PEERS_MESSAGE])?;
    let response = read_frame(stream, 1 + MAX_PEERS_RESPONSE_SIZE)?;
    if response.first() != Some(&PEERS_MESSAGE) {
        return Err("peer returned an unexpected discovery response".into());
    }
    let declared_peers = response
        .get(1..5)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or("peer discovery response is truncated")? as usize;
    if declared_peers > MAX_DISCOVERED_PEERS {
        return Err("peer discovery response exceeds peer limit".into());
    }
    let peers: Vec<String> = canonical_decode(&response[1..])
        .map_err(|error| format!("decode discovered peers: {error}"))?;
    if peers.len() > MAX_DISCOVERED_PEERS {
        return Err("peer discovery response exceeds peer limit".into());
    }
    Ok(peers
        .into_iter()
        .filter_map(|peer| peer.parse().ok())
        .filter(is_admissible_discovered_peer)
        .collect())
}

fn relay_mempool(database: &Path, stream: &mut TcpStream) -> Result<(), String> {
    for transaction in read_mempool(database)?
        .into_iter()
        .take(MAX_RELAY_ITEMS_PER_SESSION)
    {
        let encoded = canonical_bytes(&transaction).map_err(|error| error.to_string())?;
        let mut message = Vec::with_capacity(1 + encoded.len());
        message.push(SUBMIT_TRANSACTION_MESSAGE);
        message.extend_from_slice(&encoded);
        write_frame(stream, &message)?;
        read_relay_result(stream)?;
    }
    Ok(())
}

fn gossip_outbound_session(
    database: &Path,
    stream: &mut TcpStream,
    peer: &Handshake,
) -> Result<(), String> {
    if peer.capabilities & CAPABILITY_RELAY == 0 {
        write_frame(stream, &[SYNC_COMPLETE_MESSAGE])?;
        return Ok(());
    }
    let mut generation = gossip_generation()?;
    loop {
        let local_before = gossip_inventory(database)?;
        let encoded = canonical_bytes(&local_before).map_err(|error| error.to_string())?;
        let mut message = Vec::with_capacity(1 + encoded.len());
        message.push(INVENTORY_MESSAGE);
        message.extend_from_slice(&encoded);
        write_frame(stream, &message)?;
        let response = read_frame(stream, 1 + MAX_GOSSIP_INVENTORY_SIZE)?;
        if response.first() != Some(&INVENTORY_MESSAGE) {
            return Err("peer returned an unexpected gossip inventory response".into());
        }
        let remote = decode_gossip_inventory(&response[1..])?;

        if remote.tip_hash != local_before.tip_hash {
            if inventory_preferred(&remote, &local_before) {
                if remote.tip_height.0 == local_before.tip_height.0.saturating_add(1) {
                    request_and_accept_gossip_block(database, stream, remote.tip_hash)?;
                    generation = gossip_generation()?;
                    continue;
                }
                return Err(format!(
                    "{GOSSIP_RESYNC_PREFIX} peer announced a preferred chain"
                ));
            }
            if inventory_preferred(&local_before, &remote) {
                let headers = canonical_headers_through(database, local_before.tip_hash)?;
                match serve_peer_requests(database, stream, &headers)? {
                    PeerSessionOutcome::Complete => return Ok(()),
                    PeerSessionOutcome::ReverseSync(_) => {
                        return Err("peer requested nested reverse synchronization".into());
                    }
                }
            }
            return Err(format!(
                "{GOSSIP_RESYNC_PREFIX} tips diverged; reconnecting for verified header sync"
            ));
        }

        exchange_gossip_transactions(database, stream, &remote)?;
        generation = wait_for_gossip(generation)?;
    }
}

fn canonical_headers_through(
    database: &Path,
    tip_hash: [u8; 32],
) -> Result<Vec<(Height, xparq::block::Header)>, String> {
    let mut headers = cached_chain_headers(database)?;
    let Some(index) = headers
        .iter()
        .position(|(_, header)| header.hash().is_ok_and(|hash| hash.0 == tip_hash))
    else {
        return Err(format!(
            "{GOSSIP_RESYNC_PREFIX} advertised local tip changed before reverse sync"
        ));
    };
    headers.truncate(index + 1);
    Ok(headers)
}

fn request_and_accept_gossip_block(
    database: &Path,
    stream: &mut TcpStream,
    block_hash: [u8; 32],
) -> Result<(), String> {
    let mut request = Vec::with_capacity(33);
    request.push(GET_BLOCK_MESSAGE);
    request.extend_from_slice(&block_hash);
    write_frame(stream, &request)?;
    let response = read_frame(stream, 1 + MAX_STORED_BLOCK_SIZE)?;
    if response.first() != Some(&BLOCK_MESSAGE) {
        return Err("peer returned an unexpected gossip block response".into());
    }
    let block = decode_block(&response[1..])
        .map_err(|error| format!("invalid gossip block response: {error}"))?;
    if block.hash().map_err(|error| error.to_string())?.0 != block_hash {
        return Err("gossip block body does not match announced hash".into());
    }
    accept_relayed_block(database, &response[1..])
}

fn exchange_gossip_transactions(
    database: &Path,
    stream: &mut TcpStream,
    remote: &GossipInventory,
) -> Result<(), String> {
    let local = gossip_inventory(database)?;
    let local_ids = local
        .transaction_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    for transaction_id in remote
        .transaction_ids
        .iter()
        .filter(|transaction_id| !local_ids.contains(*transaction_id))
        .take(MAX_RELAY_ITEMS_PER_SESSION)
    {
        let mut request = Vec::with_capacity(33);
        request.push(GET_TRANSACTION_MESSAGE);
        request.extend_from_slice(transaction_id);
        write_frame(stream, &request)?;
        let response = read_frame(stream, 1 + MAX_STORED_TRANSACTION_SIZE)?;
        if response.first() != Some(&TRANSACTION_MESSAGE) {
            return Err("peer returned an unexpected transaction response".into());
        }
        let transaction: AuthorizedTransaction = canonical_decode(&response[1..])
            .map_err(|error| format!("invalid gossip transaction: {error}"))?;
        if transaction.id().map_err(|error| error.to_string())? != *transaction_id {
            return Err("gossip transaction body does not match announced ID".into());
        }
        accept_relayed_transaction(database, &response[1..])?;
    }

    let remote_ids = remote
        .transaction_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    for transaction in read_mempool(database)?
        .into_iter()
        .filter(|transaction| {
            transaction
                .id()
                .is_ok_and(|transaction_id| !remote_ids.contains(&transaction_id))
        })
        .take(MAX_RELAY_ITEMS_PER_SESSION)
    {
        let encoded = canonical_bytes(&transaction).map_err(|error| error.to_string())?;
        let mut message = Vec::with_capacity(1 + encoded.len());
        message.push(SUBMIT_TRANSACTION_MESSAGE);
        message.extend_from_slice(&encoded);
        write_frame(stream, &message)?;
        read_relay_result(stream)?;
    }
    Ok(())
}

fn gossip_notifier() -> &'static (Mutex<u64>, Condvar) {
    GOSSIP_NOTIFIER.get_or_init(|| (Mutex::new(0), Condvar::new()))
}

fn gossip_generation() -> Result<u64, String> {
    gossip_notifier()
        .0
        .lock()
        .map(|generation| *generation)
        .map_err(|_| "gossip notifier lock is poisoned".into())
}

fn notify_gossip() {
    let (generation, wake) = gossip_notifier();
    if let Ok(mut generation) = generation.lock() {
        *generation = generation.wrapping_add(1);
        wake.notify_all();
    }
}

fn wait_for_gossip(previous: u64) -> Result<u64, String> {
    let (generation, wake) = gossip_notifier();
    let generation = generation
        .lock()
        .map_err(|_| "gossip notifier lock is poisoned")?;
    if *generation != previous {
        return Ok(*generation);
    }
    let (generation, _) = wake
        .wait_timeout(generation, GOSSIP_HEARTBEAT)
        .map_err(|_| "gossip notifier lock is poisoned")?;
    Ok(*generation)
}

fn gossip_error_is_malicious(error: &str) -> bool {
    error.contains("invalid gossip")
        || error.contains("does not match announced")
        || error.contains("exceeds")
        || error.contains("invalid relayed")
        || error.contains("unexpected gossip")
}

fn relay_next_block(
    database: &Path,
    stream: &mut TcpStream,
    peer_height: Height,
    peer_tip_hash: [u8; 32],
) -> Result<bool, String> {
    let ledger = load_or_initialize(database)?;
    let Some(local_height) = ledger.tip_height() else {
        return Ok(false);
    };
    if local_height.0 != peer_height.0.saturating_add(1) {
        return Ok(false);
    }
    let block = ledger
        .chain
        .block(&local_height)
        .ok_or("local relay tip block is missing")?;
    if block.previous_hash().0 != peer_tip_hash {
        return Ok(false);
    }
    let encoded = block_bytes(block).map_err(|error| error.to_string())?;
    let mut message = Vec::with_capacity(1 + encoded.len());
    message.push(SUBMIT_BLOCK_MESSAGE);
    message.extend_from_slice(&encoded);
    write_frame(stream, &message)?;
    read_relay_result(stream)?;
    Ok(true)
}

fn read_relay_result(stream: &mut TcpStream) -> Result<(), String> {
    let response = read_frame(stream, 1024)?;
    match response.first() {
        Some(&ACCEPTED_MESSAGE) => Ok(()),
        Some(&REJECTED_MESSAGE) => Err(String::from_utf8_lossy(&response[1..]).into_owned()),
        _ => Err("peer returned an invalid relay response".into()),
    }
}

fn write_relay_result(stream: &mut TcpStream, result: Result<(), String>) -> Result<(), String> {
    match result {
        Ok(()) => write_frame(stream, &[ACCEPTED_MESSAGE]),
        Err(error) => {
            let mut response = Vec::with_capacity(1 + error.len().min(1023));
            response.push(REJECTED_MESSAGE);
            response.extend_from_slice(&error.as_bytes()[..error.len().min(1023)]);
            write_frame(stream, &response)
        }
    }
}

fn accept_relayed_transaction(database: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > MAX_STORED_TRANSACTION_SIZE {
        return Err("relayed transaction size is outside allowed range".into());
    }
    let transaction: AuthorizedTransaction =
        canonical_decode(bytes).map_err(|error| format!("invalid relayed transaction: {error}"))?;
    insert_mempool_transaction(database, transaction, true).map(|_| ())
}

fn insert_mempool_transaction(
    database: &Path,
    transaction: AuthorizedTransaction,
    duplicate_is_ok: bool,
) -> Result<[u8; 32], String> {
    let _mutation = state_mutation_lock()?
        .lock()
        .map_err(|_| "state mutation lock is poisoned")?;
    let transaction_id = transaction.id().map_err(|error| error.to_string())?;
    let ledger = load_or_initialize(database)?;
    let mut transactions = read_mempool(database)?;
    if transactions
        .iter()
        .any(|existing| existing.id().ok() == Some(transaction_id))
    {
        return if duplicate_is_ok {
            Ok(transaction_id)
        } else {
            Err("transaction is already in mempool".into())
        };
    }
    transactions.push(transaction);
    validate_mempool(&ledger, &transactions)?;
    write_mempool(database, &transactions)?;
    notify_gossip();
    Ok(transaction_id)
}

fn accept_relayed_block(database: &Path, bytes: &[u8]) -> Result<(), String> {
    let block = decode_block(bytes).map_err(|error| format!("invalid relayed block: {error}"))?;
    let hash = block.hash().map_err(|error| error.to_string())?;
    let _mutation = state_mutation_lock()?
        .lock()
        .map_err(|_| "state mutation lock is poisoned")?;
    let mut ledger = load_or_initialize(database)?;
    if ledger.tip_hash() == Some(hash) {
        return Ok(());
    }
    if ledger.tip_hash().map(|tip| tip.0) != Some(block.previous_hash().0) {
        return Err(format!(
            "{GOSSIP_RESYNC_PREFIX} relayed block does not directly extend the canonical tip"
        ));
    }
    apply_block(&mut ledger, block.clone())
        .map_err(|error| format!("invalid relayed block: {error}"))?;
    let included = block
        .transactions()
        .iter()
        .map(|transaction| transaction.id().map_err(|error| error.to_string()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mempool = reconcile_mempool(&ledger, read_mempool(database)?, &included);
    persist_block_and_mempool(database, &block, &mempool)?;
    update_ledger_cache(database, &ledger)?;
    notify_gossip();
    Ok(())
}

fn record_discovered_peer(database: &Path, address: SocketAddr) -> Result<(), String> {
    let _guard = peer_store_lock()?
        .lock()
        .map_err(|_| "peer store lock is poisoned")?;
    let mut store = PeerStore::load(database)?;
    if store.insert_discovered(address) {
        store.save(database)?;
    }
    Ok(())
}

fn record_peer_success(database: &Path, address: SocketAddr) -> Result<(), String> {
    let _guard = peer_store_lock()?
        .lock()
        .map_err(|_| "peer store lock is poisoned")?;
    let mut store = PeerStore::load(database)?;
    store.record_success(address);
    store.save(database)
}

fn record_peer_failure(
    database: &Path,
    address: SocketAddr,
    malicious: bool,
) -> Result<(), String> {
    let _guard = peer_store_lock()?
        .lock()
        .map_err(|_| "peer store lock is poisoned")?;
    let mut store = PeerStore::load(database)?;
    store.record_failure(address, malicious);
    store.save(database)
}

fn peer_store_lock() -> Result<&'static Mutex<()>, String> {
    Ok(PEER_STORE_LOCK.get_or_init(|| Mutex::new(())))
}

fn synchronize_headers(
    database: &Path,
    stream: &mut TcpStream,
    peer: &Handshake,
) -> Result<HeaderSyncResult, String> {
    let local_headers = cached_chain_headers(database)?
        .into_iter()
        .map(|(height, header)| xparq::consensus::HeaderAtHeight::new(height, header))
        .collect::<Vec<_>>();
    let locator = header_locator(&local_headers)?;
    let mut validation_state = None;
    let mut ancestor_height = None;
    let mut ancestor_hash = None;
    let mut downloaded = Vec::new();
    let mut request_locator = locator;
    let mut verified_headers = 0_usize;
    let mut pow_memory = None;

    loop {
        write_frame(stream, &encode_locator(&request_locator)?)?;
        let response = read_frame(stream, 33 + MAX_HEADER_CHAIN_CHUNK_SIZE)?;
        let (&message, body) = response.split_first().ok_or("empty header response")?;
        let ancestor: [u8; 32] = body
            .get(..32)
            .ok_or("header response has no ancestor")?
            .try_into()
            .map_err(|_| "invalid ancestor hash")?;
        if message == HEADERS_COMPLETE_MESSAGE {
            let state = match validation_state.take() {
                Some(state) => state,
                None => local_header_state_at_hash(&local_headers, ancestor)?
                    .ok_or("common ancestor is not canonical locally")?,
            };
            if state.header.hash().map_err(|error| error.to_string())?.0 != ancestor {
                return Err("peer completion does not match verified header tip".into());
            }
            if state.header.hash().map_err(|error| error.to_string())?.0 != peer.tip_hash
                || state.cumulative_work.to_be_limbs() != peer.cumulative_work
                || state.cumulative_weight != peer.cumulative_weight
            {
                return Err("peer handshake tip/work does not match verified headers".into());
            }
            let local = validated_header_state(&local_headers)?;
            let peer_work = state.cumulative_work;
            let peer_weight = state.cumulative_weight;
            let local_hash = local.header.hash().map_err(|error| error.to_string())?.0;
            let preferred = compare_chain_tips(
                peer_work,
                peer_weight,
                BlockHash(peer.tip_hash),
                local.cumulative_work,
                local.cumulative_weight,
                BlockHash(local_hash),
            )
            .is_gt();
            return Ok(HeaderSyncResult {
                ancestor_height: ancestor_height.unwrap_or(state.height),
                ancestor_hash: BlockHash(ancestor_hash.unwrap_or(ancestor)),
                headers: downloaded,
                peer_work,
                peer_weight,
                preferred,
            });
        }
        if message != HEADERS_MESSAGE {
            return Err("unexpected P2P message during header sync".into());
        }
        let chunk = decode_header_chain_chunk(&body[32..]).map_err(|error| error.to_string())?;
        let current = match validation_state.take() {
            Some(current) => {
                if current.header.hash().map_err(|error| error.to_string())?.0 != ancestor {
                    return Err("peer changed common ancestor during header sync".into());
                }
                current
            }
            None => local_header_state_at_hash(&local_headers, ancestor)?
                .ok_or("peer response ancestor is not canonical locally")?,
        };
        if ancestor_height.is_none() {
            ancestor_height = Some(current.height);
            ancestor_hash = Some(ancestor);
        }
        let advanced = xparq::consensus::advance_header_validation_state_with_memory(
            &current,
            &chunk.headers,
            pow_memory.get_or_insert_with(new_pow_memory),
        )
        .map_err(map_peer_header_error)?;
        verified_headers = verified_headers
            .checked_add(chunk.headers.len())
            .ok_or("verified header count overflow")?;
        if verified_headers > MAX_SYNC_HEADERS {
            return Err("header synchronization exceeds session limit".into());
        }
        if verified_headers.is_multiple_of(256) {
            println!(
                "sync_progress: verified_headers={verified_headers} peer_height={}",
                peer.tip_height.0
            );
        }
        let tip_hash = advanced.header.hash().map_err(|error| error.to_string())?.0;
        downloaded.extend(chunk.headers);
        validation_state = Some(advanced);
        request_locator = vec![tip_hash, EXPECTED_GENESIS_HASH.0];
    }
}

fn map_peer_header_error(error: xparq::consensus::HeaderChainError) -> String {
    let invalid_pow = matches!(
        error,
        xparq::consensus::HeaderChainError::InvalidHeaderChain(
            xparq::consensus::ForkChoiceError::InvalidProofOfWork(_)
        )
    );
    if invalid_pow {
        format!("{INVALID_POW_ERROR_PREFIX} {error}")
    } else {
        format!("peer header extension is invalid: {error}")
    }
}

fn reconnect_delay_for_error(error: &str, failures: u32, peer: &str) -> Duration {
    if error.starts_with(INVALID_POW_ERROR_PREFIX) {
        INVALID_POW_COOLDOWN
    } else {
        let exponent = failures.saturating_sub(1).min(5);
        let base = RECONNECT_INTERVAL.as_secs() * (1_u64 << exponent);
        let jitter = peer.bytes().fold(failures as u64, |value, byte| {
            value.wrapping_mul(33) ^ byte as u64
        }) % 10;
        Duration::from_secs((base + jitter).min(300))
    }
}

fn synchronize_blocks(
    database: &Path,
    stream: &mut TcpStream,
    sync: HeaderSyncResult,
) -> Result<usize, String> {
    let count = sync.headers.len();
    let mut blocks = Vec::with_capacity(count);
    for expected in &sync.headers {
        let expected_hash = expected.hash().map_err(|error| error.to_string())?;
        let mut request = Vec::with_capacity(33);
        request.push(GET_BLOCK_MESSAGE);
        request.extend_from_slice(&expected_hash.0);
        write_frame(stream, &request)?;
        let response = read_frame(stream, 1 + MAX_STORED_BLOCK_SIZE)?;
        if response.first() != Some(&BLOCK_MESSAGE) {
            return Err("peer returned an unexpected block response".into());
        }
        let block =
            decode_block(&response[1..]).map_err(|error| format!("invalid peer block: {error}"))?;
        if block.height() != expected.height
            || block.header != expected.header
            || block.hash().map_err(|error| error.to_string())? != expected_hash
        {
            return Err("peer block body does not match the verified header".into());
        }
        blocks.push(block);
    }
    let included = blocks
        .iter()
        .flat_map(|block| block.transactions())
        .map(|transaction| transaction.id().map_err(|error| error.to_string()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let _mutation = state_mutation_lock()?
        .lock()
        .map_err(|_| "state mutation lock is poisoned")?;
    let mut staged = load_or_initialize(database)?;
    let old_tip = staged.tip_hash();
    let new_tip = blocks
        .last()
        .map(Block::hash)
        .transpose()
        .map_err(|error| error.to_string())?
        .unwrap_or(sync.ancestor_hash);
    let current_headers = staged
        .chain
        .chain_headers()
        .into_iter()
        .map(|(height, header)| xparq::consensus::HeaderAtHeight::new(height, header))
        .collect::<Vec<_>>();
    let current_state = validated_header_state(&current_headers)?;
    let current_tip = old_tip.ok_or("canonical chain has no tip during reorg")?;
    if !compare_chain_tips(
        sync.peer_work,
        sync.peer_weight,
        new_tip,
        current_state.cumulative_work,
        current_state.cumulative_weight,
        current_tip,
    )
    .is_gt()
    {
        println!("sync: downloaded peer branch is no longer preferred after local tip advanced");
        return Ok(0);
    }
    let mut disconnect = Vec::new();
    let mut height = staged.tip_height();
    while height.is_some_and(|height| height > sync.ancestor_height) {
        let current = height.expect("height was checked above");
        disconnect.push(
            staged
                .chain
                .block(&current)
                .cloned()
                .ok_or("reorg disconnect block is missing from canonical chain")?,
        );
        height = current.0.checked_sub(1).map(Height);
    }
    let ancestor = staged
        .chain
        .block(&sync.ancestor_height)
        .ok_or("reorg ancestor is missing from canonical chain")?;
    if ancestor.hash().map_err(|error| error.to_string())? != sync.ancestor_hash {
        return Err("reorg ancestor hash does not match canonical chain".into());
    }
    let plan = ReorgPlan::new(sync.ancestor_hash, old_tip, new_tip, disconnect, blocks)
        .map_err(|error| format!("invalid canonical reorg plan: {error}"))?;
    let ancestor = plan.ancestor();
    let (disconnect, apply) = plan.into_branches();
    let disconnected_blocks = disconnect.len();
    let disconnected_transactions = disconnect
        .iter()
        .rev()
        .flat_map(|block| block.transactions().iter().cloned())
        .collect::<Vec<_>>();
    let disconnected_transaction_ids = disconnected_transactions
        .iter()
        .map(|transaction| transaction.id().map_err(|error| error.to_string()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    for expected in disconnect {
        let removed = staged
            .rollback_tip()
            .map_err(|error| format!("rollback canonical tip: {error}"))?;
        if removed.hash().map_err(|error| error.to_string())?
            != expected.hash().map_err(|error| error.to_string())?
        {
            return Err("rollback removed a block outside the reorg disconnect plan".into());
        }
    }
    if staged.tip_hash() != Some(ancestor) {
        return Err("rollback did not stop at the planned common ancestor".into());
    }
    for block in apply {
        apply_block(&mut staged, block)
            .map_err(|error| format!("apply synchronized block: {error}"))?;
    }
    let mut mempool_candidates = disconnected_transactions;
    mempool_candidates.extend(read_mempool(database)?);
    let mempool = reconcile_mempool(&staged, mempool_candidates, &included);
    let requeued_transactions = mempool
        .iter()
        .filter_map(|transaction| transaction.id().ok())
        .filter(|transaction_id| disconnected_transaction_ids.contains(transaction_id))
        .count();
    persist_chain_and_mempool(database, &staged, &mempool)?;
    update_ledger_cache(database, &staged)?;
    if let Err(error) = crate::snapshot::write_after_large_sync(database, &staged, count) {
        eprintln!("node: post-sync snapshot write failed: {error}");
    }
    notify_gossip();
    if disconnected_blocks > 0 {
        println!(
            "reorg: disconnected_blocks={disconnected_blocks} disconnected_transactions={} requeued_transactions={requeued_transactions}",
            disconnected_transaction_ids.len(),
        );
    }
    Ok(count)
}

fn reconcile_mempool(
    ledger: &Ledger,
    transactions: Vec<AuthorizedTransaction>,
    included: &BTreeSet<[u8; 32]>,
) -> Vec<AuthorizedTransaction> {
    let height = Height(
        ledger
            .tip_height()
            .map_or(0, |height| height.0.saturating_add(1)),
    );
    let Ok(chain) = xparq::genesis::chain_context() else {
        return Vec::new();
    };
    let mut state = ledger.state().clone();
    let mut retained = Vec::new();
    let mut seen = BTreeSet::new();
    for transaction in transactions {
        if retained.len() >= MAX_MEMPOOL_TRANSACTIONS {
            break;
        }
        let Ok(transaction_id) = transaction.id() else {
            continue;
        };
        if included.contains(&transaction_id) || !seen.insert(transaction_id) {
            continue;
        }
        let Ok(encoded) = canonical_bytes(&transaction) else {
            continue;
        };
        if encoded.len() > xparq::block::MAX_BLOCK_WEIGHT {
            continue;
        }
        if !meets_minimum_relay_fee(&transaction, encoded.len()) {
            continue;
        }
        let Ok(validated) = validate_transaction(transaction.clone(), chain, height.0, &state)
        else {
            continue;
        };
        if state
            .apply_validated_transaction(&validated, height, Address::ZERO)
            .is_err()
        {
            continue;
        }
        retained.push(transaction);
    }
    retained
}

fn header_locator(headers: &[xparq::consensus::HeaderAtHeight]) -> Result<Vec<[u8; 32]>, String> {
    if headers.is_empty() {
        return Err("local header chain is empty".into());
    }
    let mut locator = Vec::new();
    let mut index = headers.len() - 1;
    let mut step = 1_usize;
    loop {
        locator.push(headers[index].hash().map_err(|error| error.to_string())?.0);
        if index == 0 || locator.len() == MAX_LOCATOR_HASHES - 1 {
            break;
        }
        index = index.saturating_sub(step);
        if locator.len() >= 10 {
            step = step.saturating_mul(2);
        }
    }
    if locator.last() != Some(&EXPECTED_GENESIS_HASH.0) {
        locator.push(EXPECTED_GENESIS_HASH.0);
    }
    Ok(locator)
}

fn local_header_state_at_hash(
    headers: &[xparq::consensus::HeaderAtHeight],
    hash: [u8; 32],
) -> Result<Option<xparq::consensus::HeaderValidationState>, String> {
    let Some(index) = headers
        .iter()
        .position(|header| header.hash().is_ok_and(|candidate| candidate.0 == hash))
    else {
        return Ok(None);
    };
    validated_header_state(&headers[..=index]).map(Some)
}

fn validated_header_state(
    headers: &[xparq::consensus::HeaderAtHeight],
) -> Result<xparq::consensus::HeaderValidationState, String> {
    let tip = headers.last().ok_or("validated header chain is empty")?;
    if headers[0].height != Height(0)
        || headers[0].hash().map_err(|error| error.to_string())? != EXPECTED_GENESIS_HASH
    {
        return Err("validated header chain has the wrong genesis".into());
    }
    let cumulative_work = headers
        .iter()
        .skip(1)
        .fold(xparq::consensus::Work::ZERO, |work, header| {
            work.saturating_add(xparq::consensus::block_work(header.header.difficulty))
        });
    let cumulative_weight = headers.iter().skip(1).fold(0_u128, |total, header| {
        total.saturating_add(u128::from(header.header.block_weight))
    });
    let start = headers
        .len()
        .saturating_sub(xparq::consensus::RECENT_HEADER_WINDOW);
    Ok(xparq::consensus::HeaderValidationState {
        height: tip.height,
        header: tip.header.clone(),
        cumulative_work,
        cumulative_weight,
        difficulty_anchor: headers[usize::from(tip.height.0 > 0)].clone(),
        recent_headers: headers[start..].to_vec(),
    })
}

fn encode_locator(locator: &[[u8; 32]]) -> Result<Vec<u8>, String> {
    if locator.is_empty() || locator.len() > MAX_LOCATOR_HASHES {
        return Err("header locator count is outside allowed range".into());
    }
    let mut bytes = Vec::with_capacity(2 + locator.len() * 32);
    bytes.push(GET_HEADERS_MESSAGE);
    bytes.push(locator.len() as u8);
    for hash in locator {
        bytes.extend_from_slice(hash);
    }
    Ok(bytes)
}

fn decode_locator(bytes: &[u8]) -> Result<Vec<[u8; 32]>, String> {
    if bytes.first() != Some(&GET_HEADERS_MESSAGE) {
        return Err("expected get-headers message".into());
    }
    let count = bytes.get(1).copied().ok_or("missing locator count")? as usize;
    if count == 0 || count > MAX_LOCATOR_HASHES || bytes.len() != 2 + count * 32 {
        return Err("invalid header locator size".into());
    }
    bytes[2..]
        .chunks_exact(32)
        .map(|chunk| {
            chunk
                .try_into()
                .map_err(|_| "invalid locator hash".to_string())
        })
        .collect()
}

fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), String> {
    let length = u32::try_from(bytes.len()).map_err(|_| "P2P frame is too large")?;
    stream
        .write_all(&length.to_le_bytes())
        .and_then(|_| stream.write_all(bytes))
        .map_err(|error| format!("write P2P frame: {error}"))
}

fn read_frame(stream: &mut TcpStream, maximum: usize) -> Result<Vec<u8>, String> {
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .map_err(|error| format!("read P2P frame length: {error}"))?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > maximum {
        return Err("P2P frame size is outside allowed range".into());
    }
    let mut bytes = vec![0_u8; length];
    stream
        .read_exact(&mut bytes)
        .map_err(|error| format!("read P2P frame: {error}"))?;
    Ok(bytes)
}

fn exchange_handshake(
    database: &Path,
    stream: &mut TcpStream,
) -> Result<HandshakeExchange, String> {
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .and_then(|_| stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT)))
        .map_err(|error| format!("configure peer timeout: {error}"))?;
    ensure_ledger_cache(database)?;
    let ledger = cached_ledger(database)?.ok_or("ledger cache does not match database")?;
    let local_headers = ledger.chain.chain_headers();
    let local = local_handshake(database, &ledger)?;
    write_handshake(stream, &local)?;
    let peer = read_handshake(stream)?;
    validate_handshake(&peer)?;
    if peer.node_id == local.node_id {
        return Err("refusing self connection".into());
    }
    Ok(HandshakeExchange {
        peer,
        local_headers,
    })
}

fn local_handshake(database: &Path, ledger: &Ledger) -> Result<Handshake, String> {
    let headers = ledger
        .chain
        .chain_headers()
        .into_iter()
        .map(|(height, header)| xparq::consensus::HeaderAtHeight::new(height, header))
        .collect::<Vec<_>>();
    let state = validated_header_state(&headers)?;
    Ok(Handshake {
        magic: P2P_MAGIC,
        protocol_version: P2P_PROTOCOL_VERSION,
        node_id: load_or_create_node_id(database)?,
        genesis_hash: EXPECTED_GENESIS_HASH.0,
        chain_spec_hash: chain_spec_hash().map_err(|error| error.to_string())?.0,
        capabilities: LOCAL_CAPABILITIES,
        tip_height: ledger.tip_height().unwrap_or(Height(0)),
        tip_hash: ledger
            .tip_hash()
            .ok_or("local chain has no canonical tip")?
            .0,
        cumulative_work: state.cumulative_work.to_be_limbs(),
        cumulative_weight: state.cumulative_weight,
    })
}

fn write_handshake(stream: &mut TcpStream, handshake: &Handshake) -> Result<(), String> {
    let bytes = canonical_bytes(handshake).map_err(|error| error.to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_HANDSHAKE_SIZE {
        return Err("local handshake exceeds size limit".into());
    }
    let length = u32::try_from(bytes.len()).map_err(|_| "handshake is too large")?;
    stream
        .write_all(&length.to_le_bytes())
        .and_then(|_| stream.write_all(&bytes))
        .map_err(|error| format!("write handshake: {error}"))
}

fn read_handshake(stream: &mut TcpStream) -> Result<Handshake, String> {
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .map_err(|error| format!("read handshake length: {error}"))?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_HANDSHAKE_SIZE {
        return Err("peer handshake size is outside allowed range".into());
    }
    let mut bytes = vec![0_u8; length];
    stream
        .read_exact(&mut bytes)
        .map_err(|error| format!("read handshake: {error}"))?;
    canonical_decode(&bytes).map_err(|error| format!("decode handshake: {error}"))
}

fn validate_handshake(handshake: &Handshake) -> Result<(), String> {
    if handshake.magic != P2P_MAGIC {
        return Err("invalid P2P network magic".into());
    }
    if handshake.protocol_version != P2P_PROTOCOL_VERSION {
        return Err(format!(
            "unsupported P2P protocol version {}",
            handshake.protocol_version
        ));
    }
    if handshake.genesis_hash != EXPECTED_GENESIS_HASH.0 {
        return Err("peer genesis does not match this canonical chain".into());
    }
    if handshake.chain_spec_hash != chain_spec_hash().map_err(|error| error.to_string())?.0 {
        return Err("peer chain specification does not match this node".into());
    }
    if handshake.tip_height == Height(0) && handshake.tip_hash != EXPECTED_GENESIS_HASH.0 {
        return Err("peer reports an invalid genesis tip".into());
    }
    Ok(())
}

fn configure_public_address(config: &RunConfig) -> Result<(), String> {
    if config.public_addr.is_some() && config.nat_traversal {
        return Err("use either --public-addr or --nat-traversal, not both".into());
    }
    if let Some(address) = config.public_addr {
        if !is_admissible_discovered_peer(&address) {
            return Err("--public-addr must be a public, non-zero socket address".into());
        }
        set_advertised_peer(Some(address))?;
    }
    if !config.nat_traversal {
        return Ok(());
    }
    let listener: SocketAddr = config
        .p2p_listen
        .parse()
        .map_err(|_| "--nat-traversal requires a numeric P2P listen address")?;
    let mapping = crate::nat::map_tcp_listener(listener, DEFAULT_NAT_LEASE)?;
    if !is_admissible_discovered_peer(&mapping.public_addr) {
        return Err("NAT gateway returned a non-public address".into());
    }
    set_advertised_peer(Some(mapping.public_addr))?;
    println!(
        "nat: mapped public_addr={} lease_secs={}",
        mapping.public_addr,
        mapping.lease.as_secs()
    );
    thread::spawn(move || {
        loop {
            thread::sleep(mapping.lease / 2);
            match crate::nat::map_tcp_listener(listener, DEFAULT_NAT_LEASE) {
                Ok(refreshed) if is_admissible_discovered_peer(&refreshed.public_addr) => {
                    if let Err(error) = set_advertised_peer(Some(refreshed.public_addr)) {
                        eprintln!("node: update NAT public address: {error}");
                    }
                }
                Ok(_) => eprintln!("node: NAT refresh returned a non-public address"),
                Err(error) => eprintln!("node: NAT mapping refresh failed: {error}"),
            }
        }
    });
    Ok(())
}

fn advertised_peer() -> Result<Option<SocketAddr>, String> {
    ADVERTISED_PEER
        .get_or_init(|| RwLock::new(None))
        .read()
        .map(|address| *address)
        .map_err(|_| "advertised peer lock is poisoned".into())
}

fn set_advertised_peer(address: Option<SocketAddr>) -> Result<(), String> {
    *ADVERTISED_PEER
        .get_or_init(|| RwLock::new(None))
        .write()
        .map_err(|_| "advertised peer lock is poisoned")? = address;
    Ok(())
}

fn format_work(limbs: [u64; 8]) -> String {
    limbs
        .into_iter()
        .map(|limb| format!("{limb:016x}"))
        .collect()
}

fn reserved_coin_inputs(transactions: &[AuthorizedTransaction]) -> BTreeSet<xparq::coin::CoinId> {
    transactions
        .iter()
        .flat_map(|transaction| match transaction {
            AuthorizedTransaction::OnChainSpend(transaction) => transaction.intent.inputs.clone(),
            AuthorizedTransaction::Withdraw(transaction) => transaction.intent.inputs.clone(),
            AuthorizedTransaction::Extension(transaction) => transaction.fee.intent.inputs.clone(),
            AuthorizedTransaction::Redeem(_)
            | AuthorizedTransaction::Merge(_)
            | AuthorizedTransaction::Split(_) => Vec::new(),
        })
        .collect()
}

fn validate_mempool(ledger: &Ledger, transactions: &[AuthorizedTransaction]) -> Result<(), String> {
    if transactions.len() > MAX_MEMPOOL_TRANSACTIONS {
        return Err("mempool transaction count exceeds limit".into());
    }
    let height = Height(
        ledger
            .tip_height()
            .map_or(0, |height| height.0.saturating_add(1)),
    );
    let chain = xparq::genesis::chain_context().map_err(|error| error.to_string())?;
    let mut state = ledger.state().clone();
    for transaction in transactions {
        let encoded = canonical_bytes(transaction).map_err(|error| error.to_string())?;
        if encoded.len() > xparq::block::MAX_BLOCK_WEIGHT {
            return Err("transaction cannot fit in a block".into());
        }
        let required_fee = minimum_relay_fee(encoded.len())?;
        let paid_fee = transaction_miner_fee(transaction)?;
        if paid_fee < required_fee {
            return Err(format!(
                "mempool transaction fee is too low: paid {paid_fee} esca, required {required_fee} esca for {} bytes",
                encoded.len()
            ));
        }
        let validated = validate_transaction(transaction.clone(), chain, height.0, &state)
            .map_err(|error| format!("mempool transaction is invalid: {error}"))?;
        state
            .apply_validated_transaction(&validated, height, Address::ZERO)
            .map_err(|error| format!("mempool state transition is invalid: {error}"))?;
    }
    Ok(())
}

fn minimum_relay_fee(encoded_size: usize) -> Result<u64, String> {
    u64::try_from(encoded_size)
        .ok()
        .and_then(|size| size.checked_mul(MIN_RELAY_FEE_ESCA_PER_BYTE))
        .ok_or("minimum relay fee overflow".into())
}

fn meets_minimum_relay_fee(transaction: &AuthorizedTransaction, encoded_size: usize) -> bool {
    minimum_relay_fee(encoded_size)
        .and_then(|required| transaction_miner_fee(transaction).map(|paid| paid >= required))
        .unwrap_or(false)
}

fn transaction_miner_fee(transaction: &AuthorizedTransaction) -> Result<u64, String> {
    fn fee_from_outputs(outputs: &[xparq::transaction::SpendOutput]) -> Result<u64, String> {
        let mut fees = outputs
            .iter()
            .filter(|output| output.target == xparq::transaction::OutputTarget::BlockMiner);
        let fee = fees.next().map_or(0, |output| output.amount.as_esca());
        if fees.next().is_some() {
            return Err("transaction has multiple block-miner fee outputs".into());
        }
        Ok(fee)
    }

    match transaction {
        AuthorizedTransaction::OnChainSpend(transaction) => {
            fee_from_outputs(&transaction.intent.outputs)
        }
        AuthorizedTransaction::Withdraw(transaction) => {
            fee_from_outputs(&transaction.intent.outputs)
        }
        AuthorizedTransaction::Redeem(transaction) => fee_from_outputs(&transaction.intent.outputs),
        AuthorizedTransaction::Merge(transaction) => {
            transaction.intent.miner_output.map_or(Ok(0), |output| {
                fee_from_outputs(std::slice::from_ref(&output))
            })
        }
        AuthorizedTransaction::Split(transaction) => {
            transaction.intent.miner_output.map_or(Ok(0), |output| {
                fee_from_outputs(std::slice::from_ref(&output))
            })
        }
        AuthorizedTransaction::Extension(transaction) => {
            fee_from_outputs(&transaction.fee.intent.outputs)
        }
    }
}

fn read_mempool(path: &Path) -> Result<Vec<AuthorizedTransaction>, String> {
    let encoded = crate::storage::read_mempool(path)?;
    let length = encoded
        .iter()
        .try_fold(0_u64, |total, transaction| {
            total.checked_add(transaction.len() as u64)
        })
        .ok_or("stored mempool size overflow")?;
    if length > MAX_STORED_MEMPOOL_SIZE {
        return Err("stored mempool exceeds size limit".into());
    }
    if encoded.len() > MAX_MEMPOOL_TRANSACTIONS {
        return Err("stored mempool transaction count exceeds limit".into());
    }
    encoded
        .into_iter()
        .map(|bytes| {
            canonical_decode(&bytes).map_err(|error| format!("decode mempool transaction: {error}"))
        })
        .collect()
}

fn write_mempool(path: &Path, transactions: &[AuthorizedTransaction]) -> Result<(), String> {
    let encoded = encode_mempool(transactions)?;
    let length = encoded
        .iter()
        .try_fold(0_u64, |total, transaction| {
            total.checked_add(transaction.len() as u64)
        })
        .ok_or("mempool size overflow")?;
    if length > MAX_STORED_MEMPOOL_SIZE {
        return Err("mempool exceeds persistence size limit".into());
    }
    crate::storage::replace_mempool(path, &encoded)
}

fn encode_mempool(transactions: &[AuthorizedTransaction]) -> Result<Vec<Vec<u8>>, String> {
    transactions
        .iter()
        .map(|transaction| canonical_bytes(transaction).map_err(|error| error.to_string()))
        .collect()
}

fn persist_block_and_mempool(
    path: &Path,
    block: &Block,
    mempool: &[AuthorizedTransaction],
) -> Result<(), String> {
    let block_bytes = block_bytes(block).map_err(|error| error.to_string())?;
    crate::storage::append_block_and_replace_mempool(
        path,
        block.height().0,
        &block_bytes,
        &encode_mempool(mempool)?,
    )
}

fn persist_chain_and_mempool(
    path: &Path,
    ledger: &Ledger,
    mempool: &[AuthorizedTransaction],
) -> Result<(), String> {
    let blocks = ledger
        .chain
        .blocks()
        .map(|block| {
            block_bytes(block)
                .map(|bytes| (block.height().0, bytes))
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    crate::storage::replace_blocks_and_mempool(path, &blocks, &encode_mempool(mempool)?)
}

fn parse_address(value: &str) -> Result<Address, String> {
    address_from_string(value)
        .map_err(|_| "miner address must be lowercase 0x hex with an XPARQ checksum".to_string())
}

fn check_database(path: Option<&str>) -> Result<(), String> {
    let database = database_path(path);
    let ledger = load_existing(&database)?;
    print_status(&ledger, &database);
    println!("database: valid");
    Ok(())
}

fn submit_block(path: Option<&str>, encoded: &str) -> Result<(), String> {
    let database = database_path(path);
    let _mutation = state_mutation_lock()?
        .lock()
        .map_err(|_| "state mutation lock is poisoned")?;
    let mut ledger = load_or_initialize(&database)?;
    let bytes = hex::decode(encoded).map_err(|error| format!("invalid block hex: {error}"))?;
    let block = decode_block(&bytes).map_err(|error| format!("invalid block: {error}"))?;
    apply_block(&mut ledger, block.clone()).map_err(|error| error.to_string())?;
    let included = block
        .transactions()
        .iter()
        .map(|transaction| transaction.id().map_err(|error| error.to_string()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mempool = reconcile_mempool(&ledger, read_mempool(&database)?, &included);
    persist_block_and_mempool(&database, &block, &mempool)?;
    update_ledger_cache(&database, &ledger)?;
    notify_gossip();
    let hash = block.hash().map_err(|error| error.to_string())?;
    println!(
        "accepted height={} hash={}",
        block.height().0,
        hex::encode(hash.0)
    );
    Ok(())
}

fn state_mutation_lock() -> Result<&'static Mutex<()>, String> {
    Ok(STATE_MUTATION_LOCK.get_or_init(|| Mutex::new(())))
}

fn load_or_initialize(path: &Path) -> Result<Ledger, String> {
    if let Some(ledger) = cached_ledger(path)? {
        return Ok(ledger);
    }
    let ledger = load_or_initialize_uncached(path)?;
    recover_mempool(path, &ledger)?;
    update_ledger_cache(path, &ledger)?;
    Ok(ledger)
}

fn recover_mempool(path: &Path, ledger: &Ledger) -> Result<(), String> {
    let transactions = match read_mempool(path) {
        Ok(transactions) => transactions,
        Err(error) => {
            eprintln!("node: discarded unreadable redb mempool reason={error}");
            Vec::new()
        }
    };
    let reconciled = reconcile_mempool(ledger, transactions, &BTreeSet::new());
    write_mempool(path, &reconciled)
}

fn load_or_initialize_uncached(path: &Path) -> Result<Ledger, String> {
    if crate::storage::has_blocks(path)? {
        return load_existing(path);
    }
    fs::create_dir_all(path).map_err(|error| format!("create database: {error}"))?;
    let block = genesis_block().map_err(|error| error.to_string())?;
    let mut ledger = Ledger::new();
    xparq::consensus::apply_genesis(&mut ledger, block.clone(), EXPECTED_GENESIS_HASH)
        .map_err(|error| error.to_string())?;
    append_block(path, &block)?;
    Ok(ledger)
}

fn ledger_cache() -> &'static RwLock<Option<CachedLedger>> {
    LEDGER_CACHE.get_or_init(|| RwLock::new(None))
}

fn cached_ledger(path: &Path) -> Result<Option<Ledger>, String> {
    let cache = ledger_cache()
        .read()
        .map_err(|_| "ledger cache read lock is poisoned")?;
    Ok(cache
        .as_ref()
        .filter(|cached| cached.database == path)
        .map(|cached| cached.ledger.clone()))
}

fn cached_chain_headers(path: &Path) -> Result<Vec<(Height, xparq::block::Header)>, String> {
    ensure_ledger_cache(path)?;
    let cache = ledger_cache()
        .read()
        .map_err(|_| "ledger cache read lock is poisoned")?;
    let cached = cache
        .as_ref()
        .filter(|cached| cached.database == path)
        .ok_or("ledger cache does not match database")?;
    Ok(cached.ledger.chain.chain_headers())
}

fn cached_canonical_block(path: &Path, hash: [u8; 32]) -> Result<Option<Block>, String> {
    ensure_ledger_cache(path)?;
    let cache = ledger_cache()
        .read()
        .map_err(|_| "ledger cache read lock is poisoned")?;
    let cached = cache
        .as_ref()
        .filter(|cached| cached.database == path)
        .ok_or("ledger cache does not match database")?;
    Ok(cached
        .ledger
        .chain
        .blocks()
        .find(|block| block.hash().is_ok_and(|candidate| candidate.0 == hash))
        .cloned())
}

fn cached_handshake(path: &Path) -> Result<Handshake, String> {
    ensure_ledger_cache(path)?;
    let cache = ledger_cache()
        .read()
        .map_err(|_| "ledger cache read lock is poisoned")?;
    let cached = cache
        .as_ref()
        .filter(|cached| cached.database == path)
        .ok_or("ledger cache does not match database")?;
    local_handshake(path, &cached.ledger)
}

fn load_or_create_node_id(database: &Path) -> Result<[u8; 32], String> {
    if let Some(bytes) = crate::storage::auxiliary_get(database, NODE_ID_FILE)? {
        return bytes
            .try_into()
            .map_err(|_| "stored node ID has invalid length".into());
    }
    let mut node_id = [0_u8; 32];
    getrandom::fill(&mut node_id).map_err(|error| format!("generate node ID: {error}"))?;
    crate::storage::auxiliary_get_or_insert(database, NODE_ID_FILE, &node_id)?
        .try_into()
        .map_err(|_| "stored node ID has invalid length".into())
}

fn ensure_ledger_cache(path: &Path) -> Result<(), String> {
    let present = ledger_cache()
        .read()
        .map_err(|_| "ledger cache read lock is poisoned")?
        .as_ref()
        .is_some_and(|cached| cached.database == path);
    if !present {
        let _ = load_or_initialize(path)?;
    }
    Ok(())
}

fn update_ledger_cache(path: &Path, ledger: &Ledger) -> Result<(), String> {
    let mut cache = ledger_cache()
        .write()
        .map_err(|_| "ledger cache write lock is poisoned")?;
    *cache = Some(CachedLedger {
        database: path.to_path_buf(),
        ledger: ledger.clone(),
    });
    drop(cache);
    if let Err(error) = crate::snapshot::write_if_due(path, ledger) {
        eprintln!("node: snapshot write failed: {error}");
    }
    Ok(())
}

fn load_existing(path: &Path) -> Result<Ledger, String> {
    let blocks = read_blocks(path)?;
    let (genesis, rest) = blocks
        .split_first()
        .ok_or("database has no genesis block")?;
    match crate::snapshot::load(path, &blocks) {
        Ok(Some((ledger, next))) => match replay_stored_blocks(path, ledger, &blocks[next..]) {
            Ok(ledger) => return Ok(ledger),
            Err(error) => eprintln!("node: snapshot replay failed, using full replay: {error}"),
        },
        Ok(None) => {}
        Err(error) => eprintln!("node: snapshot ignored, using full replay: {error}"),
    }
    let mut ledger = Ledger::new();
    xparq::consensus::apply_genesis(&mut ledger, genesis.clone(), EXPECTED_GENESIS_HASH)
        .map_err(|error| format!("invalid stored genesis: {error}"))?;
    replay_stored_blocks(path, ledger, rest)
}

fn replay_stored_blocks(
    path: &Path,
    mut ledger: Ledger,
    blocks: &[Block],
) -> Result<Ledger, String> {
    for block in blocks {
        apply_block(&mut ledger, block.clone()).map_err(|error| {
            format!(
                "invalid stored block at height {}: {error}",
                block.height().0
            )
        })?;
        if let Err(error) = crate::snapshot::write_if_due(path, &ledger) {
            eprintln!("node: snapshot write failed: {error}");
        }
    }
    Ok(ledger)
}

fn read_blocks(path: &Path) -> Result<Vec<Block>, String> {
    crate::storage::read_blocks(path)?
        .into_iter()
        .map(|bytes| {
            if bytes.is_empty() || bytes.len() > MAX_STORED_BLOCK_SIZE {
                return Err("stored block size is outside allowed range".into());
            }
            decode_block(&bytes).map_err(|error| format!("decode stored block: {error}"))
        })
        .collect()
}

fn append_block(path: &Path, block: &Block) -> Result<(), String> {
    let bytes = block_bytes(block).map_err(|error| error.to_string())?;
    crate::storage::append_block(path, block.height().0, &bytes)
}

fn print_status(ledger: &Ledger, database: &Path) {
    let height = ledger.tip_height().unwrap_or(Height(0));
    let tip = ledger
        .tip_hash()
        .map(|hash| hex::encode(hash.0))
        .unwrap_or_else(|| "none".into());
    println!("database: {}", database.display());
    println!("genesis: {}", hex::encode(EXPECTED_GENESIS_HASH.0));
    println!("height: {}", height.0);
    println!("tip: {tip}");
    println!("coin_utxos: {}", ledger.state().coins.len());
    println!("qcash_utxos: {}", ledger.state().qcash.len());
}

fn print_network_info() -> Result<(), String> {
    println!("genesis: {}", hex::encode(EXPECTED_GENESIS_HASH.0));
    println!(
        "chain_spec: {}",
        hex::encode(chain_spec_hash().map_err(|error| error.to_string())?.0)
    );
    println!("p2p_protocol: {P2P_PROTOCOL_VERSION}");
    println!("pow: {}", xparq::consensus::POW_ALGORITHM);
    println!("difficulty: {}", xparq::consensus::DIFFICULTY_ALGORITHM);
    Ok(())
}

fn print_help() {
    println!(
        "node run [--data PATH] [--p2p ADDRESS] [--rpc ADDRESS] [--peer ADDRESS]... [--miner ADDRESS] [--public-addr ADDRESS | --nat-traversal]\nnode network [data-dir] [listen-address] [peer-address...]\nnode rpc [data-dir] [listen-address]\nnode p2p-listen [data-dir] [listen-address]\nnode peer [data-dir] <peer-address>\nnode info\nnode check [data-dir]\nnode account [data-dir] <address>\nnode mempool [data-dir]\nnode mine-block [data-dir] <miner-address>\nnode submit-transaction [data-dir] <transaction-hex>\nnode submit-block [data-dir] <block-hex>\nnode version"
    );
}

fn database_path(path: Option<&str>) -> PathBuf {
    PathBuf::from(path.unwrap_or(default_database()))
}

#[cfg(feature = "mainnet")]
fn default_p2p_listen() -> &'static str {
    "0.0.0.0:6677"
}

#[cfg(feature = "mainnet")]
fn default_rpc_listen() -> &'static str {
    "127.0.0.1:6666"
}
#[cfg(feature = "testnet")]
fn default_rpc_listen() -> &'static str {
    "127.0.0.1:16666"
}
#[cfg(feature = "devnet")]
fn default_rpc_listen() -> &'static str {
    "127.0.0.1:26666"
}
#[cfg(feature = "testnet")]
fn default_p2p_listen() -> &'static str {
    "0.0.0.0:16677"
}
#[cfg(feature = "devnet")]
fn default_p2p_listen() -> &'static str {
    "0.0.0.0:26677"
}

#[cfg(feature = "mainnet")]
fn default_database() -> &'static str {
    "./data/mainnet"
}
#[cfg(feature = "testnet")]
fn default_database() -> &'static str {
    "./data/testnet"
}
#[cfg(feature = "devnet")]
fn default_database() -> &'static str {
    "./data/devnet"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_api_documentation_is_valid_and_references_every_rpc_route() {
        let specification: serde_json::Value = serde_json::from_slice(OPENAPI_JSON).unwrap();
        assert_eq!(specification["openapi"], "3.1.0");
        for route in [
            "/status",
            "/fee-policy",
            "/blocks/latest",
            "/block/{height}",
            "/account/{address}",
            "/asset/nonce/{address}",
            "/asset/{asset_id}",
            "/asset/{asset_id}/balance/{address}",
            "/explorer/address/{address}",
            "/explorer/transaction/{transaction_id}",
            "/transaction",
        ] {
            assert!(
                specification["paths"].get(route).is_some(),
                "missing {route}"
            );
        }
        assert!(
            API_DOCS_HTML
                .windows(b"/openapi.json".len())
                .any(|window| window == b"/openapi.json")
        );
    }

    #[test]
    fn asset_transaction_projection_exposes_asset_id_and_action() {
        let chain = xparq::genesis::chain_context().unwrap();
        let seed = xparq::crypto::ProfileSigningSeed::new(
            xparq::crypto::SignatureProfile::MlDsa44,
            [0x51; 32],
        );
        let asset_call = xparq::extension::asset::AssetCall::sign(
            chain.genesis_hash,
            xparq::extension::asset::AssetAction::Register {
                name: "Test Token".into(),
                symbol: "TEST".into(),
                decimals: 8,
                max_supply: 100_000_000_000_000_000_000_000,
            },
            0,
            &seed,
        )
        .unwrap();
        let asset_id = asset_call.asset_id().to_string();
        let transaction = xparq::transaction::AuthorizedExtensionTransaction {
            call: asset_call.into_extension_call().unwrap(),
            fee: xparq::transaction::AuthorizedAccountIntent {
                intent: xparq::transaction::OnChainSpendIntent {
                    sender: Address::ZERO,
                    inputs: vec![],
                    outputs: vec![],
                },
                authorization: xparq::transaction::AccountAuthorization::ProfileKnown {
                    profile: xparq::crypto::SignatureProfile::MlDsa44,
                    signature: xparq::crypto::ProfileSignature {
                        profile: xparq::crypto::SignatureProfile::MlDsa44,
                        bytes: vec![],
                    },
                },
            },
        };
        let response = extension_transaction_response(&transaction, Address::ZERO);
        assert_eq!(response["asset_id"], asset_id);
        assert_eq!(response["asset_action"]["type"], "register");
        assert_eq!(
            response["asset_action"]["max_supply"],
            "100000000000000000000000"
        );
    }

    fn policy_split_transaction(fee: u64) -> AuthorizedTransaction {
        let input_seed = xparq::qcash::QCashSigningSeed::from_bytes([0x41; 32]);
        let input = xparq::qcash::QCash::new(
            xparq::coin::CoinId::from_bytes([0x42; xparq::coin::CoinId::SIZE]),
            Amount::from_esca(1_000_000),
        );
        let intent = xparq::transaction::SplitIntent::new(
            input,
            vec![
                xparq::transaction::QCashOutput::new(
                    Amount::from_esca(1),
                    xparq::qcash::QCashSigningSeed::from_bytes([0x43; 32]).public_key(),
                ),
                xparq::transaction::QCashOutput::new(
                    Amount::from_esca(999_999 - fee),
                    xparq::qcash::QCashSigningSeed::from_bytes([0x44; 32]).public_key(),
                ),
            ],
            Some(SpendOutput::block_miner(Amount::from_esca(fee))),
        )
        .unwrap();
        let chain = xparq::genesis::chain_context().unwrap();
        let commitment = intent.commitment(chain).unwrap();
        let authorized = xparq::transaction::AuthorizedQCashIntent::new(
            intent,
            vec![xparq::transaction::QCashAuthorization {
                signature: input_seed.sign(commitment.as_bytes()),
            }],
        )
        .unwrap();
        AuthorizedTransaction::Split(Box::new(authorized))
    }

    #[test]
    fn relay_policy_requires_one_esca_per_canonical_byte() {
        let underpaid = policy_split_transaction(1);
        let underpaid_size = canonical_bytes(&underpaid).unwrap().len();
        assert!(!meets_minimum_relay_fee(&underpaid, underpaid_size));

        let paid = policy_split_transaction(10_000);
        let paid_size = canonical_bytes(&paid).unwrap().len();
        assert!(meets_minimum_relay_fee(&paid, paid_size));
        assert_eq!(transaction_miner_fee(&paid), Ok(10_000));
    }

    #[test]
    fn explorer_address_response_is_aggregate_only() {
        let ledger = xparq::genesis::genesis_ledger().unwrap();
        let response = explorer_address_response(&ledger, &[], Address([7; 20]), true).unwrap();
        assert_eq!(response["balance"]["total"], 0);
        assert_eq!(response["activity_count"], 0);
        assert!(response.get("utxos").is_none());
    }

    #[test]
    fn explorer_activity_reports_net_transfer_for_sender_and_recipient() {
        let mnemonic = xparq_wallet::encode_xparq_mnemonic(&[3; 16]).unwrap();
        let sender = xparq_wallet::profile_wallet_from_xparq_mnemonic(
            &mnemonic,
            xparq::crypto::SignatureProfile::MlDsa44,
        )
        .unwrap();
        let recipient = Address([4; 20]);
        let miner = Address([5; 20]);
        let intent = xparq::transaction::OnChainSpendIntent::new(
            sender.address,
            vec![xparq::coin::CoinId::from_bytes([6; 32])],
            vec![
                SpendOutput::new(recipient, Amount::from_esca(10)),
                SpendOutput::new(sender.address, Amount::from_esca(5)),
            ],
        )
        .unwrap();
        let transaction = AuthorizedTransaction::OnChainSpend(Box::new(
            sender.sign_account_intent(intent, false).unwrap(),
        ));
        let genesis = genesis_block().unwrap();
        let block = Block::from_protocol_transactions(
            Height(1),
            genesis.hash().unwrap(),
            1,
            Nonce(0),
            Some(Emission::new(miner, Amount::from_esca(1))),
            vec![transaction.clone()],
        )
        .unwrap();

        let outgoing = address_transaction_activity(&transaction, sender.address, &block)
            .unwrap()
            .unwrap();
        assert_eq!(outgoing["direction"], "out");
        assert_eq!(outgoing["amount"], 10);
        assert_eq!(
            outgoing["size_bytes"],
            canonical_bytes(&transaction).unwrap().len()
        );
        let incoming = address_transaction_activity(&transaction, recipient, &block)
            .unwrap()
            .unwrap();
        assert_eq!(incoming["direction"], "in");
        assert_eq!(incoming["amount"], 10);
        assert!(
            address_transaction_activity(&transaction, Address([9; 20]), &block)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            parse_transaction_id(&hex::encode(transaction.id().unwrap())).unwrap(),
            transaction.id().unwrap()
        );
    }

    fn read_test_http_request(parts: &[&[u8]]) -> Result<HttpRequest, String> {
        let bytes = parts.concat();
        read_http_request(&mut std::io::Cursor::new(bytes))
    }

    fn test_database(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "xparq-node-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn handshake_rejects_a_different_wire_version() {
        let mut handshake = Handshake {
            magic: P2P_MAGIC,
            protocol_version: P2P_PROTOCOL_VERSION + 1,
            node_id: [1; 32],
            genesis_hash: EXPECTED_GENESIS_HASH.0,
            chain_spec_hash: chain_spec_hash().unwrap().0,
            capabilities: LOCAL_CAPABILITIES,
            tip_height: Height(0),
            tip_hash: EXPECTED_GENESIS_HASH.0,
            cumulative_work: [0; 8],
            cumulative_weight: 0,
        };
        assert!(
            validate_handshake(&handshake)
                .unwrap_err()
                .contains("unsupported P2P protocol version")
        );

        handshake.protocol_version = P2P_PROTOCOL_VERSION;
        assert!(validate_handshake(&handshake).is_ok());

        handshake.chain_spec_hash[0] ^= 1;
        assert!(
            validate_handshake(&handshake)
                .unwrap_err()
                .contains("chain specification")
        );
    }

    #[test]
    fn discovered_peer_response_is_bounded() {
        let peers = (0..MAX_DISCOVERED_PEERS)
            .map(|index| format!("8.8.{}.{}:6677", index / 255, index % 255))
            .collect::<Vec<_>>();
        let encoded = canonical_bytes(&peers).unwrap();
        assert!(encoded.len() <= MAX_PEERS_RESPONSE_SIZE);
    }

    #[test]
    fn rpc_request_reader_accepts_fragmented_binary_body() {
        let request = read_test_http_request(&[
            b"POST /transaction HTTP/1.1\r\nContent-Len",
            b"gth: 4\r\nConnection: close\r\n\r\n\x00\x01",
            b"\x02\x03",
        ])
        .unwrap();

        assert!(request.headers.starts_with("POST /transaction HTTP/1.1"));
        assert_eq!(request.body, [0, 1, 2, 3]);
    }

    #[test]
    fn rpc_request_reader_rejects_ambiguous_or_oversized_framing() {
        let duplicate = read_test_http_request(&[
            b"POST /transaction HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        ])
        .unwrap_err();
        assert!(duplicate.contains("duplicate RPC Content-Length"));

        let transfer = read_test_http_request(&[
            b"POST /transaction HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        ])
        .unwrap_err();
        assert!(transfer.contains("Transfer-Encoding"));

        let oversized = format!(
            "POST /transaction HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_STORED_TRANSACTION_SIZE + 1
        );
        let oversized = read_test_http_request(&[oversized.as_bytes()]).unwrap_err();
        assert!(oversized.contains("exceeds transaction size limit"));
    }

    #[test]
    fn gossip_inventory_round_trips_and_rejects_excess_items_before_decode() {
        let inventory = GossipInventory {
            tip_height: Height(7),
            tip_hash: [3; 32],
            cumulative_work: Work::pow2(7).to_be_limbs(),
            cumulative_weight: 123,
            transaction_ids: vec![[4; 32], [5; 32]],
        };
        let encoded = canonical_bytes(&inventory).unwrap();
        let decoded = decode_gossip_inventory(&encoded).unwrap();
        assert_eq!(decoded.tip_height, inventory.tip_height);
        assert_eq!(decoded.tip_hash, inventory.tip_hash);
        assert_eq!(decoded.cumulative_work, inventory.cumulative_work);
        assert_eq!(decoded.cumulative_weight, inventory.cumulative_weight);
        assert_eq!(decoded.transaction_ids, inventory.transaction_ids);

        let mut oversized = encoded;
        oversized[120..124]
            .copy_from_slice(&((MAX_GOSSIP_INVENTORY_ITEMS + 1) as u32).to_le_bytes());
        assert!(
            decode_gossip_inventory(&oversized)
                .unwrap_err()
                .contains("item count exceeds limit")
        );
    }

    #[test]
    fn gossip_inventory_prefers_work_then_weight_then_smaller_tip_hash() {
        let inventory = |work, weight, tip_hash| GossipInventory {
            tip_height: Height(7),
            tip_hash,
            cumulative_work: Work::from_be_limbs(work).to_be_limbs(),
            cumulative_weight: weight,
            transaction_ids: Vec::new(),
        };
        let weaker = inventory([0, 0, 0, 0, 0, 0, 0, 7], 999, [1; 32]);
        let stronger = inventory([0, 0, 0, 0, 0, 0, 0, 8], 1, [9; 32]);
        assert!(inventory_preferred(&stronger, &weaker));

        let lighter = inventory([0, 0, 0, 0, 0, 0, 0, 8], 10, [1; 32]);
        let heavier = inventory([0, 0, 0, 0, 0, 0, 0, 8], 11, [9; 32]);
        assert!(inventory_preferred(&heavier, &lighter));

        let larger_hash = inventory([0, 0, 0, 0, 0, 0, 0, 8], 11, [9; 32]);
        let smaller_hash = inventory([0, 0, 0, 0, 0, 0, 0, 8], 11, [2; 32]);
        assert!(inventory_preferred(&smaller_hash, &larger_hash));
    }

    #[test]
    fn redb_startup_round_trips_canonical_genesis() {
        let database = test_database("redb-roundtrip");
        let ledger = load_or_initialize_uncached(&database).unwrap();
        let recovered = load_existing(&database).unwrap();
        assert_eq!(recovered.tip_hash(), ledger.tip_hash());
        assert!(database.join("xparq.redb").is_file());
        fs::remove_dir_all(database).unwrap();
    }

    #[test]
    fn startup_discards_invalid_redb_mempool_entries() {
        let database = test_database("corrupt-mempool");
        let ledger = load_or_initialize_uncached(&database).unwrap();
        crate::storage::replace_mempool(&database, &[vec![0xff, 0xff, 0xff]]).unwrap();

        recover_mempool(&database, &ledger).unwrap();

        assert!(read_mempool(&database).unwrap().is_empty());
        fs::remove_dir_all(database).unwrap();
    }
}
