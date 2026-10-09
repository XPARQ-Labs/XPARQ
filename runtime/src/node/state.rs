use super::*;
use super::{config::*, gossip::*, mempool::*, protocol::*};

pub(super) fn check_database(path: Option<&str>, full: bool) -> Result<(), String> {
    let database = database_path(path);
    let start = std::time::Instant::now();
    let ledger = if full {
        replay_from_genesis(&database)?
    } else {
        load_existing(&database)?
    };
    if full {
        println!(
            "database: full replay verified elapsed_ms={:.3}",
            start.elapsed().as_secs_f64() * 1000.0
        );
    }
    print_status(&ledger, &database);
    println!("database: valid");
    Ok(())
}

pub(super) fn submit_block(path: Option<&str>, encoded: &str) -> Result<(), String> {
    let database = database_path(path);
    let _mutation = state_mutation_lock()?
        .lock()
        .map_err(|_| "state mutation lock is poisoned")?;
    let mut ledger = load_or_initialize_owned(&database)?;
    let bytes = hex::decode(encoded).map_err(|error| format!("invalid block hex: {error}"))?;
    let block = decode_block(&bytes).map_err(|error| format!("invalid block: {error}"))?;
    apply_block(&mut ledger, block.clone()).map_err(|error| error.to_string())?;
    let included = block
        .operations()
        .iter()
        .map(|operation| {
            operation
                .id()
                .map(|id| id.into_bytes())
                .map_err(|error| error.to_string())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mempool =
        reconcile_pending_operations(&ledger, read_pending_operations(&database)?, &included);
    persist_block_and_pending(&database, &block, &mempool)?;
    let _ = update_ledger_cache(&database, ledger)?;
    notify_gossip();
    let hash = block.hash().map_err(|error| error.to_string())?;
    println!(
        "accepted height={} hash={}",
        block.height().0,
        hex::encode(hash.0)
    );
    Ok(())
}

pub(super) fn state_mutation_lock() -> Result<&'static Mutex<()>, String> {
    Ok(STATE_MUTATION_LOCK.get_or_init(|| Mutex::new(())))
}

pub(super) fn load_or_initialize(path: &Path) -> Result<Arc<Ledger>, String> {
    if let Some(ledger) = cached_ledger(path)? {
        return Ok(ledger);
    }
    let ledger = load_or_initialize_uncached(path)?;
    recover_mempool(path, &ledger)?;
    update_ledger_cache(path, ledger)
}

/// Returns an owned staging ledger for a state mutation.
///
/// Read-only callers should use `load_or_initialize()` so they only clone the
/// `Arc`, not the full ledger. Mutating callers intentionally clone once so a
/// failed state transition or persistence operation cannot corrupt the cached
/// canonical state.
pub(super) fn load_or_initialize_owned(path: &Path) -> Result<Ledger, String> {
    let ledger = load_or_initialize(path)?;
    Ok(ledger.as_ref().clone())
}

pub(super) fn recover_mempool(path: &Path, ledger: &Ledger) -> Result<(), String> {
    let pending = match read_pending_operations(path) {
        Ok(pending) => pending,
        Err(error) => {
            eprintln!("node: discarded unreadable redb mempool reason={error}");
            return write_pending_operations(path, &[]);
        }
    };
    let reconciled = reconcile_pending_operations(ledger, pending, &BTreeSet::new());
    write_pending_operations(path, &reconciled)
}

pub(super) fn load_or_initialize_uncached(path: &Path) -> Result<Ledger, String> {
    if crate::storage::has_blocks(path)? {
        return load_existing(path);
    }
    fs::create_dir_all(path).map_err(|error| format!("create database: {error}"))?;
    let block = genesis_block().map_err(|error| error.to_string())?;
    let mut ledger = Ledger::new().with_applications(extension::SystemApplications);
    kernel::consensus::apply_genesis(&mut ledger, block.clone(), EXPECTED_GENESIS_HASH)
        .map_err(|error| error.to_string())?;
    persist_block_and_mempool(path, &block, &[])?;
    Ok(ledger)
}

const HEADER_STATE_CHECKPOINT_INTERVAL: u64 = 256;

#[derive(Debug, Clone)]
pub(super) struct HeaderStateCheckpoint {
    pub(super) height: Height,
    pub(super) hash: [u8; 32],
    pub(super) cumulative_work: kernel::consensus::Work,
    pub(super) cumulative_weight: u64,
}

pub(super) type HeaderSnapshot = (
    Arc<Ledger>,
    Arc<Vec<HeaderStateCheckpoint>>,
    kernel::consensus::Work,
    u64,
);

pub(super) fn build_header_state_checkpoints(
    ledger: &Ledger,
) -> Result<(Vec<HeaderStateCheckpoint>, kernel::consensus::Work, u64), String> {
    let mut checkpoints = Vec::new();

    let mut cumulative_work = kernel::consensus::Work::ZERO;
    let mut cumulative_weight = 0_u64;

    for (height, block) in ledger.chain.headers() {
        let height = *height;

        let hash = block.hash().map_err(|error| error.to_string())?.0;

        if height == Height(0) {
            if hash != EXPECTED_GENESIS_HASH.0 {
                return Err("canonical checkpoint chain has the wrong genesis".into());
            }

            checkpoints.push(HeaderStateCheckpoint {
                height,
                hash,
                cumulative_work,
                cumulative_weight,
            });

            continue;
        }

        let block_work = kernel::consensus::block_work(block.target_bits).ok_or_else(|| {
            format!(
                "invalid target bits {:08x} at height {}",
                block.target_bits, height.0,
            )
        })?;

        cumulative_work = cumulative_work.saturating_add(block_work);

        cumulative_weight = cumulative_weight.saturating_add(u64::from(block.block_weight));

        if height.0.is_multiple_of(HEADER_STATE_CHECKPOINT_INTERVAL) {
            checkpoints.push(HeaderStateCheckpoint {
                height,
                hash,
                cumulative_work,
                cumulative_weight,
            });
        }
    }

    if checkpoints.is_empty() {
        return Err("canonical chain has no genesis checkpoint".into());
    }

    Ok((checkpoints, cumulative_work, cumulative_weight))
}

fn updated_header_state_checkpoints(
    path: &Path,
    ledger: &Ledger,
) -> Result<(Vec<HeaderStateCheckpoint>, kernel::consensus::Work, u64), String> {
    let previous = {
        let cache = ledger_cache()
            .read()
            .map_err(|_| "ledger cache read lock is poisoned")?;

        cache
            .as_ref()
            .filter(|cached| cached.database == path)
            .map(|cached| Arc::clone(&cached.header_checkpoints))
    };

    let Some(previous) = previous else {
        return build_header_state_checkpoints(ledger);
    };

    let Some(tip_height) = ledger.tip_height() else {
        return Err("canonical chain has no tip".into());
    };

    let anchor_index = previous.iter().rposition(|checkpoint| {
        checkpoint.height <= tip_height
            && ledger
                .chain
                .header(&checkpoint.height)
                .and_then(|block| block.hash().ok())
                .is_some_and(|hash| hash.0 == checkpoint.hash)
    });

    let Some(anchor_index) = anchor_index else {
        return build_header_state_checkpoints(ledger);
    };

    let anchor = &previous[anchor_index];

    let mut checkpoints = previous[..=anchor_index].to_vec();
    let mut cumulative_work = anchor.cumulative_work;
    let mut cumulative_weight = anchor.cumulative_weight;

    let mut next_height = anchor.height.0.saturating_add(1);

    while next_height <= tip_height.0 {
        let height = Height(next_height);

        let block = ledger
            .chain
            .header(&height)
            .ok_or("canonical block is missing while updating checkpoints")?;

        let block_work = kernel::consensus::block_work(block.target_bits).ok_or_else(|| {
            format!(
                "invalid target bits {:08x} at height {}",
                block.target_bits, height.0,
            )
        })?;

        cumulative_work = cumulative_work.saturating_add(block_work);

        cumulative_weight = cumulative_weight.saturating_add(u64::from(block.block_weight));

        if height.0.is_multiple_of(HEADER_STATE_CHECKPOINT_INTERVAL) {
            checkpoints.push(HeaderStateCheckpoint {
                height,
                hash: block.hash().map_err(|error| error.to_string())?.0,
                cumulative_work,
                cumulative_weight,
            });
        }

        let Some(next) = next_height.checked_add(1) else {
            break;
        };

        next_height = next;
    }

    Ok((checkpoints, cumulative_work, cumulative_weight))
}

pub(super) fn ledger_cache() -> &'static RwLock<Option<CachedLedger>> {
    LEDGER_CACHE.get_or_init(|| RwLock::new(None))
}

pub(super) fn cached_ledger(path: &Path) -> Result<Option<Arc<Ledger>>, String> {
    let cache = ledger_cache()
        .read()
        .map_err(|_| "ledger cache read lock is poisoned")?;
    Ok(cache
        .as_ref()
        .filter(|cached| cached.database == path)
        .map(|cached| Arc::clone(&cached.ledger)))
}

pub(super) fn load_or_initialize_header_snapshot(path: &Path) -> Result<HeaderSnapshot, String> {
    let _ = load_or_initialize(path)?;
    let cache = ledger_cache()
        .read()
        .map_err(|_| "ledger cache read lock is poisoned")?;

    let cached = cache
        .as_ref()
        .filter(|cached| cached.database == path)
        .ok_or("ledger cache does not match database")?;

    Ok((
        Arc::clone(&cached.ledger),
        Arc::clone(&cached.header_checkpoints),
        cached.cumulative_work,
        cached.cumulative_weight,
    ))
}

pub(super) fn cached_canonical_block_bytes(
    path: &Path,
    hash: [u8; 32],
) -> Result<Option<Vec<u8>>, String> {
    let ledger = load_or_initialize(path)?;

    let Some(height) = index::canonical_block_height(path, &ledger, hash)? else {
        return Ok(None);
    };

    let block = canonical_block(path, &ledger, height)?;
    if block.hash().map_err(|error| error.to_string())?.0 != hash {
        return Err("block index does not match canonical chain".into());
    }
    Ok(Some(
        block_bytes(&block).map_err(|error| error.to_string())?,
    ))
}

// Logical canonical bytes, not a whole-process RSS limit. Headers, state and
// journal retention is managed separately; genesis/tip may exceed a smaller budget.
pub(super) const BODY_CACHE_BYTES: usize = 16 * 1024 * 1024;
pub(super) const BODY_CACHE_BLOCKS: usize = 128;

pub(super) fn trim_body_cache(ledger: &mut Ledger) -> Result<(), String> {
    ledger
        .chain
        .retain_recent_bodies(BODY_CACHE_BYTES, BODY_CACHE_BLOCKS)
        .map_err(|error| format!("trim resident body cache: {error}"))
}

/// A missing/corrupt local body is a storage error, never evidence of invalid consensus.
/// The pinned ledger header guards reads across concurrent canonical replacements.
pub(super) fn canonical_block(
    path: &Path,
    ledger: &Ledger,
    height: Height,
) -> Result<Block, String> {
    let header = ledger
        .chain
        .header(&height)
        .ok_or("block was not found in this chain")?;
    if let Some(block) = ledger.chain.block(&height) {
        if &block.header != header {
            return Err("resident body does not match pinned header".into());
        }
        return Ok(block.clone());
    }
    let bytes = crate::storage::read_block_at_height(path, height.0)?
        .ok_or("local canonical body is missing; recovery is required")?;
    decode_pinned_local_body(height, header, &bytes)
}

/// Only for a body whose header belongs to this node's already validated chain.
/// Authenticate local bytes without repeating VM/operation validity checks on each
/// read. Untrusted peer blocks and full replay still use decode_block/apply_block.
pub(super) fn decode_pinned_local_body(
    height: Height,
    header: &kernel::block::Header,
    bytes: &[u8],
) -> Result<Block, String> {
    if bytes.is_empty() || bytes.len() > kernel::block::MAX_BLOCK_SIZE {
        return Err("local body size is outside allowed range".into());
    }
    let block: Block =
        canonical_decode(bytes).map_err(|error| format!("local body decode failed: {error}"))?;
    if block.height() != height || &block.header != header {
        return Err("local body does not match pinned canonical header; retry or recover".into());
    }
    if block
        .calculate_merkle_root()
        .map_err(|error| format!("local body Merkle calculation failed: {error}"))?
        != header.merkle_root
    {
        return Err("local body Merkle commitment failed; recovery is required".into());
    }
    Ok(block)
}

pub(super) fn cached_handshake(path: &Path) -> Result<Handshake, String> {
    let (ledger, _header_checkpoints, cumulative_work, cumulative_weight) =
        load_or_initialize_header_snapshot(path)?;

    local_handshake(path, &ledger, cumulative_work, cumulative_weight)
}

pub(super) fn load_or_create_node_id(database: &Path) -> Result<[u8; 32], String> {
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

pub(super) fn update_ledger_cache(path: &Path, mut ledger: Ledger) -> Result<Arc<Ledger>, String> {
    let (checkpoints, cumulative_work, cumulative_weight) =
        updated_header_state_checkpoints(path, &ledger)?;

    let checkpoints = Arc::new(checkpoints);

    super::journal::prune_journals(path, &mut ledger)?;
    trim_body_cache(&mut ledger)?;
    let ledger = Arc::new(ledger);

    let mut cache = ledger_cache()
        .write()
        .map_err(|_| "ledger cache write lock is poisoned")?;

    *cache = Some(CachedLedger {
        database: path.to_path_buf(),
        ledger: Arc::clone(&ledger),
        header_checkpoints: checkpoints,
        cumulative_work,
        cumulative_weight,
    });

    drop(cache);

    if let Err(error) = crate::snapshot::write_if_due(path, &ledger) {
        eprintln!("node: snapshot write failed: {error}");
    }

    Ok(ledger)
}

pub(super) fn load_existing(path: &Path) -> Result<Ledger, String> {
    match crate::snapshot::load_streamed(path, BODY_CACHE_BYTES, BODY_CACHE_BLOCKS) {
        Ok(Some((ledger, next))) => match replay_body_stream(path, ledger, next) {
            Ok(ledger) => {
                if ledger.tip_height().is_some_and(|height| height.0 >= next) {
                    if let Err(error) = crate::snapshot::write(path, &ledger) {
                        eprintln!("node: replayed restart checkpoint write failed: {error}");
                    }
                }
                return Ok(ledger);
            }
            Err(error) => eprintln!("node: snapshot replay failed, using full replay: {error}"),
        },
        Ok(None) => {}
        Err(error) => eprintln!("node: snapshot ignored, using full replay: {error}"),
    }
    replay_from_genesis(path)
}

fn replay_from_genesis(path: &Path) -> Result<Ledger, String> {
    let mut reader = crate::storage::CanonicalBodyReader::new(path)?;
    let genesis = decode_block(&reader.next().ok_or("database has no genesis block")??)
        .map_err(|error| format!("decode stored genesis: {error}"))?;
    let mut ledger = Ledger::new().with_applications(extension::SystemApplications);
    kernel::consensus::apply_genesis(&mut ledger, genesis, EXPECTED_GENESIS_HASH)
        .map_err(|error| format!("invalid stored genesis: {error}"))?;
    let ledger = replay_body_reader(path, ledger, reader)?;
    // A full replay admits every transition under the current rules. Publish
    // its checkpoint even below the periodic snapshot interval, so an older
    // database needs this expensive migration only once.
    if let Err(error) = crate::snapshot::write(path, &ledger) {
        eprintln!("node: validated restart checkpoint write failed: {error}");
    }
    Ok(ledger)
}

fn replay_body_stream(path: &Path, ledger: Ledger, next: u64) -> Result<Ledger, String> {
    let mut reader = crate::storage::CanonicalBodyReader::new(path)?;
    // Skip encoded entries without retaining or decoding the snapshot prefix.
    for _ in 0..next {
        reader
            .next()
            .ok_or("snapshot prefix missing from body log")??;
    }
    replay_body_reader(path, ledger, reader)
}

fn replay_body_reader(
    path: &Path,
    mut ledger: Ledger,
    reader: crate::storage::CanonicalBodyReader,
) -> Result<Ledger, String> {
    let mut pow_memory = None;
    for bytes in reader {
        let block =
            decode_block(&bytes?).map_err(|error| format!("decode stored body: {error}"))?;
        kernel::consensus::apply_block_with_pow_memory(
            &mut ledger,
            block,
            pow_memory.get_or_insert_with(new_pow_memory),
        )
        .map_err(|error| format!("validate stored body: {error}"))?;
        super::journal::prune_journals(path, &mut ledger)?;
        trim_body_cache(&mut ledger)?;
        if let Err(error) = crate::snapshot::write_if_due(path, &ledger) {
            eprintln!("node: snapshot write failed: {error}");
        }
    }
    super::journal::prune_journals(path, &mut ledger)?;
    Ok(ledger)
}

pub(super) fn print_status(ledger: &Ledger, database: &Path) {
    let height = ledger.tip_height().unwrap_or(Height(0));
    let tip = ledger
        .tip_hash()
        .map(|hash| hex::encode(hash.0))
        .unwrap_or_else(|| "none".into());
    println!("database: {}", database.display());
    println!("genesis: {}", hex::encode(EXPECTED_GENESIS_HASH.0));
    println!("height: {}", height.0);
    println!("tip: {tip}");
    println!("utxos: {}", ledger.state().utxos().len());
}
