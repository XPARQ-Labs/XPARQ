use super::*;
use super::{config::*, gossip::*, mempool::*, protocol::*};

pub(super) fn check_database(path: Option<&str>) -> Result<(), String> {
    let database = database_path(path);
    let ledger = load_existing(&database)?;
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
        .transactions()
        .iter()
        .map(|transaction| transaction.id().map_err(|error| error.to_string()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mempool = reconcile_mempool(&ledger, read_mempool(&database)?, &included);
    persist_block_and_mempool(&database, &block, &mempool)?;
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

pub(super) fn load_or_initialize_uncached(path: &Path) -> Result<Ledger, String> {
    if crate::storage::has_blocks(path)? {
        return load_existing(path);
    }
    fs::create_dir_all(path).map_err(|error| format!("create database: {error}"))?;
    let block = genesis_block().map_err(|error| error.to_string())?;
    let mut ledger = Ledger::new();
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

    for block in ledger.chain.blocks() {
        let height = block.height();

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

        let block_work = kernel::consensus::block_work(block.target_bits()).ok_or_else(|| {
            format!(
                "invalid target bits {:08x} at height {}",
                block.target_bits(),
                height.0,
            )
        })?;

        cumulative_work = cumulative_work.saturating_add(block_work);

        cumulative_weight = cumulative_weight.saturating_add(u64::from(block.block_weight()));

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
                .block(&checkpoint.height)
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
            .block(&height)
            .ok_or("canonical block is missing while updating checkpoints")?;

        let block_work = kernel::consensus::block_work(block.target_bits()).ok_or_else(|| {
            format!(
                "invalid target bits {:08x} at height {}",
                block.target_bits(),
                height.0,
            )
        })?;

        cumulative_work = cumulative_work.saturating_add(block_work);

        cumulative_weight = cumulative_weight.saturating_add(u64::from(block.block_weight()));

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

    let block = ledger
        .chain
        .block(&height)
        .ok_or("indexed canonical block is missing")?;

    let actual_hash = block.hash().map_err(|error| error.to_string())?.0;

    if actual_hash != hash {
        return Err("block index does not match canonical chain".into());
    }

    Ok(Some(block_bytes(block).map_err(|error| error.to_string())?))
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

pub(super) fn update_ledger_cache(path: &Path, ledger: Ledger) -> Result<Arc<Ledger>, String> {
    let (checkpoints, cumulative_work, cumulative_weight) =
        updated_header_state_checkpoints(path, &ledger)?;

    let checkpoints = Arc::new(checkpoints);

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
    kernel::consensus::apply_genesis(&mut ledger, genesis.clone(), EXPECTED_GENESIS_HASH)
        .map_err(|error| format!("invalid stored genesis: {error}"))?;
    replay_stored_blocks(path, ledger, rest)
}

pub(super) fn replay_stored_blocks(
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

pub(super) fn read_blocks(path: &Path) -> Result<Vec<Block>, String> {
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
    println!("utxos: {}", ledger.state().utxos.len());
}
