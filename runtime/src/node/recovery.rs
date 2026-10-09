//! Local recovery when the rollback journal no longer covers a preferred fork.
//! Scratch bodies are never canonical until the final redb transaction commits.
use super::*;
use super::{chain_sync::*, gossip::*, mempool::*, state::*};

#[cfg(test)]
pub(super) static RECOVERY_TEST_LOCK: Mutex<()> = Mutex::new(());

static RECOVERY: Mutex<()> = Mutex::new(());
static INVALID_CANDIDATES: Mutex<Vec<(PathBuf, BlockHash)>> = Mutex::new(Vec::new());
static NEXT_SCRATCH: AtomicUsize = AtomicUsize::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new(database: &Path) -> Result<Self, String> {
        let parent = database.join("recovery");
        fs::create_dir_all(&parent)
            .map_err(|error| format!("create recovery directory: {error}"))?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos();
        let path = parent.join(format!(
            "scratch-{}-{timestamp}-{}",
            std::process::id(),
            NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).map_err(|error| format!("create scratch database: {error}"))?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        crate::storage::release_cached_database(&self.0);
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("recovery: scratch cleanup failed: {error}");
        }
    }
}

pub(super) fn recover_branch<I>(
    database: &Path,
    captured: Arc<Ledger>,
    sync: HeaderSyncResult,
    mut blocks: I,
) -> Result<usize, String>
where
    I: Iterator<Item = Result<Block, String>>,
{
    let _flight = RECOVERY
        .try_lock()
        .map_err(|_| "recovery deferred: another recovery is active")?;
    {
        let invalid = INVALID_CANDIDATES
            .lock()
            .map_err(|_| "recovery history lock is poisoned")?;
        if sync.headers.iter().any(|header| {
            header.hash().ok().is_some_and(|hash| {
                invalid
                    .iter()
                    .any(|(path, known)| path == database && *known == hash)
            })
        }) {
            return Err("invalid recovery candidate was already validated".into());
        }
    }
    let checkpoints = build_header_state_checkpoints(&captured)?.0;
    let ancestor_state =
        ledger_header_state_at_height(&captured, &checkpoints, sync.ancestor_height)?;
    let mut pow_memory = new_pow_memory();
    let verified = kernel::consensus::advance_header_validation_state_with_memory(
        &ancestor_state,
        &sync.headers,
        &mut pow_memory,
    )
    .map_err(map_peer_header_error)?;
    let tip = verified.header.hash().map_err(|error| error.to_string())?;
    if verified.cumulative_work != sync.peer_work || verified.cumulative_weight != sync.peer_weight
    {
        return Err("recovery candidate work does not match validated headers".into());
    }
    if !super::chain_minimums::allows(
        database,
        verified.cumulative_work,
        verified.cumulative_weight,
    )? {
        return Ok(0);
    }
    let scratch = Scratch::new(database)?;
    // Snapshots are local caches. An unusable cache falls back to full genesis replay.
    let restored = crate::snapshot::load_streamed_through(
        database,
        BODY_CACHE_BYTES,
        BODY_CACHE_BLOCKS,
        sync.ancestor_height.0,
    )
    .unwrap_or_else(|error| {
        eprintln!("recovery: local snapshot unavailable, replaying genesis: {error}");
        None
    });
    let (mut staged, next) = restored.unwrap_or_else(|| {
        (
            Ledger::new().with_applications(extension::SystemApplications),
            0,
        )
    });
    for (height, header) in staged.chain.headers() {
        if captured.chain.header(height) != Some(header) {
            return Err("recovery deferred: local snapshot branch changed".into());
        }
    }
    let mut reader = crate::storage::CanonicalBodyReader::new(database)?;
    for value in 0..=sync.ancestor_height.0 {
        let bytes = reader.next().ok_or("recovery local body is missing")??;
        let height = Height(value);
        let header = captured
            .chain
            .header(&height)
            .ok_or("recovery prefix header is missing")?;
        let block = decode_pinned_local_body(height, header, &bytes)?;
        if value >= next {
            if value == 0 {
                kernel::consensus::apply_genesis(&mut staged, block.clone(), EXPECTED_GENESIS_HASH)
                    .map_err(|error| format!("recovery genesis: {error}"))?;
            } else {
                kernel::consensus::apply_block_with_pow_memory(
                    &mut staged,
                    block.clone(),
                    &mut pow_memory,
                )
                .map_err(|error| format!("recovery local replay: {error}"))?;
            }
        }
        super::journal::copy_receipt(database, &scratch.0, &captured, &block)?;
        persist_block_and_pending(&scratch.0, &block, &[])?;
        super::journal::prune_journals(&scratch.0, &mut staged)?;
        trim_body_cache(&mut staged)?;
    }
    drop(reader);
    if staged.tip_hash() != Some(sync.ancestor_hash) {
        return Err("recovery prefix does not reach common ancestor".into());
    }
    let mut included = BTreeSet::new();
    for expected in &sync.headers {
        let block = blocks
            .next()
            .ok_or("recovery candidate body is missing")??;
        if block.height() != expected.height || block.header != expected.header {
            return Err("recovery body does not match validated header".into());
        }
        for operation in block.operations() {
            included.insert(
                operation
                    .id()
                    .map_err(|error| error.to_string())?
                    .into_bytes(),
            );
        }
        // An uncommitted/corrupt body must not poison the cache for an honest header.
        block
            .validate_structure()
            .map_err(|error| format!("invalid recovery body: {error}"))?;
        if let Err(error) = kernel::consensus::apply_block_with_pow_memory(
            &mut staged,
            block.clone(),
            &mut pow_memory,
        ) {
            let mut invalid = INVALID_CANDIDATES
                .lock()
                .map_err(|_| "recovery history lock is poisoned")?;
            if invalid.len() >= 64 {
                invalid.remove(0);
            }
            invalid.push((
                database.to_path_buf(),
                block.hash().map_err(|error| error.to_string())?,
            ));
            return Err(format!("invalid recovery candidate block: {error}"));
        }
        persist_block_and_pending(&scratch.0, &block, &[])?;
        super::journal::prune_journals(&scratch.0, &mut staged)?;
        trim_body_cache(&mut staged)?;
    }
    if blocks.next().is_some() || staged.tip_hash() != Some(tip) {
        return Err("recovery candidate does not reach validated tip".into());
    }
    drop(pow_memory);
    // Persist the fully validated execution state in the isolated database too.
    crate::snapshot::write(&scratch.0, &staged)?;
    let checkpoint = crate::storage::snapshots_descending(&scratch.0)?
        .into_iter()
        .next()
        .ok_or("scratch state snapshot is missing")?;
    let _mutation = state_mutation_lock()?
        .lock()
        .map_err(|_| "state mutation lock is poisoned")?;
    let (active, _, work, weight) = load_or_initialize_header_snapshot(database)?;
    // A concurrent append is safe: compare against its fresh work below. Only a
    // change below the planned fork invalidates the captured replay prefix.
    if active
        .chain
        .header(&sync.ancestor_height)
        .and_then(|header| header.hash().ok())
        != Some(sync.ancestor_hash)
    {
        return Err("recovery deferred: fork ancestor changed during replay".into());
    }
    let active_height = active.tip_height().ok_or("active tip is missing")?;
    if active.state_root().map_err(|error| error.to_string())?
        != active
            .chain
            .header(&active_height)
            .ok_or("active tip header is missing")?
            .state_root
    {
        return Err("active state root does not match canonical tip during recovery".into());
    }
    if !compare_chain_tips(
        verified.cumulative_work,
        verified.cumulative_weight,
        tip,
        work,
        weight,
        active.tip_hash().ok_or("active tip is missing")?,
    )
    .is_gt()
    {
        return Ok(0);
    }
    let mut pending = Vec::new();
    for (height, _) in active
        .chain
        .headers()
        .filter(|(height, _)| **height > sync.ancestor_height)
    {
        pending.extend(
            canonical_block(database, &active, *height)?
                .operations()
                .iter()
                .cloned(),
        );
    }
    pending.extend(read_pending_operations(database)?);
    let pending = reconcile_pending_operations(&staged, pending, &included);
    // redb publishes bodies, indexes and pending operations in one transaction.
    // The in-memory state becomes visible only after that transaction succeeds.
    persist_chain_and_pending_from_store_with_snapshot(
        database,
        &scratch.0,
        &staged,
        &pending,
        Some((checkpoint.0, &checkpoint.1)),
    )?;
    update_ledger_cache(database, staged)?;
    notify_gossip();
    println!(
        "recovery: committed fork_height={} applied_blocks={}",
        sync.ancestor_height.0,
        sync.headers.len()
    );
    Ok(sync.headers.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_single_flight_defers_without_consuming_bodies() {
        let _test = RECOVERY_TEST_LOCK.lock().unwrap();
        let _flight = RECOVERY.lock().unwrap();
        let ledger = Arc::new(kernel::genesis::genesis_ledger().unwrap());
        let sync = HeaderSyncResult {
            ancestor_height: Height(0),
            ancestor_hash: EXPECTED_GENESIS_HASH,
            headers: vec![],
            peer_work: Work::MAX,
            peer_weight: 0,
            preferred: true,
        };
        let bodies = std::iter::from_fn(|| -> Option<Result<Block, String>> {
            panic!("busy recovery must not consume candidate bodies")
        });
        assert!(
            recover_branch(Path::new("unused-busy-recovery"), ledger, sync, bodies)
                .unwrap_err()
                .contains("another recovery is active")
        );
    }
}
