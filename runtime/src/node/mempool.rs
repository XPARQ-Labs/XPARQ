use super::*;
use super::{config::*, gossip::*, state::*};
use kernel::operation::{AuthorizedDeployProgram, BlockOperation};
use std::collections::BTreeMap;

#[derive(Clone)]
struct PendingEntry {
    operation: BlockOperation,
    bytes: Vec<u8>,
    id: [u8; 32],
    relay_size: usize,
}
impl PendingEntry {
    fn new(operation: BlockOperation) -> Result<Self, String> {
        let bytes = canonical_bytes(&operation).map_err(|error| error.to_string())?;
        let id = kernel::crypto::domain(kernel::crypto::HashDomain::Operation, &bytes).into_bytes();
        let relay_size = match &operation {
            BlockOperation::ProgramCall(call) => {
                // Both envelopes use one u8 tag, but their tag values and IDs differ.
                // Count the actual legacy envelope without cloning its payload.
                #[derive(borsh::BorshSerialize)]
                enum LegacyRef<'a> {
                    Program(&'a kernel::program::AuthorizedProgramInvocation),
                }
                usize::try_from(
                    kernel::crypto::canonical_length(&LegacyRef::Program(call))
                        .map_err(|error| error.to_string())?,
                )
                .map_err(|_| "relay size overflow")?
            }
            BlockOperation::DeployProgram(_) => bytes.len(),
        };
        Ok(Self {
            operation,
            bytes,
            id,
            relay_size,
        })
    }
}
#[derive(Clone, Default)]
struct PendingPool {
    entries: Vec<Arc<PendingEntry>>,
    ids: BTreeSet<[u8; 32]>,
    total_bytes: u64,
    fingerprint: [u8; 32],
    validated: Option<ValidatedPendingState>,
}
type PendingAnchor = (Option<kernel::crypto::BlockHash>, kernel::crypto::StateRoot);
#[derive(Clone)]
struct ValidatedPendingState {
    anchor: PendingAnchor,
    state: kernel::ledger::LedgerState,
}
type RejectionKey = (PendingAnchor, [u8; 32], [u8; 32]);
#[derive(Default)]
struct Rejections {
    errors: BTreeMap<RejectionKey, String>,
    order: std::collections::VecDeque<RejectionKey>,
}
impl Rejections {
    fn insert(&mut self, key: RejectionKey, error: String) {
        const CAPACITY: usize = 256;
        if self.errors.contains_key(&key) {
            return;
        }
        if self.order.len() == CAPACITY {
            self.errors.remove(&self.order.pop_front().unwrap());
        }
        self.order.push_back(key);
        self.errors.insert(key, error);
    }
}
static REJECTIONS: OnceLock<Mutex<Rejections>> = OnceLock::new();
fn rejections() -> &'static Mutex<Rejections> {
    REJECTIONS.get_or_init(|| Mutex::new(Rejections::default()))
}
impl PendingPool {
    fn push(&mut self, entry: Arc<PendingEntry>) -> Result<(), String> {
        if self.ids.contains(&entry.id) {
            return Err("duplicate pending operation".into());
        }
        let total = self
            .total_bytes
            .checked_add(entry.bytes.len() as u64)
            .ok_or("mempool size overflow")?;
        if total > MAX_STORED_MEMPOOL_SIZE || self.entries.len() >= MAX_MEMPOOL_TRANSACTIONS {
            return Err("mempool exceeds persistence limit".into());
        }
        self.total_bytes = total;
        self.ids.insert(entry.id);
        let mut fingerprint_input = [0; 64];
        fingerprint_input[..32].copy_from_slice(&self.fingerprint);
        fingerprint_input[32..].copy_from_slice(&entry.id);
        self.fingerprint = kernel::crypto::hash_bytes(&fingerprint_input).into_bytes();
        self.validated = None;
        self.entries.push(entry);
        Ok(())
    }
    fn matches(&self, bytes: &[Vec<u8>]) -> bool {
        self.entries.len() == bytes.len()
            && self
                .entries
                .iter()
                .zip(bytes)
                .all(|(entry, raw)| entry.bytes == *raw)
    }
}
static PENDING_CACHE: OnceLock<Mutex<Option<(std::path::PathBuf, Arc<PendingPool>)>>> =
    OnceLock::new();
fn pending_cache() -> &'static Mutex<Option<(std::path::PathBuf, Arc<PendingPool>)>> {
    PENDING_CACHE.get_or_init(|| Mutex::new(None))
}
fn publish_pending(path: &Path, pending: Arc<PendingPool>) {
    *pending_cache()
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some((path.to_path_buf(), pending));
}
fn load_pending_pool(path: &Path) -> Result<Arc<PendingPool>, String> {
    // Compare exact committed bytes on every read, including writes outside node helpers.
    let raw = crate::storage::read_mempool(path)?;
    let total = raw
        .iter()
        .try_fold(0u64, |sum, bytes| sum.checked_add(bytes.len() as u64))
        .ok_or("stored mempool size overflow")?;
    if total > MAX_STORED_MEMPOOL_SIZE || raw.len() > MAX_MEMPOOL_TRANSACTIONS {
        return Err("stored mempool exceeds limit".into());
    }
    {
        let cache = pending_cache()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some((database, pending)) = cache.as_ref() {
            if database == path && pending.matches(&raw) {
                return Ok(Arc::clone(pending));
            }
        }
    }
    let mut pool = PendingPool::default();
    for bytes in &raw {
        if bytes.is_empty() || bytes.len() > kernel::block::MAX_OPERATION_SIZE {
            return Err("stored operation size is outside allowed range".into());
        }
        let operation = canonical_decode(bytes)
            .map_err(|error| format!("decode pending operation: {error}"))?;
        pool.push(Arc::new(PendingEntry::new(operation)?))?;
    }
    let pool = Arc::new(pool);
    // Do not change historical decoding behavior for a noncanonical input encoding.
    if pool.matches(&raw) {
        publish_pending(path, Arc::clone(&pool));
    }
    Ok(pool)
}

pub(super) fn submit_deploy(path: Option<&str>, encoded: &str) -> Result<(), String> {
    if encoded.is_empty() || encoded.len() > 2 * kernel::block::MAX_OPERATION_SIZE {
        return Err("deploy size is outside allowed range".into());
    }
    let database = database_path(path);
    let bytes = hex::decode(encoded).map_err(|error| format!("invalid deploy hex: {error}"))?;
    let deploy: AuthorizedDeployProgram =
        canonical_decode(&bytes).map_err(|error| format!("invalid deploy: {error}"))?;
    let id = insert_pending_operation(
        &database,
        BlockOperation::DeployProgram(Box::new(deploy)),
        false,
    )?;
    println!("accepted deploy_operation={}", hex::encode(id));
    Ok(())
}

pub(super) fn insert_pending_operation(
    database: &Path,
    operation: BlockOperation,
    duplicate_is_ok: bool,
) -> Result<[u8; 32], String> {
    static ADMISSION: super::admission::AdmissionGate = super::admission::AdmissionGate::new(2);
    let _permit = ADMISSION.enter()?;
    operation
        .validate_structure()
        .map_err(|error| format!("invalid operation: {error:?}"))?;
    let entry = Arc::new(PendingEntry::new(operation)?);
    if entry.bytes.len() > kernel::block::MAX_OPERATION_SIZE {
        return Err("operation exceeds block size limit".into());
    }
    validate_relay_entry(&entry)?;
    let _mutation = state_mutation_lock()?
        .lock()
        .map_err(|_| "state mutation lock is poisoned")?;
    let ledger = load_or_initialize(database)?;
    let current = load_pending_pool(database)?;
    let id = entry.id;
    if current.ids.contains(&id) {
        return if duplicate_is_ok {
            Ok(id)
        } else {
            Err("operation is already in mempool".into())
        };
    }
    let anchor = (
        ledger.tip_hash(),
        ledger.state_root().map_err(|error| error.to_string())?,
    );
    let rejection_key = (anchor, current.fingerprint, id);
    if let Some(error) = rejections()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .errors
        .get(&rejection_key)
    {
        return Err(error.clone());
    }
    let pending = match extend_pending_pool(&ledger, &current, entry, anchor) {
        Ok(pending) => pending,
        Err(error) => {
            rejections()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(rejection_key, error.clone());
            return Err(error);
        }
    };
    let slices: Vec<&[u8]> = pending
        .entries
        .iter()
        .map(|entry| entry.bytes.as_slice())
        .collect();
    crate::storage::replace_mempool_slices(database, &slices)?;
    // Publish only after the complete database transaction commits.
    publish_pending(database, Arc::new(pending));
    notify_gossip();
    Ok(id)
}

fn extend_pending_pool(
    ledger: &Ledger,
    current: &PendingPool,
    entry: Arc<PendingEntry>,
    anchor: PendingAnchor,
) -> Result<PendingPool, String> {
    let mut pending = current.clone();
    // Check pool limits before any cryptographic work; push invalidates only
    // the new private copy, leaving the accepted prefix/cache untouched.
    pending.push(Arc::clone(&entry))?;
    let mut state =
        if let Some(validated) = current.validated.as_ref().filter(|v| v.anchor == anchor) {
            validated.state.clone()
        } else {
            replay_pending_pool(ledger, current)?
        };
    let chain = kernel::genesis::chain_context().map_err(|error| error.to_string())?;
    let height = Height(ledger.tip_height().map_or(0, |h| h.0.saturating_add(1)));
    apply_pending_operation(&mut state, &entry.operation, chain, height)?;
    pending.validated = Some(ValidatedPendingState { anchor, state });
    Ok(pending)
}

fn apply_pending_operation(
    state: &mut kernel::ledger::LedgerState,
    operation: &BlockOperation,
    chain: kernel::common::ChainContext,
    height: Height,
) -> Result<(), String> {
    match operation {
        BlockOperation::ProgramCall(call) => {
            state
                .apply_program_call_with_applications(
                    (**call).clone(),
                    ProgramId::ZERO,
                    chain,
                    height.0,
                    &extension::SystemApplications,
                )
                .map_err(|error| format!("invalid program call: {error}"))?;
        }
        BlockOperation::DeployProgram(deploy) => {
            state
                .apply_deploy_with_applications(
                    (**deploy).clone(),
                    ProgramId::ZERO,
                    chain,
                    height,
                    &extension::SystemApplications,
                )
                .map_err(|error| format!("invalid deploy: {error}"))?;
        }
    }
    Ok(())
}

fn pending_relay_size(operation: &BlockOperation) -> Result<usize, String> {
    match operation {
        BlockOperation::ProgramCall(call) => {
            let legacy = AuthorizedProgramEnvelope::Program(call.clone());
            let size = canonical_bytes(&legacy)
                .map_err(|error| error.to_string())?
                .len();
            if size > MAX_STORED_TRANSACTION_SIZE {
                return Err("program call exceeds transaction size limit".into());
            }
            Ok(size)
        }
        BlockOperation::DeployProgram(_) => Ok(canonical_bytes(operation)
            .map_err(|error| error.to_string())?
            .len()),
    }
}

pub(super) fn validate_pending_operations(
    ledger: &Ledger,
    operations: &[BlockOperation],
) -> Result<(), String> {
    if operations.len() > MAX_MEMPOOL_TRANSACTIONS {
        return Err("mempool operation count exceeds limit".into());
    }
    let cached = pending_cache()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
        .map(|(_, pool)| Arc::clone(pool));
    let mut pending = PendingPool::default();
    for (index, operation) in operations.iter().enumerate() {
        let reusable = cached
            .as_ref()
            .and_then(|pool| pool.entries.get(index))
            .filter(|entry| entry.operation == *operation);
        let entry = if let Some(entry) = reusable {
            Arc::clone(entry)
        } else {
            Arc::new(PendingEntry::new(operation.clone())?)
        };
        pending.push(entry)?;
    }
    validate_pending_pool(ledger, &pending)
}

fn validate_pending_pool(ledger: &Ledger, pending: &PendingPool) -> Result<(), String> {
    replay_pending_pool(ledger, pending).map(|_| ())
}

fn validate_relay_entry(entry: &PendingEntry) -> Result<(), String> {
    if entry.bytes.len() > kernel::block::MAX_OPERATION_SIZE {
        return Err("operation cannot fit in a block".into());
    }
    let fee = match &entry.operation {
        BlockOperation::ProgramCall(call) => call.payment.charges.miner_fee.as_zeno(),
        BlockOperation::DeployProgram(deploy) => deploy.payment.charges.miner_fee.as_zeno(),
    };
    if matches!(entry.operation, BlockOperation::ProgramCall(_))
        && entry.relay_size > MAX_STORED_TRANSACTION_SIZE
    {
        return Err("program call exceeds transaction size limit".into());
    }
    if fee < minimum_relay_fee(entry.relay_size)? {
        return Err("operation relay fee is too low".into());
    }
    Ok(())
}

fn replay_pending_pool(
    ledger: &Ledger,
    pending: &PendingPool,
) -> Result<kernel::ledger::LedgerState, String> {
    let chain = kernel::genesis::chain_context().map_err(|error| error.to_string())?;
    let height = Height(ledger.tip_height().map_or(0, |h| h.0.saturating_add(1)));
    let mut state = ledger.state().clone();
    for entry in &pending.entries {
        validate_relay_entry(entry)?;
        apply_pending_operation(&mut state, &entry.operation, chain, height)?;
    }
    Ok(state)
}

pub(super) fn read_pending_operations(path: &Path) -> Result<Vec<BlockOperation>, String> {
    Ok(load_pending_pool(path)?
        .entries
        .iter()
        .map(|entry| entry.operation.clone())
        .collect())
}

pub(super) fn write_pending_operations(
    path: &Path,
    pending: &[BlockOperation],
) -> Result<(), String> {
    let encoded = encode_pending_operations(pending)?;
    crate::storage::replace_mempool(path, &encoded)
}

pub(super) fn encode_pending_operations(
    pending: &[BlockOperation],
) -> Result<Vec<Vec<u8>>, String> {
    let encoded = pending
        .iter()
        .map(|operation| canonical_bytes(operation).map_err(|error| error.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let total = encoded
        .iter()
        .try_fold(0u64, |sum, bytes| sum.checked_add(bytes.len() as u64))
        .ok_or("mempool size overflow")?;
    if total > MAX_STORED_MEMPOOL_SIZE || pending.len() > MAX_MEMPOOL_TRANSACTIONS {
        return Err("mempool exceeds persistence limit".into());
    }
    Ok(encoded)
}

pub(super) fn reconcile_pending_operations(
    ledger: &Ledger,
    pending: Vec<BlockOperation>,
    included: &BTreeSet<[u8; 32]>,
) -> Vec<BlockOperation> {
    let Ok(chain) = kernel::genesis::chain_context() else {
        return Vec::new();
    };
    let height = Height(ledger.tip_height().map_or(0, |h| h.0.saturating_add(1)));
    let mut state = ledger.state().clone();
    let mut retained = Vec::new();
    let mut seen = BTreeSet::new();
    for operation in pending {
        if retained.len() >= MAX_MEMPOOL_TRANSACTIONS {
            break;
        }
        let Ok(id) = operation.id() else {
            continue;
        };
        if included.contains(&id.into_bytes()) || !seen.insert(id.into_bytes()) {
            continue;
        }
        let Ok(bytes) = canonical_bytes(&operation) else {
            continue;
        };
        if bytes.len() > kernel::block::MAX_OPERATION_SIZE {
            continue;
        }
        let fee = match &operation {
            BlockOperation::ProgramCall(call) => call.payment.charges.miner_fee.as_zeno(),
            BlockOperation::DeployProgram(deploy) => deploy.payment.charges.miner_fee.as_zeno(),
        };
        if pending_relay_size(&operation)
            .and_then(minimum_relay_fee)
            .map_or(true, |minimum| fee < minimum)
        {
            continue;
        }
        if apply_pending_operation(&mut state, &operation, chain, height).is_err() {
            continue;
        }
        retained.push(operation);
    }
    retained
}

pub(super) fn submit_transaction(path: Option<&str>, encoded: &str) -> Result<(), String> {
    if encoded.is_empty() || encoded.len() > 2 * MAX_STORED_TRANSACTION_SIZE {
        return Err("transaction size is outside allowed range".into());
    }
    let database = database_path(path);
    let bytes =
        hex::decode(encoded).map_err(|error| format!("invalid transaction hex: {error}"))?;
    if bytes.is_empty() || bytes.len() > MAX_STORED_TRANSACTION_SIZE {
        return Err("transaction size is outside allowed range".into());
    }
    let transaction: Transaction =
        canonical_decode(&bytes).map_err(|error| format!("invalid transaction: {error}"))?;
    let hash = insert_mempool_transaction(&database, transaction, false)?;
    println!("accepted transaction={}", hex::encode(hash));
    Ok(())
}

pub(super) fn print_mempool(path: Option<&str>) -> Result<(), String> {
    let database = database_path(path);
    let pending = read_pending_operations(&database)?;
    println!("operations: {}", pending.len());
    for operation in pending {
        println!(
            "{}",
            hex::encode(
                operation
                    .id()
                    .map_err(|error| error.to_string())?
                    .into_bytes()
            )
        );
    }
    Ok(())
}

pub(super) fn accept_relayed_transaction(database: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > MAX_STORED_TRANSACTION_SIZE {
        return Err("relayed transaction size is outside allowed range".into());
    }
    let transaction: Transaction =
        canonical_decode(bytes).map_err(|error| format!("invalid relayed transaction: {error}"))?;
    insert_mempool_transaction(database, transaction, true).map(|_| ())
}

pub(super) fn insert_mempool_transaction(
    database: &Path,
    transaction: Transaction,
    duplicate_is_ok: bool,
) -> Result<[u8; 32], String> {
    let encoded = canonical_bytes(&transaction).map_err(|error| error.to_string())?;
    if encoded.len() > MAX_STORED_TRANSACTION_SIZE {
        return Err("transaction exceeds consensus size limit".into());
    }
    transaction
        .validate_structure()
        .map_err(|error| error.to_string())?;
    let hash = transaction.id().map_err(|error| error.to_string())?;
    insert_pending_operation(database, BlockOperation::from(transaction), duplicate_is_ok)?;
    Ok(hash)
}

pub(super) fn reserved_coin_inputs(
    operations: &[BlockOperation],
) -> BTreeSet<kernel::monetary::coin::CoinShare> {
    operations
        .iter()
        .flat_map(|operation| match operation {
            BlockOperation::ProgramCall(call) => call.payment.coin_parts(),
            BlockOperation::DeployProgram(deploy) => deploy.payment.coin_parts(),
        })
        .flat_map(|(inputs, _)| inputs.iter().copied())
        .collect()
}

pub(super) fn minimum_relay_fee(encoded_size: usize) -> Result<u64, String> {
    u64::try_from(encoded_size)
        .ok()
        .and_then(|size| size.checked_mul(MIN_RELAY_FEE_ZENO_PER_BYTE))
        .ok_or("minimum relay fee overflow".into())
}

pub(super) fn read_mempool(path: &Path) -> Result<Vec<Transaction>, String> {
    Ok(read_pending_operations(path)?
        .into_iter()
        .filter_map(|operation| match operation {
            BlockOperation::ProgramCall(call) => Some(AuthorizedProgramEnvelope::Program(call)),
            BlockOperation::DeployProgram(_) => None,
        })
        .collect())
}

/// Legacy program-call view for explorer and transaction RPC consumers.
pub(super) fn block_program_transactions(block: &Block) -> impl Iterator<Item = Transaction> + '_ {
    block.operations().iter().filter_map(|operation| {
        operation
            .as_program_call()
            .map(|call| AuthorizedProgramEnvelope::Program(Box::new(call.clone())))
    })
}

pub(super) fn persist_block_and_mempool(
    path: &Path,
    block: &Block,
    mempool: &[Transaction],
) -> Result<(), String> {
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
    let mut pending = read_pending_operations(path)?
        .into_iter()
        .filter(|operation| matches!(operation, BlockOperation::DeployProgram(_)))
        .filter(|operation| {
            operation
                .id()
                .is_ok_and(|id| !included.contains(&id.into_bytes()))
        })
        .collect::<Vec<_>>();
    pending.extend(mempool.iter().cloned().map(BlockOperation::from));
    persist_block_and_pending(path, block, &pending)
}

pub(super) fn persist_block_and_pending(
    path: &Path,
    block: &Block,
    pending: &[BlockOperation],
) -> Result<(), String> {
    let stored = crate::storage::StoredCanonicalBlock {
        height: block.height().0,

        hash: block.hash().map_err(|error| error.to_string())?.0,

        bytes: block_bytes(block).map_err(|error| error.to_string())?,

        transactions: block_program_transactions(block)
            .map(|transaction| transaction.id().map_err(|error| error.to_string()))
            .collect::<Result<Vec<_>, _>>()?,

        activities: super::index::stored_program_activities(block)?,
    };

    crate::storage::append_block_and_replace_mempool(
        path,
        &stored,
        &encode_pending_operations(pending)?,
    )
}

pub(super) fn persist_chain_and_pending(
    path: &Path,
    ledger: &Ledger,
    pending: &[BlockOperation],
) -> Result<(), String> {
    persist_chain_and_pending_from_store(path, path, ledger, pending)
}

pub(super) fn persist_chain_and_pending_from_store(
    path: &Path,
    source: &Path,
    ledger: &Ledger,
    pending: &[BlockOperation],
) -> Result<(), String> {
    persist_chain_and_pending_from_store_with_snapshot(path, source, ledger, pending, None)
}

pub(super) fn persist_chain_and_pending_from_store_with_snapshot(
    path: &Path,
    source: &Path,
    ledger: &Ledger,
    pending: &[BlockOperation],
    snapshot: Option<(u64, &[u8])>,
) -> Result<(), String> {
    if source != path {
        for (height, _) in ledger.chain.headers() {
            let block = canonical_block(source, ledger, *height)?;
            super::journal::copy_receipt(source, path, ledger, &block)?;
        }
    }
    let blocks = || {
        ledger.chain.headers().map(|(height, _)| {
            let block = canonical_block(source, ledger, *height)?;
            Ok(crate::storage::StoredCanonicalBlock {
                height: block.height().0,
                hash: block.hash().map_err(|error| error.to_string())?.0,
                bytes: block_bytes(&block).map_err(|error| error.to_string())?,
                transactions: block_program_transactions(&block)
                    .map(|transaction| transaction.id().map_err(|error| error.to_string()))
                    .collect::<Result<Vec<_>, String>>()?,
                activities: super::index::stored_program_activities(&block)?,
            })
        })
    };
    let pending = encode_pending_operations(pending)?;
    match snapshot {
        Some(snapshot) => crate::storage::replace_blocks_mempool_and_snapshot_stream(
            path,
            blocks,
            &pending,
            Some(snapshot),
        ),
        None => crate::storage::replace_blocks_and_mempool_stream(path, blocks, &pending),
    }
}

#[cfg(test)]
mod serialization_benchmarks {
    use super::*;

    #[test]
    #[ignore = "manual CPU comparison; run release with --nocapture --test-threads=1"]
    fn benchmark_pending_prefix_validation() {
        use std::{hint::black_box, time::Instant};
        let (ledger, key, input, amount) = funded_cache_fixture();
        let anchor = (ledger.tip_hash(), ledger.state_root().unwrap());
        let owner = kernel::crypto::program_id_from_public_key(&key.public_key()).unwrap();
        let mut prefix = PendingPool::default();
        let mut share = input;
        let mut value = amount;
        println!("prefix,full_replay_ms,cached_advance_ms");
        for length in 0..=128 {
            let entry = funded_call(&key, share, value);
            let next = extend_pending_pool(&ledger, &prefix, Arc::clone(&entry), anchor).unwrap();
            if [0, 16, 64, 128].contains(&length) {
                let mut full = Vec::new();
                let mut cached = Vec::new();
                for sample in 0..=5 {
                    let start = Instant::now();
                    let replayed =
                        replay_pending_pool(black_box(&ledger), black_box(&next)).unwrap();
                    let replay_ms = start.elapsed().as_secs_f64() * 1000.;
                    let start = Instant::now();
                    let advanced = extend_pending_pool(
                        black_box(&ledger),
                        black_box(&prefix),
                        Arc::clone(black_box(&entry)),
                        anchor,
                    )
                    .unwrap();
                    let advance_ms = start.elapsed().as_secs_f64() * 1000.;
                    assert_eq!(replayed, advanced.validated.as_ref().unwrap().state);
                    if sample != 0 {
                        full.push(replay_ms);
                        cached.push(advance_ms);
                    }
                }
                full.sort_by(f64::total_cmp);
                cached.sort_by(f64::total_cmp);
                println!("{length},{:.6},{:.6}", full[2], cached[2]);
            }
            prefix = next;
            let (id, coin) = prefix
                .validated
                .as_ref()
                .unwrap()
                .state
                .utxos
                .coins_by_owner(kernel::common::Owner::Program(owner))
                .next()
                .unwrap();
            share = id;
            value = coin.amount.as_zeno();
        }
    }

    fn mine_cache_emission(ledger: &Ledger, miner: ProgramId) -> Block {
        let mut block =
            super::super::mining::candidate_operation_block(ledger, miner, vec![]).unwrap();
        let mut memory = new_pow_memory();
        assert!(
            crate::miner::mine_range(
                &mut block,
                crate::miner::MiningRange {
                    start_nonce: 0,
                    attempts: 1000
                },
                &mut memory
            )
            .unwrap()
            .is_some()
        );
        block
    }

    fn funded_cache_fixture() -> (
        Ledger,
        kernel::crypto::SigningSeed,
        kernel::monetary::coin::CoinShare,
        u64,
    ) {
        let key = kernel::crypto::SigningSeed::new(
            kernel::crypto::AccountSignatureScheme::MlDsa44,
            Box::new([0x63; 32]),
        );
        let owner = kernel::crypto::program_id_from_public_key(&key.public_key()).unwrap();
        let mut ledger = kernel::genesis::genesis_ledger()
            .unwrap()
            .with_applications(extension::SystemApplications);
        let block = mine_cache_emission(&ledger, owner);
        kernel::consensus::apply_block(&mut ledger, block).unwrap();
        let (share, coin) = ledger
            .state
            .utxos
            .coins_by_owner(kernel::common::Owner::Program(owner))
            .next()
            .unwrap();
        let amount = coin.amount.as_zeno();
        (ledger, key, share, amount)
    }

    fn funded_call(
        key: &kernel::crypto::SigningSeed,
        input: kernel::monetary::coin::CoinShare,
        amount: u64,
    ) -> Arc<PendingEntry> {
        use kernel::program::{
            AccountAuthorization, AuthorizedProgramInvocation, CoinCharges, CoinTransition,
        };
        let public_key = key.public_key();
        let signer = kernel::crypto::program_id_from_public_key(&public_key).unwrap();
        let mut tx = AuthorizedProgramInvocation {
            signer,
            call: kernel::program::system::coin_program::transfer_call(),
            payment: CoinTransition::coin_with_charges(
                signer,
                vec![input],
                vec![CoinOutput::new(signer, Zeno::ONE)],
                CoinCharges::new(Zeno::from_zeno(1_000_000)),
            )
            .unwrap(),
            authorization: AccountAuthorization {
                salt: [0; 32],
                public_key,
                signature: kernel::crypto::AccountSignature {
                    account: key.scheme(),
                    bytes: vec![0; key.scheme().signature_size()],
                },
            },
        };
        let size = kernel::crypto::canonical_length(
            &kernel::operation::BlockOperationRef::ProgramCall(&tx),
        )
        .unwrap();
        let burn = kernel::consensus::ProtocolBurn::for_program_call(
            kernel::consensus::StateTransitionWeight {
                created_coin_utxos: 2,
                consumed_coin_utxos: 1,
                created_state_weight: 0,
            },
            size,
        )
        .unwrap()
        .total()
        .unwrap()
        .as_zeno();
        tx.payment = CoinTransition::coin_with_charges(
            signer,
            vec![input],
            vec![CoinOutput::new(
                signer,
                Zeno::from_zeno(amount - 1_000_000 - burn),
            )],
            CoinCharges::new(Zeno::from_zeno(1_000_000)),
        )
        .unwrap();
        let commitment = kernel::program::program_invocation_commitment(
            signer,
            &tx.call,
            &tx.payment,
            kernel::genesis::chain_context().unwrap(),
        )
        .unwrap();
        tx.authorization.signature = key.sign(commitment.as_bytes());
        Arc::new(PendingEntry::new(BlockOperation::ProgramCall(Box::new(tx))).unwrap())
    }

    #[test]
    fn staged_prefix_accepts_children_rejects_double_spends_and_invalidates_on_state_change() {
        let (mut ledger, key, input, amount) = funded_cache_fixture();
        let anchor = (ledger.tip_hash(), ledger.state_root().unwrap());
        let first = funded_call(&key, input, amount);
        let initial = extend_pending_pool(&ledger, &PendingPool::default(), first, anchor).unwrap();
        let before = initial.validated.as_ref().unwrap().state.clone();
        let owner = kernel::crypto::program_id_from_public_key(&key.public_key()).unwrap();
        let (child_input, child_coin) = before
            .utxos
            .coins_by_owner(kernel::common::Owner::Program(owner))
            .next()
            .unwrap();
        let child = funded_call(&key, child_input, child_coin.amount.as_zeno());
        let next = extend_pending_pool(&ledger, &initial, Arc::clone(&child), anchor).unwrap();
        assert_eq!(
            next.validated.as_ref().unwrap().state,
            replay_pending_pool(&ledger, &next).unwrap()
        );
        // A conflicting spend and a forged child cannot mutate the accepted prefix.
        let mut conflict = funded_call(&key, input, amount).operation.clone();
        let BlockOperation::ProgramCall(tx) = &mut conflict else {
            unreachable!()
        };
        tx.payment.charges.miner_fee = tx.payment.charges.miner_fee.checked_add(Zeno::ONE).unwrap();
        tx.payment.outputs[0].amount = tx.payment.outputs[0].amount.checked_sub(Zeno::ONE).unwrap();
        let commitment = kernel::program::program_invocation_commitment(
            tx.signer,
            &tx.call,
            &tx.payment,
            kernel::genesis::chain_context().unwrap(),
        )
        .unwrap();
        tx.authorization.signature = key.sign(commitment.as_bytes());
        assert!(
            extend_pending_pool(
                &ledger,
                &initial,
                Arc::new(PendingEntry::new(conflict).unwrap()),
                anchor
            )
            .err()
            .unwrap()
            .contains("input UTXO was not found")
        );
        let mut forged = child.operation.clone();
        let BlockOperation::ProgramCall(tx) = &mut forged else {
            unreachable!()
        };
        tx.authorization.signature.bytes[0] ^= 1;
        assert!(
            extend_pending_pool(
                &ledger,
                &initial,
                Arc::new(PendingEntry::new(forged).unwrap()),
                anchor
            )
            .is_err()
        );
        assert_eq!(initial.validated.as_ref().unwrap().state, before);
        // Same tip with changed canonical state must not reuse the old prefix state.
        let previous_chain = ledger.chain.clone();
        let block = mine_cache_emission(&ledger, owner);
        let extra = kernel::monetary::coin::CoinShare::from_emission(
            kernel::consensus::emission_origin(&block)
                .unwrap()
                .as_bytes(),
        );
        kernel::consensus::apply_block(&mut ledger, block).unwrap();
        ledger.chain = previous_chain; // Deliberately keep the tip key fixed to exercise the state-root key.
        let changed_anchor = (ledger.tip_hash(), ledger.state_root().unwrap());
        assert_ne!(anchor, changed_anchor);
        let rebuilt = extend_pending_pool(&ledger, &initial, child, changed_anchor).unwrap();
        assert!(
            rebuilt
                .validated
                .as_ref()
                .unwrap()
                .state
                .utxos
                .coin(&extra)
                .is_some()
        );
        assert_eq!(
            rebuilt.validated.as_ref().unwrap().state,
            replay_pending_pool(&ledger, &rebuilt).unwrap()
        );
    }

    #[test]
    fn rejection_cache_is_bounded_and_keys_include_state_prefix_and_tip() {
        let mut cache = Rejections::default();
        let anchor = (
            Some(kernel::crypto::BlockHash([1; 32])),
            kernel::crypto::StateRoot([2; 32]),
        );
        for i in 0..300u32 {
            let mut id = [0; 32];
            id[..4].copy_from_slice(&i.to_le_bytes());
            cache.insert((anchor, [3; 32], id), "invalid".into());
        }
        assert_eq!(cache.errors.len(), 256);
        assert_eq!(cache.order.len(), 256);
        assert!(!cache.errors.contains_key(&(anchor, [3; 32], [0; 32])));
        let key = *cache.order.back().unwrap();
        assert!(cache.errors.contains_key(&key));
        assert!(!cache.errors.contains_key(&(anchor, [4; 32], key.2)));
        assert!(!cache.errors.contains_key(&(
            (anchor.0, kernel::crypto::StateRoot([4; 32])),
            key.1,
            key.2
        )));
        assert!(!cache.errors.contains_key(&(
            (Some(kernel::crypto::BlockHash([4; 32])), anchor.1),
            key.1,
            key.2
        )));
        cache.insert(key, "same invalid".into());
        assert_eq!(cache.order.len(), 256);
    }

    fn cache_test_database(label: &str) -> std::path::PathBuf {
        let tick = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("xparq-{label}-{}-{tick}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn cache_fixture(nonce: u64) -> BlockOperation {
        use kernel::{
            crypto::{AccountSignatureScheme, SigningSeed, program_id_from_public_key},
            program::{AccountAuthorization, CoinTransition, DeployProgram},
        };
        let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([0x75; 32]));
        let public_key = seed.public_key();
        let owner = program_id_from_public_key(&public_key).unwrap();
        BlockOperation::DeployProgram(Box::new(AuthorizedDeployProgram {
            deploy: DeployProgram {
                owner,
                nonce,
                code: vec![1; 65536].into(),
            },
            payment: CoinTransition::coin(
                owner,
                vec![kernel::monetary::coin::CoinShare::from_bytes([1; 32])],
                vec![kernel::monetary::coin::CoinOutput::new(
                    owner,
                    kernel::monetary::coin::Zeno::ONE,
                )],
            )
            .unwrap(),
            authorization: AccountAuthorization {
                salt: [0; 32],
                public_key,
                signature: seed.sign(b"cache-fixture"),
            },
        }))
    }

    #[test]
    fn cached_call_id_and_relay_size_preserve_distinct_legacy_envelope() {
        let BlockOperation::DeployProgram(signed) = cache_fixture(1) else {
            unreachable!()
        };
        let call = kernel::program::AuthorizedProgramInvocation {
            signer: signed.deploy.owner,
            call: kernel::program::system::script::call::ProgramCall {
                program: kernel::program::system::script::call::SystemProgramId::VM,
                opcode: 0,
                payload: vec![8; 65536],
            },
            payment: signed.payment,
            authorization: signed.authorization,
        };
        let legacy = AuthorizedProgramEnvelope::Program(Box::new(call.clone()));
        let operation = BlockOperation::ProgramCall(Box::new(call));
        let entry = PendingEntry::new(operation.clone()).unwrap();
        assert_eq!(entry.bytes, canonical_bytes(&operation).unwrap());
        assert_eq!(entry.id, operation.id().unwrap().into_bytes());
        assert_eq!(entry.relay_size, canonical_bytes(&legacy).unwrap().len());
        assert_ne!(entry.id, legacy.id().unwrap());
        let mut pool = PendingPool::default();
        pool.push(Arc::new(entry)).unwrap();
        assert!(pool.ids.contains(&operation.id().unwrap().into_bytes()));
        assert!(!pool.ids.contains(&legacy.id().unwrap()));
    }

    #[test]
    fn cached_ids_and_bytes_follow_committed_storage_and_reject_corruption() {
        let path = cache_test_database("pending-cache-source");
        let first = cache_fixture(1);
        let second = cache_fixture(2);
        let a = canonical_bytes(&first).unwrap();
        let b = canonical_bytes(&second).unwrap();
        crate::storage::replace_mempool(&path, &[a.clone()]).unwrap();
        for _ in 0..2 {
            let pool = load_pending_pool(&path).unwrap();
            assert_eq!(pool.entries[0].operation, first);
            assert_eq!(pool.entries[0].bytes, a);
            assert_eq!(pool.entries[0].id, first.id().unwrap().into_bytes());
            assert!(pool.ids.contains(&first.id().unwrap().into_bytes()));
        }
        // Bypass node cache helpers, as can happen during recovery or reorg writes.
        crate::storage::replace_mempool_slices(&path, &[&b, &a]).unwrap();
        let pool = load_pending_pool(&path).unwrap();
        assert_eq!(pool.entries.len(), 2);
        assert_eq!(pool.entries[0].operation, second);
        assert_eq!(pool.entries[1].operation, first);
        assert_eq!(pool.total_bytes, (a.len() + b.len()) as u64);
        crate::storage::replace_mempool(&path, &[vec![255]]).unwrap();
        assert!(load_pending_pool(&path).is_err());
        crate::storage::replace_mempool(&path, &[]).unwrap();
        assert!(load_pending_pool(&path).unwrap().entries.is_empty());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn cached_pending_candidates_are_isolated_until_storage_commit() {
        let path = cache_test_database("pending-cache-uncommitted");
        let first = cache_fixture(3);
        let second = cache_fixture(4);
        write_pending_operations(&path, &[first.clone()]).unwrap();
        let original = load_pending_pool(&path).unwrap();
        let mut candidate = original.as_ref().clone();
        candidate
            .push(Arc::new(PendingEntry::new(second.clone()).unwrap()))
            .unwrap();
        assert_eq!(original.entries.len(), 1);
        assert_eq!(candidate.entries.len(), 2);
        // A failed write cannot publish the candidate; committed bytes remain authoritative.
        let invalid = path.join("not-a-directory");
        fs::write(&invalid, b"file").unwrap();
        let slices: Vec<_> = candidate
            .entries
            .iter()
            .map(|entry| entry.bytes.as_slice())
            .collect();
        assert!(crate::storage::replace_mempool_slices(&invalid, &slices).is_err());
        assert_eq!(load_pending_pool(&path).unwrap().entries.len(), 1);
        assert_eq!(read_pending_operations(&path).unwrap(), vec![first]);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    #[ignore = "manual retained mempool cache benchmark; use release mode and --nocapture"]
    fn benchmark_retained_pending_cache() {
        use std::{hint::black_box, time::Instant};
        let path = cache_test_database("pending-cache-benchmark");
        let fixture = cache_fixture(0);
        let mut pending = Vec::new();
        for nonce in 0..512 {
            let mut operation = fixture.clone();
            let BlockOperation::DeployProgram(ref mut signed) = operation else {
                unreachable!()
            };
            signed.deploy.nonce = nonce;
            pending.push(operation);
        }
        write_pending_operations(&path, &pending).unwrap();
        let primed = load_pending_pool(&path).unwrap();
        let needle = primed.entries.last().unwrap().id;
        let rounds = 8;
        let start = Instant::now();
        for _ in 0..rounds {
            let raw = crate::storage::read_mempool(&path).unwrap();
            let ops: Vec<BlockOperation> = raw
                .iter()
                .map(|bytes| canonical_decode(bytes).unwrap())
                .collect();
            assert!(
                ops.iter()
                    .any(|operation| operation.id().unwrap().into_bytes() == needle)
            );
            black_box(encode_pending_operations(&ops).unwrap());
        }
        let cold = start.elapsed();
        let start = Instant::now();
        for _ in 0..rounds {
            let pool = load_pending_pool(&path).unwrap();
            assert!(Arc::ptr_eq(&primed, &pool));
            assert!(pool.ids.contains(&needle));
            black_box(
                pool.entries
                    .iter()
                    .map(|entry| entry.bytes.as_slice())
                    .collect::<Vec<_>>(),
            );
        }
        let warm = start.elapsed();
        println!(
            "pending=512 rounds={rounds} raw_read_decode_ids_encode_ms={:.3} raw_read_cache_lookup_borrow_ms={:.3}",
            cold.as_secs_f64() * 1000.0,
            warm.as_secs_f64() * 1000.0
        );
        fs::remove_dir_all(path).unwrap();
    }

    /// Models the serialization/hash work in successful program-call admission.
    /// Does not call apply_pending_operation, verify signatures or access storage.
    #[test]
    #[ignore = "manual mempool serialization benchmark; use release mode and --nocapture"]
    fn benchmark_mempool_repeated_serialization() {
        use kernel::{
            crypto::{AccountSignatureScheme, SigningSeed, program_id_from_public_key},
            monetary::coin::{CoinOutput, CoinShare, Zeno},
            program::system::script::call::{ProgramCall, SystemProgramId},
            program::{AccountAuthorization, AuthorizedProgramInvocation, CoinTransition},
        };
        use std::{
            hint::black_box,
            time::{Duration, Instant},
        };
        let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([0x73; 32]));
        let public_key = seed.public_key();
        let owner = program_id_from_public_key(&public_key).unwrap();
        let authorization = AccountAuthorization {
            salt: [0; 32],
            public_key,
            signature: seed.sign(b"serialization-only-fixture"),
        };
        for payload_bytes in [4096, 65536] {
            for existing in [0usize, 64, 512] {
                let pending: Vec<_> = (0..=existing)
                    .map(|index| {
                        let mut input = [0; 32];
                        input[..8].copy_from_slice(&(index as u64).to_le_bytes());
                        BlockOperation::ProgramCall(Box::new(AuthorizedProgramInvocation {
                            signer: owner,
                            call: ProgramCall {
                                program: SystemProgramId::VM,
                                opcode: 0,
                                payload: vec![7; payload_bytes],
                            },
                            payment: CoinTransition::coin(
                                owner,
                                vec![CoinShare::from_bytes(input)],
                                vec![CoinOutput::new(owner, Zeno::ONE)],
                            )
                            .unwrap(),
                            authorization: authorization.clone(),
                        }))
                    })
                    .collect();
                let new = pending.last().unwrap();
                let BlockOperation::ProgramCall(call) = new else {
                    unreachable!()
                };
                let legacy = AuthorizedProgramEnvelope::Program(call.clone());
                let encoded_bytes = canonical_bytes(new).unwrap().len();
                assert_eq!(canonical_bytes(&legacy).unwrap().len(), encoded_bytes);
                let expected_ids: Vec<_> = pending
                    .iter()
                    .map(|operation| operation.id().unwrap())
                    .collect();
                let legacy_id = legacy.id().unwrap();
                let rounds = 8u64;
                let mut timings = [Duration::ZERO; 5];
                for _ in 0..rounds {
                    let start = Instant::now();
                    assert_eq!(
                        black_box(canonical_bytes(black_box(&legacy)).unwrap()).len(),
                        encoded_bytes
                    );
                    assert_eq!(black_box(black_box(&legacy).id().unwrap()), legacy_id);
                    timings[0] += start.elapsed();
                    let start = Instant::now();
                    assert_eq!(
                        black_box(canonical_bytes(black_box(new)).unwrap()).len(),
                        encoded_bytes
                    );
                    assert_eq!(
                        black_box(black_box(new).id().unwrap()),
                        expected_ids[existing]
                    );
                    for (operation, id) in pending[..existing].iter().zip(&expected_ids) {
                        assert_eq!(black_box(black_box(operation).id().unwrap()), *id);
                    }
                    timings[1] += start.elapsed();
                    let start = Instant::now();
                    for operation in black_box(&pending) {
                        assert_eq!(
                            black_box(canonical_bytes(operation).unwrap()).len(),
                            encoded_bytes
                        );
                    }
                    timings[2] += start.elapsed();
                    let start = Instant::now();
                    for operation in black_box(&pending) {
                        assert_eq!(
                            black_box(pending_relay_size(operation).unwrap()),
                            encoded_bytes
                        );
                    }
                    timings[3] += start.elapsed();
                    let start = Instant::now();
                    let encoded =
                        black_box(encode_pending_operations(black_box(&pending)).unwrap());
                    assert_eq!(encoded.len(), pending.len());
                    assert!(encoded.iter().all(|bytes| bytes.len() == encoded_bytes));
                    timings[4] += start.elapsed();
                }
                let passes = 7 + 4 * existing;
                let total_ms: f64 = timings.iter().map(|t| t.as_secs_f64() * 1000.0).sum();
                println!(
                    "existing={existing} payload_bytes={payload_bytes} operation_bytes={encoded_bytes} rounds={rounds} serializations_per_insert={passes} encoded_bytes_per_insert={} total_ms={total_ms:.3} legacy_size_id_ms={:.3} operation_size_duplicate_ids_ms={:.3} limits_ms={:.3} relay_size_ms={:.3} persistence_encode_ms={:.3}",
                    passes * encoded_bytes,
                    timings[0].as_secs_f64() * 1000.0,
                    timings[1].as_secs_f64() * 1000.0,
                    timings[2].as_secs_f64() * 1000.0,
                    timings[3].as_secs_f64() * 1000.0,
                    timings[4].as_secs_f64() * 1000.0
                );
            }
        }
    }
}
