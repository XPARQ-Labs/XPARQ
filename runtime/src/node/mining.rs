use super::*;
use super::{config::*, gossip::*, mempool::*, state::*, util::*};

pub(super) fn mining_loop(database: PathBuf, miner: Address) {
    let mut next_nonce = 0_u64;
    let mut memory = new_pow_memory();
    println!("mining_state: ready");
    loop {
        match mine_block_database(&database, miner, next_nonce, 1_000_000, &mut memory) {
            Ok(MiningAttempt::Mined) => next_nonce = 0,
            Ok(MiningAttempt::Exhausted { next }) => next_nonce = next,
            Err(error) => {
                next_nonce = 0;
                eprintln!("node: mining attempt failed: {error}");
            }
        }
    }
}

pub(super) enum MiningAttempt {
    Mined,
    Exhausted { next: u64 },
}

pub(super) fn mine_block_database(
    database: &Path,
    miner: Address,
    start_nonce: u64,
    attempts: u64,
    memory: &mut PoWMemory,
) -> Result<MiningAttempt, String> {
    let ledger = load_or_initialize(database)?;
    let mempool = read_mempool(database)?;
    let transactions = select_block_transactions(&ledger, miner, &mempool)?;
    validate_mempool(&ledger, &transactions)?;
    let mut block = candidate_block(&ledger, miner, transactions.clone())?;
    block
        .validate_structure()
        .map_err(|error| format!("mining candidate is invalid: {error}"))?;
    let height = block.height();
    let found = crate::miner::mine_range(
        &mut block,
        crate::miner::MiningRange {
            start_nonce,
            attempts,
        },
        memory,
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
    let mut ledger = load_or_initialize_owned(database)?;
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
    let _ = update_ledger_cache(database, ledger)?;
    notify_gossip();
    println!(
        "mined height={} nonce={} hash={}",
        height.0,
        block.header.nonce.0,
        hex::encode(block.hash().map_err(|error| error.to_string())?.0)
    );
    Ok(MiningAttempt::Mined)
}

pub(super) fn mine_one_block(path: Option<&str>, miner: &str) -> Result<(), String> {
    let database = database_path(path);
    let miner = parse_address(miner)?;
    let mut next_nonce = 0_u64;
    let mut memory = new_pow_memory();
    loop {
        match mine_block_database(&database, miner, next_nonce, 1_000_000, &mut memory)? {
            MiningAttempt::Mined => return Ok(()),
            MiningAttempt::Exhausted { next } => next_nonce = next,
        }
    }
}

pub(super) fn select_block_transactions(
    ledger: &Ledger,
    miner: Address,
    mempool: &[Transaction],
) -> Result<Vec<Transaction>, String> {
    let mut selected = Vec::new();
    for transaction in mempool {
        let mut candidate = selected.clone();
        candidate.push(transaction.clone());
        let block = candidate_block(ledger, miner, candidate.clone())?;
        if block.block_weight() as usize > kernel::block::MAX_BLOCK_SIZE {
            break;
        }
        selected = candidate;
    }
    Ok(selected)
}

pub(super) fn candidate_block(
    ledger: &Ledger,
    miner: Address,
    transactions: Vec<Transaction>,
) -> Result<Block, String> {
    let height = Height(
        ledger
            .tip_height()
            .map_or(0, |height| height.0.saturating_add(1)),
    );
    let previous = ledger.tip_hash().ok_or("canonical genesis is missing")?;
    let difficulty = expected_next_difficulty(&ledger.chain).map_err(|error| error.to_string())?;
    let subsidy = expected_next_emission(ledger)?;
    let mut block = Block::from_protocol_transactions(
        height,
        previous,
        difficulty,
        Nonce(0),
        Some(Emission::new(miner, subsidy)),
        transactions,
    )
    .map_err(|error| error.to_string())?;
    let (state_root, block_weight) = ledger
        .preview_block_commitments(&block)
        .map_err(|error| error.to_string())?;
    block.set_state_root(state_root);
    block.set_block_weight(block_weight);
    Ok(block)
}

pub(super) fn expected_next_emission(ledger: &Ledger) -> Result<Zeno, String> {
    let height = Height(
        ledger
            .tip_height()
            .map_or(0, |height| height.0.saturating_add(1)),
    );

    Ok(expected_emission_for_height(height))
}
