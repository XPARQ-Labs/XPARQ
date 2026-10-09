use std::io::IsTerminal;

use super::*;
use super::{config::*, gossip::*, mempool::*, state::*, util::*};

pub(super) fn mining_loop(database: PathBuf, miner: ProgramId) {
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
    miner: ProgramId,
    start_nonce: u64,
    attempts: u64,
    memory: &mut PoWMemory,
) -> Result<MiningAttempt, String> {
    let ledger = load_or_initialize(database)?;
    let mempool = read_pending_operations(database)?;
    let operations = select_block_operations(&ledger, miner, &mempool)?;
    validate_pending_operations(&ledger, &operations)?;
    let mut block = candidate_operation_block(&ledger, miner, operations.clone())?;
    block
        .validate_structure()
        .map_err(|error| format!("mining candidate is invalid: {error}"))?;
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
    let burned_before = ledger.state.coin.total_burned;
    apply_block(&mut ledger, block.clone()).map_err(|error| error.to_string())?;
    let state_burn = ledger
        .state
        .coin
        .total_burned
        .checked_sub(burned_before)
        .ok_or("block burn accounting decreased unexpectedly")?
        .as_zeno();
    let included = operations
        .iter()
        .map(|operation| {
            operation
                .id()
                .map(|id| id.into_bytes())
                .map_err(|error| error.to_string())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let remaining =
        reconcile_pending_operations(&ledger, read_pending_operations(database)?, &included);
    persist_block_and_pending(database, &block, &remaining)?;
    let _ = update_ledger_cache(database, ledger)?;
    notify_gossip();
    print_mined_block(&block, state_burn);
    Ok(MiningAttempt::Mined)
}

// Refresh one terminal frame for each mined block; redirected logs remain append-only.
// state_burn is the block's native protocol burn (archival plus state growth),
// in zeno; subsidy is the gross emission in XPQ, before burns and miner fees.
fn print_mined_block(block: &Block, state_burn: u64) {
    let stdout = std::io::stdout();
    let terminal = stdout.is_terminal();
    let mut output = stdout.lock();
    let height = block.height().0;
    if !terminal {
        if let Ok(hash) = block.hash() {
            let _ = writeln!(
                output,
                "mined height={height} nonce={} hash={}",
                block.header.nonce.0,
                hex::encode(hash.0)
            );
        }
        return;
    }
    {
        // Replace the current screen without accumulating mining rows in scrollback.
        // Dumb terminals cannot interpret cursor/erase sequences.
        if std::env::var("TERM").is_ok_and(|term| term != "dumb") {
            let _ = write!(output, "\x1b[H\x1b[2J");
        }
        let _ = writeln!(
            output,
            "\n  XPARQ MINING  |  subsidy: XPQ  |  state_burn: zeno"
        );
        let _ = writeln!(
            output,
            "{:>9} | {:>10} | {:>12} | {:>12} | {:>8} | {:>10}",
            "height", "weight", "subsidy", "state_burn", "tx_count", "difficulty"
        );
        let _ = writeln!(
            output,
            "----------+------------+--------------+--------------+----------+-----------"
        );
    }
    let subsidy = block
        .emission()
        .map_or(0, |emission| emission.subsidy.as_zeno());
    let scale = 10_u64.pow(kernel::monetary::coin::DECIMALS.into());
    let subsidy = format!("{}.{:08}", subsidy / scale, subsidy % scale);
    let subsidy = subsidy.trim_end_matches('0').trim_end_matches('.');
    let _ = writeln!(
        output,
        "{height:>9} | {:>10} | {subsidy:>12} | {state_burn:>12} | {:>8} | {:>10}",
        block.block_weight(),
        block.operations().len(),
        block.target_bits()
    );
    let _ = output.flush();
}

pub(super) fn mine_one_block(path: Option<&str>, miner: &str) -> Result<(), String> {
    let database = database_path(path);
    let miner = parse_program_id(miner)?;
    let mut next_nonce = 0_u64;
    let mut memory = new_pow_memory();
    loop {
        match mine_block_database(&database, miner, next_nonce, 1_000_000, &mut memory)? {
            MiningAttempt::Mined => return Ok(()),
            MiningAttempt::Exhausted { next } => next_nonce = next,
        }
    }
}

pub(super) fn select_block_operations(
    ledger: &Ledger,
    miner: ProgramId,
    mempool: &[kernel::operation::BlockOperation],
) -> Result<Vec<kernel::operation::BlockOperation>, String> {
    let mut selected = Vec::new();
    for operation in mempool {
        let mut candidate = selected.clone();
        candidate.push(operation.clone());
        let block = candidate_operation_block(ledger, miner, candidate.clone())?;
        if block.block_weight() as usize > kernel::block::MAX_BLOCK_SIZE {
            break;
        }
        selected = candidate;
    }
    Ok(selected)
}

pub(super) fn candidate_operation_block(
    ledger: &Ledger,
    miner: ProgramId,
    operations: Vec<kernel::operation::BlockOperation>,
) -> Result<Block, String> {
    let height = Height(
        ledger
            .tip_height()
            .map_or(0, |height| height.0.saturating_add(1)),
    );
    let previous = ledger.tip_hash().ok_or("canonical genesis is missing")?;
    let difficulty = expected_next_difficulty(&ledger.chain).map_err(|error| error.to_string())?;
    let subsidy = expected_next_emission(ledger)?;
    let mut block = Block::from_protocol_operations(
        height,
        previous,
        difficulty,
        Nonce(0),
        Some(Emission::new(miner, subsidy)),
        operations,
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
