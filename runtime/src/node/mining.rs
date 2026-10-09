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
    let burned_before = ledger.state().coin().total_burned;
    apply_block(&mut ledger, block.clone()).map_err(|error| error.to_string())?;
    let state_burn = ledger
        .state()
        .coin()
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

// Display accounting is separate from consensus and only records persisted blocks.
#[derive(Default)]
struct MiningDashboard {
    blocks: u64,
    subsidy: u128,
    recent: std::collections::VecDeque<String>,
}

fn format_xpq(zeno: u128) -> String {
    let scale = 10_u128.pow(kernel::monetary::coin::DECIMALS.into());
    let amount = format!("{}.{:08}", zeno / scale, zeno % scale);
    amount
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_owned()
}

// Refresh on each persisted block. Redirected logs remain append-only.
fn print_mined_block(block: &Block, state_burn: u64) {
    let stdout = std::io::stdout();
    let terminal = stdout.is_terminal();
    let height = block.height().0;
    let hash = block
        .hash()
        .map(|hash| hex::encode(hash.0))
        .unwrap_or_default();
    let interactive = terminal && std::env::var("TERM").is_ok_and(|term| term != "dumb");
    if !interactive {
        let mut output = stdout.lock();
        let _ = writeln!(
            output,
            "mined height={height} nonce={} hash={hash}",
            block.header.nonce.0
        );
        return;
    }

    static DASHBOARD: OnceLock<Mutex<MiningDashboard>> = OnceLock::new();
    let Ok(mut dashboard) = DASHBOARD
        .get_or_init(|| Mutex::new(MiningDashboard::default()))
        .lock()
    else {
        return;
    };
    let subsidy = block
        .emission()
        .map_or(0, |emission| emission.subsidy.as_zeno());
    dashboard.blocks = dashboard.blocks.saturating_add(1);
    dashboard.subsidy = dashboard.subsidy.saturating_add(u128::from(subsidy));
    dashboard.recent.push_front(format!(
        "{height:>10}  {:>10}  {:>14}  {state_burn:>12}  {:>7}",
        block.block_weight(),
        format_xpq(u128::from(subsidy)),
        block.operations().len()
    ));
    dashboard.recent.truncate(5);

    let color = std::env::var_os("NO_COLOR").is_none();
    let cyan = if color { "\x1b[1;36m" } else { "" };
    let green = if color { "\x1b[1;32m" } else { "" };
    let reset = if color { "\x1b[0m" } else { "" };
    let mut output = stdout.lock();
    let _ = write!(output, "\x1b[H\x1b[2J");
    let border = format!("+{}+", "-".repeat(72));
    let _ = writeln!(output, "{cyan}{border}{reset}");
    for text in [
        "",
        "X P A R Q   /   MINING CONSOLE",
        "Proof of Work  |  Refreshes after each locally mined block",
        "",
    ] {
        let _ = writeln!(output, "| {text:<70} |");
    }
    let _ = writeln!(output, "{cyan}{border}{reset}");
    let _ = writeln!(
        output,
        "{green}  BLOCK #{height} PERSISTED{reset}"
    );
    let _ = writeln!(output, "{border}");
    let _ = writeln!(
        output,
        "  SESSION BLOCKS  {:<16} GROSS SUBSIDY  {} XPQ",
        dashboard.blocks,
        format_xpq(dashboard.subsidy)
    );
    let _ = writeln!(
        output,
        "  BLOCK WEIGHT    {:<16} OPERATIONS     {}",
        block.block_weight(),
        block.operations().len()
    );
    let _ = writeln!(
        output,
        "  BLOCK SUBSIDY   {:<16} STATE BURN     {} zeno",
        format!("{} XPQ", format_xpq(u128::from(subsidy))),
        state_burn
    );
    let _ = writeln!(
        output,
        "  NONCE          {:<16} COMPACT TARGET {}",
        block.header.nonce.0,
        block.target_bits()
    );
    let _ = writeln!(output, "\n  BLOCK HASH\n  {hash}");
    let _ = writeln!(
        output,
        "\n{cyan}  RECENT LOCAL BLOCKS  /  newest first{reset}"
    );
    let _ = writeln!(output, "{border}");
    let _ = writeln!(
        output,
        "{:>12}  {:>10}  {:>14}  {:>12}  {:>7}",
        "HEIGHT", "WEIGHT", "SUBSIDY XPQ", "BURN zeno", "OPS"
    );
    for recent in &dashboard.recent {
        let _ = writeln!(output, "  {recent}");
    }
    let _ = writeln!(
        output,
        "{border}\n  Subsidy is gross emission before burns and miner fees.\n  Session totals count locally mined blocks in this process.\n  Ctrl+C to stop"
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
