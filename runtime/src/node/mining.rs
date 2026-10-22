use std::{
    collections::VecDeque,
    io::IsTerminal,
    sync::atomic::{AtomicBool, Ordering},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use super::*;
use super::{config::*, gossip::*, mempool::*, state::*, util::*};

pub(super) fn mining_loop(database: PathBuf, miner: ProgramId) {
    INTERACTIVE_MINING.store(mining_dashboard_is_interactive(), Ordering::Relaxed);
    let workers = configured_mining_workers();
    log_node(format!(
        "mining: workers={workers} pow_memory_mib_per_worker={} total_pow_memory_mib={}",
        kernel::consensus::POW_ARGON2_MEMORY_KIB / 1024,
        u64::from(kernel::consensus::POW_ARGON2_MEMORY_KIB / 1024) * workers as u64,
    ));
    println!("mining_state: ready workers={workers}");
    loop {
        match mine_next_block_database(&database, miner, workers) {
            Ok(()) => {}
            Err(error) => {
                log_node(format!("node: mining attempt failed: {error}"));
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

const MAX_MINING_WORKERS: usize = 8;

fn configured_mining_workers() -> usize {
    let default = thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .saturating_sub(1)
        .clamp(1, 4);
    match std::env::var("XPARQ_MINING_THREADS") {
        Ok(value) => match value.parse::<usize>() {
            Ok(workers) if (1..=MAX_MINING_WORKERS).contains(&workers) => workers,
            _ => {
                log_node(format!(
                    "mining: ignoring invalid XPARQ_MINING_THREADS={value:?}; using {default}"
                ));
                default
            }
        },
        Err(std::env::VarError::NotPresent) => default,
        Err(error) => {
            log_node(format!(
                "mining: cannot read XPARQ_MINING_THREADS: {error}; using {default}"
            ));
            default
        }
    }
}

#[cfg(test)]
pub(super) enum MiningAttempt {
    Mined,
    Exhausted { next: u64 },
}

#[cfg(test)]
pub(super) fn mine_block_database(
    database: &Path,
    miner: ProgramId,
    start_nonce: u64,
    attempts: u64,
    memory: &mut PoWMemory,
) -> Result<MiningAttempt, String> {
    let (operations, mut block) = build_mining_candidate(database, miner)?;
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
    persist_mined_block(database, &operations, &block)?;
    Ok(MiningAttempt::Mined)
}

fn build_mining_candidate(
    database: &Path,
    miner: ProgramId,
) -> Result<(Vec<kernel::operation::BlockOperation>, Block), String> {
    let ledger = load_or_initialize(database)?;
    let mempool = read_pending_operations(database)?;
    let operations = select_block_operations(&ledger, miner, &mempool)?;
    validate_pending_operations(&ledger, &operations)?;
    let block = candidate_operation_block(&ledger, miner, operations.clone())?;
    block
        .validate_structure()
        .map_err(|error| format!("mining candidate is invalid: {error}"))?;
    Ok((operations, block))
}

fn persist_mined_block(
    database: &Path,
    operations: &[kernel::operation::BlockOperation],
    block: &Block,
) -> Result<(), String> {
    let created_at = format_timestamp(SystemTime::now());
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
    print_mined_block(&block, state_burn, &created_at);
    Ok(())
}

fn mine_next_block_database(
    database: &Path,
    miner: ProgramId,
    workers: usize,
) -> Result<(), String> {
    let mut stale_templates = 0_u64;
    loop {
        let generation = gossip_generation()?;
        let prepared_at = Instant::now();
        let (operations, mut block) = build_mining_candidate(database, miner)?;
        let preparation_time = prepared_at.elapsed();
        let preparation_generation = gossip_generation()?;
        if preparation_generation != generation {
            stale_templates = stale_templates.saturating_add(1);
            continue;
        }

        let height = block.height().0;
        let operation_count = operations.len();
        let weight = block.block_weight();
        let mut last_report = Instant::now();
        let mut last_sample = Instant::now();
        let mut last_hashes = 0_u64;
        let search_started = Instant::now();
        let progress = |hashes, hash_rate, phase: &str| MiningProgress {
            phase: phase.to_owned(),
            height,
            workers,
            hashes,
            hash_rate,
            elapsed_secs: search_started.elapsed().as_secs_f64(),
            template_ms: preparation_time.as_secs_f64() * 1_000.0,
            operations: operation_count,
            weight,
            target: block.target_bits(),
            stale_templates,
        };
        update_mining_progress(progress(0, 0.0, "MINING"));
        let nonce = crate::miner::mine_until_cancelled(
            &block,
            workers,
            || gossip_generation().map_or(true, |current| current != generation),
            |hashes| {
                let sample_interval = last_sample.elapsed();
                let rate = hashes.saturating_sub(last_hashes) as f64
                    / sample_interval.as_secs_f64().max(0.001);
                last_hashes = hashes;
                last_sample = Instant::now();
                update_mining_progress(progress(hashes, rate, "MINING"));

                if last_report.elapsed() >= Duration::from_secs(10) {
                    log_node(format!(
                        "mining_progress: height={height} workers={workers} hash_rate={} hashes={hashes} elapsed_secs={:.1} template_ms={:.3} operations={operation_count} weight={weight} target_bits={} stale_templates={stale_templates}",
                        format_hash_rate(rate),
                        search_started.elapsed().as_secs_f64(),
                        preparation_time.as_secs_f64() * 1_000.0,
                        block.target_bits(),
                    ));
                    last_report = Instant::now();
                }
            },
        )
        .map_err(|error| error.to_string())?;

        if let Some(nonce) = nonce {
            block.header.nonce = nonce;
            match persist_mined_block(database, &operations, &block) {
                Ok(()) => return Ok(()),
                Err(error) if error == "mined candidate became stale while mining" => {
                    stale_templates = stale_templates.saturating_add(1);
                    continue;
                }
                Err(error) => return Err(error),
            }
        }

        stale_templates = stale_templates.saturating_add(1);
        update_mining_progress(MiningProgress {
            phase: "REFRESHING TEMPLATE".into(),
            height,
            workers,
            elapsed_secs: search_started.elapsed().as_secs_f64(),
            template_ms: preparation_time.as_secs_f64() * 1_000.0,
            operations: operation_count,
            weight,
            target: block.target_bits(),
            stale_templates,
            ..MiningProgress::default()
        });
        log_node(format!(
            "mining_template_refresh: height={height} elapsed_secs={:.1} stale_templates={stale_templates}",
            search_started.elapsed().as_secs_f64(),
        ));
    }
}

// Display accounting is separate from consensus and only records persisted blocks.
#[derive(Clone, Default)]
struct MiningDashboard {
    blocks: u64,
    subsidy: u128,
    recent: std::collections::VecDeque<String>,
    progress: MiningProgress,
    latest: Option<LatestMinedBlock>,
}

#[derive(Clone, Default)]
struct MiningProgress {
    phase: String,
    height: u64,
    workers: usize,
    hashes: u64,
    hash_rate: f64,
    elapsed_secs: f64,
    template_ms: f64,
    operations: usize,
    weight: u32,
    target: u32,
    stale_templates: u64,
}

#[derive(Clone)]
struct LatestMinedBlock {
    height: u64,
    created_at: String,
    nonce: u64,
    hash: String,
    subsidy: u64,
    state_burn: u64,
}

static RECENT_NODE_LOGS: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();
static MINING_DASHBOARD: OnceLock<Mutex<MiningDashboard>> = OnceLock::new();
static INTERACTIVE_MINING: AtomicBool = AtomicBool::new(false);

fn mining_dashboard_is_interactive() -> bool {
    std::io::stdout().is_terminal() && std::env::var("TERM").is_ok_and(|term| term != "dumb")
}

pub(super) fn log_node(message: impl AsRef<str>) {
    let message = message.as_ref();
    if let Ok(mut logs) = RECENT_NODE_LOGS
        .get_or_init(|| Mutex::new(VecDeque::new()))
        .lock()
    {
        logs.push_back(message.to_owned());
        while logs.len() > 5 {
            logs.pop_front();
        }
    }
    if !INTERACTIVE_MINING.load(Ordering::Relaxed) {
        eprintln!("{message}");
    }
}

fn update_mining_progress(progress: MiningProgress) {
    if let Ok(mut dashboard) = MINING_DASHBOARD
        .get_or_init(|| Mutex::new(MiningDashboard::default()))
        .lock()
    {
        dashboard.progress = progress;
    }
    if INTERACTIVE_MINING.load(Ordering::Relaxed) {
        render_mining_dashboard();
    }
}

fn format_hash_rate(rate: f64) -> String {
    if rate >= 1_000_000.0 {
        format!("{:.2} MH/s", rate / 1_000_000.0)
    } else if rate >= 1_000.0 {
        format!("{:.2} kH/s", rate / 1_000.0)
    } else {
        format!("{rate:.2} H/s")
    }
}

fn render_mining_dashboard() {
    if !INTERACTIVE_MINING.load(Ordering::Relaxed) {
        return;
    }
    let dashboard = MINING_DASHBOARD
        .get_or_init(|| Mutex::new(MiningDashboard::default()))
        .lock()
        .map(|dashboard| dashboard.clone());
    let Ok(dashboard) = dashboard else {
        return;
    };
    let recent_logs = RECENT_NODE_LOGS
        .get_or_init(|| Mutex::new(VecDeque::new()))
        .lock()
        .map(|logs| {
            logs.iter()
                .rev()
                .take(3)
                .map(|message| {
                    let mut line: String = message.chars().take(74).collect();
                    if message.chars().count() > 74 {
                        line.push_str("...");
                    }
                    line
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let color = std::env::var_os("NO_COLOR").is_none();
    let cyan = if color { "\x1b[1;36m" } else { "" };
    let green = if color { "\x1b[1;32m" } else { "" };
    let yellow = if color { "\x1b[1;33m" } else { "" };
    let reset = if color { "\x1b[0m" } else { "" };
    let progress = &dashboard.progress;
    let border = format!("+{}+", "-".repeat(78));
    let mut output = std::io::stdout().lock();
    let _ = write!(output, "\x1b[H\x1b[2J");
    let _ = writeln!(output, "{cyan}{border}{reset}");
    let _ = writeln!(output, "|{:^78}|", "XPARQ  /  MINING STATUS");
    let _ = writeln!(output, "{cyan}{border}{reset}");
    let _ = writeln!(
        output,
        "  Status           {green}{:<20}{reset}  Candidate height  {}",
        progress.phase, progress.height,
    );
    let _ = writeln!(
        output,
        "  Workers          {:<20}  Hash rate         {}",
        progress.workers,
        format_hash_rate(progress.hash_rate),
    );
    let _ = writeln!(
        output,
        "  Template         {:>4} operations  {:>8} weight  built in {:.2} ms",
        progress.operations, progress.weight, progress.template_ms,
    );
    let _ = writeln!(
        output,
        "  Search           {:>12} hashes  {:>8.1} s  target bits {}",
        progress.hashes, progress.elapsed_secs, progress.target,
    );
    let _ = writeln!(
        output,
        "  Template refreshes {:<5}  PoW memory {:>4} MiB",
        progress.stale_templates,
        progress.workers * (kernel::consensus::POW_ARGON2_MEMORY_KIB as usize / 1024),
    );
    if let Some(latest) = &dashboard.latest {
        let _ = writeln!(output, "{border}");
        let _ = writeln!(
            output,
            "  {yellow}Last block #{} persisted at {}{reset}",
            latest.height, latest.created_at,
        );
        let _ = writeln!(output, "  Nonce {}", latest.nonce);
        let _ = writeln!(output, "  Hash  {}", latest.hash);
        let _ = writeln!(
            output,
            "  Reward {} XPQ  |  State burn {} zeno",
            format_xpq(u128::from(latest.subsidy)),
            latest.state_burn,
        );
    }
    let _ = writeln!(output, "{border}");
    let _ = writeln!(
        output,
        "  Session blocks {:<8}  Gross subsidy {} XPQ",
        dashboard.blocks,
        format_xpq(dashboard.subsidy),
    );
    if !dashboard.recent.is_empty() {
        let _ = writeln!(output, "\n  RECENT LOCAL BLOCKS  /  newest first");
        let _ = writeln!(
            output,
            "  {:<24}  {:>12}  {:>10}  {:>5}",
            "CREATED (UTC)", "HEIGHT", "WEIGHT", "OPS"
        );
        for recent in &dashboard.recent {
            let _ = writeln!(output, "  {recent}");
        }
    }
    if !recent_logs.is_empty() {
        let _ = writeln!(output, "\n  RECENT NODE ACTIVITY");
        for line in recent_logs {
            let _ = writeln!(output, "  {line}");
        }
    }
    let _ = writeln!(
        output,
        "{border}\n  Hash rate is local PoW throughput. Ctrl+C to stop."
    );
    let _ = output.flush();
}

fn format_xpq(zeno: u128) -> String {
    let scale = 10_u128.pow(kernel::monetary::coin::DECIMALS.into());
    let amount = format!("{}.{:08}", zeno / scale, zeno % scale);
    amount
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_owned()
}

fn format_timestamp(time: SystemTime) -> String {
    let Ok(duration) = time.duration_since(UNIX_EPOCH) else {
        return "unknown time".into();
    };
    let seconds = duration.as_secs();
    let days = (seconds / 86_400) as i64;
    let day_seconds = seconds % 86_400;

    // Convert Unix days to a Gregorian date without a platform-specific timezone dependency.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);

    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        day_seconds / 3_600,
        (day_seconds % 3_600) / 60,
        day_seconds % 60
    )
}

// Refresh on each persisted block. Redirected logs remain append-only.
fn print_mined_block(block: &Block, state_burn: u64, created_at: &str) {
    let stdout = std::io::stdout();
    let terminal = stdout.is_terminal();
    let height = block.height().0;
    let hash = block
        .hash()
        .map(|hash| hex::encode(hash.0))
        .unwrap_or_default();
    let subsidy = block
        .emission()
        .map_or(0, |emission| emission.subsidy.as_zeno());
    let operations = block.operations().len();
    let weight = block.block_weight();
    let interactive = terminal && mining_dashboard_is_interactive();
    if !interactive {
        let mut output = stdout.lock();
        let _ = writeln!(
            output,
            "mined height={height} created_at={created_at} nonce={} hash={hash} operations={operations} weight={weight} target_bits={} subsidy_zeno={subsidy} state_burn_zeno={state_burn}",
            block.header.nonce.0,
            block.target_bits(),
        );
        return;
    }

    let Ok(mut dashboard) = MINING_DASHBOARD
        .get_or_init(|| Mutex::new(MiningDashboard::default()))
        .lock()
    else {
        return;
    };
    dashboard.blocks = dashboard.blocks.saturating_add(1);
    dashboard.subsidy = dashboard.subsidy.saturating_add(u128::from(subsidy));
    dashboard.recent.push_front(format!(
        "{created_at:<24}  {height:>12}  {:>10}  {:>5}",
        weight, operations
    ));
    dashboard.recent.truncate(5);
    dashboard.progress.phase = "BLOCK PERSISTED".into();
    dashboard.progress.height = height;
    dashboard.progress.weight = weight;
    dashboard.progress.operations = operations;
    dashboard.progress.target = block.target_bits();
    dashboard.latest = Some(LatestMinedBlock {
        height,
        created_at: created_at.to_owned(),
        nonce: block.header.nonce.0,
        hash,
        subsidy,
        state_burn,
    });
    drop(dashboard);
    render_mining_dashboard();
}

pub(super) fn mine_one_block(path: Option<&str>, miner: &str) -> Result<(), String> {
    INTERACTIVE_MINING.store(mining_dashboard_is_interactive(), Ordering::Relaxed);
    let database = database_path(path);
    let miner = parse_program_id(miner)?;
    let workers = configured_mining_workers();
    mine_next_block_database(&database, miner, workers)
}

pub(super) fn select_block_operations(
    ledger: &Ledger,
    miner: ProgramId,
    mempool: &[kernel::operation::BlockOperation],
) -> Result<Vec<kernel::operation::BlockOperation>, String> {
    let mut selected = Vec::new();
    let empty_block = candidate_operation_block(ledger, miner, Vec::new())?;
    let mut block_weight = u64::from(empty_block.block_weight());
    for operation in mempool {
        let operation_weight =
            kernel::crypto::canonical_length(operation).map_err(|error| error.to_string())?;
        let Some(candidate_weight) = block_weight.checked_add(operation_weight) else {
            break;
        };
        if candidate_weight > kernel::block::MAX_BLOCK_SIZE as u64 {
            break;
        }
        block_weight = candidate_weight;
        selected.push(operation.clone());
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
    let subsidy = expected_next_emission(ledger, &operations)?;
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

pub(super) fn expected_next_emission(
    ledger: &Ledger,
    operations: &[kernel::operation::BlockOperation],
) -> Result<Zeno, String> {
    let height = Height(
        ledger
            .tip_height()
            .map_or(0, |height| height.0.saturating_add(1)),
    );

    kernel::consensus::expected_emission_for_operations(height, operations)
        .map_err(|error| error.to_string())
}
