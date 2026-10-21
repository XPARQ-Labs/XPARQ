use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(test)]
use kernel::crypto::PoWMemory;
use kernel::{
    block::Block,
    common::Nonce,
    consensus::{ConsensusError, PoWTarget, calculate_work_with_memory, new_pow_memory},
};

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MiningRange {
    pub start_nonce: u64,
    pub attempts: u64,
}

#[cfg(test)]
pub fn mine_range(
    block: &mut Block,
    range: MiningRange,
    memory: &mut PoWMemory,
) -> Result<Option<Nonce>, ConsensusError> {
    let target =
        PoWTarget::from_compact(block.target_bits()).ok_or(ConsensusError::InvalidDifficulty)?;

    for offset in 0..range.attempts {
        let nonce = Nonce(range.start_nonce.wrapping_add(offset));

        block.header.nonce = nonce;

        let hash = calculate_work_with_memory(&block.header, memory)?;

        if target.meets(&hash) {
            return Ok(Some(nonce));
        }
    }

    Ok(None)
}

/// Search a block template with independent PoW memory per worker.
///
/// Workers search disjoint nonce lanes and stop when a winner is found or the
/// caller reports that the template is stale. `on_progress` receives the
/// cumulative hash count about once per second.
pub fn mine_until_cancelled(
    block: &Block,
    workers: usize,
    mut should_cancel: impl FnMut() -> bool,
    mut on_progress: impl FnMut(u64),
) -> Result<Option<Nonce>, ConsensusError> {
    let target =
        PoWTarget::from_compact(block.target_bits()).ok_or(ConsensusError::InvalidDifficulty)?;
    let workers = workers.max(1);
    let stride = workers as u64;
    let stopped = AtomicBool::new(false);
    let hashes = AtomicU64::new(0);
    let winner = Mutex::new(None);

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for worker in 0..workers {
            let stopped = &stopped;
            let hashes = &hashes;
            let winner = &winner;
            let mut worker_block = block.clone();
            handles.push(scope.spawn(move || {
                if stopped.load(Ordering::Relaxed) {
                    return Ok(());
                }
                let mut memory = new_pow_memory();
                let mut offset = worker as u64;
                loop {
                    if stopped.load(Ordering::Relaxed) {
                        return Ok(());
                    }
                    let nonce = Nonce(offset);
                    worker_block.header.nonce = nonce;
                    let hash = match calculate_work_with_memory(&worker_block.header, &mut memory) {
                        Ok(hash) => hash,
                        Err(error) => {
                            stopped.store(true, Ordering::Relaxed);
                            return Err(error);
                        }
                    };
                    hashes.fetch_add(1, Ordering::Relaxed);
                    if target.meets(&hash) {
                        let mut found = winner.lock().unwrap_or_else(|error| error.into_inner());
                        if found.is_none() {
                            *found = Some(nonce);
                        }
                        stopped.store(true, Ordering::Relaxed);
                        return Ok(());
                    }
                    offset = offset.wrapping_add(stride);
                }
            }));
        }

        let mut last_report = Instant::now();
        while !stopped.load(Ordering::Relaxed) {
            if should_cancel() {
                stopped.store(true, Ordering::Relaxed);
                break;
            }
            thread::sleep(Duration::from_millis(100));
            if last_report.elapsed() >= Duration::from_secs(1) {
                on_progress(hashes.load(Ordering::Relaxed));
                last_report = Instant::now();
            }
        }

        stopped.store(true, Ordering::Relaxed);
        let mut worker_error = None;
        for handle in handles {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    worker_error.get_or_insert(error);
                }
                Err(_) => {
                    worker_error.get_or_insert(ConsensusError::PoWHashFailed);
                }
            }
        }
        if let Some(error) = worker_error {
            return Err(error);
        }
        Ok(*winner.lock().unwrap_or_else(|error| error.into_inner()))
    })
}
