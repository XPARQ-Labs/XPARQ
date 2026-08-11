use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Instant;

use tokio::sync::oneshot;

const STATE_QUEUE_CAPACITY: usize = 128;
const MAX_STATE_WORKERS: usize = 4;

type StateJob = Box<dyn FnOnce() + Send + 'static>;

#[derive(Clone)]
pub(crate) struct StatePipeline {
    sender: mpsc::SyncSender<StateJob>,
    metrics: Arc<StatePipelineMetrics>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatePipelineError {
    Full,
    Closed,
    Cancelled,
}

#[derive(Default)]
pub(crate) struct StatePipelineMetrics {
    depth: AtomicUsize,
    queued_total: AtomicU64,
    rejected_total: AtomicU64,
    wait_micros_total: AtomicU64,
    run_micros_total: AtomicU64,
    completed_total: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct StatePipelineSnapshot {
    pub(crate) depth: usize,
    pub(crate) capacity: usize,
    pub(crate) queued_total: u64,
    pub(crate) rejected_total: u64,
    pub(crate) wait_micros_total: u64,
    pub(crate) run_micros_total: u64,
    pub(crate) completed_total: u64,
}

impl StatePipeline {
    pub(crate) fn new() -> Self {
        let (sender, receiver) = mpsc::sync_channel::<StateJob>(STATE_QUEUE_CAPACITY);
        let receiver = Arc::new(Mutex::new(receiver));
        let metrics = Arc::new(StatePipelineMetrics::default());
        let workers = thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .clamp(1, MAX_STATE_WORKERS);

        for index in 0..workers {
            let receiver = Arc::clone(&receiver);
            thread::Builder::new()
                .name(format!("xparq-state-{index}"))
                .spawn(move || {
                    loop {
                        let job = match receiver.lock() {
                            Ok(receiver) => receiver.recv(),
                            Err(_) => return,
                        };
                        match job {
                            Ok(job) => job(),
                            Err(_) => return,
                        }
                    }
                })
                .expect("state pipeline worker must start");
        }

        Self { sender, metrics }
    }

    pub(crate) async fn run<T, F>(&self, operation: F) -> Result<T, StatePipelineError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let queued_at = Instant::now();
        let metrics = Arc::clone(&self.metrics);
        let (result_sender, result_receiver) = oneshot::channel();
        let job = Box::new(move || {
            metrics.depth.fetch_sub(1, Ordering::Relaxed);
            metrics
                .wait_micros_total
                .fetch_add(elapsed_micros(queued_at), Ordering::Relaxed);
            let started = Instant::now();
            let result = operation();
            metrics
                .run_micros_total
                .fetch_add(elapsed_micros(started), Ordering::Relaxed);
            metrics.completed_total.fetch_add(1, Ordering::Relaxed);
            let _ = result_sender.send(result);
        }) as StateJob;

        self.metrics.depth.fetch_add(1, Ordering::Relaxed);
        match self.sender.try_send(job) {
            Ok(()) => {
                self.metrics.queued_total.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::TrySendError::Full(_)) => {
                self.metrics.depth.fetch_sub(1, Ordering::Relaxed);
                self.metrics.rejected_total.fetch_add(1, Ordering::Relaxed);
                return Err(StatePipelineError::Full);
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                self.metrics.depth.fetch_sub(1, Ordering::Relaxed);
                self.metrics.rejected_total.fetch_add(1, Ordering::Relaxed);
                return Err(StatePipelineError::Closed);
            }
        }

        result_receiver
            .await
            .map_err(|_| StatePipelineError::Cancelled)
    }

    pub(crate) fn snapshot(&self) -> StatePipelineSnapshot {
        StatePipelineSnapshot {
            depth: self.metrics.depth.load(Ordering::Relaxed),
            capacity: STATE_QUEUE_CAPACITY,
            queued_total: self.metrics.queued_total.load(Ordering::Relaxed),
            rejected_total: self.metrics.rejected_total.load(Ordering::Relaxed),
            wait_micros_total: self.metrics.wait_micros_total.load(Ordering::Relaxed),
            run_micros_total: self.metrics.run_micros_total.load(Ordering::Relaxed),
            completed_total: self.metrics.completed_total.load(Ordering::Relaxed),
        }
    }
}

fn elapsed_micros(started: Instant) -> u64 {
    started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn executes_jobs_and_records_metrics() {
        let pipeline = StatePipeline::new();
        assert_eq!(pipeline.run(|| 42_u64).await.unwrap(), 42);
        let snapshot = pipeline.snapshot();
        assert_eq!(snapshot.depth, 0);
        assert_eq!(snapshot.queued_total, 1);
        assert_eq!(snapshot.completed_total, 1);
        assert_eq!(snapshot.rejected_total, 0);
    }
}
