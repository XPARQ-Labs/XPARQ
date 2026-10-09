//! Local CPU queue bound; independent of consensus and peer connection limits.
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) struct AdmissionGate {
    active: AtomicUsize,
    limit: usize,
}
impl AdmissionGate {
    pub(super) const fn new(limit: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            limit,
        }
    }
    pub(super) fn enter(&self) -> Result<AdmissionPermit<'_>, String> {
        let mut active = self.active.load(Ordering::Acquire);
        loop {
            if active >= self.limit {
                return Err("transaction validation queue is busy; retry later".into());
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(AdmissionPermit(self)),
                Err(observed) => active = observed,
            }
        }
    }
}
pub(super) struct AdmissionPermit<'a>(&'a AdmissionGate);
impl Drop for AdmissionPermit<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn queue_bound_and_unwind_release_permits() {
        let gate = AdmissionGate::new(2);
        let first = gate.enter().unwrap();
        let second = gate.enter().unwrap();
        assert!(gate.enter().is_err());
        drop(first);
        assert!(
            std::panic::catch_unwind(|| {
                let _permit = gate.enter().unwrap();
                panic!("simulate failed admission");
            })
            .is_err()
        );
        assert!(gate.enter().is_ok());
        drop(second);
        assert_eq!(gate.active.load(Ordering::Acquire), 0);
    }
}
