//! Process-wide memory budget for remote proof-of-work verification.

use std::sync::{Condvar, Mutex};

/// Each active Argon2id verification consumes 64 MiB. Two permits cap the
/// explicitly parallel header-sync path at 128 MiB while retaining progress
/// across competing peers.
pub const MAX_PARALLEL_POW_VERIFICATIONS: usize = 2;

pub struct PowVerificationBudget {
    available: Mutex<usize>,
    changed: Condvar,
}

impl PowVerificationBudget {
    const fn new(limit: usize) -> Self {
        Self {
            available: Mutex::new(limit),
            changed: Condvar::new(),
        }
    }

    pub fn acquire(&self) -> Result<PowVerificationPermit<'_>, &'static str> {
        let mut available = self
            .available
            .lock()
            .map_err(|_| "PoW verification budget lock poisoned")?;
        while *available == 0 {
            available = self
                .changed
                .wait(available)
                .map_err(|_| "PoW verification budget lock poisoned")?;
        }
        *available -= 1;
        Ok(PowVerificationPermit { budget: self })
    }
}

pub struct PowVerificationPermit<'a> {
    budget: &'a PowVerificationBudget,
}

impl Drop for PowVerificationPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut available) = self.budget.available.lock() {
            *available = available
                .saturating_add(1)
                .min(MAX_PARALLEL_POW_VERIFICATIONS);
            self.budget.changed.notify_one();
        }
    }
}

pub static POW_VERIFICATION_BUDGET: PowVerificationBudget =
    PowVerificationBudget::new(MAX_PARALLEL_POW_VERIFICATIONS);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permit_is_returned_when_guard_drops() {
        let budget = PowVerificationBudget::new(1);
        drop(budget.acquire().unwrap());
        assert!(budget.acquire().is_ok());
    }
}
