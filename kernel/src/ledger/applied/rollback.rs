//! Journal validation and rollback of coin, program, and asset state.

use crate::ledger::{CoinRollbackJournal, LedgerState, StateError, StateRollbackJournal};

impl LedgerState {
    pub(crate) fn rollback_state(
        &mut self,

        journal: StateRollbackJournal,
    ) -> Result<(), StateError> {
        let mut staged = self.clone();

        if let Some(program) = journal.program {
            crate::program::rollback_program(&mut staged.programs, program)
                .map_err(|_| StateError::InvalidTransition)?;
        }

        if let Some(extension) = journal.extension {
            staged.extensions.assets.rollback(extension);
        }

        if let Some(coin) = journal.coin {
            staged.rollback_coin(coin)?;
        }

        *self = staged;

        Ok(())
    }

    pub(crate) fn rollback_coin(&mut self, journal: CoinRollbackJournal) -> Result<(), StateError> {
        let total_mined = self
            .coin
            .total_mined
            .checked_sub(journal.mined)
            .ok_or(StateError::AmountOverflow)?;

        let total_burned = self
            .coin
            .total_burned
            .checked_sub(journal.burned)
            .ok_or(StateError::BurnUnderflow)?;

        let mut created = std::collections::BTreeSet::new();

        for id in &journal.created_coin_ids {
            if !created.insert(*id) || self.utxos.coin(id).is_none() {
                return Err(StateError::InvalidTransition);
            }
        }

        let mut consumed = std::collections::BTreeSet::new();

        for (id, _) in &journal.consumed_coins {
            if !consumed.insert(*id) || (self.utxos.coin(id).is_some() && !created.contains(id)) {
                return Err(StateError::InvalidTransition);
            }
        }

        self.coin.total_mined = total_mined;

        self.coin.total_burned = total_burned;

        for id in journal.created_coin_ids {
            self.utxos.consume_coin(&id)?;
        }

        for (id, coin) in journal.consumed_coins {
            self.utxos.insert_coin(id, coin)?;
        }

        Ok(())
    }
}
