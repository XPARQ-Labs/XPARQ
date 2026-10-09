//! Read-only consensus view of canonical program state.

use crate::{
    consensus::{CoinInputState, ProgramStateView},
    ledger::LedgerState,
    monetary::coin::CoinShare,
};

impl ProgramStateView for LedgerState {
    fn ledger_state(&self) -> Option<&LedgerState> {
        Some(self)
    }
    fn registry(&self) -> Option<&crate::program::ProgramRegistry> {
        Some(&self.programs)
    }
    fn extension_state(&self) -> Option<&crate::program::system::script::state::ExtensionState> {
        Some(&self.extensions)
    }

    fn coin(&self, id: CoinShare) -> Option<CoinInputState> {
        self.utxos.coin(&id).map(|coin| CoinInputState {
            amount: coin.amount,

            owner: coin.owner,
        })
    }
}
