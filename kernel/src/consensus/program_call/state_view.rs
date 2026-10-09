use crate::{
    common::Owner,
    monetary::coin::{CoinShare, Zeno},
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinInputState {
    pub amount: Zeno,
    pub owner: Owner,
}

pub trait ProgramStateView {
    fn ledger_state(&self) -> Option<&crate::ledger::LedgerState> {
        None
    }
    fn registry(&self) -> Option<&crate::program::ProgramRegistry> {
        None
    }

    fn extension_state(&self) -> Option<&crate::program::system::script::state::ExtensionState> {
        None
    }

    fn coin(&self, id: CoinShare) -> Option<CoinInputState>;
}
