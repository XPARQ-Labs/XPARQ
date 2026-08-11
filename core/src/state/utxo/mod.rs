//! Consensus UTXO state.
//!
//! XPQ and QCash deliberately use separate coin types and lifecycle rules.
//! Shared authenticated QCash proof machinery lives in `proof`.

mod proof;
mod qcash;
mod xpq;

pub use proof::{
    QCashProofSide, QCashStateProof, QCashStateProofNode, empty_qcash_state_root,
    verify_qcash_state_proof,
};
pub use qcash::{
    QCashBlockJournal, QCashCoinId, QCashJournalState, QCashOutPoint, QCashRedeemability,
    QCashUtxo, QCashUtxoError, QCashUtxoSet,
};
pub use xpq::{XpqCoinId, XpqCoinSource, XpqOutPoint, XpqUtxo, XpqUtxoError, XpqUtxoSet};
