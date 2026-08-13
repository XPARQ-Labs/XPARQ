#![allow(clippy::module_inception)]

pub mod chain;
pub mod checkpoint;
pub mod emission;
pub mod fork_choice;
pub mod header_chain;
pub mod invariants;
pub mod ledger;
pub mod reorg;
pub mod state_proof;
pub mod transition;

pub use crate::error::LedgerError;

pub const CONFIRMATION_DEPTH: u32 = 2;
pub const BLOCK_REWARD_MATURITY: u32 = 50;
/// Wallet/API transaction lifecycle threshold. This is not a PoW reorganization
/// limit; only an explicitly authenticated trust anchor can pin older history.
pub const FINALITY_DEPTH: u32 = 5;
/// Minimum height difference between the confirming withdraw and a redeem.
///
/// The QCash coin is active as soon as the withdraw block is accepted; only
/// redeem eligibility is delayed.
pub const QCASH_REDEEM_DELAY: u32 = 1;
/// A redeemed QCash credit follows the same spendability delay as a normal transfer.
pub const QCASH_REDEEM_CREDIT_MATURITY: u32 = CONFIRMATION_DEPTH;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionLifecycle {
    Pending,
    Included,
    Confirmed,
    Finalized,
}

impl TransactionLifecycle {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Included => "included",
            Self::Confirmed => "confirmed",
            Self::Finalized => "finalized",
        }
    }
}

pub const fn canonical_transaction_lifecycle(depth: u64) -> TransactionLifecycle {
    if depth >= FINALITY_DEPTH as u64 {
        TransactionLifecycle::Finalized
    } else if depth >= CONFIRMATION_DEPTH as u64 {
        TransactionLifecycle::Confirmed
    } else {
        TransactionLifecycle::Included
    }
}

pub use chain::Chain;
pub use checkpoint::{Checkpoint, CheckpointSet};
pub use fork_choice::Work;
pub use header_chain::{
    ChainHeader, HEADER_CHAIN_CHUNK_VERSION, HeaderChainChunk, HeaderChainChunkError,
    HeaderChainError, MAX_HEADER_CHAIN_CHUNK_HEADERS, MAX_HEADER_CHAIN_CHUNK_SIZE,
    RECENT_HEADER_WINDOW, TrustedHeaderCheckpoint, advance_trusted_header_checkpoint,
    decode_header_chain_chunk, trusted_header_checkpoint, verify_header_chain,
    verify_header_chain_extension,
};
pub use invariants::validate_ledger_invariants;
pub use ledger::{
    Ledger, QCashAccountJournal, calculate_protocol_state_root,
    calculate_protocol_state_root_from_roots,
};
pub use reorg::{ReorgPlan, common_ancestor, plan_reorg, reorg_crosses_checkpoint};
pub use state_proof::{
    ACCOUNT_STATE_PROOF_BUNDLE_VERSION, AccountNonMembershipProof, AccountNonMembershipProofBundle,
    AccountStateProof, AccountStateProofBundle, AccountStateProofBundleError,
    MAX_STATE_PROOF_BUNDLE_SIZE, ProofSide, QCashStateProofBundle, QCashStateProofBundleError,
    SparseStateTree, StateProofNode, VerifiedAccountAbsence, VerifiedAccountState,
    VerifiedQCashState, calculate_state_root, create_account_state_proof,
    decode_account_non_membership_proof_bundle, decode_account_state_proof_bundle,
    decode_qcash_state_proof_bundle, verify_account_non_membership_proof,
    verify_account_state_proof,
};
pub use transition::{
    BlockExecution, TransactionExecution, validate_signed_transaction_against_state,
    validate_transaction_against_state,
};

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn transaction_lifecycle_changes_at_confirmation_and_finality_boundaries() {
        assert_eq!(
            canonical_transaction_lifecycle(0),
            TransactionLifecycle::Included
        );
        assert_eq!(
            canonical_transaction_lifecycle(CONFIRMATION_DEPTH as u64 - 1),
            TransactionLifecycle::Included
        );
        assert_eq!(
            canonical_transaction_lifecycle(CONFIRMATION_DEPTH as u64),
            TransactionLifecycle::Confirmed
        );
        assert_eq!(
            canonical_transaction_lifecycle(FINALITY_DEPTH as u64),
            TransactionLifecycle::Finalized
        );
    }

    #[test]
    fn qcash_uses_one_block_offchain_delay_and_normal_redeem_confirmation() {
        assert_eq!(QCASH_REDEEM_DELAY, 1);
        assert_eq!(CONFIRMATION_DEPTH, 2);
        assert_eq!(FINALITY_DEPTH, 5);
        assert_eq!(QCASH_REDEEM_CREDIT_MATURITY, CONFIRMATION_DEPTH);
    }

    #[test]
    fn development_lifecycle_uses_one_two_five_boundaries() {
        assert_eq!(
            canonical_transaction_lifecycle(0),
            TransactionLifecycle::Included
        );
        assert_eq!(
            canonical_transaction_lifecycle(1),
            TransactionLifecycle::Included
        );
        assert_eq!(
            canonical_transaction_lifecycle(2),
            TransactionLifecycle::Confirmed
        );
        assert_eq!(
            canonical_transaction_lifecycle(5),
            TransactionLifecycle::Finalized
        );
    }
}
