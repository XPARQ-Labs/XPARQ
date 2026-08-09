pub mod block;
pub mod codec;
pub mod consensus;
pub mod crypto;
pub mod genesis;
pub mod ledger;
pub mod state;
pub mod transaction;

pub use block::BlockError;
pub use codec::CodecError;
pub use consensus::ConsensusError;
pub use crypto::CryptoError;
pub use genesis::GenesisError;
pub use ledger::LedgerError;
pub use state::StateError;
pub use transaction::TransactionError;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn nested_consensus_error_preserves_complete_source_chain() {
        let error =
            ConsensusError::InvalidBlock(BlockError::Serialization(CodecError::EncodeFailed));
        let block = error.source().unwrap();
        let codec = block.source().unwrap();

        assert_eq!(
            block.to_string(),
            "block encoding failed: canonical value could not be encoded"
        );
        assert_eq!(codec.to_string(), "canonical value could not be encoded");
    }

    #[test]
    fn nested_ledger_transaction_error_preserves_source_chain() {
        let error = LedgerError::InvalidTransaction(TransactionError::Serialization(
            CodecError::InvalidTransaction,
        ));
        let transaction = error.source().unwrap();
        let codec = transaction.source().unwrap();

        assert_eq!(
            transaction.to_string(),
            "transaction encoding failed: decoded transaction is invalid"
        );
        assert_eq!(codec.to_string(), "decoded transaction is invalid");
    }
}
