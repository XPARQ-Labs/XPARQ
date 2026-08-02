use crate::block::{Block, BlockHeader, BlockHeight, MAX_BLOCK_WEIGHT};
use crate::crypto::{BlockHash, HASH_SIZE, StateRoot, TransactionHash};
pub use crate::crypto::{HashDomain, domain_hash, hash_bytes};
use crate::error::CodecError;
use crate::event::{MAX_PROTOCOL_EVENT_SIZE, ProtocolEvent};
use crate::transaction::{
    BatchTransfer, QCashTransaction, SignedBatchTransfer, SignedProtocolTransaction,
    SignedQCashTransaction,
};
use borsh::{BorshDeserialize, BorshSerialize};

/// Frozen consensus encoding profile. Changing any on-chain Borsh layout requires a new version.
pub const CANONICAL_ENCODING_VERSION: u8 = 1;
pub const CANONICAL_ENCODING_PROFILE: &str = "paqus-borsh-le";

/// Consensus-critical serialization. Do not replace or wrap this format under encoding version 1.
pub fn canonical_bytes<T: BorshSerialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    borsh::to_vec(value).map_err(|_| CodecError::EncodeFailed)
}

/// Canonically deserializes bytes without applying domain validation.
pub fn canonical_deserialize<T: BorshDeserialize>(bytes: &[u8]) -> Result<T, CodecError> {
    T::try_from_slice(bytes).map_err(|_| CodecError::DecodeFailed)
}

/// Alias for canonical deserialization. This does not imply consensus validity.
pub fn canonical_decode<T: BorshDeserialize>(bytes: &[u8]) -> Result<T, CodecError> {
    canonical_deserialize(bytes)
}

pub fn transaction_bytes(transaction: &BatchTransfer) -> Result<Vec<u8>, CodecError> {
    canonical_bytes(transaction)
}

pub fn signed_transaction_bytes(transaction: &SignedBatchTransfer) -> Result<Vec<u8>, CodecError> {
    canonical_bytes(transaction)
}

pub fn signed_protocol_transaction_bytes(
    transaction: &SignedProtocolTransaction,
) -> Result<Vec<u8>, CodecError> {
    canonical_bytes(transaction)
}

pub fn protocol_event_bytes(event: &ProtocolEvent) -> Result<Vec<u8>, CodecError> {
    canonical_bytes(event)
}

pub fn decode_protocol_event(bytes: &[u8]) -> Result<ProtocolEvent, CodecError> {
    if bytes.len() > MAX_PROTOCOL_EVENT_SIZE {
        return Err(CodecError::DecodeFailed);
    }
    let event: ProtocolEvent = canonical_deserialize(bytes)?;
    if !event.validate() {
        return Err(CodecError::DecodeFailed);
    }
    Ok(event)
}

pub fn block_header_bytes(header: &BlockHeader) -> Result<Vec<u8>, CodecError> {
    canonical_bytes(header)
}

pub fn block_bytes(block: &Block) -> Result<Vec<u8>, CodecError> {
    canonical_bytes(block)
}

pub fn state_root_bytes(state_root: &StateRoot) -> [u8; HASH_SIZE] {
    state_root.0
}

pub fn transaction_hash(transaction: &BatchTransfer) -> Result<TransactionHash, CodecError> {
    Ok(TransactionHash(
        domain_hash(HashDomain::Transaction, &transaction_bytes(transaction)?).0,
    ))
}

pub fn signed_transaction_hash(
    transaction: &SignedBatchTransfer,
) -> Result<TransactionHash, CodecError> {
    Ok(TransactionHash(
        domain_hash(
            HashDomain::Transaction,
            &signed_transaction_bytes(transaction)?,
        )
        .0,
    ))
}

pub fn block_header_hash(header: &BlockHeader) -> Result<BlockHash, CodecError> {
    Ok(BlockHash(
        domain_hash(HashDomain::BlockHeader, &block_header_bytes(header)?).0,
    ))
}

pub fn decode_transaction(bytes: &[u8]) -> Result<BatchTransfer, CodecError> {
    if bytes.len() > crate::transaction::MAX_TX_SIZE {
        return Err(CodecError::InvalidTransaction);
    }
    let transaction: BatchTransfer = canonical_deserialize(bytes)?;
    transaction
        .validate()
        .map_err(|_| CodecError::InvalidTransaction)?;
    Ok(transaction)
}

/// Decodes a signed transaction and verifies its signature and sender address.
pub fn decode_signed_transaction(bytes: &[u8]) -> Result<SignedBatchTransfer, CodecError> {
    if bytes.len() > crate::transaction::MAX_TX_SIZE {
        return Err(CodecError::InvalidTransaction);
    }
    let transaction: SignedBatchTransfer = canonical_deserialize(bytes)?;
    transaction
        .validate_signed()
        .map_err(|_| CodecError::InvalidTransaction)?;
    Ok(transaction)
}

#[cfg(feature = "devnet")]
pub fn decode_signed_batch_transfer_v2(
    bytes: &[u8],
    height: crate::block::BlockHeight,
    upgrade: Option<crate::crypto::CryptoUpgradePlan>,
) -> Result<crate::transaction::SignedBatchTransferV2, CodecError> {
    if bytes.len() > crate::transaction::MAX_TX_SIZE {
        return Err(CodecError::InvalidTransaction);
    }
    let transaction: crate::transaction::SignedBatchTransferV2 = canonical_deserialize(bytes)?;
    transaction
        .validate_signed_for_height(height, upgrade)
        .map_err(|_| CodecError::InvalidTransaction)?;
    Ok(transaction)
}

pub fn decode_qcash_transaction(bytes: &[u8]) -> Result<QCashTransaction, CodecError> {
    if bytes.len() > crate::transaction::qcash::MAX_QCASH_TX_SIZE {
        return Err(CodecError::InvalidTransaction);
    }
    let transaction: QCashTransaction = canonical_deserialize(bytes)?;
    transaction
        .validate()
        .map_err(|_| CodecError::InvalidTransaction)?;
    Ok(transaction)
}

pub fn decode_signed_qcash_transaction(bytes: &[u8]) -> Result<SignedQCashTransaction, CodecError> {
    if bytes.len() > crate::transaction::qcash::MAX_QCASH_TX_SIZE {
        return Err(CodecError::InvalidTransaction);
    }
    let transaction: SignedQCashTransaction = canonical_deserialize(bytes)?;
    transaction
        .validate_signed()
        .map_err(|_| CodecError::InvalidTransaction)?;
    Ok(transaction)
}

/// Decodes and validates a unified envelope in its block context.
///
/// Authorization signatures are state-dependent, so the caller supplies the
/// active policy resolver for the decoded account.
pub fn decode_signed_protocol_transaction_at<F>(
    bytes: &[u8],
    height: BlockHeight,
    _policy_for: F,
) -> Result<SignedProtocolTransaction, CodecError> {
    if bytes.len() > crate::transaction::MAX_PROTOCOL_TRANSACTION_SIZE {
        return Err(CodecError::InvalidTransaction);
    }
    let transaction: SignedProtocolTransaction = canonical_deserialize(bytes)?;
    let valid = match &transaction {
        SignedProtocolTransaction::BatchTransfer(transaction) => {
            transaction.validate_signed_for_height(height)
        }
        SignedProtocolTransaction::QCash(transaction) => {
            transaction.validate_signed_for_height(height)
        }
    };
    valid.map_err(|_| CodecError::InvalidTransaction)?;
    Ok(transaction)
}

/// Decodes a structurally valid block.
///
/// This validates block-local rules, including transaction signatures, merkle root, and size. It
/// does not validate proof of work, parent linkage, ledger state root, fork
/// choice, or coinbase subsidy against a ledger.
pub fn decode_block(bytes: &[u8]) -> Result<Block, CodecError> {
    if bytes.len() > MAX_BLOCK_WEIGHT {
        return Err(CodecError::InvalidBlock);
    }
    let block: Block = canonical_deserialize(bytes)?;
    block
        .validate_structure()
        .map_err(|_| CodecError::InvalidBlock)?;
    Ok(block)
}
