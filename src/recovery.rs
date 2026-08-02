use crate::block::merkle::MerkleInclusionProof;
use crate::block::{Block, BlockHeader, BlockHeight, BlockProof, Nonce};
use crate::crypto::{BlockHash, HashDomain};
use crate::genesis::GENESIS_HASH;
use crate::ledger::fork_choice::{ForkChoice, Work};
use crate::transaction::{SignedProtocolTransaction, TransactionError};
use borsh::{BorshDeserialize, BorshSerialize};
use std::error::Error;
use std::fmt;

pub const ROLLBACK_PROOF_VERSION: u8 = 1;
pub const RECENT_HEADER_WINDOW: usize = crate::consensus::WBDA_WINDOW;
pub const MAX_ROLLBACK_PROOF_HEADERS: usize = 1_000_000;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlockHeaderProof {
    pub header: BlockHeader,
    pub proof: BlockProof,
}

impl BlockHeaderProof {
    pub fn new(header: BlockHeader, proof: BlockProof) -> Self {
        Self { header, proof }
    }

    pub fn block(&self) -> Block {
        Block::from_header_with_proof(self.header.clone(), self.proof.clone())
    }

    pub fn hash(&self) -> Result<BlockHash, crate::error::CodecError> {
        self.block().hash()
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct TrustedHeaderCheckpoint {
    pub header: BlockHeader,
    pub cumulative_work: Work,
    pub difficulty_anchor: BlockHeader,
    pub recent_headers: Vec<BlockHeader>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct RollbackProofBundle {
    pub version: u8,
    pub transaction: SignedProtocolTransaction,
    pub disconnected_block_header: BlockHeader,
    pub transaction_proof: MerkleInclusionProof,
    /// Complete header path from frozen genesis through the disconnected tip.
    pub losing_headers: Vec<BlockHeader>,
    /// Complete header path from frozen genesis through the selected canonical tip.
    pub canonical_headers: Vec<BlockHeader>,
    pub common_ancestor: BlockHash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedRollbackProof {
    pub transaction_hash: crate::crypto::TransactionHash,
    pub disconnected_block_hash: BlockHash,
    pub common_ancestor: BlockHash,
    pub losing_tip: BlockHash,
    pub canonical_tip: BlockHash,
    pub losing_work: Work,
    pub canonical_work: Work,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RollbackProofError {
    UnsupportedVersion,
    HeaderLimitExceeded,
    EmptyHeaderChain,
    WrongGenesis,
    InvalidHeaderChain(crate::ledger::fork_choice::ForkChoiceError),
    InvalidCommonAncestor,
    DisconnectedBlockNotOnLosingBranch,
    TransactionInvalid(TransactionError),
    TransactionProofInvalid,
    CanonicalBranchDoesNotWin,
    Serialization(crate::error::CodecError),
}

impl fmt::Display for RollbackProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedVersion => "unsupported rollback proof version",
            Self::HeaderLimitExceeded => "rollback proof header limit exceeded",
            Self::EmptyHeaderChain => "rollback proof contains an empty header chain",
            Self::WrongGenesis => "rollback proof does not start at frozen genesis",
            Self::InvalidHeaderChain(_) => "rollback proof header chain is invalid",
            Self::InvalidCommonAncestor => "rollback proof common ancestor is invalid",
            Self::DisconnectedBlockNotOnLosingBranch => {
                "disconnected block is not on the losing branch"
            }
            Self::TransactionInvalid(_) => "rollback proof transaction is invalid",
            Self::TransactionProofInvalid => "rollback transaction inclusion proof is invalid",
            Self::CanonicalBranchDoesNotWin => "rollback canonical branch does not win fork choice",
            Self::Serialization(_) => "rollback proof serialization failed",
        };
        match self {
            Self::InvalidHeaderChain(error) => write!(f, "{message}: {error}"),
            Self::TransactionInvalid(error) => write!(f, "{message}: {error}"),
            Self::Serialization(error) => write!(f, "{message}: {error}"),
            _ => f.write_str(message),
        }
    }
}

impl Error for RollbackProofError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidHeaderChain(error) => Some(error),
            Self::TransactionInvalid(error) => Some(error),
            Self::Serialization(error) => Some(error),
            _ => None,
        }
    }
}

impl RollbackProofBundle {
    pub fn verify(&self) -> Result<VerifiedRollbackProof, RollbackProofError> {
        if self.version != ROLLBACK_PROOF_VERSION {
            return Err(RollbackProofError::UnsupportedVersion);
        }
        if self.losing_headers.len() > MAX_ROLLBACK_PROOF_HEADERS
            || self.canonical_headers.len() > MAX_ROLLBACK_PROOF_HEADERS
        {
            return Err(RollbackProofError::HeaderLimitExceeded);
        }
        let (losing_tip, losing_work) = verify_header_chain(&self.losing_headers)?;
        let (canonical_tip, canonical_work) = verify_header_chain(&self.canonical_headers)?;
        let shared_count = self
            .losing_headers
            .iter()
            .zip(&self.canonical_headers)
            .take_while(|(left, right)| left == right)
            .count();
        if shared_count == 0
            || shared_count == self.losing_headers.len()
            || shared_count == self.canonical_headers.len()
        {
            return Err(RollbackProofError::InvalidCommonAncestor);
        }
        let common_ancestor = self.losing_headers[shared_count - 1]
            .hash()
            .map_err(RollbackProofError::Serialization)?;
        if common_ancestor != self.common_ancestor {
            return Err(RollbackProofError::InvalidCommonAncestor);
        }
        let disconnected_block_hash = self
            .disconnected_block_header
            .hash()
            .map_err(RollbackProofError::Serialization)?;
        if !self.losing_headers[shared_count..]
            .iter()
            .any(|header| header == &self.disconnected_block_header)
        {
            return Err(RollbackProofError::DisconnectedBlockNotOnLosingBranch);
        }
        validate_signed_transaction(&self.transaction, self.disconnected_block_header.height)?;
        let transaction_hash = self
            .transaction
            .hash()
            .map_err(RollbackProofError::Serialization)?;
        if !self.transaction_proof.verify(
            transaction_hash.as_hash(),
            self.disconnected_block_header.merkle_root.as_hash(),
            HashDomain::MerkleNode,
        ) {
            return Err(RollbackProofError::TransactionProofInvalid);
        }
        if canonical_work < losing_work
            || (canonical_work == losing_work && canonical_tip >= losing_tip)
        {
            return Err(RollbackProofError::CanonicalBranchDoesNotWin);
        }
        Ok(VerifiedRollbackProof {
            transaction_hash,
            disconnected_block_hash,
            common_ancestor,
            losing_tip,
            canonical_tip,
            losing_work,
            canonical_work,
        })
    }
}

/// Verifies a complete header chain from the frozen genesis, including
/// linkage, difficulty adjustment and proof of work.
///
/// The returned work is suitable for comparing independently obtained
/// candidate chains. Callers must still bind any state data to the returned
/// tip hash and the tip header's state commitment.
pub fn verify_header_chain(
    headers: &[BlockHeader],
) -> Result<(BlockHash, Work), RollbackProofError> {
    let headers = headers
        .iter()
        .cloned()
        .map(|header| BlockHeaderProof::new(header, BlockProof::new(Nonce(0))))
        .collect::<Vec<_>>();
    verify_header_proof_chain(&headers)
}

pub fn verify_header_proof_chain(
    headers: &[BlockHeaderProof],
) -> Result<(BlockHash, Work), RollbackProofError> {
    let first = headers
        .first()
        .ok_or(RollbackProofError::EmptyHeaderChain)?;
    if first.header.height.0 != 0
        || first.hash().map_err(RollbackProofError::Serialization)?.0 != GENESIS_HASH
    {
        return Err(RollbackProofError::WrongGenesis);
    }
    let mut fork_choice = ForkChoice::new();
    for header in headers {
        let block = header.block();
        fork_choice
            .insert_block(block)
            .map_err(RollbackProofError::InvalidHeaderChain)?;
    }
    let tip = fork_choice
        .best_tip()
        .ok_or(crate::ledger::fork_choice::ForkChoiceError::MissingParent)
        .map_err(RollbackProofError::InvalidHeaderChain)?;
    Ok((tip.hash, tip.cumulative_work))
}

pub fn trusted_header_checkpoint(
    validated_headers: &[BlockHeader],
) -> Result<TrustedHeaderCheckpoint, RollbackProofError> {
    let (_, cumulative_work) = verify_header_chain(validated_headers)?;
    let header = validated_headers
        .last()
        .cloned()
        .ok_or(RollbackProofError::EmptyHeaderChain)?;
    let difficulty_anchor = validated_headers
        .get(usize::from(header.height.0 > 0))
        .cloned()
        .ok_or(RollbackProofError::EmptyHeaderChain)?;
    let start = validated_headers.len().saturating_sub(RECENT_HEADER_WINDOW);
    Ok(TrustedHeaderCheckpoint {
        header,
        cumulative_work,
        difficulty_anchor,
        recent_headers: validated_headers[start..].to_vec(),
    })
}

/// Validates only the headers following a previously fully validated
/// checkpoint. Non-boundary headers inherit parent difficulty. WBDA epoch
/// boundaries are verified from the raw block weights committed in recent
/// headers.
pub fn verify_header_chain_extension(
    checkpoint: &TrustedHeaderCheckpoint,
    headers: &[BlockHeader],
) -> Result<(BlockHash, Work), RollbackProofError> {
    let checkpoint_hash = checkpoint
        .header
        .hash()
        .map_err(RollbackProofError::Serialization)?;
    if checkpoint.recent_headers.is_empty()
        || checkpoint.recent_headers.len() > RECENT_HEADER_WINDOW
        || checkpoint.recent_headers.last() != Some(&checkpoint.header)
    {
        return Err(RollbackProofError::InvalidCommonAncestor);
    }
    let mut previous = checkpoint.header.clone();
    let mut previous_hash = checkpoint_hash;
    let mut cumulative_work = checkpoint.cumulative_work;
    let mut recent = checkpoint.recent_headers.clone();
    for header in headers {
        if header.height.0 != previous.height.0.saturating_add(1)
            || BlockHash(header.previous_hash.0) != previous_hash
        {
            return Err(RollbackProofError::InvalidCommonAncestor);
        }
        let expected_difficulty = if crate::consensus::is_wbda_epoch_boundary(header.height.0) {
            if recent.len() < crate::consensus::WBDA_WINDOW {
                return Err(RollbackProofError::InvalidHeaderChain(
                    crate::ledger::fork_choice::ForkChoiceError::MissingParent,
                ));
            }
            let start = recent.len() - crate::consensus::WBDA_WINDOW;
            let weights = recent[start..]
                .iter()
                .map(|header| usize::try_from(header.block_weight))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| {
                    RollbackProofError::InvalidHeaderChain(
                        crate::ledger::fork_choice::ForkChoiceError::InvalidDifficulty,
                    )
                })?;
            crate::consensus::next_difficulty_from_window(previous.difficulty, &weights).ok_or(
                RollbackProofError::InvalidHeaderChain(
                    crate::ledger::fork_choice::ForkChoiceError::InvalidDifficulty,
                ),
            )?
        } else {
            previous.difficulty
        };
        if header.difficulty != expected_difficulty {
            return Err(RollbackProofError::InvalidHeaderChain(
                crate::ledger::fork_choice::ForkChoiceError::InvalidDifficulty,
            ));
        }
        let block = Block::from_header_with_proof(header.clone(), BlockProof::new(Nonce(0)));
        crate::consensus::Consensus::validate_proof_of_work_at_difficulty(
            &block,
            expected_difficulty,
        )
        .map_err(|error| {
            RollbackProofError::InvalidHeaderChain(
                crate::ledger::fork_choice::ForkChoiceError::InvalidProofOfWork(error),
            )
        })?;
        cumulative_work = cumulative_work
            .saturating_add(crate::ledger::fork_choice::block_work(expected_difficulty));
        previous_hash = header.hash().map_err(RollbackProofError::Serialization)?;
        previous = header.clone();
        recent.push(header.clone());
        if recent.len() > RECENT_HEADER_WINDOW {
            recent.remove(0);
        }
    }
    Ok((previous_hash, cumulative_work))
}

pub fn advance_trusted_header_checkpoint(
    checkpoint: &TrustedHeaderCheckpoint,
    headers: &[BlockHeader],
) -> Result<TrustedHeaderCheckpoint, RollbackProofError> {
    let (_, cumulative_work) = verify_header_chain_extension(checkpoint, headers)?;
    let mut recent_headers = checkpoint.recent_headers.clone();
    recent_headers.extend_from_slice(headers);
    if recent_headers.len() > RECENT_HEADER_WINDOW {
        recent_headers = recent_headers[recent_headers.len() - RECENT_HEADER_WINDOW..].to_vec();
    }
    Ok(TrustedHeaderCheckpoint {
        header: headers
            .last()
            .cloned()
            .unwrap_or_else(|| checkpoint.header.clone()),
        cumulative_work,
        difficulty_anchor: checkpoint.difficulty_anchor.clone(),
        recent_headers,
    })
}

fn validate_signed_transaction(
    transaction: &SignedProtocolTransaction,
    height: BlockHeight,
) -> Result<(), RollbackProofError> {
    let result = match transaction {
        SignedProtocolTransaction::Transfer(transaction) => {
            transaction.validate_signed_for_height(height)
        }
        SignedProtocolTransaction::QCash(transaction) => {
            transaction.validate_signed_for_height(height)
        }
    };
    result.map_err(RollbackProofError::TransactionInvalid)
}
