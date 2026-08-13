//! Generic authenticated header-chain verification for PoW fork choice,
//! checkpoints, snapshots, and wallet proofs.

use crate::block::{Block, BlockHeight, Header};
use crate::crypto::BlockHash;
use crate::genesis::genesis_hash;
use crate::ledger::fork_choice::{ForkChoice, Work};
use borsh::{BorshDeserialize, BorshSerialize};
use std::error::Error;
use std::fmt;

pub const RECENT_HEADER_WINDOW: usize = crate::consensus::WBDA_WINDOW;
pub const HEADER_CHAIN_CHUNK_VERSION: u8 = 1;
pub const MAX_HEADER_CHAIN_CHUNK_HEADERS: usize = 4_096;
pub const MAX_HEADER_CHAIN_CHUNK_SIZE: usize = 1024 * 1024;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChainHeader {
    pub height: BlockHeight,
    pub header: Header,
}

impl ChainHeader {
    pub fn new(height: BlockHeight, header: Header) -> Self {
        Self { height, header }
    }

    pub fn block(&self) -> Block {
        Block::from_header(self.height, self.header.clone())
    }

    pub fn hash(&self) -> Result<BlockHash, crate::error::CodecError> {
        self.block().hash()
    }
}

/// A bounded transport unit for an otherwise unbounded header chain.
/// Verifiers retain only a [`TrustedHeaderCheckpoint`] between chunks.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct HeaderChainChunk {
    pub version: u8,
    pub headers: Vec<ChainHeader>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderChainChunkError {
    UnsupportedVersion,
    Empty,
    HeaderLimitExceeded,
    ChunkSizeExceeded,
    Serialization(crate::error::CodecError),
}

impl fmt::Display for HeaderChainChunkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion => f.write_str("unsupported header-chain chunk version"),
            Self::Empty => f.write_str("header-chain chunk is empty"),
            Self::HeaderLimitExceeded => f.write_str("header-chain chunk header limit exceeded"),
            Self::ChunkSizeExceeded => f.write_str("header-chain chunk size limit exceeded"),
            Self::Serialization(error) => write!(f, "header-chain chunk decoding failed: {error}"),
        }
    }
}

impl Error for HeaderChainChunkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serialization(error) => Some(error),
            _ => None,
        }
    }
}

impl HeaderChainChunk {
    pub fn new(headers: Vec<ChainHeader>) -> Result<Self, HeaderChainChunkError> {
        if headers.is_empty() {
            return Err(HeaderChainChunkError::Empty);
        }
        if headers.len() > MAX_HEADER_CHAIN_CHUNK_HEADERS {
            return Err(HeaderChainChunkError::HeaderLimitExceeded);
        }
        Ok(Self {
            version: HEADER_CHAIN_CHUNK_VERSION,
            headers,
        })
    }
}

pub fn decode_header_chain_chunk(bytes: &[u8]) -> Result<HeaderChainChunk, HeaderChainChunkError> {
    if bytes.len() > MAX_HEADER_CHAIN_CHUNK_SIZE {
        return Err(HeaderChainChunkError::ChunkSizeExceeded);
    }
    // Borsh encodes the version byte followed by the Vec's little-endian u32
    // length. Reject a hostile count before Vec decoding can allocate.
    let Some(length_bytes) = bytes.get(1..5) else {
        return Err(HeaderChainChunkError::Serialization(
            crate::error::CodecError::DecodeFailed,
        ));
    };
    let declared_headers = u32::from_le_bytes(
        length_bytes
            .try_into()
            .expect("the checked header-count slice is four bytes"),
    ) as usize;
    if declared_headers > MAX_HEADER_CHAIN_CHUNK_HEADERS {
        return Err(HeaderChainChunkError::HeaderLimitExceeded);
    }
    let chunk: HeaderChainChunk =
        crate::codec::canonical_deserialize(bytes).map_err(HeaderChainChunkError::Serialization)?;
    if chunk.version != HEADER_CHAIN_CHUNK_VERSION {
        return Err(HeaderChainChunkError::UnsupportedVersion);
    }
    if chunk.headers.is_empty() {
        return Err(HeaderChainChunkError::Empty);
    }
    if chunk.headers.len() > MAX_HEADER_CHAIN_CHUNK_HEADERS {
        return Err(HeaderChainChunkError::HeaderLimitExceeded);
    }
    Ok(chunk)
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct TrustedHeaderCheckpoint {
    pub height: BlockHeight,
    pub header: Header,
    pub cumulative_work: Work,
    pub difficulty_anchor: ChainHeader,
    pub recent_headers: Vec<ChainHeader>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderChainError {
    EmptyHeaderChain,
    WrongGenesis,
    InvalidHeaderChain(crate::ledger::fork_choice::ForkChoiceError),
    InvalidCommonAncestor,
    Serialization(crate::error::CodecError),
}

impl fmt::Display for HeaderChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyHeaderChain => "header chain is empty",
            Self::WrongGenesis => "header chain does not start at configured genesis",
            Self::InvalidHeaderChain(_) => "header chain is invalid",
            Self::InvalidCommonAncestor => "header chain common ancestor is invalid",
            Self::Serialization(_) => "header chain serialization failed",
        };
        match self {
            Self::InvalidHeaderChain(error) => write!(f, "{message}: {error}"),
            Self::Serialization(error) => write!(f, "{message}: {error}"),
            _ => f.write_str(message),
        }
    }
}

impl Error for HeaderChainError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidHeaderChain(error) => Some(error),
            Self::Serialization(error) => Some(error),
            _ => None,
        }
    }
}

/// Verifies a complete header chain from the configured genesis, including
/// linkage, difficulty adjustment and proof of work.
///
/// The returned work is suitable for comparing independently obtained
/// candidate chains. Callers must still bind any state data to the returned
/// tip hash and the tip header's state commitment.
pub fn verify_header_chain(headers: &[ChainHeader]) -> Result<(BlockHash, Work), HeaderChainError> {
    let first = headers.first().ok_or(HeaderChainError::EmptyHeaderChain)?;
    let expected_genesis = genesis_hash().map_err(HeaderChainError::Serialization)?;
    if first.height.0 != 0
        || first.hash().map_err(HeaderChainError::Serialization)?.0 != expected_genesis.0
    {
        return Err(HeaderChainError::WrongGenesis);
    }
    let mut fork_choice = ForkChoice::new(expected_genesis.into());
    for header in headers {
        let block = header.block();
        fork_choice
            .insert_block(block)
            .map_err(HeaderChainError::InvalidHeaderChain)?;
    }
    let tip = fork_choice
        .best_tip()
        .ok_or(crate::ledger::fork_choice::ForkChoiceError::MissingParent)
        .map_err(HeaderChainError::InvalidHeaderChain)?;
    Ok((tip.hash, tip.cumulative_work))
}

pub fn trusted_header_checkpoint(
    validated_headers: &[ChainHeader],
) -> Result<TrustedHeaderCheckpoint, HeaderChainError> {
    let (_, cumulative_work) = verify_header_chain(validated_headers)?;
    let tip = validated_headers
        .last()
        .cloned()
        .ok_or(HeaderChainError::EmptyHeaderChain)?;
    let difficulty_anchor = validated_headers
        .get(usize::from(tip.height.0 > 0))
        .cloned()
        .ok_or(HeaderChainError::EmptyHeaderChain)?;
    let start = validated_headers.len().saturating_sub(RECENT_HEADER_WINDOW);
    Ok(TrustedHeaderCheckpoint {
        height: tip.height,
        header: tip.header,
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
    headers: &[ChainHeader],
) -> Result<(BlockHash, Work), HeaderChainError> {
    let checkpoint_hash = checkpoint
        .header
        .hash()
        .map_err(HeaderChainError::Serialization)?;
    if checkpoint.recent_headers.is_empty()
        || checkpoint.recent_headers.len() > RECENT_HEADER_WINDOW
        || checkpoint
            .recent_headers
            .last()
            .is_none_or(|tip| tip.header != checkpoint.header)
    {
        return Err(HeaderChainError::InvalidCommonAncestor);
    }
    let mut previous_height = checkpoint.height;
    let mut previous = checkpoint.header.clone();
    let mut previous_hash = checkpoint_hash;
    let mut cumulative_work = checkpoint.cumulative_work;
    let mut recent = checkpoint.recent_headers.clone();
    for chain_header in headers {
        let header = &chain_header.header;
        if chain_header.height.0 != previous_height.0.saturating_add(1)
            || BlockHash(header.previous_hash.0) != previous_hash
        {
            return Err(HeaderChainError::InvalidCommonAncestor);
        }
        let expected_difficulty = if crate::consensus::is_wbda_epoch_boundary(chain_header.height.0)
        {
            if recent.len() < crate::consensus::WBDA_WINDOW {
                return Err(HeaderChainError::InvalidHeaderChain(
                    crate::ledger::fork_choice::ForkChoiceError::MissingParent,
                ));
            }
            let start = recent.len() - crate::consensus::WBDA_WINDOW;
            let weights = recent[start..]
                .iter()
                .map(|header| usize::try_from(header.header.block_weight))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| {
                    HeaderChainError::InvalidHeaderChain(
                        crate::ledger::fork_choice::ForkChoiceError::InvalidDifficulty,
                    )
                })?;
            crate::consensus::next_difficulty_from_window(previous.difficulty, &weights).ok_or(
                HeaderChainError::InvalidHeaderChain(
                    crate::ledger::fork_choice::ForkChoiceError::InvalidDifficulty,
                ),
            )?
        } else {
            previous.difficulty
        };
        if header.difficulty != expected_difficulty {
            return Err(HeaderChainError::InvalidHeaderChain(
                crate::ledger::fork_choice::ForkChoiceError::InvalidDifficulty,
            ));
        }
        let block = chain_header.block();
        crate::consensus::Consensus::validate_pow_at_difficulty(&block, expected_difficulty)
            .map_err(|error| {
                HeaderChainError::InvalidHeaderChain(
                    crate::ledger::fork_choice::ForkChoiceError::InvalidProofOfWork(error),
                )
            })?;
        cumulative_work = cumulative_work
            .saturating_add(crate::ledger::fork_choice::block_work(expected_difficulty));
        previous_hash = header.hash().map_err(HeaderChainError::Serialization)?;
        previous_height = chain_header.height;
        previous = header.clone();
        recent.push(chain_header.clone());
        if recent.len() > RECENT_HEADER_WINDOW {
            recent.remove(0);
        }
    }
    Ok((previous_hash, cumulative_work))
}

pub fn advance_trusted_header_checkpoint(
    checkpoint: &TrustedHeaderCheckpoint,
    headers: &[ChainHeader],
) -> Result<TrustedHeaderCheckpoint, HeaderChainError> {
    let (_, cumulative_work) = verify_header_chain_extension(checkpoint, headers)?;
    let mut recent_headers = checkpoint.recent_headers.clone();
    recent_headers.extend_from_slice(headers);
    if recent_headers.len() > RECENT_HEADER_WINDOW {
        recent_headers = recent_headers[recent_headers.len() - RECENT_HEADER_WINDOW..].to_vec();
    }
    Ok(TrustedHeaderCheckpoint {
        height: headers
            .last()
            .map(|header| header.height)
            .unwrap_or(checkpoint.height),
        header: headers
            .last()
            .map(|header| header.header.clone())
            .unwrap_or_else(|| checkpoint.header.clone()),
        cumulative_work,
        difficulty_anchor: checkpoint.difficulty_anchor.clone(),
        recent_headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{EmissionTransaction, Height, Nonce};
    use crate::consensus::supply::Amount;
    use crate::consensus::{Consensus, DIFFICULTY_START};
    use crate::crypto::Address;

    #[test]
    fn header_chain_verification_uses_the_original_pow_nonce() {
        let genesis = crate::genesis::genesis_block().unwrap();
        let genesis_hash = genesis.hash().unwrap();
        let miner = Address([7; crate::crypto::ADDRESS_SIZE]);
        let mut block = Block::from_protocol_transactions(
            Height(1),
            genesis_hash,
            DIFFICULTY_START,
            Nonce(1),
            Some(EmissionTransaction::new(miner, Amount(0))),
            Vec::new(),
        )
        .unwrap();
        while Consensus::validate_pow_at_difficulty(&block, DIFFICULTY_START).is_err() {
            block.header.nonce.0 = block.header.nonce.0.saturating_add(1);
        }
        assert_ne!(block.header.nonce, Nonce(0));

        let headers = vec![
            ChainHeader::new(genesis.height(), genesis.header),
            ChainHeader::new(block.height(), block.header.clone()),
        ];
        assert!(verify_header_chain(&headers).is_ok());

        let mut wrong_nonce = headers;
        let mut invalid_nonce = 0_u64;
        loop {
            wrong_nonce[1].header.nonce = Nonce(invalid_nonce);
            if wrong_nonce[1].header.nonce != block.header.nonce
                && Consensus::validate_pow_at_difficulty(&wrong_nonce[1].block(), DIFFICULTY_START)
                    .is_err()
            {
                break;
            }
            invalid_nonce = invalid_nonce.saturating_add(1);
        }
        assert!(verify_header_chain(&wrong_nonce).is_err());
    }

    #[test]
    fn header_chain_chunk_roundtrips_with_a_per_chunk_bound() {
        let genesis = crate::genesis::genesis_block().unwrap();
        let chunk = HeaderChainChunk::new(vec![ChainHeader::new(genesis.height(), genesis.header)])
            .unwrap();
        let bytes = crate::codec::canonical_bytes(&chunk).unwrap();

        assert_eq!(decode_header_chain_chunk(&bytes).unwrap(), chunk);
        assert_eq!(
            HeaderChainChunk::new(vec![
                chunk.headers[0].clone();
                MAX_HEADER_CHAIN_CHUNK_HEADERS + 1
            ]),
            Err(HeaderChainChunkError::HeaderLimitExceeded)
        );
        let mut hostile = vec![HEADER_CHAIN_CHUNK_VERSION];
        hostile.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            decode_header_chain_chunk(&hostile),
            Err(HeaderChainChunkError::HeaderLimitExceeded)
        );
    }
}
