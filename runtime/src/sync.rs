use std::{error::Error, fmt};

use borsh::{BorshDeserialize, BorshSerialize};
use xparq::{common::canonical_decode, consensus::HeaderAtHeight};

/// Keep verified-header batches small enough that Argon2id validation finishes
/// before the peer session read timeout and naturally provides regular
/// request/response progress on long catch-up sessions.
pub const MAX_HEADER_CHAIN_CHUNK_HEADERS: usize = 32;
pub const MAX_HEADER_CHAIN_CHUNK_SIZE: usize = 1024 * 1024;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct HeaderChainChunk {
    pub headers: Vec<HeaderAtHeight>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderChainChunkError {
    Empty,
    HeaderLimitExceeded,
    ChunkSizeExceeded,
    DecodeFailed,
}

impl fmt::Display for HeaderChainChunkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("header-chain chunk is empty"),
            Self::HeaderLimitExceeded => {
                formatter.write_str("header-chain chunk header limit exceeded")
            }
            Self::ChunkSizeExceeded => {
                formatter.write_str("header-chain chunk size limit exceeded")
            }
            Self::DecodeFailed => formatter.write_str("header-chain chunk decoding failed"),
        }
    }
}

impl Error for HeaderChainChunkError {}

impl HeaderChainChunk {
    pub fn new(headers: Vec<HeaderAtHeight>) -> Result<Self, HeaderChainChunkError> {
        if headers.is_empty() {
            return Err(HeaderChainChunkError::Empty);
        }
        if headers.len() > MAX_HEADER_CHAIN_CHUNK_HEADERS {
            return Err(HeaderChainChunkError::HeaderLimitExceeded);
        }
        Ok(Self { headers })
    }
}

pub fn decode_header_chain_chunk(bytes: &[u8]) -> Result<HeaderChainChunk, HeaderChainChunkError> {
    if bytes.len() > MAX_HEADER_CHAIN_CHUNK_SIZE {
        return Err(HeaderChainChunkError::ChunkSizeExceeded);
    }
    let declared_headers = bytes
        .get(..4)
        .and_then(|length| length.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(HeaderChainChunkError::DecodeFailed)? as usize;
    if declared_headers > MAX_HEADER_CHAIN_CHUNK_HEADERS {
        return Err(HeaderChainChunkError::HeaderLimitExceeded);
    }
    let chunk: HeaderChainChunk =
        canonical_decode(bytes).map_err(|_| HeaderChainChunkError::DecodeFailed)?;
    if chunk.headers.is_empty() {
        return Err(HeaderChainChunkError::Empty);
    }
    if chunk.headers.len() > MAX_HEADER_CHAIN_CHUNK_HEADERS {
        return Err(HeaderChainChunkError::HeaderLimitExceeded);
    }
    Ok(chunk)
}
