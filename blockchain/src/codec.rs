use crate::block::{Block, Header, MAX_BLOCK_WEIGHT};
use xparq_common::CodecError;
use xparq_crypto::BlockHash;

pub use xparq_common::{canonical_bytes, canonical_decode, canonical_deserialize};
pub use xparq_crypto::{HashDomain, domain_hash, hash_bytes};

pub fn block_header_bytes(header: &Header) -> Result<Vec<u8>, CodecError> {
    canonical_bytes(header)
}

pub fn block_bytes(block: &Block) -> Result<Vec<u8>, CodecError> {
    canonical_bytes(block)
}

pub fn block_header_hash(header: &Header) -> Result<BlockHash, CodecError> {
    Ok(BlockHash(
        domain_hash(HashDomain::Header, &block_header_bytes(header)?).0,
    ))
}

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
