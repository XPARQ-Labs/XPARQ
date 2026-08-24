use xparq::{
    block::{Block, Nonce},
    consensus::{ConsensusError, calculate_work_with_memory},
    crypto::{PoWMemory, hash_meets_difficulty},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MiningRange {
    pub start_nonce: u64,
    pub attempts: u64,
}

pub fn mine_range(
    block: &mut Block,
    range: MiningRange,
    memory: &mut PoWMemory,
) -> Result<Option<Nonce>, ConsensusError> {
    for offset in 0..range.attempts {
        let nonce = Nonce(range.start_nonce.wrapping_add(offset));
        block.header.nonce = nonce;
        let hash = calculate_work_with_memory(&block.header, memory)?;
        if hash_meets_difficulty(&hash, block.difficulty()) {
            return Ok(Some(nonce));
        }
    }
    Ok(None)
}
