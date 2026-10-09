use kernel::{
    block::Block,
    common::Nonce,
    consensus::{ConsensusError, PoWTarget, calculate_work_with_memory},
    crypto::PoWMemory,
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
    let target =
        PoWTarget::from_compact(block.target_bits()).ok_or(ConsensusError::InvalidDifficulty)?;

    for offset in 0..range.attempts {
        let nonce = Nonce(range.start_nonce.wrapping_add(offset));

        block.header.nonce = nonce;

        let hash = calculate_work_with_memory(&block.header, memory)?;

        if target.meets(&hash) {
            return Ok(Some(nonce));
        }
    }

    Ok(None)
}
