use crate::block::Block;
use crate::crypto::BlockHash;
use crate::error::LedgerError;
use crate::ledger::FINALITY_DEPTH;
use crate::ledger::Ledger;
use crate::ledger::fork_choice::ForkChoice;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReorgPlan {
    pub ancestor: BlockHash,
    pub old_tip: Option<BlockHash>,
    pub new_tip: BlockHash,
    pub apply: Vec<Block>,
}

pub fn plan_reorg(
    active: &Ledger,
    fork_choice: &ForkChoice,
    new_tip: BlockHash,
) -> Result<ReorgPlan, LedgerError> {
    let old_tip = active.tip_hash();
    let ancestor =
        common_ancestor(old_tip, new_tip, fork_choice).ok_or(LedgerError::InvalidParent)?;
    if reorg_crosses_finality_boundary(active, fork_choice, ancestor) {
        return Err(LedgerError::FinalityViolation);
    }
    let apply = fork_choice
        .branch_from_ancestor(ancestor, new_tip)
        .ok_or(LedgerError::InvalidParent)?;

    Ok(ReorgPlan {
        ancestor,
        old_tip,
        new_tip,
        apply,
    })
}

pub fn common_ancestor(
    old_tip: Option<BlockHash>,
    new_tip: BlockHash,
    fork_choice: &ForkChoice,
) -> Option<BlockHash> {
    let old_tip = old_tip?;
    let old_ancestors: std::collections::BTreeSet<_> =
        fork_choice.ancestor_hashes(old_tip).into_iter().collect();

    fork_choice
        .ancestor_hashes(new_tip)
        .into_iter()
        .find(|hash| old_ancestors.contains(hash))
}

pub fn reorg_crosses_finality_boundary(
    active: &Ledger,
    fork_choice: &ForkChoice,
    ancestor: BlockHash,
) -> bool {
    let Some(tip_height) = active.tip_height() else {
        return false;
    };
    let Some(ancestor) = fork_choice.get(&ancestor) else {
        return true;
    };

    reorg_crosses_finality_height(tip_height.0, ancestor.height.0)
}

pub const fn reorg_crosses_finality_height(tip_height: u64, ancestor_height: u64) -> bool {
    let finalized_height = tip_height.saturating_sub(FINALITY_DEPTH as u64);
    ancestor_height < finalized_height
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finality_boundary_accepts_exact_checkpoint_and_rejects_one_block_deeper() {
        let tip = 100;
        let finalized = tip - FINALITY_DEPTH as u64;

        assert!(!reorg_crosses_finality_height(tip, finalized));
        assert!(reorg_crosses_finality_height(tip, finalized - 1));
    }

    #[test]
    fn short_chain_does_not_finalize_genesis_early() {
        assert!(!reorg_crosses_finality_height(FINALITY_DEPTH as u64 - 1, 0));
    }
}
