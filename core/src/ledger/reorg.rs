use crate::block::Block;
use crate::crypto::BlockHash;
use crate::error::LedgerError;
use crate::ledger::fork_choice::ForkChoice;
use crate::ledger::{CheckpointSet, Ledger};

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
    checkpoints: &CheckpointSet,
    new_tip: BlockHash,
) -> Result<ReorgPlan, LedgerError> {
    let old_tip = active.tip_hash();
    let ancestor =
        common_ancestor(old_tip, new_tip, fork_choice).ok_or(LedgerError::InvalidParent)?;
    if !checkpoints.is_compatible(fork_choice, new_tip)
        || reorg_crosses_checkpoint(fork_choice, checkpoints, ancestor)?
    {
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

pub fn reorg_crosses_checkpoint(
    fork_choice: &ForkChoice,
    checkpoints: &CheckpointSet,
    ancestor: BlockHash,
) -> Result<bool, LedgerError> {
    let Some(checkpoint) = checkpoints.highest() else {
        return Ok(false);
    };
    let ancestor = fork_choice
        .get(&ancestor)
        .ok_or(LedgerError::InvalidParent)?;
    Ok(ancestor.height.0 < checkpoint.height.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_checkpoints_do_not_create_local_finality() {
        let checkpoints = CheckpointSet::empty();
        let genesis = crate::genesis::genesis_block().unwrap();
        let mut fork_choice = ForkChoice::new(genesis.hash().unwrap());
        let genesis = fork_choice.insert_block(genesis).unwrap();

        assert!(!reorg_crosses_checkpoint(&fork_choice, &checkpoints, genesis).unwrap());
    }
}
