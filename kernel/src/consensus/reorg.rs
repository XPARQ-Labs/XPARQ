use crate::blockchain::Block;
use crate::consensus::ForkChoice;
use crate::crypto::BlockHash;
use std::{collections::BTreeSet, error::Error, fmt};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReorgPlan {
    ancestor: BlockHash,
    old_tip: Option<BlockHash>,
    new_tip: BlockHash,
    /// Blocks to revert, ordered from the old tip down to the child of the
    /// common ancestor.
    disconnect: Vec<Block>,
    /// Blocks to connect, ordered from the child of the common ancestor up to
    /// the new tip.
    apply: Vec<Block>,
}

impl ReorgPlan {
    pub fn new(
        ancestor: BlockHash,
        old_tip: Option<BlockHash>,
        new_tip: BlockHash,
        disconnect: Vec<Block>,
        apply: Vec<Block>,
    ) -> Result<Self, ReorgError> {
        validate_disconnect(ancestor, old_tip, &disconnect)?;
        validate_apply(ancestor, new_tip, &apply)?;
        Ok(Self {
            ancestor,
            old_tip,
            new_tip,
            disconnect,
            apply,
        })
    }

    pub fn ancestor(&self) -> BlockHash {
        self.ancestor
    }

    pub fn old_tip(&self) -> Option<BlockHash> {
        self.old_tip
    }

    pub fn new_tip(&self) -> BlockHash {
        self.new_tip
    }

    pub fn disconnect(&self) -> &[Block] {
        &self.disconnect
    }

    pub fn apply(&self) -> &[Block] {
        &self.apply
    }

    pub fn into_branches(self) -> (Vec<Block>, Vec<Block>) {
        (self.disconnect, self.apply)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReorgError {
    InvalidBranch,
}

impl fmt::Display for ReorgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBranch => f.write_str("reorganization branch is incomplete or invalid"),
        }
    }
}

impl Error for ReorgError {}

pub fn plan_reorg(
    old_tip: Option<BlockHash>,
    fork_choice: &ForkChoice,
    new_tip: BlockHash,
) -> Result<ReorgPlan, ReorgError> {
    let ancestor =
        common_ancestor(old_tip, new_tip, fork_choice).ok_or(ReorgError::InvalidBranch)?;
    let apply = fork_choice
        .branch_from_ancestor(ancestor, new_tip)
        .ok_or(ReorgError::InvalidBranch)?;
    let mut disconnect = fork_choice
        .branch_from_ancestor(ancestor, old_tip.ok_or(ReorgError::InvalidBranch)?)
        .ok_or(ReorgError::InvalidBranch)?;
    disconnect.reverse();

    ReorgPlan::new(ancestor, old_tip, new_tip, disconnect, apply)
}

fn validate_disconnect(
    ancestor: BlockHash,
    old_tip: Option<BlockHash>,
    disconnect: &[Block],
) -> Result<(), ReorgError> {
    if disconnect.is_empty() {
        return (old_tip == Some(ancestor))
            .then_some(())
            .ok_or(ReorgError::InvalidBranch);
    }
    if disconnect.first().and_then(|block| block.hash().ok()) != old_tip {
        return Err(ReorgError::InvalidBranch);
    }
    for pair in disconnect.windows(2) {
        if pair[0].previous_hash() != pair[1].hash().map_err(|_| ReorgError::InvalidBranch)? {
            return Err(ReorgError::InvalidBranch);
        }
    }
    if disconnect
        .last()
        .ok_or(ReorgError::InvalidBranch)?
        .previous_hash()
        != ancestor
    {
        return Err(ReorgError::InvalidBranch);
    }
    Ok(())
}

fn validate_apply(
    ancestor: BlockHash,
    new_tip: BlockHash,
    apply: &[Block],
) -> Result<(), ReorgError> {
    if apply.is_empty() {
        return (new_tip == ancestor)
            .then_some(())
            .ok_or(ReorgError::InvalidBranch);
    }
    let mut expected_parent = ancestor;
    for block in apply {
        if block.previous_hash() != expected_parent {
            return Err(ReorgError::InvalidBranch);
        }
        expected_parent = block.hash().map_err(|_| ReorgError::InvalidBranch)?;
    }
    (expected_parent == new_tip)
        .then_some(())
        .ok_or(ReorgError::InvalidBranch)
}

pub fn common_ancestor(
    old_tip: Option<BlockHash>,
    new_tip: BlockHash,
    fork_choice: &ForkChoice,
) -> Option<BlockHash> {
    let old_ancestors: BTreeSet<_> = fork_choice.ancestor_hashes(old_tip?).into_iter().collect();
    fork_choice
        .ancestor_hashes(new_tip)
        .into_iter()
        .find(|hash| old_ancestors.contains(hash))
}
