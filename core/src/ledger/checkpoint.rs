use crate::block::Height;
use crate::crypto::BlockHash;
use crate::ledger::fork_choice::ForkChoice;
use std::collections::BTreeMap;

/// Hard checkpoints authenticated by an explicit snapshot or release trust
/// anchor. Nodes never derive a checkpoint from their local canonical view;
/// an empty set leaves cumulative-work fork choice unrestricted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CheckpointSet {
    checkpoints: BTreeMap<u64, BlockHash>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: Height,
    pub hash: BlockHash,
}

impl CheckpointSet {
    pub const fn empty() -> Self {
        Self {
            checkpoints: BTreeMap::new(),
        }
    }

    pub fn from_pairs(pairs: impl IntoIterator<Item = (Height, BlockHash)>) -> Self {
        Self {
            checkpoints: pairs
                .into_iter()
                .map(|(height, hash)| (height.0, hash))
                .collect(),
        }
    }

    pub fn highest(&self) -> Option<Checkpoint> {
        self.checkpoints
            .iter()
            .next_back()
            .map(|(&height, &hash)| Checkpoint {
                height: Height(height),
                hash,
            })
    }

    pub fn insert(&mut self, checkpoint: Checkpoint) -> Result<(), crate::error::LedgerError> {
        if self
            .checkpoints
            .get(&checkpoint.height.0)
            .is_some_and(|hash| *hash != checkpoint.hash)
        {
            return Err(crate::error::LedgerError::FinalityViolation);
        }
        self.checkpoints
            .insert(checkpoint.height.0, checkpoint.hash);
        Ok(())
    }

    /// A candidate below a checkpoint is merely incomplete. Once it reaches a
    /// checkpoint height it must contain the exact trust-anchor-defined block.
    pub fn is_compatible(&self, fork_choice: &ForkChoice, tip: BlockHash) -> bool {
        let Some(candidate) = fork_choice.get(&tip) else {
            return false;
        };
        self.checkpoints.iter().all(|(&height, &expected)| {
            if candidate.height.0 < height {
                return true;
            }
            fork_choice.ancestor_hash_at_height(tip, Height(height)) == Some(expected)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reached_checkpoint_must_match_exact_hash() {
        let genesis = crate::genesis::genesis_block().unwrap();
        let genesis_hash = genesis.hash().unwrap();
        let mut fork_choice = ForkChoice::new(genesis_hash);
        fork_choice.insert_block(genesis).unwrap();

        assert!(
            CheckpointSet::from_pairs([(Height(0), genesis_hash)])
                .is_compatible(&fork_choice, genesis_hash)
        );
        assert!(
            !CheckpointSet::from_pairs([(Height(0), BlockHash::ZERO)])
                .is_compatible(&fork_choice, genesis_hash)
        );
    }

    #[test]
    fn checkpoint_hash_cannot_be_replaced_at_the_same_height() {
        let mut checkpoints = CheckpointSet::empty();
        checkpoints
            .insert(Checkpoint {
                height: Height(4_100),
                hash: BlockHash([1; crate::crypto::HASH_SIZE]),
            })
            .unwrap();

        assert_eq!(
            checkpoints.insert(Checkpoint {
                height: Height(4_100),
                hash: BlockHash([2; crate::crypto::HASH_SIZE]),
            }),
            Err(crate::error::LedgerError::FinalityViolation)
        );
    }
}
