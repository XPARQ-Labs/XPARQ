use crate::block::{BlockHeight, Height};
use crate::crypto::{BlockHash, Hash, HashDomain, StateRoot, domain_hash};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

pub type BlockStateCommitmentId = Hash;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct BlockStateCommitment {
    pub height: BlockHeight,
    pub block_hash: BlockHash,
    pub account_state_root: StateRoot,
    pub qcash_state_root: StateRoot,
    pub governance_state_root: StateRoot,
    pub credential_use_state_root: StateRoot,
    pub protocol_state_root: StateRoot,
}

impl BlockStateCommitment {
    pub const ZERO: Self = Self {
        height: Height(0),
        block_hash: BlockHash([0; crate::crypto::HASH_SIZE]),
        account_state_root: StateRoot::ZERO,
        qcash_state_root: StateRoot::ZERO,
        governance_state_root: StateRoot::ZERO,
        credential_use_state_root: StateRoot::ZERO,
        protocol_state_root: StateRoot::ZERO,
    };

    pub fn new(
        height: BlockHeight,
        block_hash: BlockHash,
        account_state_root: StateRoot,
        qcash_state_root: StateRoot,
        governance_state_root: StateRoot,
        credential_use_state_root: StateRoot,
        protocol_state_root: StateRoot,
    ) -> Self {
        Self {
            height,
            block_hash,
            account_state_root,
            qcash_state_root,
            governance_state_root,
            credential_use_state_root,
            protocol_state_root,
        }
    }

    pub fn calculate_id(&self) -> Result<BlockStateCommitmentId, crate::error::CodecError> {
        Ok(domain_hash(
            HashDomain::BlockStateCommitment,
            &crate::codec::canonical_bytes(self)?,
        ))
    }

    pub fn matches_protocol_root(&self) -> Result<bool, crate::error::CodecError> {
        Ok(self.protocol_state_root
            == StateRoot(
                domain_hash(
                    HashDomain::ProtocolState,
                    &crate::codec::canonical_bytes(&(
                        self.account_state_root,
                        self.qcash_state_root,
                        self.governance_state_root,
                        self.credential_use_state_root,
                    ))?,
                )
                .0,
            ))
    }
}
