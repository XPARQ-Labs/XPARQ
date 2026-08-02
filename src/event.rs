//! Deterministic receipts emitted by successful protocol state transitions.

use crate::block::BlockHeight;
use crate::consensus::supply::Amount;
use crate::crypto::{Address, BlockHash, Hash, HashDomain, TransactionHash, domain_hash};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

pub const PROTOCOL_EVENT_VERSION: u8 = 1;
pub const MAX_PROTOCOL_EVENT_SIZE: usize = 256 * 1024;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct EventId(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSnapshot {
    pub balance: Amount,
    pub statement: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRollback {
    pub address: Address,
    /// State before rollback, while the disconnected branch was active.
    pub before: Option<AccountSnapshot>,
    /// State after rollback, at the restored chain tip.
    pub after: Option<AccountSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisconnectedBlock {
    pub height: BlockHeight,
    pub hash: BlockHash,
    pub transaction_ids: Vec<TransactionHash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackEvent {
    pub from_height: BlockHeight,
    pub to_height: BlockHeight,
    pub old_tip: BlockHash,
    pub new_tip: BlockHash,
    pub disconnected_blocks: Vec<DisconnectedBlock>,
    pub affected_accounts: Vec<AccountRollback>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainEvent {
    RollbackCompleted(RollbackEvent),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackHistory {
    events: Vec<RollbackEvent>,
}

impl RollbackHistory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, event: RollbackEvent) {
        self.events.push(event);
    }

    pub fn events(&self) -> &[RollbackEvent] {
        &self.events
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn last(&self) -> Option<&RollbackEvent> {
        self.events.last()
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum ProtocolEventKind {
    BatchTransfer {
        from: Address,
        to: Address,
        amount: Amount,
    },
    QCashWithdrawn {
        signer: Address,
        amount: Amount,
    },
    QCashRedeemed {
        signer: Address,
        recipient: Address,
        amount: Amount,
    },
    QCashRecoverRedeemed {
        signer: Address,
        claimant: Address,
        amount: Amount,
    },
    GenesisAllocation {
        recipient: Address,
        amount: Amount,
    },
    CoinbasePaid {
        miner: Address,
        subsidy: Amount,
    },
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct ProtocolEvent {
    pub version: u8,
    pub block_height: BlockHeight,
    pub block_hash: BlockHash,
    pub transaction_hash: Option<TransactionHash>,
    pub event_index: u32,
    pub kind: ProtocolEventKind,
}

impl ProtocolEvent {
    pub fn new(
        block_height: BlockHeight,
        block_hash: BlockHash,
        transaction_hash: Option<TransactionHash>,
        event_index: u32,
        kind: ProtocolEventKind,
    ) -> Self {
        Self {
            version: PROTOCOL_EVENT_VERSION,
            block_height,
            block_hash,
            transaction_hash,
            event_index,
            kind,
        }
    }

    pub fn id(&self) -> Result<EventId, crate::error::CodecError> {
        Ok(EventId(
            domain_hash(HashDomain::ProtocolEvent, &self.to_bytes()?).0,
        ))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::CodecError> {
        crate::codec::protocol_event_bytes(self)
    }

    pub fn validate(&self) -> bool {
        self.version == PROTOCOL_EVENT_VERSION && self.block_hash != BlockHash::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Height;

    #[test]
    fn rollback_history_records_events_in_order() {
        let mut history = RollbackHistory::new();
        let event = RollbackEvent {
            from_height: Height(3),
            to_height: Height(2),
            old_tip: BlockHash([1; 32]),
            new_tip: BlockHash([2; 32]),
            disconnected_blocks: Vec::new(),
            affected_accounts: Vec::new(),
        };

        history.record(event.clone());

        assert_eq!(history.len(), 1);
        assert_eq!(history.last(), Some(&event));
        assert_eq!(history.events(), &[event]);
    }
}
