use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crypto::ProgramId;

use crate::monetary::coin::Zeno;

pub use crypto::ChainContext;

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct Height(pub u64);

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct Nonce(pub u64);

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub enum Owner {
    Program(ProgramId),
}

impl Owner {
    pub const fn program(self) -> ProgramId {
        let Self::Program(id) = self;
        id
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recipient {
    Program(ProgramId),
    BlockMiner,
}

impl Recipient {
    pub const fn resolve(self, block_miner: ProgramId) -> Owner {
        match self {
            Self::Program(program) => Owner::Program(program),
            Self::BlockMiner => Owner::Program(block_miner),
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    Coin(Zeno),
}

impl Value {
    pub const fn coin(self) -> Option<Zeno> {
        match self {
            Self::Coin(amount) => Some(amount),
        }
    }

    pub const fn is_zero(self) -> bool {
        match self {
            Self::Coin(amount) => amount.is_zero(),
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub to: Recipient,
    pub value: Value,
}

impl Output {
    pub const fn new(to: ProgramId, value: Value) -> Self {
        Self {
            to: Recipient::Program(to),
            value,
        }
    }

    pub const fn block_miner(value: Value) -> Self {
        Self {
            to: Recipient::BlockMiner,
            value,
        }
    }

    pub const fn recipient(&self) -> Recipient {
        self.to
    }

    pub const fn value(&self) -> Value {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_has_one_canonical_program_variant_for_wallets_and_contracts() {
        let identity = ProgramId([7; crypto::PROGRAM_ID_SIZE]);
        let owner = Owner::Program(identity);
        assert_eq!(owner, Owner::Program(identity));
        let bytes = borsh::to_vec(&owner).unwrap();
        assert_eq!(bytes[0], 0);
        assert_eq!(&bytes[1..], identity.as_bytes());
        let mut removed_tag = bytes.clone();
        removed_tag[0] = 1;
        assert!(borsh::from_slice::<Owner>(&removed_tag).is_err());
    }

    #[test]
    fn recipient_resolves_block_miner_at_application_time() {
        let miner = ProgramId([9; crypto::PROGRAM_ID_SIZE]);

        assert_eq!(
            Recipient::BlockMiner.resolve(miner),
            crate::common::Owner::Program(miner)
        );
        assert_eq!(
            Recipient::Program(ProgramId::ZERO).resolve(miner),
            crate::common::Owner::Program(ProgramId::ZERO)
        );
    }
}
