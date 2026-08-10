use crate::block::BlockHeight;
use crate::codec::canonical_bytes;
use crate::consensus::supply::Amount;
use crate::crypto::{Address, HASH_SIZE, Hash, HashDomain, TransactionHash, domain_hash};
use crate::error::CodecError;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

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
pub struct XpqCoinId(pub [u8; HASH_SIZE]);

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
pub struct XpqOutPoint {
    pub transaction_hash: TransactionHash,
    pub output_index: u32,
}

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
pub enum XpqCoinSource {
    Transfer,
    MiningReward,
    QCashRedeem,
    TrustedGenesis,
}

impl XpqCoinSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::MiningReward => "mining_reward",
            Self::QCashRedeem => "qcash_redeem",
            Self::TrustedGenesis => "trusted_genesis",
        }
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct XpqUtxo {
    pub id: XpqCoinId,
    pub outpoint: XpqOutPoint,
    pub owner: Address,
    pub amount: Amount,
    pub maturity_height: BlockHeight,
    pub source: XpqCoinSource,
}

#[derive(
    Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct XpqUtxoSet {
    coins: BTreeMap<XpqCoinId, XpqUtxo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XpqUtxoError {
    EmptyInputs,
    EmptyOutputs,
    DuplicateInput,
    CoinNotFound,
    CoinOwnerMismatch,
    CoinImmature,
    CoinIdCollision,
    ValueMismatch,
    AmountOverflow,
    OutputIndexOverflow,
    Serialization(CodecError),
}

impl fmt::Display for XpqUtxoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInputs => f.write_str("XPQ transaction has no inputs"),
            Self::EmptyOutputs => f.write_str("XPQ transaction has no outputs"),
            Self::DuplicateInput => f.write_str("XPQ transaction contains a duplicate input"),
            Self::CoinNotFound => f.write_str("XPQ input coin does not exist or is already spent"),
            Self::CoinOwnerMismatch => f.write_str("XPQ input coin is not owned by the signer"),
            Self::CoinImmature => f.write_str("XPQ input coin is not mature yet"),
            Self::CoinIdCollision => f.write_str("derived XPQ coin ID already exists"),
            Self::ValueMismatch => f.write_str("XPQ input and output values do not match"),
            Self::AmountOverflow => f.write_str("XPQ amount overflow"),
            Self::OutputIndexOverflow => f.write_str("XPQ output index exceeds u32"),
            Self::Serialization(error) => write!(f, "XPQ state encoding failed: {error}"),
        }
    }
}

impl Error for XpqUtxoError {}

impl From<CodecError> for XpqUtxoError {
    fn from(value: CodecError) -> Self {
        Self::Serialization(value)
    }
}

impl XpqCoinId {
    pub fn derive(
        transaction_hash: TransactionHash,
        output_index: u32,
    ) -> Result<Self, CodecError> {
        Ok(Self(
            domain_hash(
                HashDomain::XpqCoin,
                &canonical_bytes(&(transaction_hash, output_index))?,
            )
            .0,
        ))
    }

    /// Synthetic issuance origins share the canonical `(hash, output_index)`
    /// namespace with transaction outpoints. A source discriminator would
    /// change every issuance coin ID and requires an explicit state migration.
    pub fn derive_issuance(origin: Hash, output_index: u32) -> Result<Self, CodecError> {
        Self::derive(TransactionHash(origin.0), output_index)
    }
}

impl XpqUtxoSet {
    pub fn coins(&self) -> &BTreeMap<XpqCoinId, XpqUtxo> {
        &self.coins
    }

    pub fn coin(&self, id: XpqCoinId) -> Option<&XpqUtxo> {
        self.coins.get(&id)
    }

    pub fn coins_for_owner(&self, owner: Address) -> impl Iterator<Item = &XpqUtxo> {
        self.coins.values().filter(move |coin| coin.owner == owner)
    }

    pub fn balance(&self, owner: Address) -> Result<Amount, XpqUtxoError> {
        self.sum(self.coins_for_owner(owner).map(|coin| coin.amount))
    }

    pub fn available_balance(
        &self,
        owner: Address,
        height: BlockHeight,
    ) -> Result<Amount, XpqUtxoError> {
        self.sum(
            self.coins_for_owner(owner)
                .filter(|coin| coin.maturity_height.0 <= height.0)
                .map(|coin| coin.amount),
        )
    }

    pub fn total_value(&self) -> Result<Amount, XpqUtxoError> {
        self.sum(self.coins.values().map(|coin| coin.amount))
    }

    fn sum(&self, mut amounts: impl Iterator<Item = Amount>) -> Result<Amount, XpqUtxoError> {
        amounts
            .try_fold(0_u64, |sum, amount| sum.checked_add(amount.0))
            .map(Amount)
            .ok_or(XpqUtxoError::AmountOverflow)
    }

    pub fn validate_inputs(
        &self,
        owner: Address,
        inputs: &[XpqCoinId],
        height: BlockHeight,
    ) -> Result<Amount, XpqUtxoError> {
        if inputs.is_empty() {
            return Err(XpqUtxoError::EmptyInputs);
        }
        let mut seen = BTreeSet::new();
        let mut total = 0_u64;
        for id in inputs {
            if !seen.insert(*id) {
                return Err(XpqUtxoError::DuplicateInput);
            }
            let coin = self.coins.get(id).ok_or(XpqUtxoError::CoinNotFound)?;
            if coin.owner != owner {
                return Err(XpqUtxoError::CoinOwnerMismatch);
            }
            if coin.maturity_height.0 > height.0 {
                return Err(XpqUtxoError::CoinImmature);
            }
            total = total
                .checked_add(coin.amount.0)
                .ok_or(XpqUtxoError::AmountOverflow)?;
        }
        Ok(Amount(total))
    }

    pub(crate) fn spend_and_create(
        &mut self,
        owner: Address,
        inputs: &[XpqCoinId],
        outputs: &[(Address, Amount, BlockHeight, XpqCoinSource)],
        transaction_hash: TransactionHash,
        height: BlockHeight,
    ) -> Result<Vec<XpqCoinId>, XpqUtxoError> {
        self.spend_and_create_with_consumed(
            owner,
            inputs,
            outputs,
            Amount(0),
            transaction_hash,
            height,
        )
    }

    /// Atomically moves inputs into ordinary outputs plus value accounted for
    /// by another committed protocol state, currently QCash withdrawal state.
    /// `consumed` is not an unrestricted burn allowance; its caller must prove
    /// the corresponding value transition.
    pub(crate) fn spend_and_create_with_consumed(
        &mut self,
        owner: Address,
        inputs: &[XpqCoinId],
        outputs: &[(Address, Amount, BlockHeight, XpqCoinSource)],
        consumed: Amount,
        transaction_hash: TransactionHash,
        height: BlockHeight,
    ) -> Result<Vec<XpqCoinId>, XpqUtxoError> {
        if outputs.is_empty() && consumed.0 == 0 {
            return Err(XpqUtxoError::EmptyOutputs);
        }
        let input_total = self.validate_inputs(owner, inputs, height)?;
        let output_total = self.sum(outputs.iter().map(|(_, amount, _, _)| *amount))?;
        let required = output_total
            .0
            .checked_add(consumed.0)
            .ok_or(XpqUtxoError::AmountOverflow)?;
        if input_total.0 != required {
            return Err(XpqUtxoError::ValueMismatch);
        }

        let mut pending = Vec::with_capacity(outputs.len());
        for (index, (output_owner, amount, maturity_height, source)) in outputs.iter().enumerate() {
            if amount.0 == 0 {
                return Err(XpqUtxoError::ValueMismatch);
            }
            let index = u32::try_from(index).map_err(|_| XpqUtxoError::OutputIndexOverflow)?;
            let id = XpqCoinId::derive(transaction_hash, index)?;
            if self.coins.contains_key(&id) || pending.iter().any(|coin: &XpqUtxo| coin.id == id) {
                return Err(XpqUtxoError::CoinIdCollision);
            }
            pending.push(XpqUtxo {
                id,
                outpoint: XpqOutPoint {
                    transaction_hash,
                    output_index: index,
                },
                owner: *output_owner,
                amount: *amount,
                maturity_height: *maturity_height,
                source: *source,
            });
        }

        for id in inputs {
            self.coins.remove(id);
        }
        let ids = pending.iter().map(|coin| coin.id).collect();
        for coin in pending {
            self.coins.insert(coin.id, coin);
        }
        Ok(ids)
    }

    /// Low-level consensus issuance. The ledger caller must validate the
    /// emission schedule or other value-preserving source before invoking it.
    pub(crate) fn issue(
        &mut self,
        origin: Hash,
        owner: Address,
        amount: Amount,
        maturity_height: BlockHeight,
        source: XpqCoinSource,
    ) -> Result<XpqCoinId, XpqUtxoError> {
        self.issue_at(origin, 0, owner, amount, maturity_height, source)
    }

    pub(crate) fn issue_at(
        &mut self,
        origin: Hash,
        output_index: u32,
        owner: Address,
        amount: Amount,
        maturity_height: BlockHeight,
        source: XpqCoinSource,
    ) -> Result<XpqCoinId, XpqUtxoError> {
        if amount.0 == 0 {
            return Err(XpqUtxoError::ValueMismatch);
        }
        let id = XpqCoinId::derive_issuance(origin, output_index)?;
        if self.coins.contains_key(&id) {
            return Err(XpqUtxoError::CoinIdCollision);
        }
        self.coins.insert(
            id,
            XpqUtxo {
                id,
                outpoint: XpqOutPoint {
                    transaction_hash: TransactionHash(origin.0),
                    output_index,
                },
                owner,
                amount,
                maturity_height,
                source,
            },
        );
        Ok(id)
    }

    pub fn consensus_root(&self) -> Result<Hash, XpqUtxoError> {
        Ok(domain_hash(
            HashDomain::XpqState,
            &canonical_bytes(&self.coins)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_and_issuance_ids_share_one_outpoint_namespace() {
        let bytes = [0x3d; HASH_SIZE];
        let output_index = 7;

        assert_eq!(
            XpqCoinId::derive(TransactionHash(bytes), output_index).unwrap(),
            XpqCoinId::derive_issuance(Hash(bytes), output_index).unwrap()
        );
    }
}
