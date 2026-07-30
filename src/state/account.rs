use crate::block::{BlockHeight, Nonce};
use crate::consensus::supply::{Amount, Balance};
use crate::crypto::{Address, PublicKey};
use crate::error::StateError;
use crate::transaction::AccountNonce;
use crate::transaction::Transaction;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash,
)]
pub struct Account {
    pub address: Address,
    pub balance: Balance,
    pub nonce: AccountNonce,
    pub authorization: Option<AccountAuthorization>,
    pub credits: Vec<Credit>,
    pub locks: Vec<BalanceLock>,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash,
)]
pub struct AccountAuthorization {
    pub owner_public_key: PublicKey,
    pub auth_public_key: PublicKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_nonce_is_rejected_instead_of_reused() {
        let mut account = Account::trusted_with_nonce(
            Address([1; crate::crypto::ADDRESS_SIZE]),
            Amount(1),
            crate::block::Nonce(u64::MAX),
        );
        assert_eq!(account.increment_nonce(), Err(StateError::NonceOverflow));
        assert_eq!(account.nonce.0, u64::MAX);
    }
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash,
)]
pub struct Credit {
    pub amount: Amount,
    pub maturity_height: BlockHeight,
    pub source: CreditSource,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash,
)]
pub struct BalanceLock {
    pub amount: Amount,
    pub until_height: BlockHeight,
}

#[derive(
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub enum CreditSource {
    Genesis,
    Transaction,
    Fee,
    MiningReward,
    QCashDeposit,
}

impl Account {
    pub fn new(address: Address, balance: Balance) -> Self {
        Self {
            address,
            balance,
            nonce: Nonce(0),
            authorization: None,
            credits: vec![Credit {
                amount: balance,
                maturity_height: crate::block::Height(0),
                source: CreditSource::Genesis,
            }],
            locks: Vec::new(),
        }
    }

    pub fn new_with_authorization(
        address: Address,
        _auth_public_key: PublicKey,
        balance: Balance,
    ) -> Self {
        Self::new(address, balance)
    }

    /// Builds account state for trusted imports or tests.
    pub fn trusted_with_nonce(address: Address, balance: Balance, nonce: AccountNonce) -> Self {
        Self {
            address,
            balance,
            nonce,
            authorization: None,
            credits: vec![Credit {
                amount: balance,
                maturity_height: crate::block::Height(0),
                source: CreditSource::Genesis,
            }],
            locks: Vec::new(),
        }
    }

    pub fn register_authorization(
        &mut self,
        owner_public_key: PublicKey,
        auth_public_key: PublicKey,
    ) -> Result<(), StateError> {
        if self.authorization.is_some() {
            return Err(StateError::InvalidAuthorization);
        }
        self.authorization = Some(AccountAuthorization {
            owner_public_key,
            auth_public_key,
        });
        Ok(())
    }

    pub fn available_balance_at(&self, height: BlockHeight) -> Amount {
        let matured = self
            .credits
            .iter()
            .filter(|credit| credit.maturity_height.0 <= height.0)
            .map(|credit| credit.amount.0)
            .sum::<u64>();
        Amount(matured.saturating_sub(self.locked_balance_at(height).0))
    }

    pub fn locked_balance_at(&self, height: BlockHeight) -> Amount {
        Amount(
            self.locks
                .iter()
                .filter(|lock| height.0 <= lock.until_height.0)
                .map(|lock| lock.amount.0)
                .sum(),
        )
    }

    pub fn immature_balance_at(&self, height: BlockHeight) -> Amount {
        Amount(
            self.balance
                .0
                .saturating_sub(self.available_balance_at(height).0),
        )
    }

    pub fn can_spend_at(&self, amount: Balance, height: BlockHeight) -> bool {
        self.available_balance_at(height).0 >= amount.0
    }

    pub fn credit(&mut self, amount: Balance) -> Result<(), StateError> {
        self.credit_at_maturity(amount, crate::block::Height(0), CreditSource::Genesis)
    }

    pub fn credit_at_maturity(
        &mut self,
        amount: Balance,
        maturity_height: BlockHeight,
        source: CreditSource,
    ) -> Result<(), StateError> {
        self.balance.0 = self
            .balance
            .0
            .checked_add(amount.0)
            .ok_or(StateError::BalanceOverflow)?;
        if amount.0 > 0 {
            self.credits.push(Credit {
                amount,
                maturity_height,
                source,
            });
        }
        self.compact_credits();
        Ok(())
    }

    pub fn debit(&mut self, amount: Balance) -> Result<(), StateError> {
        self.debit_at(amount, crate::block::Height(0))
    }

    pub fn debit_at(&mut self, amount: Balance, height: BlockHeight) -> Result<(), StateError> {
        if !self.can_spend_at(amount, height) {
            return Err(StateError::InsufficientBalance);
        }

        self.balance.0 -= amount.0;
        let mut remaining = amount.0;
        for credit in &mut self.credits {
            if remaining == 0 {
                break;
            }
            if credit.maturity_height.0 > height.0 || credit.amount.0 == 0 {
                continue;
            }

            let spent = credit.amount.0.min(remaining);
            credit.amount.0 -= spent;
            remaining -= spent;
        }
        self.credits.retain(|credit| credit.amount.0 > 0);
        self.compact_credits();
        Ok(())
    }

    pub fn lock_until(
        &mut self,
        amount: Balance,
        until_height: BlockHeight,
        current_height: BlockHeight,
    ) -> Result<(), StateError> {
        if amount.0 == 0 {
            return Ok(());
        }
        if self.available_balance_at(current_height).0 < amount.0 {
            return Err(StateError::InsufficientBalance);
        }
        self.locks.push(BalanceLock {
            amount,
            until_height,
        });
        self.compact_locks();
        Ok(())
    }

    pub fn compact_credits(&mut self) {
        let mut compacted: BTreeMap<(BlockHeight, CreditSource), u64> = BTreeMap::new();
        for credit in &self.credits {
            if credit.amount.0 == 0 {
                continue;
            }

            let entry = compacted
                .entry((credit.maturity_height, credit.source))
                .or_insert(0);
            *entry = entry.saturating_add(credit.amount.0);
        }

        self.credits = compacted
            .into_iter()
            .map(|((maturity_height, source), amount)| Credit {
                amount: Amount(amount),
                maturity_height,
                source,
            })
            .collect();
    }

    pub fn compact_locks(&mut self) {
        let mut compacted: BTreeMap<BlockHeight, u64> = BTreeMap::new();
        for lock in &self.locks {
            if lock.amount.0 == 0 {
                continue;
            }
            let entry = compacted.entry(lock.until_height).or_insert(0);
            *entry = entry.saturating_add(lock.amount.0);
        }
        self.locks = compacted
            .into_iter()
            .map(|(until_height, amount)| BalanceLock {
                amount: Amount(amount),
                until_height,
            })
            .collect();
    }

    pub fn increment_nonce(&mut self) -> Result<(), StateError> {
        self.nonce.0 = self
            .nonce
            .0
            .checked_add(1)
            .ok_or(StateError::NonceOverflow)?;
        Ok(())
    }

    pub fn apply_outgoing_transaction(
        &mut self,
        transaction: &Transaction,
        height: BlockHeight,
    ) -> Result<(), StateError> {
        if transaction.from != self.address {
            return Err(StateError::AddressMismatch);
        }

        if transaction.nonce != self.nonce {
            return Err(StateError::InvalidNonce);
        }

        let total = transaction
            .total_amount()
            .map_err(|_| StateError::BalanceOverflow)?
            .0
            .checked_add(transaction.fee.0)
            .ok_or(StateError::BalanceOverflow)?;

        self.debit_at(Amount(total), height)?;
        self.increment_nonce()?;
        Ok(())
    }

    pub fn apply_incoming_transaction(
        &mut self,
        transaction: &Transaction,
        maturity_height: BlockHeight,
    ) -> Result<(), StateError> {
        let output = transaction
            .outputs()
            .find(|output| output.to == self.address)
            .ok_or(StateError::AddressMismatch)?;
        self.credit_at_maturity(output.amount, maturity_height, CreditSource::Transaction)
    }
}
