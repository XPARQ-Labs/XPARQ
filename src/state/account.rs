use crate::block::BlockHeight;
use crate::consensus::supply::{Amount, Balance};
use crate::crypto::{Address, Hash, HashDomain, PublicKey, domain_hash};
use crate::error::StateError;
use crate::transaction::Transaction;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type AccountStatement = Hash;

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash,
)]
pub struct Account {
    pub address: Address,
    pub balance: Balance,
    pub authorization: Option<AccountAuthorization>,
    pub credits: Vec<Credit>,
    pub statement: AccountStatement,
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
    fn account_statement_binds_applied_transaction_hash() {
        let account = Account::new(Address([1; crate::crypto::ADDRESS_SIZE]), Amount(10));
        let first = account
            .calculate_statement(
                account.statement,
                Hash([1; crate::crypto::HASH_SIZE]),
                Hash::ZERO,
            )
            .unwrap();
        let second = account
            .calculate_statement(
                account.statement,
                Hash([2; crate::crypto::HASH_SIZE]),
                Hash::ZERO,
            )
            .unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn account_statement_binds_authorization_proof_hash() {
        let account = Account::new(Address([2; crate::crypto::ADDRESS_SIZE]), Amount(10));
        let tx_hash = Hash([3; crate::crypto::HASH_SIZE]);
        let first = account
            .calculate_statement(
                account.statement,
                tx_hash,
                Hash([4; crate::crypto::HASH_SIZE]),
            )
            .unwrap();
        let second = account
            .calculate_statement(
                account.statement,
                tx_hash,
                Hash([5; crate::crypto::HASH_SIZE]),
            )
            .unwrap();

        assert_ne!(first, second);
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
    QCashRedeem,
}

#[derive(BorshSerialize)]
struct AccountStatementPayload {
    address: Address,
    balance: Balance,
    authorization: Option<AccountAuthorization>,
    credits: Vec<Credit>,
    authorized_tx_hash: Hash,
    authorization_proof_hash: Hash,
    last_state: AccountStatement,
}

impl Account {
    pub fn new(address: Address, balance: Balance) -> Self {
        let mut account = Self {
            address,
            balance,
            authorization: None,
            credits: vec![Credit {
                amount: balance,
                maturity_height: crate::block::Height(0),
                source: CreditSource::Genesis,
            }],
            statement: AccountStatement::ZERO,
        };
        account.advance_statement(AccountStatement::ZERO, Hash::ZERO, Hash::ZERO);
        account
    }

    pub fn new_with_authorization(
        address: Address,
        _auth_public_key: PublicKey,
        balance: Balance,
    ) -> Self {
        Self::new(address, balance)
    }

    /// Builds account state for trusted imports or tests.
    pub fn trusted(address: Address, balance: Balance) -> Self {
        let mut account = Self {
            address,
            balance,
            authorization: None,
            credits: vec![Credit {
                amount: balance,
                maturity_height: crate::block::Height(0),
                source: CreditSource::Genesis,
            }],
            statement: AccountStatement::ZERO,
        };
        account.advance_statement(AccountStatement::ZERO, Hash::ZERO, Hash::ZERO);
        account
    }

    pub fn calculate_statement(
        &self,
        last_state: AccountStatement,
        authorized_tx_hash: Hash,
        authorization_proof_hash: Hash,
    ) -> Result<AccountStatement, crate::error::CodecError> {
        let payload = AccountStatementPayload {
            address: self.address,
            balance: self.balance,
            authorization: self.authorization.clone(),
            credits: self.credits.clone(),
            authorized_tx_hash,
            authorization_proof_hash,
            last_state,
        };
        Ok(domain_hash(
            HashDomain::AccountStatement,
            &crate::codec::canonical_bytes(&payload)?,
        ))
    }

    pub fn advance_statement(
        &mut self,
        last_state: AccountStatement,
        authorized_tx_hash: Hash,
        authorization_proof_hash: Hash,
    ) {
        self.statement = self
            .calculate_statement(last_state, authorized_tx_hash, authorization_proof_hash)
            .expect("account statement payload is canonically serializable");
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
        Amount(matured)
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

    pub fn apply_outgoing_transaction(
        &mut self,
        transaction: &Transaction,
        height: BlockHeight,
        applied_tx_hash: Hash,
        authorization_proof_hash: Hash,
    ) -> Result<(), StateError> {
        if transaction.from != self.address {
            return Err(StateError::AddressMismatch);
        }

        if transaction.last_state != self.statement {
            return Err(StateError::InvalidAccountStatement);
        }

        let total = transaction
            .total_amount()
            .map_err(|_| StateError::BalanceOverflow)?;

        let last_state = self.statement;
        self.debit_at(total, height)?;
        self.advance_statement(last_state, applied_tx_hash, authorization_proof_hash);
        Ok(())
    }

    pub fn apply_incoming_transaction(
        &mut self,
        transaction: &Transaction,
        maturity_height: BlockHeight,
    ) -> Result<(), StateError> {
        let output = transaction
            .outputs()
            .find(|output| output.to.address() == Some(self.address))
            .ok_or(StateError::AddressMismatch)?;
        self.credit_at_maturity(output.amount, maturity_height, CreditSource::Transaction)
    }
}
