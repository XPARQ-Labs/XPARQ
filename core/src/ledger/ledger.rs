use crate::block::{Block, BlockHeight, Height};
use crate::consensus::supply::{Amount, Balance};
use crate::crypto::{Address, PublicKey};
use crate::crypto::{BlockHash, HASH_SIZE, Hash, HashDomain, StateRoot, domain_hash};
use crate::error::LedgerError;
use crate::event::{
    AccountRollback, AccountSnapshot, ChainEvent, DisconnectedBlock, ProtocolEvent, RollbackEvent,
    RollbackHistory,
};
use crate::ledger::chain::Chain;
use crate::ledger::{AccountNonMembershipProof, AccountStateProof, SparseStateTree};
use crate::state::{Account, BlockStateCommitment, QCashUtxoSet, XpqUtxoSet};
use crate::transaction::{
    QCashTransaction, QCashTransactionKind, SignedQCashTransaction, SignedTransfer,
    TransactionError,
};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    pub(crate) accounts: BTreeMap<Address, Account>,
    account_state_tree: Arc<SparseStateTree>,
    pub chain: Chain,
    pub xpq_utxos: XpqUtxoSet,
    pub qcash_utxos: QCashUtxoSet,
    pub qcash_account_journals: BTreeMap<BlockHash, QCashAccountJournal>,
    rollback_states: BTreeMap<BlockHash, AccountRollbackState>,
    /// Derived receipts keyed by their canonical block. Not part of the protocol state root.
    pub events_by_block: BTreeMap<BlockHash, Vec<ProtocolEvent>>,
    /// Local non-consensus history of disconnected active tips.
    pub rollback_history: RollbackHistory,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QCashAccountJournal {
    pub block_hash: BlockHash,
    pub block_height: BlockHeight,
    /// `None` means the account did not exist before this block.
    pub previous_accounts: BTreeMap<Address, Option<Account>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AccountRollbackState {
    block_height: BlockHeight,
    accounts: BTreeMap<Address, Account>,
    account_state_tree: Arc<SparseStateTree>,
    xpq_utxos: XpqUtxoSet,
}

fn account_snapshot(account: &Account, xpq_utxos: &XpqUtxoSet) -> AccountSnapshot {
    AccountSnapshot {
        balance: xpq_utxos.balance(account.address).unwrap_or(Amount(0)),
        authorization_registered: account.authorization.is_some(),
    }
}

fn account_rollbacks(
    before: &BTreeMap<Address, Account>,
    before_utxos: &XpqUtxoSet,
    after: &BTreeMap<Address, Account>,
    after_utxos: &XpqUtxoSet,
) -> Vec<AccountRollback> {
    let mut addresses = before
        .keys()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    addresses.extend(after.keys().copied());
    addresses.extend(before_utxos.coins().values().map(|coin| coin.owner));
    addresses.extend(after_utxos.coins().values().map(|coin| coin.owner));
    addresses
        .into_iter()
        .filter_map(|address| {
            let before_snapshot = before
                .get(&address)
                .map(|account| account_snapshot(account, before_utxos));
            let after_snapshot = after
                .get(&address)
                .map(|account| account_snapshot(account, after_utxos));
            if before_snapshot == after_snapshot {
                return None;
            }
            Some(AccountRollback {
                address,
                before: before_snapshot,
                after: after_snapshot,
            })
        })
        .collect()
}

impl Ledger {
    pub(crate) fn remember_rollback_state(
        &mut self,
        block_hash: BlockHash,
        block_height: BlockHeight,
        previous: &Self,
    ) {
        self.rollback_states
            .entry(block_hash)
            .or_insert_with(|| AccountRollbackState {
                block_height,
                accounts: previous.accounts.clone(),
                account_state_tree: previous.account_state_tree.clone(),
                xpq_utxos: previous.xpq_utxos.clone(),
            });
    }

    /// Drops rollback-only state at or below the reorganization finality boundary.
    ///
    /// Canonical blocks, transaction indexes, and protocol events are deliberately
    /// retained because explorer history does not depend on these rollback caches.
    pub fn prune_finalized_rollback_state(&mut self, finalized_height: BlockHeight) {
        self.rollback_states
            .retain(|_, state| state.block_height.0 > finalized_height.0);
        self.qcash_account_journals
            .retain(|_, journal| journal.block_height.0 > finalized_height.0);
        self.qcash_utxos.prune_journals(finalized_height);
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_accounts_and_chain(
        accounts: BTreeMap<Address, Account>,
        chain: Chain,
    ) -> Result<Self, LedgerError> {
        Ok(Self {
            account_state_tree: Arc::new(SparseStateTree::from_accounts(&accounts)?),
            accounts,
            chain,
            ..Self::default()
        })
    }

    pub(crate) fn from_snapshot_parts(
        accounts: BTreeMap<Address, Account>,
        xpq_utxos: XpqUtxoSet,
        qcash_utxos: QCashUtxoSet,
        headers: &[crate::qcash::recovery::ChainHeader],
    ) -> Result<Self, LedgerError> {
        let mut chain = Chain::new();
        let checkpoint_height = headers.last().ok_or(LedgerError::InvalidParent)?.height;
        chain.install_verified_headers(headers, checkpoint_height)?;
        let genesis = crate::genesis::genesis_block().map_err(|_| LedgerError::InvalidParent)?;
        chain.attach_full_block(genesis)?;
        Ok(Self {
            account_state_tree: Arc::new(SparseStateTree::from_accounts(&accounts)?),
            accounts,
            chain,
            xpq_utxos,
            qcash_utxos,
            ..Self::default()
        })
    }

    pub fn accounts(&self) -> &BTreeMap<Address, Account> {
        &self.accounts
    }

    pub fn replace_accounts(
        &mut self,
        accounts: BTreeMap<Address, Account>,
    ) -> Result<(), LedgerError> {
        self.account_state_tree = Arc::new(SparseStateTree::from_accounts(&accounts)?);
        self.accounts = accounts;
        Ok(())
    }

    /// Restores a previously authenticated pruned chain index. The complete
    /// header sequence is re-verified before it can become canonical.
    pub fn restore_authenticated_headers(
        &mut self,
        headers: &[crate::qcash::recovery::ChainHeader],
        checkpoint_height: BlockHeight,
    ) -> Result<(), LedgerError> {
        self.chain
            .install_verified_headers(headers, checkpoint_height)
    }

    /// Restores an optional locally retained body for an authenticated header.
    pub fn attach_stored_block_body(&mut self, block: Block) -> Result<(), LedgerError> {
        self.chain.attach_full_block(block)
    }

    pub(crate) fn refresh_account_state(&mut self, address: &Address) -> Result<(), LedgerError> {
        if let Some(account) = self.accounts.get(address) {
            Arc::make_mut(&mut self.account_state_tree).update_account(account)?;
        } else {
            Arc::make_mut(&mut self.account_state_tree).remove_account(address);
        }
        Ok(())
    }

    fn refresh_qcash_accounts(
        &mut self,
        transaction: &QCashTransaction,
        miner_address: Address,
    ) -> Result<(), LedgerError> {
        self.refresh_account_state(&transaction.signer)?;
        match &transaction.kind {
            QCashTransactionKind::Redeem { outputs, .. } => {
                for recipient in outputs.iter().map(|output| {
                    crate::ledger::transition::resolve_output_target(output.to, miner_address)
                }) {
                    self.refresh_account_state(&recipient)?;
                }
            }
            QCashTransactionKind::Withdraw { .. } => {}
        }
        Ok(())
    }

    pub fn create_account(
        &mut self,
        address: Address,
        balance: Balance,
    ) -> Result<(), LedgerError> {
        self.create_account_with_authorization(
            address,
            PublicKey([0; crate::crypto::PUBLIC_KEY_SIZE]),
            balance,
        )
    }

    pub fn create_account_with_authorization(
        &mut self,
        address: Address,
        auth_public_key: PublicKey,
        balance: Balance,
    ) -> Result<(), LedgerError> {
        if self.accounts.contains_key(&address) {
            return Err(LedgerError::AccountAlreadyExists);
        }
        self.reject_non_consensus_issuance(balance)?;

        let mut staged = self.clone();
        let account = Account::new_with_authorization(address, auth_public_key);
        staged.accounts.insert(address, account);
        if balance.0 > 0 {
            let origin = domain_hash(
                HashDomain::XpqCoin,
                &crate::codec::canonical_bytes(&(b"trusted-genesis", address))?,
            );
            staged.xpq_utxos.issue(
                origin,
                address,
                balance,
                Height(0),
                crate::state::XpqCoinSource::TrustedGenesis,
            )?;
        }
        staged.refresh_account_state(&address)?;
        staged.validate_supply()?;
        *self = staged;
        Ok(())
    }

    pub fn insert_account(&mut self, account: Account) -> Result<(), LedgerError> {
        if self.accounts.contains_key(&account.address) {
            return Err(LedgerError::AccountAlreadyExists);
        }
        self.reject_non_consensus_issuance(Amount(0))?;

        let mut staged = self.clone();
        let address = account.address;
        let opening_balance = Amount(0);
        staged.accounts.insert(address, account);
        if opening_balance.0 > 0 {
            let origin = domain_hash(
                HashDomain::XpqCoin,
                &crate::codec::canonical_bytes(&(b"trusted-genesis", address))?,
            );
            staged.xpq_utxos.issue(
                origin,
                address,
                opening_balance,
                Height(0),
                crate::state::XpqCoinSource::TrustedGenesis,
            )?;
        }
        staged.refresh_account_state(&address)?;
        staged.validate_supply()?;
        *self = staged;
        Ok(())
    }

    /// Account construction is used while assembling genesis and in isolated
    /// test ledgers. Once a chain has a tip, a non-zero opening balance would
    /// be an issuance path outside consensus emission and is always rejected.
    ///
    /// This check is independent of the aggregate supply invariant so it
    /// cannot be used to "repair" an already-deflated or corrupted ledger by
    /// minting the missing difference.
    fn reject_non_consensus_issuance(&self, opening_balance: Balance) -> Result<(), LedgerError> {
        if opening_balance.0 != 0 && self.tip_height().is_some() {
            return Err(LedgerError::UnauthorizedSupplyCreation);
        }
        Ok(())
    }

    pub fn account(&self, address: &Address) -> Option<&Account> {
        self.accounts.get(address)
    }

    pub fn balance(&self, address: &Address) -> Option<Balance> {
        (self.accounts.contains_key(address)
            || self.xpq_utxos.coins_for_owner(*address).next().is_some())
        .then(|| self.xpq_utxos.balance(*address).ok())
        .flatten()
    }

    pub fn confirmed_balance(&self, address: &Address) -> Option<Balance> {
        let height = self.chain.tip_height().unwrap_or(crate::block::Height(0));
        (self.accounts.contains_key(address)
            || self.xpq_utxos.coins_for_owner(*address).next().is_some())
        .then(|| self.xpq_utxos.available_balance(*address, height).ok())
        .flatten()
    }

    pub fn total_supply(&self) -> Result<Amount, LedgerError> {
        self.xpq_utxos
            .total_value()
            .map_err(|_| LedgerError::SupplyOverflow)
    }

    /// Account balances and issued bearer cash.
    pub fn economic_supply(&self) -> Result<Amount, LedgerError> {
        let xpq = self.total_supply()?;
        let cash = self.qcash_utxos.total_value()?;
        xpq.0
            .checked_add(cash.0)
            .map(Amount)
            .ok_or(LedgerError::SupplyOverflow)
    }

    pub fn validate_supply(&self) -> Result<(), LedgerError> {
        let economic = self.economic_supply()?;
        let Some(tip_height) = self.tip_height() else {
            // Uninitialized ledgers are used only for trusted construction and
            // tests. Once genesis exists, issuance must match the chain.
            return Ok(());
        };
        if economic != self.expected_issued_supply_at(tip_height)? {
            return Err(LedgerError::SupplyMismatch);
        }
        Ok(())
    }

    pub(crate) fn validate_supply_for_block(&self, block: &Block) -> Result<(), LedgerError> {
        let economic = self.economic_supply()?;
        let expected = if block.is_genesis() {
            Amount(0)
        } else {
            let headers = self.chain.headers.values().cloned().collect::<Vec<_>>();
            let prior = expected_issued_supply_from_headers(&headers)?;
            let subsidy = block
                .body
                .emission
                .as_ref()
                .ok_or(LedgerError::InvalidEmission)?
                .subsidy;
            Amount(
                prior
                    .0
                    .checked_add(subsidy.0)
                    .ok_or(LedgerError::SupplyOverflow)?,
            )
        };
        if economic != expected {
            return Err(LedgerError::SupplyMismatch);
        }
        Ok(())
    }

    fn expected_issued_supply_at(&self, height: BlockHeight) -> Result<Amount, LedgerError> {
        let headers = self
            .chain
            .headers
            .range(..=height)
            .map(|(_, header)| header.clone())
            .collect::<Vec<_>>();
        expected_issued_supply_from_headers(&headers)
    }

    pub fn apply_signed_qcash_transaction(
        &mut self,
        signed: &SignedQCashTransaction,
        height: BlockHeight,
    ) -> Result<(), LedgerError> {
        let mut staged = self.clone();
        if !staged.accounts.contains_key(&signed.transaction.signer)
            && signed.authorization_proof.carries_registration_keys()
        {
            staged.accounts.insert(
                signed.transaction.signer,
                Account::new(signed.transaction.signer),
            );
        }
        let account = staged
            .accounts
            .get(&signed.transaction.signer)
            .ok_or(LedgerError::AccountNotFound)?;
        let protocol = crate::transaction::SignedProtocolTransaction::from(signed.clone());
        if let Some((owner, auth)) = protocol
            .validate_with_account_authorization(account, height)
            .map_err(LedgerError::from)?
        {
            staged
                .accounts
                .get_mut(&signed.transaction.signer)
                .ok_or(LedgerError::AccountNotFound)?
                .register_authorization(owner, auth)?;
        }
        let applied_tx_hash = signed.transaction.hash()?.as_hash();
        let authorization_proof_hash = signed
            .authorization_proof
            .hash_with_transaction(applied_tx_hash)?;
        staged.apply_qcash_transaction(
            &signed.transaction,
            height,
            None,
            authorization_proof_hash,
            Address([0; 20]),
        )?;
        staged.refresh_qcash_accounts(&signed.transaction, Address([0; 20]))?;
        *self = staged;
        Ok(())
    }

    pub fn apply_signed_qcash_transaction_in_block(
        &mut self,
        signed: &SignedQCashTransaction,
        height: BlockHeight,
        block_hash: BlockHash,
        miner_address: Address,
    ) -> Result<(), LedgerError> {
        let mut staged = self.clone();
        if !staged.accounts.contains_key(&signed.transaction.signer)
            && signed.authorization_proof.carries_registration_keys()
        {
            staged.accounts.insert(
                signed.transaction.signer,
                Account::new(signed.transaction.signer),
            );
        }
        let account = staged
            .accounts
            .get(&signed.transaction.signer)
            .ok_or(LedgerError::AccountNotFound)?;
        let protocol = crate::transaction::SignedProtocolTransaction::from(signed.clone());
        let registration = protocol
            .validate_with_account_authorization(account, height)
            .map_err(LedgerError::from)?;
        staged.capture_qcash_accounts(block_hash, height, &signed.transaction, miner_address)?;
        staged.remember_rollback_state(block_hash, height, self);
        if let Some((owner, auth)) = registration {
            staged
                .accounts
                .get_mut(&signed.transaction.signer)
                .ok_or(LedgerError::AccountNotFound)?
                .register_authorization(owner, auth)?;
        }
        let applied_tx_hash = signed.transaction.hash()?.as_hash();
        let authorization_proof_hash = signed
            .authorization_proof
            .hash_with_transaction(applied_tx_hash)?;
        staged.apply_qcash_transaction(
            &signed.transaction,
            height,
            Some(block_hash),
            authorization_proof_hash,
            miner_address,
        )?;
        staged.refresh_qcash_accounts(&signed.transaction, miner_address)?;
        // Supply is checked once the enclosing block has applied emission.
        *self = staged;
        Ok(())
    }

    fn capture_qcash_accounts(
        &mut self,
        block_hash: BlockHash,
        height: BlockHeight,
        transaction: &QCashTransaction,
        miner_address: Address,
    ) -> Result<(), LedgerError> {
        let mut addresses = vec![transaction.signer];
        match &transaction.kind {
            QCashTransactionKind::Redeem { outputs, .. } => {
                addresses.extend(outputs.iter().map(|output| {
                    crate::ledger::transition::resolve_output_target(output.to, miner_address)
                }));
            }
            QCashTransactionKind::Withdraw { .. } => {}
        }
        let journal = self
            .qcash_account_journals
            .entry(block_hash)
            .or_insert_with(|| QCashAccountJournal {
                block_hash,
                block_height: height,
                previous_accounts: BTreeMap::new(),
            });
        if journal.block_height != height {
            return Err(LedgerError::MissingQCashAccountJournal);
        }
        for address in addresses {
            journal
                .previous_accounts
                .entry(address)
                .or_insert_with(|| self.accounts.get(&address).cloned());
        }
        Ok(())
    }

    /// Atomically restores account and coin state for a disconnected QCash block.
    pub fn rollback_qcash_block(&mut self, block_hash: BlockHash) -> Result<(), LedgerError> {
        let mut staged = self.clone();
        staged
            .qcash_account_journals
            .remove(&block_hash)
            .ok_or(LedgerError::MissingQCashAccountJournal)?;
        let rollback_state = staged
            .rollback_states
            .remove(&block_hash)
            .ok_or(LedgerError::MissingQCashAccountJournal)?;
        staged.qcash_utxos.rollback_block(block_hash)?;
        staged.accounts = rollback_state.accounts;
        staged.account_state_tree = rollback_state.account_state_tree;
        staged.xpq_utxos = rollback_state.xpq_utxos;
        staged.validate_supply()?;
        *self = staged;
        Ok(())
    }

    /// Disconnects the active tip and restores its complete rollback state.
    pub fn rollback_block(&mut self, block_hash: BlockHash) -> Result<(), LedgerError> {
        self.rollback_block_inner(block_hash).map(|event| {
            self.rollback_history.record(event);
        })
    }

    /// Disconnects the active tip and returns a chain event describing the rollback impact.
    pub fn rollback_block_with_event(
        &mut self,
        block_hash: BlockHash,
    ) -> Result<ChainEvent, LedgerError> {
        self.rollback_block_inner(block_hash).map(|event| {
            self.rollback_history.record(event.clone());
            ChainEvent::RollbackCompleted(event)
        })
    }

    pub fn rollback_history(&self) -> &RollbackHistory {
        &self.rollback_history
    }

    fn rollback_block_inner(
        &mut self,
        block_hash: BlockHash,
    ) -> Result<RollbackEvent, LedgerError> {
        let mut staged = self.clone();
        let block = staged
            .chain
            .block(&staged.tip_height().ok_or(LedgerError::InvalidParent)?)
            .filter(|block| block.hash() == Ok(block_hash))
            .cloned()
            .ok_or(LedgerError::InvalidParent)?;
        let from_height = block.height();
        let old_tip = block_hash;
        let before_accounts = staged.accounts.clone();
        let before_utxos = staged.xpq_utxos.clone();
        staged.chain.remove_tip(block_hash)?;
        let rollback_state = staged
            .rollback_states
            .remove(&block_hash)
            .ok_or(LedgerError::MissingQCashAccountJournal)?;
        if staged.qcash_utxos.journal(block_hash).is_some() {
            staged.qcash_utxos.rollback_block(block_hash)?;
        }
        staged.qcash_account_journals.remove(&block_hash);
        staged.accounts = rollback_state.accounts;
        staged.account_state_tree = rollback_state.account_state_tree;
        staged.xpq_utxos = rollback_state.xpq_utxos;
        staged.events_by_block.remove(&block_hash);
        staged.validate_supply()?;
        let to_height = staged.tip_height().unwrap_or(Height(0));
        let new_tip = staged.tip_hash().unwrap_or(BlockHash::ZERO);
        let affected_accounts = account_rollbacks(
            &before_accounts,
            &before_utxos,
            &staged.accounts,
            &staged.xpq_utxos,
        );
        let event = RollbackEvent {
            from_height,
            to_height,
            old_tip,
            new_tip,
            disconnected_blocks: vec![DisconnectedBlock {
                height: block.height(),
                hash: block.hash()?,
                transaction_ids: block
                    .transactions()
                    .iter()
                    .map(|transaction| transaction.hash())
                    .collect::<Result<Vec<_>, _>>()?,
            }],
            affected_accounts,
        };
        *self = staged;
        Ok(event)
    }

    fn apply_qcash_transaction(
        &mut self,
        transaction: &QCashTransaction,
        height: BlockHeight,
        block_hash: Option<BlockHash>,
        _authorization_proof_hash: Hash,
        miner_address: Address,
    ) -> Result<(), LedgerError> {
        match &transaction.kind {
            QCashTransactionKind::Withdraw {
                inputs,
                outputs,
                amount,
                metadata,
            } => {
                let maturity_height = Height(
                    height
                        .0
                        .saturating_add(crate::ledger::CONFIRMATION_DEPTH as u64),
                );
                let xpq_outputs = outputs
                    .iter()
                    .map(|output| {
                        (
                            crate::ledger::transition::resolve_output_target(
                                output.to,
                                miner_address,
                            ),
                            output.amount,
                            maturity_height,
                            crate::state::XpqCoinSource::Transfer,
                        )
                    })
                    .collect::<Vec<_>>();
                self.xpq_utxos.spend_and_create_with_consumed(
                    transaction.signer,
                    inputs,
                    &xpq_outputs,
                    *amount,
                    transaction.hash()?,
                    height,
                )?;
                for (owner, _, _, _) in xpq_outputs {
                    self.accounts
                        .entry(owner)
                        .or_insert_with(|| Account::new(owner));
                }
                if let Some(block_hash) = block_hash {
                    self.qcash_utxos.apply_withdraw_in_block(
                        block_hash,
                        height,
                        transaction.signer,
                        transaction.hash()?,
                        metadata,
                    )?;
                } else {
                    self.qcash_utxos.apply_withdraw(
                        transaction.signer,
                        transaction.hash()?,
                        metadata,
                        height,
                    )?;
                }
            }
            QCashTransactionKind::Redeem { outputs, metadata } => {
                let transaction_commitment = transaction.redeem_transaction_commitment()?.ok_or(
                    LedgerError::InvalidTransaction(TransactionError::InvalidQCashMetadata),
                )?;
                let amount = if let Some(block_hash) = block_hash {
                    self.qcash_utxos.apply_redeem_in_block(
                        block_hash,
                        height,
                        metadata,
                        transaction
                            .redeem_recipient()
                            .ok_or(LedgerError::InvalidTransaction(
                                TransactionError::InvalidQCashRecipient,
                            ))?
                            .0,
                        transaction_commitment,
                    )?
                } else {
                    self.qcash_utxos.apply_redeem(
                        metadata,
                        transaction
                            .redeem_recipient()
                            .ok_or(LedgerError::InvalidTransaction(
                                TransactionError::InvalidQCashRecipient,
                            ))?
                            .0,
                        height,
                        transaction_commitment,
                    )?
                };
                let maturity_height = crate::block::Height(
                    height
                        .0
                        .saturating_add(crate::ledger::QCASH_REDEEM_CREDIT_MATURITY as u64),
                );
                let transaction_hash = transaction.hash()?;
                let output_total = outputs
                    .iter()
                    .try_fold(0_u64, |total, output| total.checked_add(output.amount.0));
                if output_total != Some(amount.0) {
                    return Err(LedgerError::InvalidTransaction(
                        TransactionError::InvalidQCashOutputs,
                    ));
                }
                for (index, output) in outputs.iter().enumerate() {
                    let owner =
                        crate::ledger::transition::resolve_output_target(output.to, miner_address);
                    self.accounts
                        .entry(owner)
                        .or_insert_with(|| Account::new(owner));
                    self.xpq_utxos.issue_at(
                        transaction_hash.as_hash(),
                        u32::try_from(index).map_err(|_| {
                            LedgerError::InvalidTransaction(TransactionError::InvalidQCashOutputs)
                        })?,
                        owner,
                        output.amount,
                        maturity_height,
                        crate::state::XpqCoinSource::QCashRedeem,
                    )?;
                }
            }
        }
        Ok(())
    }

    pub fn apply_signed_transaction(
        &mut self,
        signed_transaction: &SignedTransfer,
    ) -> Result<(), LedgerError> {
        self.apply_signed_transaction_at(signed_transaction, crate::block::Height(1))
    }

    pub fn apply_block(&mut self, block: Block) -> Result<(), LedgerError> {
        block.validate_structure()?;
        let (mut staged, _) = self.staged_after_validated_block(&block, true)?;
        if !block.is_genesis() && block.state_root() == Hash([0; HASH_SIZE]) {
            return Err(LedgerError::InvalidStateRoot);
        }

        let block_hash = block.hash()?;
        staged.rollback_states.insert(
            block_hash,
            AccountRollbackState {
                block_height: block.height(),
                accounts: self.accounts.clone(),
                account_state_tree: self.account_state_tree.clone(),
                xpq_utxos: self.xpq_utxos.clone(),
            },
        );
        staged.record_protocol_events(&block)?;
        staged.chain.insert_block(block)?;
        *self = staged;

        Ok(())
    }

    pub fn state_root_after_block(&self, block: &Block) -> Result<StateRoot, LedgerError> {
        self.staged_after_validated_block(block, true)
            .map(|(_, state_root)| state_root)
    }

    pub fn block(&self, height: &BlockHeight) -> Option<&Block> {
        self.chain.block(height)
    }

    pub fn has_blocks(&self) -> bool {
        self.chain.has_blocks()
    }

    pub fn tip_height(&self) -> Option<BlockHeight> {
        self.chain.tip_height()
    }

    pub fn tip_hash(&self) -> Option<BlockHash> {
        self.chain.tip_hash()
    }

    pub fn state_root(&self) -> StateRoot {
        self.account_state_tree.root()
    }

    /// Root committing accounts and all protocol extension state.
    pub fn protocol_state_root(&self) -> Result<StateRoot, LedgerError> {
        calculate_protocol_state_root(self.state_root(), &self.xpq_utxos, &self.qcash_utxos)
    }

    pub fn state_commitment_for_block_hash(
        &self,
        block_hash: BlockHash,
    ) -> Result<BlockStateCommitment, LedgerError> {
        let account_state_root = self.state_root();
        let xpq_state_root = StateRoot(self.xpq_utxos.consensus_root()?.0);
        let qcash_state_root = StateRoot(self.qcash_utxos.consensus_root()?.0);
        Ok(BlockStateCommitment::new(
            self.tip_height().unwrap_or(crate::block::Height(0)),
            block_hash,
            account_state_root,
            xpq_state_root,
            qcash_state_root,
            calculate_protocol_state_root_from_roots(
                account_state_root,
                xpq_state_root,
                qcash_state_root,
            )?,
        ))
    }

    pub fn tip_state_commitment(&self) -> Result<Option<BlockStateCommitment>, LedgerError> {
        self.tip_hash()
            .map(|block_hash| self.state_commitment_for_block_hash(block_hash))
            .transpose()
    }

    pub fn create_account_state_proof(&self, address: &Address) -> Option<AccountStateProof> {
        self.accounts
            .get(address)
            .map(|account| self.account_state_tree.create_account_proof(account))
    }

    pub fn create_account_non_membership_proof(
        &self,
        address: &Address,
    ) -> Option<AccountNonMembershipProof> {
        (!self.accounts.contains_key(address)).then(|| {
            self.account_state_tree
                .create_account_non_membership_proof(*address)
        })
    }
}

/// Commits account state and protocol extension state into one root.
pub fn calculate_protocol_state_root(
    account_state_root: StateRoot,
    xpq_utxos: &XpqUtxoSet,
    qcash_utxos: &QCashUtxoSet,
) -> Result<StateRoot, LedgerError> {
    let xpq_state_root = StateRoot(xpq_utxos.consensus_root()?.0);
    let qcash_state_root = StateRoot(qcash_utxos.consensus_root()?.0);
    Ok(calculate_protocol_state_root_from_roots(
        account_state_root,
        xpq_state_root,
        qcash_state_root,
    )?)
}

pub fn calculate_protocol_state_root_from_roots(
    account_state_root: StateRoot,
    xpq_state_root: StateRoot,
    qcash_state_root: StateRoot,
) -> Result<StateRoot, crate::error::CodecError> {
    Ok(StateRoot(
        domain_hash(
            HashDomain::ProtocolState,
            &crate::codec::canonical_bytes(&(
                account_state_root,
                xpq_state_root,
                qcash_state_root,
            ))?,
        )
        .0,
    ))
}

pub(crate) fn expected_issued_supply_from_headers(
    headers: &[crate::block::Header],
) -> Result<Amount, LedgerError> {
    let tip = headers
        .len()
        .checked_sub(1)
        .map(|height| Height(height as u64))
        .ok_or(LedgerError::InvalidParent)?;
    let mut total = 0_u64;
    let mut reward = Amount(crate::consensus::BASE_BLOCK_REWARD);
    for height in 1..=tip.0 {
        if crate::consensus::is_wbda_epoch_boundary(height) {
            let start = height as usize - crate::consensus::WBDA_WINDOW;
            let weights = headers[start..height as usize]
                .iter()
                .map(|header| usize::try_from(header.block_weight))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| LedgerError::InvalidParent)?;
            reward = crate::consensus::next_reward_from_window(reward, &weights)
                .ok_or(LedgerError::InvalidParent)?;
        }
        total = total
            .checked_add(reward.0)
            .ok_or(LedgerError::SupplyOverflow)?;
    }
    Ok(Amount(total))
}

#[cfg(test)]
mod tests {
    include!("ledger_tests.rs");
}
