use crate::block::Block;
use crate::block::BlockHeight;
use crate::consensus::supply::Amount;
use crate::consensus::{
    Consensus, DIFFICULTY_START, WBDA_WINDOW, is_wbda_epoch_boundary, next_difficulty_from_window,
};
use crate::crypto::Address;
use crate::crypto::{BlockHash, StateRoot, TransactionHash};
use crate::event::{ProtocolEvent, ProtocolEventKind};
use crate::ledger::{CONFIRMATION_DEPTH, Ledger, LedgerError};
use crate::state::Account;
use crate::transaction::{OutputTarget, QCashTransactionKind, SignedTransaction, Transaction};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionExecution {
    pub transaction_hash: TransactionHash,
    pub from: crate::crypto::Address,
    pub to: crate::crypto::Address,
    pub amount: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockExecution {
    pub block_hash: BlockHash,
    pub height: BlockHeight,
    pub state_root_before: StateRoot,
    pub state_root_after: StateRoot,
    pub transactions: Vec<TransactionExecution>,
}

impl TransactionExecution {
    pub fn from_output(
        transaction_hash: TransactionHash,
        transaction: &Transaction,
        output: crate::transaction::TransferOutput,
        miner_address: Address,
    ) -> Self {
        Self {
            transaction_hash,
            from: transaction.from,
            to: resolve_output_target(output.to, miner_address),
            amount: output.amount,
        }
    }
}

pub(crate) fn resolve_output_target(target: OutputTarget, miner_address: Address) -> Address {
    match target {
        OutputTarget::Address(address) => address,
        OutputTarget::BlockMiner => miner_address,
    }
}

pub(crate) fn apply_transaction_to_state_with_miner(
    accounts: &mut BTreeMap<Address, Account>,
    transaction: &Transaction,
    height: BlockHeight,
    miner_address: Address,
    authorization_proof_hash: crate::crypto::Hash,
) -> Result<(), LedgerError> {
    transaction.validate_for_height(height)?;
    if !accounts.contains_key(&transaction.from) {
        return Err(LedgerError::AccountNotFound);
    }
    let applied_tx_hash = transaction.hash()?.as_hash();

    {
        let sender = accounts
            .get_mut(&transaction.from)
            .ok_or(LedgerError::AccountNotFound)?;
        sender.apply_outgoing_transaction(
            transaction,
            height,
            applied_tx_hash,
            authorization_proof_hash,
        )?;
    }

    let maturity_height = crate::block::Height(height.0.saturating_add(CONFIRMATION_DEPTH as u64));
    for output in transaction.outputs() {
        let to = resolve_output_target(output.to, miner_address);
        let receiver = accounts
            .entry(to)
            .or_insert_with(|| Account::new(to, Amount(0)));
        receiver.credit_at_maturity(
            output.amount,
            maturity_height,
            crate::state::CreditSource::Transaction,
        )?;
    }

    Ok(())
}

pub(crate) fn apply_transaction_to_state(
    accounts: &mut BTreeMap<Address, Account>,
    transaction: &Transaction,
    height: BlockHeight,
) -> Result<(), LedgerError> {
    apply_transaction_to_state_with_miner(
        accounts,
        transaction,
        height,
        Address([0; 20]),
        crate::crypto::Hash::ZERO,
    )
}

pub(crate) fn apply_signed_transaction_to_state_with_miner(
    accounts: &mut BTreeMap<Address, Account>,
    signed: &SignedTransaction,
    height: BlockHeight,
    miner_address: Address,
) -> Result<(), LedgerError> {
    let account = accounts
        .get(&signed.transaction.from)
        .ok_or(LedgerError::AccountNotFound)?;
    let protocol = crate::transaction::SignedProtocolTransaction::from(signed.clone());
    let registration = protocol
        .validate_with_account_authorization(account, height)
        .map_err(LedgerError::from)?;
    if let Some((owner, auth)) = registration {
        accounts
            .get_mut(&signed.transaction.from)
            .ok_or(LedgerError::AccountNotFound)?
            .register_authorization(owner, auth)?;
    }
    let applied_tx_hash = signed.transaction.hash()?.as_hash();
    let authorization_proof_hash = signed
        .authorization_proof
        .hash_with_transaction(applied_tx_hash)?;
    apply_transaction_to_state_with_miner(
        accounts,
        &signed.transaction,
        height,
        miner_address,
        authorization_proof_hash,
    )
}

pub fn validate_transaction_against_state(
    accounts: &BTreeMap<Address, Account>,
    transaction: &Transaction,
    height: BlockHeight,
) -> Result<(), LedgerError> {
    let mut staged = accounts.clone();
    apply_transaction_to_state(&mut staged, transaction, height)
}

pub fn validate_signed_transaction_against_state(
    accounts: &BTreeMap<Address, Account>,
    transaction: &SignedTransaction,
    height: BlockHeight,
) -> Result<(), LedgerError> {
    let account = accounts
        .get(&transaction.transaction.from)
        .ok_or(LedgerError::AccountNotFound)?;
    crate::transaction::SignedProtocolTransaction::from(transaction.clone())
        .validate_with_account_authorization(account, height)
        .map_err(LedgerError::from)?;
    validate_transaction_against_state(accounts, &transaction.transaction, height)
}

impl Ledger {
    pub fn events_for_block(&self, block_hash: &BlockHash) -> &[ProtocolEvent] {
        self.events_by_block
            .get(block_hash)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn event(&self, id: crate::event::EventId) -> Option<&ProtocolEvent> {
        self.events_by_block
            .values()
            .flatten()
            .find(|event| event.id() == Ok(id))
    }

    pub(crate) fn record_protocol_events(&mut self, block: &Block) -> Result<(), LedgerError> {
        let height = block.height();
        let block_hash = block.hash()?;
        let mut events = Vec::with_capacity(
            block.transaction_count()
                + block.body.genesis_allocations.len()
                + usize::from(!block.is_genesis()),
        );
        let mut emit = |transaction_hash, kind| {
            let event_index = events.len() as u32;
            events.push(ProtocolEvent::new(
                height,
                block_hash,
                transaction_hash,
                event_index,
                kind,
            ));
        };

        for signed in block.transfer_transactions() {
            let tx = &signed.transaction;
            for output in tx.outputs() {
                emit(
                    Some(tx.hash()?),
                    ProtocolEventKind::Transfer {
                        from: tx.from,
                        to: resolve_output_target(output.to, block.miner_address()),
                        amount: output.amount,
                    },
                );
            }
        }
        for signed in block.qcash_transactions() {
            let tx = &signed.transaction;
            let kind = match &tx.kind {
                QCashTransactionKind::Withdraw { amount, .. } => {
                    ProtocolEventKind::QCashWithdrawn {
                        signer: tx.signer,
                        amount: *amount,
                    }
                }
                QCashTransactionKind::Redeem {
                    recipient,
                    metadata,
                } => ProtocolEventKind::QCashRedeemed {
                    signer: tx.signer,
                    recipient: *recipient,
                    amount: metadata
                        .amount()
                        .map_err(|_| LedgerError::EventInvariantViolation)?,
                },
                QCashTransactionKind::RecoverRedeem {
                    claimant, metadata, ..
                } => ProtocolEventKind::QCashRecoverRedeemed {
                    signer: tx.signer,
                    claimant: *claimant,
                    amount: metadata
                        .amount()
                        .map_err(|_| LedgerError::EventInvariantViolation)?,
                },
            };
            emit(Some(tx.hash()?), kind);
        }
        if block.is_genesis() {
            for allocation in &block.body.genesis_allocations {
                emit(
                    None,
                    ProtocolEventKind::GenesisAllocation {
                        recipient: allocation.to,
                        amount: allocation.amount,
                    },
                );
            }
        } else if let Some(coinbase) = &block.body.coinbase {
            emit(
                None,
                ProtocolEventKind::CoinbasePaid {
                    miner: coinbase.to,
                    subsidy: coinbase.subsidy,
                },
            );
        }

        self.events_by_block.insert(block_hash, events);
        Ok(())
    }

    pub fn apply_signed_transaction_at(
        &mut self,
        transaction: &SignedTransaction,
        height: BlockHeight,
    ) -> Result<(), LedgerError> {
        self.apply_signed_transaction_at_with_miner(transaction, height, Address([0; 20]))
    }

    pub fn apply_signed_transaction_at_with_miner(
        &mut self,
        transaction: &SignedTransaction,
        height: BlockHeight,
        miner_address: Address,
    ) -> Result<(), LedgerError> {
        let mut staged = self.clone();
        staged.validate_account_statement_is_active(transaction.transaction.last_state, height)?;
        apply_signed_transaction_to_state_with_miner(
            &mut staged.accounts,
            transaction,
            height,
            miner_address,
        )?;
        staged.register_account_statement_for_address(&transaction.transaction.from, height)?;
        staged.refresh_account_state(&transaction.transaction.from)?;
        for output in transaction.transaction.outputs() {
            let recipient = resolve_output_target(output.to, miner_address);
            staged.register_account_bootstrap_statement_for_address(&recipient)?;
            staged.refresh_account_state(&recipient)?;
        }
        *self = staged;
        Ok(())
    }

    pub fn validate_transaction_against_state(
        &self,
        transaction: &Transaction,
        height: BlockHeight,
    ) -> Result<(), LedgerError> {
        validate_transaction_against_state(&self.accounts, transaction, height)
    }

    pub fn validate_signed_transaction_against_state(
        &self,
        transaction: &SignedTransaction,
        height: BlockHeight,
    ) -> Result<(), LedgerError> {
        validate_signed_transaction_against_state(&self.accounts, transaction, height)
    }

    pub fn validate_block(&self, block: &Block) -> Result<StateRoot, LedgerError> {
        self.staged_after_validated_block(block, true)
            .map(|(_, expected_state_root)| expected_state_root)
    }

    pub fn execute_block(&self, block: &Block) -> Result<(Ledger, BlockExecution), LedgerError> {
        let state_root_before = self.state_root();
        let (mut staged, expected_state_root) = self.staged_after_validated_block(block, false)?;
        let mut committed_block = block.clone();
        if committed_block.state_root() == crate::crypto::Hash([0; crate::crypto::HASH_SIZE]) {
            committed_block.set_state_root(expected_state_root);
        }
        let block_hash = committed_block.hash()?;
        staged.record_protocol_events(&committed_block)?;
        staged.chain.insert_block(committed_block)?;

        let mut transaction_executions = Vec::new();
        for signed in block.transfer_transactions() {
            let transaction_hash = signed.hash()?;
            for output in signed.transaction.outputs() {
                transaction_executions.push(TransactionExecution::from_output(
                    transaction_hash,
                    &signed.transaction,
                    output,
                    block.miner_address(),
                ));
            }
        }
        let execution = BlockExecution {
            block_hash,
            height: block.height(),
            state_root_before,
            state_root_after: expected_state_root,
            transactions: transaction_executions,
        };

        Ok((staged, execution))
    }

    pub(crate) fn staged_after_validated_block(
        &self,
        block: &Block,
        enforce_proof_of_work: bool,
    ) -> Result<(Self, StateRoot), LedgerError> {
        block.validate_structure()?;
        self.chain.validate_next_block(block)?;
        if enforce_proof_of_work && !block.is_genesis() {
            let expected_difficulty = self.expected_difficulty_for_block(block)?;
            Consensus::validate_proof_of_work_at_difficulty(block, expected_difficulty)?;
        }

        let mut staged = self.clone();

        let block_hash = block.hash()?;
        for transaction in &block.body.transactions {
            match transaction {
                crate::transaction::SignedProtocolTransaction::Transfer(transaction) => {
                    staged.apply_signed_transaction_at_with_miner(
                        transaction,
                        block.height(),
                        block.miner_address(),
                    )?;
                }
                crate::transaction::SignedProtocolTransaction::QCash(transaction) => {
                    staged.apply_signed_qcash_transaction_in_block(
                        transaction,
                        block.height(),
                        block_hash,
                    )?;
                }
            }
        }
        if block.is_genesis() {
            for allocation in &block.body.genesis_allocations {
                staged.create_account(allocation.to, allocation.amount)?;
            }
        } else {
            staged.apply_coinbase(block)?;
        }

        let expected_state_root = if block.is_genesis() {
            staged.state_root()
        } else {
            staged.protocol_state_root()?
        };
        if !block.is_genesis()
            && block.state_root() != StateRoot::ZERO
            && block.state_root() != expected_state_root
        {
            return Err(LedgerError::InvalidStateRoot);
        }

        staged.validate_supply_for_block(block)?;
        Ok((staged, expected_state_root))
    }

    pub fn expected_difficulty_after_tip(&self) -> Result<u32, LedgerError> {
        let Some(tip_height) = self.chain.tip_height() else {
            return Ok(DIFFICULTY_START);
        };
        let next_height = crate::block::Height(tip_height.0.saturating_add(1));
        self.expected_difficulty_for_height(next_height)
    }

    fn expected_difficulty_for_block(&self, block: &Block) -> Result<u32, LedgerError> {
        self.expected_difficulty_for_height(block.height())
    }

    fn expected_difficulty_for_height(
        &self,
        height: crate::block::BlockHeight,
    ) -> Result<u32, LedgerError> {
        if height.0 == 0 {
            return Ok(DIFFICULTY_START);
        }
        let parent = self
            .chain
            .block(&crate::block::Height(height.0 - 1))
            .ok_or(LedgerError::InvalidParent)?;
        if !is_wbda_epoch_boundary(height.0) {
            return Ok(parent.difficulty());
        }
        let start = height.0.saturating_sub(WBDA_WINDOW as u64);
        let weights = (start..height.0)
            .map(|height| {
                self.chain
                    .block(&crate::block::Height(height))
                    .ok_or(LedgerError::InvalidParent)?
                    .block_weight()
                    .try_into()
                    .map_err(|_| LedgerError::InvalidParent)
            })
            .collect::<Result<Vec<_>, _>>()?;
        next_difficulty_from_window(parent.difficulty(), &weights).ok_or(LedgerError::InvalidParent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Address, dual_address_from_public_keys, generate_keypair, sign};
    use crate::state::CreditSource;
    use crate::transaction::{OutputTarget, SignedTransaction, TransferOutput};

    #[test]
    fn batch_transfer_uses_candidate_height_for_mature_balance() {
        let primary = generate_keypair();
        let authorization = generate_keypair();
        let sender = dual_address_from_public_keys(&primary.public_key, &authorization.public_key);
        let mut ledger = Ledger::new();
        ledger
            .create_account_with_authorization(sender, authorization.public_key, Amount(0))
            .unwrap();
        let account = ledger.accounts.get_mut(&sender).unwrap();
        account
            .credit_at_maturity(
                Amount(100),
                crate::block::Height(50),
                CreditSource::MiningReward,
            )
            .unwrap();

        let transaction = Transaction::new(
            sender,
            vec![
                TransferOutput {
                    to: (Address([2; 20])).into(),
                    amount: Amount(10),
                },
                TransferOutput {
                    to: (Address([3; 20])).into(),
                    amount: Amount(10),
                },
            ],
        )
        .with_last_state(ledger.account(&sender).unwrap().statement);
        let signing_bytes = transaction.signing_bytes().unwrap();
        let signed = SignedTransaction::new_authorized(
            transaction,
            primary.public_key,
            sign(&primary.secret_key, &signing_bytes),
            authorization.public_key,
            sign(&authorization.secret_key, &signing_bytes),
        );

        assert!(
            ledger
                .clone()
                .apply_signed_transaction_at(&signed, crate::block::Height(49))
                .is_err()
        );
        ledger
            .apply_signed_transaction_at(&signed, crate::block::Height(50))
            .unwrap();
        assert_eq!(ledger.account(&sender).unwrap().balance, Amount(80));
        assert_eq!(
            ledger.account(&Address([2; 20])).unwrap().balance,
            Amount(10)
        );
        assert_eq!(
            ledger.account(&Address([3; 20])).unwrap().balance,
            Amount(10)
        );
    }

    #[test]
    fn block_miner_output_is_paid_to_candidate_miner() {
        let primary = generate_keypair();
        let authorization = generate_keypair();
        let sender = dual_address_from_public_keys(&primary.public_key, &authorization.public_key);
        let miner = Address([9; 20]);
        let mut ledger = Ledger::new();
        ledger
            .create_account_with_authorization(sender, authorization.public_key, Amount(100))
            .unwrap();

        let transaction = Transaction::new(
            sender,
            vec![TransferOutput {
                to: OutputTarget::BlockMiner,
                amount: Amount(7),
            }],
        )
        .with_last_state(ledger.account(&sender).unwrap().statement);
        let signing_bytes = transaction.signing_bytes().unwrap();
        let signed = SignedTransaction::new_authorized(
            transaction,
            primary.public_key,
            sign(&primary.secret_key, &signing_bytes),
            authorization.public_key,
            sign(&authorization.secret_key, &signing_bytes),
        );

        ledger
            .apply_signed_transaction_at_with_miner(&signed, crate::block::Height(1), miner)
            .unwrap();

        assert_eq!(ledger.account(&sender).unwrap().balance, Amount(93));
        assert_eq!(ledger.account(&miner).unwrap().balance, Amount(7));
        assert_eq!(
            ledger
                .account(&miner)
                .unwrap()
                .available_balance_at(crate::block::Height(1)),
            Amount(0)
        );
    }
}
