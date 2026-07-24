use crate::block::Block;
use crate::block::BlockHeight;
use crate::consensus::supply::Amount;
use crate::consensus::{Consensus, DIFFICULTY_START};
use crate::crypto::Address;
use crate::crypto::{BlockHash, StateRoot, TransactionHash};
use crate::event::{ProtocolEvent, ProtocolEventKind};
use crate::ledger::{CONFIRMATION_DEPTH, Ledger, LedgerError};
use crate::state::Account;
use crate::transaction::{QCashTransactionKind, SignedTransaction, Transaction};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionExecution {
    pub transaction_hash: TransactionHash,
    pub from: crate::crypto::Address,
    pub to: crate::crypto::Address,
    pub amount: Amount,
    pub fee: Amount,
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
        fee: Amount,
    ) -> Self {
        Self {
            transaction_hash,
            from: transaction.from,
            to: output.to,
            amount: output.amount,
            fee,
        }
    }
}

pub(crate) fn apply_transaction_to_state(
    accounts: &mut BTreeMap<Address, Account>,
    transaction: &Transaction,
    height: BlockHeight,
) -> Result<(), LedgerError> {
    transaction.validate_for_height(height)?;
    if !accounts.contains_key(&transaction.from) {
        return Err(LedgerError::AccountNotFound);
    }

    {
        let sender = accounts
            .get_mut(&transaction.from)
            .ok_or(LedgerError::AccountNotFound)?;
        sender.apply_outgoing_transaction(transaction, height)?;
    }

    let spendable_height = crate::block::Height(height.0.saturating_add(CONFIRMATION_DEPTH as u64));
    for output in transaction.outputs() {
        let receiver = accounts
            .entry(output.to)
            .or_insert_with(|| Account::new(output.to, Amount(0)));
        receiver.credit_locked(
            output.amount,
            spendable_height,
            crate::state::CreditSource::Transaction,
        )?;
    }

    Ok(())
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
    transaction
        .validate_signed_for_height(height)
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
            .find(|event| event.id() == id)
    }

    pub(crate) fn record_protocol_events(&mut self, block: &Block) {
        let height = block.height();
        let block_hash = block.hash();
        let mut events = Vec::with_capacity(
            block.transaction_count()
                + block.genesis_allocations.len()
                + usize::from(!block.is_genesis()),
        );
        let mut emit = |transaction_hash, kind| {
            let event_index = u32::try_from(events.len())
                .expect("a valid block cannot contain more than u32::MAX events");
            events.push(ProtocolEvent::new(
                height,
                block_hash,
                transaction_hash,
                event_index,
                kind,
            ));
        };

        for signed in &block.transactions {
            let tx = &signed.transaction;
            for (index, output) in tx.outputs().enumerate() {
                emit(
                    Some(tx.hash()),
                    ProtocolEventKind::Transfer {
                        from: tx.from,
                        to: output.to,
                        amount: output.amount,
                        fee: if index == 0 { tx.fee } else { Amount(0) },
                    },
                );
            }
        }
        for signed in &block.qcash_transactions {
            let tx = &signed.transaction;
            let kind = match &tx.kind {
                QCashTransactionKind::WithdrawCash { amount, .. } => {
                    ProtocolEventKind::QCashWithdrawn {
                        signer: tx.signer,
                        amount: *amount,
                    }
                }
                QCashTransactionKind::DepositCash {
                    recipient,
                    metadata,
                } => ProtocolEventKind::QCashDeposited {
                    signer: tx.signer,
                    recipient: *recipient,
                    amount: metadata
                        .amount()
                        .expect("an applied QCash deposit has a valid amount"),
                },
            };
            emit(Some(tx.hash()), kind);
        }
        if block.is_genesis() {
            for allocation in &block.genesis_allocations {
                emit(
                    None,
                    ProtocolEventKind::GenesisAllocation {
                        recipient: allocation.to,
                        amount: allocation.amount,
                    },
                );
            }
        } else if let Some(coinbase) = &block.coinbase {
            emit(
                None,
                ProtocolEventKind::CoinbasePaid {
                    miner: coinbase.to,
                    subsidy: coinbase.subsidy,
                },
            );
            if coinbase.fees.0 > 0 {
                emit(
                    None,
                    ProtocolEventKind::MinerFeeRevenue {
                        miner: coinbase.to,
                        fees: coinbase.fees,
                    },
                );
            }
        }

        self.events_by_block.insert(block_hash, events);
    }

    pub(crate) fn apply_transaction_at(
        &mut self,
        transaction: &Transaction,
        height: BlockHeight,
    ) -> Result<(), LedgerError> {
        apply_transaction_to_state(&mut self.accounts, transaction, height)?;
        self.refresh_account_state(&transaction.from);
        for output in transaction.outputs() {
            self.refresh_account_state(&output.to);
        }
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
        let block_hash = committed_block.hash();
        staged.record_protocol_events(&committed_block);
        staged.chain.insert_block(committed_block)?;

        let execution = BlockExecution {
            block_hash,
            height: block.height(),
            state_root_before,
            state_root_after: expected_state_root,
            transactions: block
                .transactions
                .iter()
                .flat_map(|signed| {
                    signed
                        .transaction
                        .outputs()
                        .enumerate()
                        .map(|(index, output)| {
                            TransactionExecution::from_output(
                                signed.hash(),
                                &signed.transaction,
                                output,
                                if index == 0 {
                                    signed.transaction.fee
                                } else {
                                    Amount(0)
                                },
                            )
                        })
                })
                .collect(),
        };

        Ok((staged, execution))
    }

    pub(crate) fn staged_after_validated_block(
        &self,
        block: &Block,
        enforce_proof_of_work: bool,
    ) -> Result<(Self, StateRoot), LedgerError> {
        block.validate()?;
        self.chain.validate_next_block(block)?;
        if enforce_proof_of_work {
            let expected_difficulty = self.expected_next_difficulty()?;
            Consensus::validate_proof_of_work_at_difficulty(block, expected_difficulty)?;
        }

        let mut staged = self.clone();
        // UTXO maturity is a consensus transition and must be committed by the
        // candidate block's protocol state root before inputs are evaluated.
        staged.finalize_qcash_at(block.height());

        for transaction in &block.transactions {
            staged.apply_transaction_at(&transaction.transaction, block.height())?;
        }

        let block_hash = block.hash();
        for transaction in &block.qcash_transactions {
            staged.apply_signed_qcash_transaction_in_block(
                transaction,
                block.height(),
                block_hash,
            )?;
        }
        if block.is_genesis() {
            for allocation in &block.genesis_allocations {
                staged.create_account(allocation.to, allocation.amount)?;
            }
        } else {
            staged.apply_coinbase(block)?;
        }

        let expected_state_root = if block.is_genesis() {
            staged.state_root()
        } else {
            staged.protocol_state_root()
        };
        if !block.is_genesis()
            && block.state_root() != StateRoot::ZERO
            && block.state_root() != expected_state_root
        {
            return Err(LedgerError::InvalidStateRoot);
        }

        staged.validate_supply()?;
        Ok((staged, expected_state_root))
    }

    fn expected_next_difficulty(&self) -> Result<u32, LedgerError> {
        let Some(tip_height) = self.chain.tip_height() else {
            return Ok(DIFFICULTY_START);
        };
        if tip_height == crate::block::Height(0) {
            return Ok(DIFFICULTY_START);
        }
        let tip = self
            .chain
            .block(&tip_height)
            .ok_or(LedgerError::InvalidParent)?;
        let anchor = self
            .chain
            .block(&crate::block::Height(1))
            .ok_or(LedgerError::InvalidParent)?;
        Ok(Consensus::with_default_config().asert_difficulty(
            anchor.difficulty(),
            anchor.timestamp(),
            anchor.height(),
            tip.timestamp(),
            tip.height(),
        )?)
    }
}
