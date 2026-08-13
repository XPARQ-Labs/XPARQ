use crate::block::Block;
use crate::block::BlockHeight;
use crate::consensus::supply::Amount;
use crate::consensus::{
    Consensus, DIFFICULTY_START, WBDA_WINDOW, is_wbda_epoch_boundary, next_difficulty_from_window,
};
use crate::crypto::Address;
use crate::crypto::{BlockHash, StateRoot, TransactionHash};
use crate::event::{ProtocolEvent, ProtocolEventKind};
use crate::ledger::{CONFIRMATION_DEPTH, Ledger, LedgerError, SparseStateTree};
use crate::state::{Account, XpqCoinSource, XpqUtxoSet};
use crate::transaction::{OutputTarget, QCashTransactionKind, SignedTransfer, Transfer};
use std::collections::BTreeMap;
use std::sync::Arc;

fn refresh_staged_account(
    tree: &mut Arc<SparseStateTree>,
    accounts: &BTreeMap<Address, Account>,
    address: &Address,
) -> Result<(), LedgerError> {
    if let Some(account) = accounts.get(address) {
        Arc::make_mut(tree).update_account(account)?;
    } else {
        Arc::make_mut(tree).remove_account(address);
    }
    Ok(())
}

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
    pub fn from_transfer(
        transaction_hash: TransactionHash,
        transaction: &Transfer,
        miner_address: Address,
    ) -> Self {
        let output = transaction
            .outputs
            .first()
            .expect("validated transfer always has an output");
        Self {
            transaction_hash,
            from: transaction.from,
            to: resolve_output_target(output.to, miner_address),
            amount: output.amount,
        }
    }
}

fn block_execution(
    block: &Block,
    block_hash: BlockHash,
    state_root_before: StateRoot,
    state_root_after: StateRoot,
) -> Result<BlockExecution, LedgerError> {
    let transactions = block
        .transfer_transactions()
        .map(|signed| {
            Ok(TransactionExecution::from_transfer(
                signed.hash()?,
                &signed.transaction,
                block.miner_address(),
            ))
        })
        .collect::<Result<Vec<_>, LedgerError>>()?;
    Ok(BlockExecution {
        block_hash,
        height: block.height(),
        state_root_before,
        state_root_after,
        transactions,
    })
}

pub(crate) fn resolve_output_target(target: OutputTarget, miner_address: Address) -> Address {
    match target {
        OutputTarget::Address(address) => address,
        OutputTarget::BlockMiner => miner_address,
    }
}

pub(crate) fn apply_transaction_to_state_with_miner(
    accounts: &mut BTreeMap<Address, Account>,
    xpq_utxos: &mut XpqUtxoSet,
    transaction: &Transfer,
    height: BlockHeight,
    miner_address: Address,
) -> Result<(), LedgerError> {
    transaction.validate_for_height(height)?;
    let maturity_height = crate::block::Height(height.0.saturating_add(CONFIRMATION_DEPTH as u64));
    let outputs = transaction
        .outputs
        .iter()
        .map(|output| {
            (
                resolve_output_target(output.to, miner_address),
                output.amount,
                maturity_height,
                XpqCoinSource::Transfer,
            )
        })
        .collect::<Vec<_>>();
    xpq_utxos.spend_and_create(
        transaction.from,
        &transaction.inputs,
        &outputs,
        transaction.hash()?,
        height,
    )?;
    for (owner, _, _, _) in outputs {
        accounts.entry(owner).or_insert_with(|| Account::new(owner));
    }
    Ok(())
}

pub(crate) fn apply_transaction_to_state(
    accounts: &mut BTreeMap<Address, Account>,
    xpq_utxos: &mut XpqUtxoSet,
    transaction: &Transfer,
    height: BlockHeight,
) -> Result<(), LedgerError> {
    apply_transaction_to_state_with_miner(accounts, xpq_utxos, transaction, height, Address::ZERO)
}

pub(crate) fn apply_signed_transaction_to_state_with_miner(
    accounts: &mut BTreeMap<Address, Account>,
    xpq_utxos: &mut XpqUtxoSet,
    signed: &SignedTransfer,
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
    if let Some(public_key) = registration {
        accounts
            .get_mut(&signed.transaction.from)
            .ok_or(LedgerError::AccountNotFound)?
            .register_authorization(public_key)?;
    }
    apply_transaction_to_state_with_miner(
        accounts,
        xpq_utxos,
        &signed.transaction,
        height,
        miner_address,
    )
}

pub fn validate_transaction_against_state(
    accounts: &BTreeMap<Address, Account>,
    xpq_utxos: &XpqUtxoSet,
    transaction: &Transfer,
    height: BlockHeight,
) -> Result<(), LedgerError> {
    let mut staged = accounts.clone();
    let mut staged_utxos = xpq_utxos.clone();
    apply_transaction_to_state(&mut staged, &mut staged_utxos, transaction, height)
}

pub fn validate_signed_transaction_against_state(
    accounts: &BTreeMap<Address, Account>,
    xpq_utxos: &XpqUtxoSet,
    transaction: &SignedTransfer,
    height: BlockHeight,
) -> Result<(), LedgerError> {
    let account = accounts
        .get(&transaction.transaction.from)
        .ok_or(LedgerError::AccountNotFound)?;
    crate::transaction::SignedProtocolTransaction::from(transaction.clone())
        .validate_with_account_authorization(account, height)
        .map_err(LedgerError::from)?;
    validate_transaction_against_state(accounts, xpq_utxos, &transaction.transaction, height)
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
        let mut events =
            Vec::with_capacity(block.transaction_count() + usize::from(!block.is_genesis()));
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
            let transaction_hash = tx.hash()?;
            for output in &tx.outputs {
                emit(
                    Some(transaction_hash),
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
                QCashTransactionKind::Redeem { .. } => match tx.redeem_recipient() {
                    Some((recipient, amount)) => ProtocolEventKind::QCashRedeemed {
                        signer: tx.signer,
                        recipient,
                        amount,
                        qcash_change_amount: tx.qcash_change_amount()?,
                    },
                    None => ProtocolEventKind::QCashSplit {
                        signer: tx.signer,
                        amount: tx.amount()?,
                    },
                },
            };
            emit(Some(tx.hash()?), kind);
        }
        if let Some(emission) = &block.body.emission {
            emit(
                None,
                ProtocolEventKind::EmissionDistributed {
                    miner: emission.to,
                    subsidy: emission.subsidy,
                },
            );
        }

        self.events_by_block.insert(block_hash, events);
        Ok(())
    }

    pub fn apply_signed_transaction_at(
        &mut self,
        transaction: &SignedTransfer,
        height: BlockHeight,
    ) -> Result<(), LedgerError> {
        self.apply_signed_transaction_at_with_miner(transaction, height, Address::ZERO)
    }

    pub fn apply_signed_transaction_at_with_miner(
        &mut self,
        transaction: &SignedTransfer,
        height: BlockHeight,
        miner_address: Address,
    ) -> Result<(), LedgerError> {
        let mut staged_accounts = self.accounts.clone();
        let mut staged_utxos = self.xpq_utxos.clone();
        apply_signed_transaction_to_state_with_miner(
            &mut staged_accounts,
            &mut staged_utxos,
            transaction,
            height,
            miner_address,
        )?;
        let mut staged_tree = self.account_state_tree.clone();
        refresh_staged_account(
            &mut staged_tree,
            &staged_accounts,
            &transaction.transaction.from,
        )?;
        for output in &transaction.transaction.outputs {
            let recipient = resolve_output_target(output.to, miner_address);
            refresh_staged_account(&mut staged_tree, &staged_accounts, &recipient)?;
        }
        self.accounts = staged_accounts;
        self.account_state_tree = staged_tree;
        self.xpq_utxos = staged_utxos;
        Ok(())
    }

    pub fn validate_transaction_against_state(
        &self,
        transaction: &Transfer,
        height: BlockHeight,
    ) -> Result<(), LedgerError> {
        validate_transaction_against_state(&self.accounts, &self.xpq_utxos, transaction, height)
    }

    pub fn validate_signed_transaction_against_state(
        &self,
        transaction: &SignedTransfer,
        height: BlockHeight,
    ) -> Result<(), LedgerError> {
        validate_signed_transaction_against_state(
            &self.accounts,
            &self.xpq_utxos,
            transaction,
            height,
        )
    }

    pub fn validate_block(&self, block: &Block) -> Result<StateRoot, LedgerError> {
        self.staged_after_validated_block(block, true)
            .map(|(_, expected_state_root)| expected_state_root)
    }

    /// Executes a fully valid network block and returns the committed ledger.
    ///
    /// Unlike candidate preview, this path enforces proof of work and requires
    /// the caller-supplied state root to be non-zero and exact.
    pub fn validate_and_execute_block(
        &self,
        block: &Block,
    ) -> Result<(Ledger, BlockExecution), LedgerError> {
        let state_root_before = self.state_root();
        let (mut staged, expected_state_root) = self.staged_after_validated_block(block, true)?;
        if !block.is_genesis()
            && (block.state_root() == StateRoot::ZERO || block.state_root() != expected_state_root)
        {
            return Err(LedgerError::InvalidStateRoot);
        }
        let block_hash = block.hash()?;
        staged.remember_rollback_state(block_hash, block.height(), self);
        staged.record_protocol_events(block)?;
        staged.chain.insert_block(block.clone())?;

        Ok((
            staged,
            block_execution(block, block_hash, state_root_before, expected_state_root)?,
        ))
    }

    /// Computes a candidate block's post-state without checking PoW and without
    /// returning or committing the staged ledger. Miners use this only to fill
    /// the state root before searching for a valid nonce.
    pub fn preview_candidate_block(&self, block: &Block) -> Result<BlockExecution, LedgerError> {
        let state_root_before = self.state_root();
        let (_, expected_state_root) = self.staged_after_validated_block(block, false)?;
        let mut committed_header = block.header.clone();
        committed_header.state_root = expected_state_root;
        let block_hash = committed_header.hash()?;

        block_execution(block, block_hash, state_root_before, expected_state_root)
    }

    pub(crate) fn staged_after_validated_block(
        &self,
        block: &Block,
        enforce_pow: bool,
    ) -> Result<(Self, StateRoot), LedgerError> {
        block.validate_structure()?;
        self.chain.validate_next_block(block)?;
        if enforce_pow && !block.is_genesis() {
            let expected_difficulty = self.expected_difficulty_for_block(block)?;
            Consensus::validate_pow_at_difficulty(block, expected_difficulty)?;
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
                        block.miner_address(),
                    )?;
                }
            }
        }
        if !block.is_genesis() {
            staged.apply_emission(block)?;
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
