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

    let maturity_height = crate::block::Height(height.0.saturating_add(CONFIRMATION_DEPTH as u64));
    for output in transaction.outputs() {
        let receiver = accounts
            .entry(output.to)
            .or_insert_with(|| Account::new(output.to, Amount(0)));
        receiver.credit_at_maturity(
            output.amount,
            maturity_height,
            crate::state::CreditSource::Transaction,
        )?;
    }

    Ok(())
}

pub(crate) fn apply_signed_transaction_to_state(
    accounts: &mut BTreeMap<Address, Account>,
    signed: &SignedTransaction,
    height: BlockHeight,
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
    apply_transaction_to_state(accounts, &signed.transaction, height)
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
                + block.genesis_allocations.len()
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
            for (index, output) in tx.outputs().enumerate() {
                emit(
                    Some(tx.hash()?),
                    ProtocolEventKind::Transfer {
                        from: tx.from,
                        to: output.to,
                        amount: output.amount,
                        fee: if index == 0 { tx.fee } else { Amount(0) },
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
                QCashTransactionKind::Deposit {
                    recipient,
                    metadata,
                } => ProtocolEventKind::QCashDeposited {
                    signer: tx.signer,
                    recipient: *recipient,
                    amount: metadata
                        .amount()
                        .map_err(|_| LedgerError::EventInvariantViolation)?,
                },
            };
            emit(Some(tx.hash()?), kind);
        }
        for signed in block.governance_actions() {
            let tx = &signed.action;
            let kind = match &tx.kind {
                crate::governance::GovernanceActionKind::RegisterIssuer {
                    issuer_public_key,
                    metadata_hash,
                    metadata_uri,
                    fee_policy_hash,
                    fee_policy_uri,
                    bond_amount,
                    bond_locked_until,
                } => {
                    let issuer = crate::governance::GovernanceIssuer::new_registered(
                        tx.signer,
                        **issuer_public_key,
                        *metadata_hash,
                        metadata_uri.clone(),
                        *fee_policy_hash,
                        fee_policy_uri.clone(),
                        *bond_amount,
                        *bond_locked_until,
                        height,
                    )
                    .map_err(|_| LedgerError::EventInvariantViolation)?;
                    ProtocolEventKind::GovernanceIssuerRegistered {
                        issuer_id: issuer.id,
                        controller: tx.signer,
                    }
                }
                crate::governance::GovernanceActionKind::ApproveIssuer { issuer_id, .. } => {
                    ProtocolEventKind::GovernanceIssuerApproved {
                        issuer_id: *issuer_id,
                        approver: tx.signer,
                    }
                }
                crate::governance::GovernanceActionKind::IssueCredential { credential } => {
                    let issuer = self
                        .governance
                        .active_issuer_by_key(&credential.issuer_public_key)
                        .ok_or(LedgerError::EventInvariantViolation)?;
                    ProtocolEventKind::GovernanceCredentialIssued {
                        issuer_id: issuer.id,
                        subject: credential
                            .subject
                            .ok_or(LedgerError::EventInvariantViolation)?,
                        credential_type: credential.credential_type.clone(),
                    }
                }
                crate::governance::GovernanceActionKind::BindCredential { credential_use } => {
                    ProtocolEventKind::GovernanceCredentialBound {
                        subject: tx.signer,
                        credential_type: credential_use.credential.credential_type.clone(),
                    }
                }
                crate::governance::GovernanceActionKind::RevokeCredential { credential_type } => {
                    ProtocolEventKind::GovernanceCredentialRevoked {
                        subject: tx.signer,
                        credential_type: credential_type.clone(),
                    }
                }
                crate::governance::GovernanceActionKind::CreateProposal {
                    proposal,
                    bond_amount,
                    ..
                } => ProtocolEventKind::GovernanceProposalCreated {
                    proposal_id: proposal.id,
                    proposer: proposal.proposer,
                    action_type: proposal.action_type.clone(),
                    voting_mode: proposal.voting_mode,
                    bond_amount: *bond_amount,
                },
                crate::governance::GovernanceActionKind::Vote {
                    proposal_id,
                    choice,
                    authorization,
                } => ProtocolEventKind::GovernanceVoteCast {
                    proposal_id: *proposal_id,
                    voter: tx.signer,
                    choice: *choice,
                    power: match authorization.as_ref() {
                        crate::governance::VoteAuthorization::Credential(_)
                        | crate::governance::VoteAuthorization::BoundCredential { .. } => 1,
                        crate::governance::VoteAuthorization::CoinPower { amount } => amount.0,
                    },
                },
                crate::governance::GovernanceActionKind::FinalizeProposal { proposal_id } => {
                    let proposal = self
                        .governance
                        .proposal(proposal_id)
                        .ok_or(LedgerError::EventInvariantViolation)?;
                    let tally = self
                        .governance
                        .vote_tally(proposal_id)
                        .ok_or(LedgerError::EventInvariantViolation)?;
                    ProtocolEventKind::GovernanceProposalFinalized {
                        proposal_id: *proposal_id,
                        outcome: tally.outcome_for(proposal),
                    }
                }
                crate::governance::GovernanceActionKind::ExecuteProposal { proposal_id } => {
                    ProtocolEventKind::GovernanceProposalExecuted {
                        proposal_id: *proposal_id,
                        executor: tx.signer,
                    }
                }
            };
            emit(Some(tx.hash()?), kind);
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
        Ok(())
    }

    pub fn apply_signed_transaction_at(
        &mut self,
        transaction: &SignedTransaction,
        height: BlockHeight,
    ) -> Result<(), LedgerError> {
        let mut staged = self.clone();
        staged.record_attached_credentials(&transaction.transaction.credential_uses)?;
        apply_signed_transaction_to_state(&mut staged.accounts, transaction, height)?;
        staged.refresh_account_state(&transaction.transaction.from)?;
        for output in transaction.transaction.outputs() {
            staged.refresh_account_state(&output.to)?;
        }
        // Fee revenue is credited by coinbase after every transaction in the
        // candidate has executed, so supply cannot be checked mid-block.
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
            for (index, output) in signed.transaction.outputs().enumerate() {
                transaction_executions.push(TransactionExecution::from_output(
                    transaction_hash,
                    &signed.transaction,
                    output,
                    if index == 0 {
                        signed.transaction.fee
                    } else {
                        Amount(0)
                    },
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
        if enforce_proof_of_work {
            let expected_difficulty = self.expected_difficulty_for_block(block)?;
            Consensus::validate_proof_of_work_at_difficulty(block, expected_difficulty)?;
        }

        let mut staged = self.clone();

        let block_hash = block.hash()?;
        for transaction in &block.transactions {
            match transaction {
                crate::transaction::SignedProtocolTransaction::Transfer(transaction) => {
                    staged.apply_signed_transaction_at(transaction, block.height())?;
                }
                crate::transaction::SignedProtocolTransaction::QCash(transaction) => {
                    staged.apply_signed_qcash_transaction_in_block(
                        transaction,
                        block.height(),
                        block_hash,
                    )?;
                }
                crate::transaction::SignedProtocolTransaction::Governance(transaction) => {
                    staged.apply_signed_governance_action(transaction, block.height())?;
                }
            }
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

    fn expected_difficulty_for_block(&self, block: &Block) -> Result<u32, LedgerError> {
        let Some(tip_height) = self.chain.tip_height() else {
            return Ok(DIFFICULTY_START);
        };
        if block.height().0 <= 1 || tip_height == crate::block::Height(0) {
            return Ok(DIFFICULTY_START);
        }
        let anchor = self
            .chain
            .block(&crate::block::Height(1))
            .ok_or(LedgerError::InvalidParent)?;
        Ok(Consensus::with_default_config().asert_difficulty(
            anchor.difficulty(),
            anchor.timestamp(),
            anchor.height(),
            block.timestamp(),
            block.height(),
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Nonce;
    use crate::crypto::{Address, dual_address_from_public_keys, generate_keypair, sign};
    use crate::state::CreditSource;
    use crate::transaction::{SignedTransaction, TransferOutput};

    #[test]
    fn batch_transfer_uses_candidate_height_for_mature_balance() {
        let primary = generate_keypair();
        let authorization = generate_keypair();
        let sender = dual_address_from_public_keys(&primary.public_key, &authorization.public_key);
        let mut ledger = Ledger::new();
        ledger
            .create_account_with_authorization(sender, authorization.public_key, Amount(0))
            .unwrap();
        ledger
            .accounts
            .get_mut(&sender)
            .unwrap()
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
                    to: Address([2; 20]),
                    amount: Amount(10),
                },
                TransferOutput {
                    to: Address([3; 20]),
                    amount: Amount(10),
                },
            ],
            Amount(1),
            Nonce(0),
        );
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
        assert_eq!(ledger.account(&sender).unwrap().balance, Amount(79));
        assert_eq!(
            ledger.account(&Address([2; 20])).unwrap().balance,
            Amount(10)
        );
        assert_eq!(
            ledger.account(&Address([3; 20])).unwrap().balance,
            Amount(10)
        );
    }
}
