use crate::block::{Block, BlockHeight, Height};
use crate::consensus::supply::{Amount, Balance};
use crate::crypto::{Address, PublicKey};
use crate::crypto::{BlockHash, HASH_SIZE, Hash, HashDomain, StateRoot, domain_hash};
use crate::error::LedgerError;
use crate::event::{
    AccountRollback, AccountSnapshot, ChainEvent, DisconnectedBlock, ProtocolEvent, RollbackEvent,
    RollbackHistory,
};
use crate::governance::{
    CredentialNullifier, GovernanceAction, GovernanceActionKind, GovernanceActionType,
    GovernanceCredential, GovernanceCredentialUse, GovernanceIssuer, GovernanceIssuerId, Proposal,
    ProposalCreationAuthorization, ProposalId, ProposalVotingMode, SignedGovernanceAction,
    VoteAuthorization,
};
use crate::ledger::CONFIRMATION_DEPTH;
use crate::ledger::chain::Chain;
use crate::ledger::{AccountNonMembershipProof, AccountStateProof, SparseStateTree};
use crate::state::{
    Account, BlockStateCommitment, CredentialUseState, CreditSource, GovernanceState,
    GovernanceVoteTally, QCashUtxoSet, Vault, VaultClaim, VaultId, VaultPayout, VaultState,
};
use crate::transaction::{
    QCashTransaction, QCashTransactionKind, SignedQCashTransaction, SignedTransaction,
    SignedVaultClaim, TransactionError,
};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    pub(crate) accounts: BTreeMap<Address, Account>,
    account_state_tree: Arc<SparseStateTree>,
    pub chain: Chain,
    pub qcash_utxos: QCashUtxoSet,
    pub governance: GovernanceState,
    pub credential_uses: CredentialUseState,
    pub vaults: VaultState,
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
    accounts: BTreeMap<Address, Account>,
    account_state_tree: Arc<SparseStateTree>,
    governance: GovernanceState,
    credential_uses: CredentialUseState,
}

fn account_snapshot(account: &Account) -> AccountSnapshot {
    AccountSnapshot {
        balance: account.balance,
        nonce: account.nonce,
    }
}

fn account_rollbacks(
    before: &BTreeMap<Address, Account>,
    after: &BTreeMap<Address, Account>,
) -> Vec<AccountRollback> {
    let mut addresses = before
        .keys()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    addresses.extend(after.keys().copied());
    addresses
        .into_iter()
        .filter_map(|address| {
            let before_snapshot = before.get(&address).map(account_snapshot);
            let after_snapshot = after.get(&address).map(account_snapshot);
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
        qcash_utxos: QCashUtxoSet,
        governance: GovernanceState,
        credential_uses: CredentialUseState,
        headers: &[crate::block::BlockHeader],
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
            qcash_utxos,
            governance,
            credential_uses,
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
        headers: &[crate::block::BlockHeader],
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
    ) -> Result<(), LedgerError> {
        self.refresh_account_state(&transaction.signer)?;
        if let QCashTransactionKind::Deposit { recipient, .. } = &transaction.kind {
            self.refresh_account_state(recipient)?;
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
        staged.accounts.insert(
            address,
            Account::new_with_authorization(address, auth_public_key, balance),
        );
        staged.refresh_account_state(&address)?;
        staged.validate_supply()?;
        *self = staged;
        Ok(())
    }

    pub fn insert_account(&mut self, account: Account) -> Result<(), LedgerError> {
        if self.accounts.contains_key(&account.address) {
            return Err(LedgerError::AccountAlreadyExists);
        }
        self.reject_non_consensus_issuance(account.balance)?;

        let mut staged = self.clone();
        let address = account.address;
        staged.accounts.insert(address, account);
        staged.refresh_account_state(&address)?;
        staged.validate_supply()?;
        *self = staged;
        Ok(())
    }

    /// Account construction is used while assembling genesis and in isolated
    /// test ledgers. Once a chain has a tip, a non-zero opening balance would
    /// be an issuance path outside consensus coinbase and is always rejected.
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
        self.account(address).map(|account| account.balance)
    }

    pub fn confirmed_balance(&self, address: &Address) -> Option<Balance> {
        let height = self.chain.tip_height().unwrap_or(crate::block::Height(0));
        self.account(address)
            .map(|account| account.available_balance_at(height))
    }

    pub fn proposal(&self, proposal_id: &ProposalId) -> Option<&Proposal> {
        self.governance.proposal(proposal_id)
    }

    pub fn governance_issuer(&self, issuer_id: &GovernanceIssuerId) -> Option<&GovernanceIssuer> {
        self.governance.issuer(issuer_id)
    }

    pub fn governance_issuer_by_key(
        &self,
        issuer_public_key: &PublicKey,
    ) -> Option<&GovernanceIssuer> {
        self.governance.issuer_by_key(issuer_public_key)
    }

    pub fn governance_credential(
        &self,
        subject: Address,
        credential_type: &GovernanceActionType,
    ) -> Option<&GovernanceCredential> {
        self.governance.credential(subject, credential_type)
    }

    pub fn governance_vote_tally(&self, proposal_id: &ProposalId) -> Option<GovernanceVoteTally> {
        self.governance.vote_tally(proposal_id)
    }

    pub fn governance_proposal_outcome(
        &self,
        proposal_id: &ProposalId,
    ) -> Option<crate::governance::ProposalOutcome> {
        self.governance.proposal_outcome(proposal_id)
    }

    pub fn governance_proposal_execution(
        &self,
        proposal_id: &ProposalId,
    ) -> Option<crate::governance::ProposalExecution> {
        self.governance.proposal_execution(proposal_id)
    }

    pub fn governance_nullifier_used(
        &self,
        proposal_id: &ProposalId,
        nullifier: &CredentialNullifier,
    ) -> bool {
        self.governance.nullifier_used(proposal_id, nullifier)
    }

    pub fn apply_signed_governance_action(
        &mut self,
        signed: &SignedGovernanceAction,
        height: BlockHeight,
    ) -> Result<(), LedgerError> {
        let mut staged = self.clone();
        let account = staged
            .accounts
            .get(&signed.action.signer)
            .ok_or(LedgerError::AccountNotFound)?;
        let protocol = crate::transaction::SignedProtocolTransaction::from(signed.clone());
        if let Some((owner, auth)) = protocol
            .validate_with_account_authorization(account, height)
            .map_err(LedgerError::from)?
        {
            staged
                .accounts
                .get_mut(&signed.action.signer)
                .ok_or(LedgerError::AccountNotFound)?
                .register_authorization(owner, auth)?;
        }
        staged.apply_governance_action(&signed.action, height)?;
        // Declared fees are credited by the enclosing block's coinbase. A
        // global supply check here would observe the temporary fee debit.
        *self = staged;
        Ok(())
    }

    pub(crate) fn record_attached_credentials(
        &mut self,
        credential_uses: &[GovernanceCredentialUse],
    ) -> Result<(), LedgerError> {
        for credential_use in credential_uses {
            self.credential_uses
                .record_use(credential_use)
                .map_err(|_| {
                    LedgerError::InvalidTransaction(TransactionError::DuplicateGovernanceCredential)
                })?;
        }
        Ok(())
    }

    fn apply_governance_action(
        &mut self,
        action: &GovernanceAction,
        height: BlockHeight,
    ) -> Result<(), LedgerError> {
        let signer = self
            .accounts
            .get(&action.signer)
            .ok_or(LedgerError::AccountNotFound)?;
        if signer.nonce != action.nonce {
            return Err(LedgerError::NonceMismatch);
        }
        self.record_attached_credentials(&action.credential_uses)?;

        match &action.kind {
            GovernanceActionKind::RegisterIssuer {
                issuer_public_key,
                metadata_hash,
                metadata_uri,
                fee_policy_hash,
                fee_policy_uri,
                bond_amount,
                bond_locked_until,
            } => {
                let issuer = GovernanceIssuer::new_registered(
                    action.signer,
                    **issuer_public_key,
                    *metadata_hash,
                    metadata_uri.clone(),
                    *fee_policy_hash,
                    fee_policy_uri.clone(),
                    *bond_amount,
                    *bond_locked_until,
                    height,
                )
                .map_err(LedgerError::from)?;
                let account = self
                    .accounts
                    .get_mut(&action.signer)
                    .ok_or(LedgerError::AccountNotFound)?;
                account.debit_at(action.fee, height)?;
                account.lock_until(*bond_amount, *bond_locked_until, height)?;
                account.increment_nonce()?;
                self.refresh_account_state(&action.signer)?;
                self.governance.insert_issuer(issuer)?;
            }
            GovernanceActionKind::ApproveIssuer {
                proposal_id,
                issuer_id,
            } => {
                let proposal = self
                    .governance
                    .proposal(proposal_id)
                    .ok_or(LedgerError::UnknownGovernanceProposal)?;
                if proposal.action_type != crate::governance::GovernanceActionType::ApproveIssuer {
                    return Err(LedgerError::InvalidTransaction(
                        TransactionError::InvalidGovernanceProposal,
                    ));
                }
                if self.governance.proposal_outcome(proposal_id)
                    != Some(crate::governance::ProposalOutcome::Accepted)
                {
                    return Err(LedgerError::GovernanceProposalNotAccepted);
                }
                let account = self
                    .accounts
                    .get_mut(&action.signer)
                    .ok_or(LedgerError::AccountNotFound)?;
                account.debit_at(action.fee, height)?;
                account.increment_nonce()?;
                self.refresh_account_state(&action.signer)?;
                self.governance.approve_issuer(*issuer_id)?;
            }
            GovernanceActionKind::IssueCredential { credential } => {
                let issuer = self
                    .governance
                    .active_issuer_by_key(&credential.issuer_public_key)
                    .ok_or(LedgerError::UnknownGovernanceIssuer)?;
                if issuer.controller != action.signer {
                    return Err(LedgerError::InvalidTransaction(
                        TransactionError::InvalidGovernanceCredential,
                    ));
                }
                let account = self
                    .accounts
                    .get_mut(&action.signer)
                    .ok_or(LedgerError::AccountNotFound)?;
                account.debit_at(action.fee, height)?;
                account.increment_nonce()?;
                self.refresh_account_state(&action.signer)?;
                self.governance
                    .insert_credential(credential.as_ref().clone())?;
            }
            GovernanceActionKind::BindCredential { credential_use } => {
                if self
                    .governance
                    .active_issuer_by_key(&credential_use.credential.issuer_public_key)
                    .is_none()
                {
                    return Err(LedgerError::UnknownGovernanceIssuer);
                }
                let expected_context = crate::governance::bind_credential_context_id(
                    action.signer,
                    credential_use.credential.credential_type.clone(),
                )?;
                if credential_use.context_id != expected_context
                    || credential_use.credential.subject.is_some()
                {
                    return Err(LedgerError::InvalidTransaction(
                        TransactionError::InvalidGovernanceCredential,
                    ));
                }
                let account = self
                    .accounts
                    .get_mut(&action.signer)
                    .ok_or(LedgerError::AccountNotFound)?;
                account.debit_at(action.fee, height)?;
                account.increment_nonce()?;
                self.refresh_account_state(&action.signer)?;
                let credential = credential_use.credential.clone().bound_to(action.signer);
                self.governance.insert_credential(credential)?;
            }
            GovernanceActionKind::RevokeCredential { credential_type } => {
                let account = self
                    .accounts
                    .get_mut(&action.signer)
                    .ok_or(LedgerError::AccountNotFound)?;
                account.debit_at(action.fee, height)?;
                account.increment_nonce()?;
                self.refresh_account_state(&action.signer)?;
                self.governance
                    .revoke_credential(action.signer, credential_type)?;
            }
            GovernanceActionKind::CreateProposal {
                proposal,
                bond_amount,
                authorization,
            } => {
                for issuer_id in &proposal.accepted_issuers {
                    if self.governance.issuer(issuer_id).is_none() {
                        return Err(LedgerError::UnknownGovernanceIssuer);
                    }
                }
                match authorization.as_ref() {
                    ProposalCreationAuthorization::Credential(credential_use) => {
                        if proposal.voting_mode != ProposalVotingMode::Credential {
                            return Err(LedgerError::InvalidTransaction(
                                TransactionError::InvalidGovernanceProposal,
                            ));
                        }
                        let issuer = self
                            .governance
                            .active_issuer_by_key(&credential_use.credential.issuer_public_key)
                            .ok_or(LedgerError::UnknownGovernanceIssuer)?;
                        if !proposal.accepted_issuers.contains(&issuer.id) {
                            return Err(LedgerError::IssuerNotAcceptedForProposal);
                        }
                        if !self.credential_authorizes_signer(
                            action.signer,
                            credential_use,
                            &GovernanceActionType::CreateProposal,
                        ) {
                            return Err(LedgerError::InvalidTransaction(
                                TransactionError::InvalidGovernanceCredential,
                            ));
                        }
                    }
                    ProposalCreationAuthorization::BoundCredential { issuer_id } => {
                        if proposal.voting_mode != ProposalVotingMode::Credential {
                            return Err(LedgerError::InvalidTransaction(
                                TransactionError::InvalidGovernanceProposal,
                            ));
                        }
                        let issuer = self
                            .governance
                            .issuer(issuer_id)
                            .ok_or(LedgerError::UnknownGovernanceIssuer)?;
                        if issuer.status != crate::governance::GovernanceIssuerStatus::Active {
                            return Err(LedgerError::UnknownGovernanceIssuer);
                        }
                        if !proposal.accepted_issuers.contains(issuer_id)
                            || self
                                .bound_credential_for_signer(
                                    action.signer,
                                    &GovernanceActionType::CreateProposal,
                                    *issuer_id,
                                )
                                .is_none()
                        {
                            return Err(LedgerError::InvalidTransaction(
                                TransactionError::InvalidGovernanceCredential,
                            ));
                        }
                    }
                    ProposalCreationAuthorization::Coin => {
                        if proposal.voting_mode != ProposalVotingMode::CoinPower {
                            return Err(LedgerError::InvalidTransaction(
                                TransactionError::InvalidGovernanceProposal,
                            ));
                        }
                    }
                }
                let account = self
                    .accounts
                    .get_mut(&action.signer)
                    .ok_or(LedgerError::AccountNotFound)?;
                account.debit_at(action.fee, height)?;
                account.lock_until(*bond_amount, proposal.voting_end, height)?;
                account.increment_nonce()?;
                self.refresh_account_state(&action.signer)?;
                if let ProposalCreationAuthorization::Credential(credential_use) =
                    authorization.as_ref()
                {
                    self.governance
                        .record_credential_use(proposal.id, credential_use.nullifier)?;
                }
                if let ProposalCreationAuthorization::BoundCredential { issuer_id } =
                    authorization.as_ref()
                {
                    let credential_public_key = self
                        .bound_credential_for_signer(
                            action.signer,
                            &GovernanceActionType::CreateProposal,
                            *issuer_id,
                        )
                        .ok_or(LedgerError::InvalidTransaction(
                            TransactionError::InvalidGovernanceCredential,
                        ))?
                        .credential_public_key;
                    self.governance.record_credential_use(
                        proposal.id,
                        crate::governance::credential_nullifier(
                            &credential_public_key,
                            crate::governance::proposal_create_context_id(proposal.id)?,
                        )?,
                    )?;
                }
                self.governance.insert_proposal(proposal.as_ref().clone())?;
            }
            GovernanceActionKind::Vote {
                proposal_id,
                choice,
                authorization,
            } => {
                let proposal = self
                    .governance
                    .proposal(proposal_id)
                    .ok_or(LedgerError::UnknownGovernanceProposal)?;
                if !proposal.is_active_at(height) {
                    return Err(LedgerError::InvalidTransaction(
                        TransactionError::InactiveGovernanceProposal,
                    ));
                }
                let lock_until = proposal.voting_end;
                match authorization.as_ref() {
                    VoteAuthorization::Credential(credential_use) => {
                        if proposal.voting_mode != ProposalVotingMode::Credential {
                            return Err(LedgerError::InvalidTransaction(
                                TransactionError::InvalidGovernanceProposal,
                            ));
                        }
                        let issuer = self
                            .governance
                            .active_issuer_by_key(&credential_use.credential.issuer_public_key)
                            .ok_or(LedgerError::UnknownGovernanceIssuer)?;
                        if !proposal.accepted_issuers.contains(&issuer.id) {
                            return Err(LedgerError::IssuerNotAcceptedForProposal);
                        }
                        if !self.credential_authorizes_signer(
                            action.signer,
                            credential_use,
                            &GovernanceActionType::ProposalVote,
                        ) {
                            return Err(LedgerError::InvalidTransaction(
                                TransactionError::InvalidGovernanceCredential,
                            ));
                        }
                    }
                    VoteAuthorization::BoundCredential { issuer_id } => {
                        if proposal.voting_mode != ProposalVotingMode::Credential {
                            return Err(LedgerError::InvalidTransaction(
                                TransactionError::InvalidGovernanceProposal,
                            ));
                        }
                        let issuer = self
                            .governance
                            .issuer(issuer_id)
                            .ok_or(LedgerError::UnknownGovernanceIssuer)?;
                        if issuer.status != crate::governance::GovernanceIssuerStatus::Active {
                            return Err(LedgerError::UnknownGovernanceIssuer);
                        }
                        if !proposal.accepted_issuers.contains(issuer_id)
                            || self
                                .bound_credential_for_signer(
                                    action.signer,
                                    &GovernanceActionType::ProposalVote,
                                    *issuer_id,
                                )
                                .is_none()
                        {
                            return Err(LedgerError::InvalidTransaction(
                                TransactionError::InvalidGovernanceCredential,
                            ));
                        }
                    }
                    VoteAuthorization::CoinPower { .. } => {
                        if proposal.voting_mode != ProposalVotingMode::CoinPower {
                            return Err(LedgerError::InvalidTransaction(
                                TransactionError::InvalidGovernanceProposal,
                            ));
                        }
                    }
                }
                let account = self
                    .accounts
                    .get_mut(&action.signer)
                    .ok_or(LedgerError::AccountNotFound)?;
                account.debit_at(action.fee, height)?;
                if let VoteAuthorization::CoinPower { amount } = authorization.as_ref() {
                    account.lock_until(*amount, lock_until, height)?;
                }
                account.increment_nonce()?;
                self.refresh_account_state(&action.signer)?;
                match authorization.as_ref() {
                    VoteAuthorization::Credential(credential_use) => {
                        self.governance.record_vote(
                            *proposal_id,
                            credential_use.nullifier,
                            *choice,
                        )?;
                    }
                    VoteAuthorization::BoundCredential { issuer_id } => {
                        let credential_public_key = self
                            .bound_credential_for_signer(
                                action.signer,
                                &GovernanceActionType::ProposalVote,
                                *issuer_id,
                            )
                            .ok_or(LedgerError::InvalidTransaction(
                                TransactionError::InvalidGovernanceCredential,
                            ))?
                            .credential_public_key;
                        self.governance.record_vote(
                            *proposal_id,
                            crate::governance::credential_nullifier(
                                &credential_public_key,
                                crate::governance::vote_context_id(*proposal_id)?,
                            )?,
                            *choice,
                        )?;
                    }
                    VoteAuthorization::CoinPower { amount } => {
                        self.governance.record_coin_power_vote(
                            *proposal_id,
                            action.signer,
                            *amount,
                            *choice,
                        )?;
                    }
                }
            }
            GovernanceActionKind::FinalizeProposal { proposal_id } => {
                let proposal = self
                    .governance
                    .proposal(proposal_id)
                    .ok_or(LedgerError::UnknownGovernanceProposal)?;
                if height.0 <= proposal.voting_end.0 {
                    return Err(LedgerError::InvalidTransaction(
                        TransactionError::InactiveGovernanceProposal,
                    ));
                }
                let account = self
                    .accounts
                    .get_mut(&action.signer)
                    .ok_or(LedgerError::AccountNotFound)?;
                account.debit_at(action.fee, height)?;
                account.increment_nonce()?;
                self.refresh_account_state(&action.signer)?;
                self.governance.finalize_proposal(*proposal_id)?;
            }
            GovernanceActionKind::ExecuteProposal { proposal_id } => {
                if self.governance.proposal(proposal_id).is_none() {
                    return Err(LedgerError::UnknownGovernanceProposal);
                }
                let account = self
                    .accounts
                    .get_mut(&action.signer)
                    .ok_or(LedgerError::AccountNotFound)?;
                account.debit_at(action.fee, height)?;
                account.increment_nonce()?;
                self.refresh_account_state(&action.signer)?;
                self.governance
                    .execute_proposal(*proposal_id, action.signer, height)?;
            }
        }
        Ok(())
    }

    fn credential_authorizes_signer(
        &self,
        signer: Address,
        credential_use: &GovernanceCredentialUse,
        credential_type: &GovernanceActionType,
    ) -> bool {
        if credential_use.authorized_signer != signer {
            return false;
        }
        match credential_use.credential.subject {
            Some(subject) if subject == signer => {
                self.governance.credential(signer, credential_type)
                    == Some(&credential_use.credential)
            }
            None => true,
            _ => false,
        }
    }

    fn bound_credential_for_signer(
        &self,
        signer: Address,
        credential_type: &GovernanceActionType,
        issuer_id: GovernanceIssuerId,
    ) -> Option<&GovernanceCredential> {
        let credential = self.governance.credential(signer, credential_type)?;
        let issuer = self.governance.issuer(&issuer_id)?;
        if credential.issuer_public_key == issuer.issuer_public_key {
            Some(credential)
        } else {
            None
        }
    }

    pub fn total_supply(&self) -> Result<Amount, LedgerError> {
        let mut total = 0_u64;
        for account in self.accounts.values() {
            total = total
                .checked_add(account.balance.0)
                .ok_or(LedgerError::SupplyOverflow)?;
        }
        Ok(Amount(total))
    }

    /// Account balances, issued bearer cash, and coins reserved by vaults.
    pub fn economic_supply(&self) -> Result<Amount, LedgerError> {
        let accounts = self.total_supply()?;
        let cash = self.qcash_utxos.total_value()?;
        let vaults = self
            .vaults
            .reserved_supply()
            .map_err(LedgerError::InvalidVault)?;
        accounts
            .0
            .checked_add(cash.0)
            .and_then(|total| total.checked_add(vaults.0))
            .map(Amount)
            .ok_or(LedgerError::SupplyOverflow)
    }

    /// Moves already-issued account funds into a new vault reserve.
    pub fn create_vault_from_account(
        &mut self,
        vault: Vault,
        height: BlockHeight,
    ) -> Result<VaultId, LedgerError> {
        let mut staged = self.clone();
        let creator = vault.creator;
        let funding = vault.remaining;
        {
            let account = staged
                .accounts
                .get_mut(&creator)
                .ok_or(LedgerError::AccountNotFound)?;
            account.debit_at(funding, height)?;
            account.increment_nonce()?;
        }
        let id = staged
            .vaults
            .create(vault)
            .map_err(LedgerError::InvalidVault)?;
        staged.refresh_account_state(&creator)?;
        staged.validate_supply()?;
        *self = staged;
        Ok(id)
    }

    /// Releases reserved coins after the transaction layer verifies every
    /// approval represented by the claim.
    pub fn apply_verified_vault_claim(
        &mut self,
        claim: &VaultClaim,
        height: BlockHeight,
    ) -> Result<VaultPayout, LedgerError> {
        let mut staged = self.clone();
        let payout = staged
            .vaults
            .claim(claim)
            .map_err(LedgerError::InvalidVault)?;
        let maturity_height = Height(height.0.saturating_add(CONFIRMATION_DEPTH as u64));
        staged
            .accounts
            .entry(payout.recipient)
            .or_insert_with(|| Account::new(payout.recipient, Amount(0)))
            .credit_at_maturity(payout.amount, maturity_height, CreditSource::Transaction)?;
        staged.refresh_account_state(&payout.recipient)?;
        staged.validate_supply()?;
        *self = staged;
        Ok(payout)
    }

    pub fn apply_signed_vault_claim(
        &mut self,
        signed: SignedVaultClaim,
        height: BlockHeight,
    ) -> Result<VaultPayout, LedgerError> {
        let claim = signed
            .verify()
            .map_err(|error| LedgerError::InvalidTransaction(error.into()))?;
        self.apply_verified_vault_claim(&claim, height)
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
        let genesis_allocations = if block.is_genesis() {
            &block.genesis_allocations
        } else {
            &self
                .chain
                .block(&crate::block::Height(0))
                .ok_or(LedgerError::InvalidParent)?
                .genesis_allocations
        };
        let expected =
            expected_issued_supply(block.height(), genesis_allocations.iter().map(|a| a.amount))?;
        if economic != expected {
            return Err(LedgerError::SupplyMismatch);
        }
        Ok(())
    }

    fn expected_issued_supply_at(&self, height: BlockHeight) -> Result<Amount, LedgerError> {
        let genesis = self
            .chain
            .block(&crate::block::Height(0))
            .ok_or(LedgerError::InvalidParent)?;
        expected_issued_supply(
            height,
            genesis
                .genesis_allocations
                .iter()
                .map(|allocation| allocation.amount),
        )
    }

    pub fn apply_signed_qcash_transaction(
        &mut self,
        signed: &SignedQCashTransaction,
        height: BlockHeight,
    ) -> Result<(), LedgerError> {
        let mut staged = self.clone();
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
        staged.apply_qcash_transaction(&signed.transaction, height, None)?;
        staged.refresh_qcash_accounts(&signed.transaction)?;
        // The enclosing block credits the declared fee to its coinbase after
        // all protocol transactions have executed.
        *self = staged;
        Ok(())
    }

    pub fn apply_signed_qcash_transaction_in_block(
        &mut self,
        signed: &SignedQCashTransaction,
        height: BlockHeight,
        block_hash: BlockHash,
    ) -> Result<(), LedgerError> {
        let mut staged = self.clone();
        let account = staged
            .accounts
            .get(&signed.transaction.signer)
            .ok_or(LedgerError::AccountNotFound)?;
        let protocol = crate::transaction::SignedProtocolTransaction::from(signed.clone());
        let registration = protocol
            .validate_with_account_authorization(account, height)
            .map_err(LedgerError::from)?;
        staged.capture_qcash_accounts(block_hash, height, &signed.transaction)?;
        if let Some((owner, auth)) = registration {
            staged
                .accounts
                .get_mut(&signed.transaction.signer)
                .ok_or(LedgerError::AccountNotFound)?
                .register_authorization(owner, auth)?;
        }
        staged.apply_qcash_transaction(&signed.transaction, height, Some(block_hash))?;
        staged.refresh_qcash_accounts(&signed.transaction)?;
        // Supply is checked once the enclosing block has applied coinbase.
        *self = staged;
        Ok(())
    }

    fn capture_qcash_accounts(
        &mut self,
        block_hash: BlockHash,
        height: BlockHeight,
        transaction: &QCashTransaction,
    ) -> Result<(), LedgerError> {
        let mut addresses = vec![transaction.signer];
        if let QCashTransactionKind::Deposit { recipient, .. } = &transaction.kind {
            addresses.push(*recipient);
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
        let journal = staged
            .qcash_account_journals
            .remove(&block_hash)
            .ok_or(LedgerError::MissingQCashAccountJournal)?;
        staged.qcash_utxos.rollback_block(block_hash)?;
        for (address, previous) in journal.previous_accounts {
            match previous {
                Some(account) => {
                    staged.accounts.insert(address, account);
                }
                None => {
                    staged.accounts.remove(&address);
                }
            }
            staged.refresh_account_state(&address)?;
        }
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
        staged.governance = rollback_state.governance;
        staged.credential_uses = rollback_state.credential_uses;
        staged.events_by_block.remove(&block_hash);
        staged.validate_supply()?;
        let to_height = staged.tip_height().unwrap_or(Height(0));
        let new_tip = staged.tip_hash().unwrap_or(BlockHash::ZERO);
        let affected_accounts = account_rollbacks(&before_accounts, &staged.accounts);
        let event = RollbackEvent {
            from_height,
            to_height,
            old_tip,
            new_tip,
            disconnected_blocks: vec![DisconnectedBlock {
                height: block.height(),
                hash: block.hash()?,
                transaction_ids: block
                    .transactions
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
    ) -> Result<(), LedgerError> {
        let signer = self
            .accounts
            .get(&transaction.signer)
            .ok_or(LedgerError::AccountNotFound)?;
        if signer.nonce != transaction.nonce {
            return Err(LedgerError::NonceMismatch);
        }
        self.record_attached_credentials(&transaction.credential_uses)?;

        match &transaction.kind {
            QCashTransactionKind::Withdraw { amount, metadata } => {
                let debit = amount
                    .0
                    .checked_add(transaction.fee.0)
                    .map(Amount)
                    .ok_or(LedgerError::SupplyOverflow)?;
                let account = self
                    .accounts
                    .get_mut(&transaction.signer)
                    .ok_or(LedgerError::AccountNotFound)?;
                account.debit_at(debit, height)?;
                account.increment_nonce()?;
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
            QCashTransactionKind::Deposit {
                recipient,
                metadata,
            } => {
                let transaction_commitment = transaction.deposit_transaction_commitment()?.ok_or(
                    LedgerError::InvalidTransaction(TransactionError::InvalidQCashMetadata),
                )?;
                let amount = if let Some(block_hash) = block_hash {
                    self.qcash_utxos.apply_deposit_in_block(
                        block_hash,
                        height,
                        metadata,
                        *recipient,
                        transaction_commitment,
                    )?
                } else {
                    self.qcash_utxos.apply_deposit_proof(
                        metadata,
                        *recipient,
                        height,
                        transaction_commitment,
                    )?
                };
                let account = self
                    .accounts
                    .get_mut(&transaction.signer)
                    .ok_or(LedgerError::AccountNotFound)?;
                account.debit_at(transaction.fee, height)?;
                account.increment_nonce()?;
                let maturity_height = crate::block::Height(
                    height
                        .0
                        .saturating_add(crate::ledger::QCASH_DEPOSIT_MATURITY as u64),
                );
                self.accounts
                    .entry(*recipient)
                    .or_insert_with(|| Account::new(*recipient, Amount(0)))
                    .credit_at_maturity(amount, maturity_height, CreditSource::QCashDeposit)?;
            }
        }
        Ok(())
    }

    pub fn apply_signed_transaction(
        &mut self,
        signed_transaction: &SignedTransaction,
    ) -> Result<(), LedgerError> {
        self.apply_signed_transaction_at(signed_transaction, crate::block::Height(0))
    }

    pub fn apply_block_at(&mut self, block: Block, now: u64) -> Result<(), LedgerError> {
        block.validate_at(now)?;
        let (mut staged, _) = self.staged_after_validated_block(&block, true)?;
        if !block.is_genesis() && block.state_root() == Hash([0; HASH_SIZE]) {
            return Err(LedgerError::InvalidStateRoot);
        }

        let block_hash = block.hash()?;
        staged.rollback_states.insert(
            block_hash,
            AccountRollbackState {
                accounts: self.accounts.clone(),
                account_state_tree: self.account_state_tree.clone(),
                governance: self.governance.clone(),
                credential_uses: self.credential_uses.clone(),
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
        calculate_protocol_state_root(
            self.state_root(),
            &self.qcash_utxos,
            &self.governance,
            &self.credential_uses,
        )
    }

    pub fn state_commitment_for_block_hash(
        &self,
        block_hash: BlockHash,
    ) -> Result<BlockStateCommitment, LedgerError> {
        let account_state_root = self.state_root();
        let qcash_state_root = StateRoot(self.qcash_utxos.consensus_root()?.0);
        let governance_state_root = self.governance.consensus_root()?;
        let credential_use_state_root = self.credential_uses.consensus_root()?;
        Ok(BlockStateCommitment::new(
            self.tip_height().unwrap_or(crate::block::Height(0)),
            block_hash,
            account_state_root,
            qcash_state_root,
            governance_state_root,
            credential_use_state_root,
            calculate_protocol_state_root_from_roots(
                account_state_root,
                qcash_state_root,
                governance_state_root,
                credential_use_state_root,
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
    qcash_utxos: &QCashUtxoSet,
    governance: &GovernanceState,
    credential_uses: &CredentialUseState,
) -> Result<StateRoot, LedgerError> {
    Ok(calculate_protocol_state_root_from_roots(
        account_state_root,
        StateRoot(qcash_utxos.consensus_root()?.0),
        governance.consensus_root()?,
        credential_uses.consensus_root()?,
    )?)
}

pub fn calculate_protocol_state_root_from_roots(
    account_state_root: StateRoot,
    qcash_state_root: StateRoot,
    governance_state_root: StateRoot,
    credential_use_state_root: StateRoot,
) -> Result<StateRoot, crate::error::CodecError> {
    Ok(StateRoot(
        domain_hash(
            HashDomain::ProtocolState,
            &crate::codec::canonical_bytes(&(
                account_state_root,
                qcash_state_root,
                governance_state_root,
                credential_use_state_root,
            ))?,
        )
        .0,
    ))
}

pub(crate) fn expected_issued_supply(
    height: BlockHeight,
    mut genesis_allocations: impl Iterator<Item = Amount>,
) -> Result<Amount, LedgerError> {
    let genesis = genesis_allocations
        .try_fold(0_u64, |total, amount| total.checked_add(amount.0))
        .ok_or(LedgerError::SupplyOverflow)?;
    let pre_tail_count = height
        .0
        .min(crate::consensus::supply::TAIL_EMISSION_START_HEIGHT.saturating_sub(1));
    let tail_count = height.0.saturating_sub(pre_tail_count);
    let pre_tail = pre_tail_count
        .checked_mul(crate::consensus::supply::BLOCK_REWARD)
        .ok_or(LedgerError::SupplyOverflow)?;
    let tail = tail_count
        .checked_mul(crate::consensus::supply::TAIL_EMISSION)
        .ok_or(LedgerError::SupplyOverflow)?;
    genesis
        .checked_add(pre_tail)
        .and_then(|total| total.checked_add(tail))
        .map(Amount)
        .ok_or(LedgerError::SupplyOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Block, Height, Nonce};
    use crate::consensus::supply::XPQ;
    use crate::consensus::{Consensus, DIFFICULTY_START};
    use crate::crypto::{dual_address_from_public_keys, generate_keypair, hash_bytes, sign};
    use crate::genesis::genesis_block;
    use crate::governance::{
        GovernanceAction, GovernanceActionType, GovernanceCredential, GovernanceCredentialUse,
        MIN_PROPOSAL_BOND, Proposal, ProposalCreationAuthorization, ProposalRules,
        ProposalVotingMode, SignedGovernanceAction, VoteAuthorization, VoteChoice,
    };
    use crate::qcash::{QCashDenomination, QCashWithdrawMetadata, qcash_coin_commitment};
    use crate::transaction::{
        QCashTransaction, SignedQCashTransaction, Transaction, TransferOutput,
    };

    fn single_output_transaction(
        from: Address,
        to: Address,
        amount: Amount,
        fee: Amount,
        nonce: Nonce,
    ) -> Transaction {
        Transaction::new(from, vec![TransferOutput { to, amount }], fee, nonce)
    }

    fn authorized_transfer(
        spend: &crate::crypto::KeyPair,
        auth: &crate::crypto::KeyPair,
        to: Address,
    ) -> SignedTransaction {
        let from = dual_address_from_public_keys(&spend.public_key, &auth.public_key);
        let transaction = single_output_transaction(from, to, Amount(25), Amount(1), Nonce(0));
        let payload = transaction.signing_bytes().unwrap();
        SignedTransaction::new_authorized(
            transaction,
            spend.public_key,
            sign(&spend.secret_key, &payload),
            auth.public_key,
            sign(&auth.secret_key, &payload),
        )
    }

    fn mine_for_test(mut block: Block) -> Block {
        for nonce in 0..100_000_u64 {
            block.header.nonce = Nonce(nonce);
            if Consensus::validate_proof_of_work_at_difficulty(&block, block.difficulty()).is_ok() {
                return block;
            }
        }
        panic!("test block nonce not found");
    }

    fn authorized_governance_action(
        action: GovernanceAction,
        signer: &crate::crypto::KeyPair,
        auth: &crate::crypto::KeyPair,
    ) -> SignedGovernanceAction {
        let payload = action.signing_bytes().unwrap();
        SignedGovernanceAction::new_authorized(
            action,
            signer.public_key,
            sign(&signer.secret_key, &payload),
            auth.public_key,
            sign(&auth.secret_key, &payload),
        )
    }

    #[test]
    fn qcash_withdraw_moves_value_out_of_account_into_bearer_utxo() {
        let spend = generate_keypair();
        let auth = generate_keypair();
        let signer = dual_address_from_public_keys(&spend.public_key, &auth.public_key);
        let initial_balance = Amount(2 * XPQ);
        let amount = QCashDenomination::One.amount();
        let fee = Amount(7);
        let opening_secret = [0x44; 32];
        let metadata = QCashWithdrawMetadata::with_denominations(
            amount,
            &[QCashDenomination::One],
            &[qcash_coin_commitment(&opening_secret)],
        )
        .unwrap();
        let transaction = QCashTransaction::withdraw(signer, amount, fee, Nonce(0), metadata);
        let payload = transaction.signing_bytes().unwrap();
        let signed = SignedQCashTransaction::new_authorized(
            transaction,
            spend.public_key,
            sign(&spend.secret_key, &payload),
            auth.public_key,
            sign(&auth.secret_key, &payload),
        );
        let mut ledger = Ledger::new();
        ledger
            .create_account_with_authorization(signer, auth.public_key, initial_balance)
            .unwrap();

        ledger
            .apply_signed_qcash_transaction(&signed, Height(1))
            .unwrap();

        let account = ledger.account(&signer).unwrap();
        assert_eq!(
            account.balance,
            Amount(initial_balance.0 - amount.0 - fee.0)
        );
        assert_eq!(account.locked_balance_at(Height(1)), Amount(0));
        assert!(account.locks.is_empty());
        assert_eq!(ledger.qcash_utxos.total_value().unwrap(), amount);
        assert_eq!(
            ledger.economic_supply().unwrap(),
            Amount(initial_balance.0 - fee.0)
        );
    }

    #[test]
    fn account_rollbacks_include_before_and_after_snapshots() {
        let alice = Address([1; 20]);
        let bob = Address([2; 20]);
        let mut before = BTreeMap::new();
        before.insert(
            alice,
            Account::trusted_with_nonce(alice, Amount(500), Nonce(12)),
        );
        before.insert(bob, Account::trusted_with_nonce(bob, Amount(100), Nonce(1)));

        let mut after = BTreeMap::new();
        after.insert(
            alice,
            Account::trusted_with_nonce(alice, Amount(800), Nonce(8)),
        );
        after.insert(bob, Account::trusted_with_nonce(bob, Amount(100), Nonce(1)));

        let rollbacks = account_rollbacks(&before, &after);

        assert_eq!(rollbacks.len(), 1);
        assert_eq!(rollbacks[0].address, alice);
        assert_eq!(
            rollbacks[0].before,
            Some(AccountSnapshot {
                balance: Amount(500),
                nonce: Nonce(12),
            })
        );
        assert_eq!(
            rollbacks[0].after,
            Some(AccountSnapshot {
                balance: Amount(800),
                nonce: Nonce(8),
            })
        );
    }

    #[test]
    fn signed_transfer_requires_account_authorization_signature() {
        let spend = generate_keypair();
        let auth = generate_keypair();
        let recipient = Address([7; 20]);
        let sender = dual_address_from_public_keys(&spend.public_key, &auth.public_key);
        let mut ledger = Ledger::new();
        ledger
            .insert_account(Account::new_with_authorization(
                sender,
                auth.public_key,
                Amount(100),
            ))
            .unwrap();

        ledger
            .apply_signed_transaction(&authorized_transfer(&spend, &auth, recipient))
            .unwrap();

        assert_eq!(ledger.balance(&sender), Some(Amount(74)));
        assert_eq!(ledger.balance(&recipient), Some(Amount(25)));
    }

    #[test]
    fn first_spend_uses_stateless_dual_authorization() {
        let spend = generate_keypair();
        let auth = generate_keypair();
        let recipient = Address([6; 20]);
        let sender = dual_address_from_public_keys(&spend.public_key, &auth.public_key);
        let mut ledger = Ledger::new();
        ledger.create_account(sender, Amount(100)).unwrap();

        let first = single_output_transaction(sender, recipient, Amount(25), Amount(1), Nonce(0));
        let first_payload = first.signing_bytes().unwrap();
        let signed_first = SignedTransaction::new_authorized(
            first,
            spend.public_key,
            sign(&spend.secret_key, &first_payload),
            auth.public_key,
            sign(&auth.secret_key, &first_payload),
        );
        ledger.apply_signed_transaction(&signed_first).unwrap();

        let second =
            single_output_transaction(sender, Address([7; 20]), Amount(1), Amount(1), Nonce(1));
        let second_payload = second.signing_bytes().unwrap();
        let unsigned_auth_second = SignedTransaction::new(
            second.clone(),
            spend.public_key,
            sign(&spend.secret_key, &second_payload),
        );
        assert!(
            ledger
                .apply_signed_transaction(&unsigned_auth_second)
                .is_err()
        );

        let signed_second = SignedTransaction::new_authorized(
            second,
            spend.public_key,
            sign(&spend.secret_key, &second_payload),
            auth.public_key,
            sign(&auth.secret_key, &second_payload),
        );
        ledger.apply_signed_transaction(&signed_second).unwrap();
    }

    #[test]
    fn registered_account_accepts_signature_only_witness_and_saves_both_keys() {
        let owner = generate_keypair();
        let auth = generate_keypair();
        let sender = dual_address_from_public_keys(&owner.public_key, &auth.public_key);
        let recipient = Address([0x44; 20]);
        let mut ledger = Ledger::new();
        ledger.create_account(sender, Amount(100)).unwrap();

        let first = single_output_transaction(sender, recipient, Amount(1), Amount(1), Nonce(0));
        let first_payload = first.signing_bytes().unwrap();
        let registration = SignedTransaction::new_authorized(
            first,
            owner.public_key,
            sign(&owner.secret_key, &first_payload),
            auth.public_key,
            sign(&auth.secret_key, &first_payload),
        );
        ledger.apply_signed_transaction(&registration).unwrap();
        assert!(ledger.account(&sender).unwrap().authorization.is_some());

        let second = single_output_transaction(sender, recipient, Amount(1), Amount(1), Nonce(1));
        let second_payload = second.signing_bytes().unwrap();
        let compact = SignedTransaction::new_stored_authorized(
            second.clone(),
            sign(&owner.secret_key, &second_payload),
            sign(&auth.secret_key, &second_payload),
        );
        let repeated = SignedTransaction::new_authorized(
            second,
            owner.public_key,
            sign(&owner.secret_key, &second_payload),
            auth.public_key,
            sign(&auth.secret_key, &second_payload),
        );
        assert_eq!(
            repeated.to_bytes().unwrap().len() - compact.to_bytes().unwrap().len(),
            2 * crate::crypto::PUBLIC_KEY_SIZE
        );
        ledger.apply_signed_transaction(&compact).unwrap();
        assert_eq!(ledger.account(&sender).unwrap().nonce, Nonce(2));
    }

    #[test]
    fn first_governance_action_uses_stateless_dual_authorization() {
        let spend = generate_keypair();
        let auth = generate_keypair();
        let signer = dual_address_from_public_keys(&spend.public_key, &auth.public_key);
        let mut ledger = Ledger::new();
        ledger.create_account(signer, Amount(200 * XPQ)).unwrap();

        let proposal = Proposal::new(
            signer,
            GovernanceActionType::ParameterPoll,
            b"lazy auth governance".to_vec(),
            hash_bytes(b"lazy-auth-governance"),
            Vec::new(),
            None,
            Vec::new(),
            ProposalVotingMode::CoinPower,
            ProposalRules::default(),
            Height(1),
            Height(10),
        )
        .unwrap();
        let action = GovernanceAction::create_proposal(
            signer,
            Amount(1),
            Nonce(0),
            proposal,
            MIN_PROPOSAL_BOND,
            ProposalCreationAuthorization::Coin,
        );
        let payload = action.signing_bytes().unwrap();
        let signed = SignedGovernanceAction::new_authorized(
            action,
            spend.public_key,
            sign(&spend.secret_key, &payload),
            auth.public_key,
            sign(&auth.secret_key, &payload),
        );

        ledger
            .apply_signed_governance_action(&signed, Height(1))
            .unwrap();

        assert_eq!(
            ledger.account(&signer).map(|account| account.nonce),
            Some(Nonce(1))
        );
    }

    #[test]
    fn signed_transfer_rejects_signature_from_wrong_authorization_key() {
        let spend = generate_keypair();
        let account_auth = generate_keypair();
        let wrong_auth = generate_keypair();
        let sender = dual_address_from_public_keys(&spend.public_key, &account_auth.public_key);
        let mut ledger = Ledger::new();
        ledger
            .insert_account(Account::new_with_authorization(
                sender,
                account_auth.public_key,
                Amount(100),
            ))
            .unwrap();

        let transaction =
            single_output_transaction(sender, Address([8; 20]), Amount(25), Amount(1), Nonce(0));
        let payload = transaction.signing_bytes().unwrap();
        let signed = SignedTransaction::new_authorized(
            transaction,
            spend.public_key,
            sign(&spend.secret_key, &payload),
            wrong_auth.public_key,
            sign(&wrong_auth.secret_key, &payload),
        );
        let error = ledger.apply_signed_transaction(&signed).unwrap_err();

        assert_eq!(error, LedgerError::InvalidSignature);
    }

    #[test]
    fn dual_authorized_transfer_block_state_root_validates() {
        let spend = generate_keypair();
        let auth = generate_keypair();
        let recipient = Address([9; 20]);
        let sender = dual_address_from_public_keys(&spend.public_key, &auth.public_key);
        let miner = Address([3; 20]);
        let mut ledger = Ledger::new();
        let genesis = genesis_block().unwrap();
        let (staged, _) = ledger.execute_block(&genesis).unwrap();
        ledger = staged;

        // Fund the sender exclusively through consensus coinbase issuance.
        // Executing the first 50 blocks without enforcing PoW keeps this unit
        // test fast while still exercising coinbase amount, maturity, state
        // commitment, and global supply validation for every transition.
        for height in 1..=crate::ledger::BLOCK_REWARD_MATURITY as u64 {
            let height = Height(height);
            let block = Block::from_protocol_transactions(
                height,
                ledger.tip_hash().unwrap(),
                sender,
                DIFFICULTY_START,
                genesis
                    .timestamp()
                    .saturating_add(height.0.saturating_mul(300)),
                Nonce(0),
                Vec::new(),
                Some(crate::block::CoinbaseTransaction::new(
                    sender,
                    ledger.mintable_subsidy(height),
                    Amount(0),
                )),
                Vec::new(),
            )
            .unwrap();
            let (staged, _) = ledger.execute_block(&block).unwrap();
            ledger = staged;
        }

        let tx = authorized_transfer(&spend, &auth, recipient);
        let transfer_height = Height(crate::ledger::BLOCK_REWARD_MATURITY as u64 + 1);
        let coinbase = crate::block::CoinbaseTransaction::new(
            miner,
            ledger.mintable_subsidy(transfer_height),
            tx.transaction.fee,
        );
        let mut block = Block::from_protocol_transactions(
            transfer_height,
            ledger.tip_hash().unwrap(),
            miner,
            DIFFICULTY_START,
            genesis
                .timestamp()
                .saturating_add(transfer_height.0.saturating_mul(300)),
            Nonce(0),
            Vec::new(),
            Some(coinbase),
            vec![tx.into()],
        )
        .unwrap();
        let state_root = ledger
            .staged_after_validated_block(&block, false)
            .map(|(_, state_root)| state_root)
            .unwrap();
        block.set_state_root(state_root);
        let block = mine_for_test(block);

        assert_eq!(ledger.validate_block(&block), Ok(state_root));
        let block_hash = block.hash().unwrap();
        ledger.apply_block_at(block, u64::MAX).unwrap();
        assert!(ledger.account(&sender).unwrap().authorization.is_some());
        ledger.rollback_block(block_hash).unwrap();
        assert!(ledger.account(&sender).unwrap().authorization.is_none());
    }

    #[test]
    fn block_state_commitment_matches_protocol_root_components() {
        let ledger = Ledger::new();
        let block_hash = BlockHash([7; crate::crypto::HASH_SIZE]);
        let commitment = ledger.state_commitment_for_block_hash(block_hash).unwrap();

        assert_eq!(commitment.block_hash, block_hash);
        assert_eq!(commitment.account_state_root, ledger.state_root());
        assert_eq!(
            commitment.protocol_state_root,
            ledger.protocol_state_root().unwrap()
        );
        assert!(commitment.matches_protocol_root().unwrap());
    }

    #[test]
    fn initialized_chain_rejects_inflated_economic_supply() {
        let mut ledger = Ledger::new();
        let genesis = genesis_block().unwrap();
        ledger
            .apply_block_at(genesis.clone(), genesis.timestamp())
            .unwrap();
        ledger.accounts.insert(
            Address([0x44; crate::crypto::ADDRESS_SIZE]),
            Account::new(Address([0x44; crate::crypto::ADDRESS_SIZE]), Amount(1)),
        );
        assert_eq!(ledger.validate_supply(), Err(LedgerError::SupplyMismatch));
    }

    #[test]
    fn initialized_chain_rejects_non_coinbase_account_issuance_atomically() {
        let mut ledger = Ledger::new();
        let genesis = genesis_block().unwrap();
        ledger
            .apply_block_at(genesis.clone(), genesis.timestamp())
            .unwrap();
        let supply_before = ledger.economic_supply().unwrap();
        let address = Address([0x45; crate::crypto::ADDRESS_SIZE]);

        assert_eq!(
            ledger.create_account(address, Amount(1)),
            Err(LedgerError::UnauthorizedSupplyCreation)
        );
        assert!(ledger.account(&address).is_none());
        assert_eq!(ledger.economic_supply().unwrap(), supply_before);

        // Zero-balance account creation is not issuance.
        ledger.create_account(address, Amount(0)).unwrap();
        assert_eq!(ledger.economic_supply().unwrap(), supply_before);
    }

    #[test]
    fn expected_supply_switches_to_tail_emission_at_the_boundary() {
        let genesis = Amount(123);
        let boundary = crate::consensus::supply::TAIL_EMISSION_START_HEIGHT;
        let before = expected_issued_supply(Height(boundary - 1), [genesis].into_iter()).unwrap();
        let at_boundary = expected_issued_supply(Height(boundary), [genesis].into_iter()).unwrap();
        let after = expected_issued_supply(Height(boundary + 1), [genesis].into_iter()).unwrap();

        assert_eq!(
            at_boundary.0 - before.0,
            crate::consensus::supply::TAIL_EMISSION
        );
        assert_eq!(
            after.0 - at_boundary.0,
            crate::consensus::supply::TAIL_EMISSION
        );
        assert_eq!(
            crate::consensus::block_reward(Height(boundary - 1)),
            Amount(crate::consensus::supply::BLOCK_REWARD)
        );
        assert_eq!(
            crate::consensus::block_reward(Height(boundary)),
            Amount(crate::consensus::supply::TAIL_EMISSION)
        );
    }

    #[test]
    fn governance_credential_can_vote_once_per_proposal() {
        let issuer = generate_keypair();
        let issuer_controller = generate_keypair();
        let issuer_controller_address = dual_address_from_public_keys(
            &issuer_controller.public_key,
            &issuer_controller.public_key,
        );
        let proposal_credential_key = generate_keypair();
        let vote_credential_key = generate_keypair();
        let voter = generate_keypair();
        let voter_address = dual_address_from_public_keys(&voter.public_key, &voter.public_key);
        let proposal_credential = GovernanceCredential::unsigned(
            voter_address,
            issuer.public_key,
            proposal_credential_key.public_key,
            GovernanceActionType::CreateProposal,
        );
        let proposal_credential = proposal_credential.clone().with_issuer_signature(sign(
            &issuer.secret_key,
            &proposal_credential.issuer_signing_bytes().unwrap(),
        ));
        let vote_credential = GovernanceCredential::unsigned(
            voter_address,
            issuer.public_key,
            vote_credential_key.public_key,
            GovernanceActionType::ProposalVote,
        );
        let vote_credential = vote_credential.clone().with_issuer_signature(sign(
            &issuer.secret_key,
            &vote_credential.issuer_signing_bytes().unwrap(),
        ));

        let mut ledger = Ledger::new();
        ledger
            .create_account_with_authorization(
                issuer_controller_address,
                issuer_controller.public_key,
                Amount(100),
            )
            .expect("issuer controller account should be created");
        ledger
            .create_account_with_authorization(voter_address, voter.public_key, Amount(200 * XPQ))
            .expect("account should be created");

        let register_issuer = GovernanceAction::register_issuer(
            issuer_controller_address,
            Amount(1),
            Nonce(0),
            issuer.public_key,
            hash_bytes(b"issuer-profile-v1"),
            b"ipfs://issuer-profile-v1".to_vec(),
            hash_bytes(b"issuer-fee-policy-v1"),
            b"ipfs://issuer-fee-policy-v1".to_vec(),
            Amount(10),
            Height(100),
        );
        let signed_register_issuer = authorized_governance_action(
            register_issuer.clone(),
            &issuer_controller,
            &issuer_controller,
        );
        ledger
            .apply_signed_governance_action(&signed_register_issuer, Height(1))
            .expect("issuer registration should apply");
        let issuer_id = ledger
            .governance_issuer_by_key(&issuer.public_key)
            .expect("issuer should be registered")
            .id;
        ledger.governance.approve_issuer(issuer_id).unwrap();

        let issue_proposal_credential = GovernanceAction::issue_credential(
            issuer_controller_address,
            Amount(1),
            Nonce(1),
            proposal_credential.clone(),
        );
        let signed_issue_proposal_credential = authorized_governance_action(
            issue_proposal_credential,
            &issuer_controller,
            &issuer_controller,
        );
        ledger
            .apply_signed_governance_action(&signed_issue_proposal_credential, Height(1))
            .expect("issuer should attach proposal credential onchain");
        let issue_vote_credential = GovernanceAction::issue_credential(
            issuer_controller_address,
            Amount(1),
            Nonce(2),
            vote_credential.clone(),
        );
        let signed_issue_vote_credential = authorized_governance_action(
            issue_vote_credential,
            &issuer_controller,
            &issuer_controller,
        );
        ledger
            .apply_signed_governance_action(&signed_issue_vote_credential, Height(1))
            .expect("issuer should attach vote credential onchain");
        assert_eq!(
            ledger.governance_credential(voter_address, &GovernanceActionType::ProposalVote),
            Some(&vote_credential)
        );

        let proposal = Proposal::new(
            voter_address,
            GovernanceActionType::ProposalVote,
            b"ship governance primitive".to_vec(),
            hash_bytes(b"governance-design-v1"),
            b"ipfs://governance-design-v1".to_vec(),
            None,
            vec![issuer_id],
            ProposalVotingMode::Credential,
            ProposalRules::default(),
            Height(1),
            Height(10),
        )
        .expect("proposal should be valid");

        let create = GovernanceAction::create_proposal(
            voter_address,
            Amount(1),
            Nonce(0),
            proposal.clone(),
            MIN_PROPOSAL_BOND,
            ProposalCreationAuthorization::BoundCredential { issuer_id },
        );
        let signed_create = authorized_governance_action(create.clone(), &voter, &voter);
        ledger
            .apply_signed_governance_action(&signed_create, Height(1))
            .expect("proposal creation should apply");

        let vote = GovernanceAction::vote(
            voter_address,
            Amount(1),
            Nonce(1),
            proposal.id,
            VoteChoice::Yes,
            VoteAuthorization::BoundCredential { issuer_id },
        );
        let signed_vote = authorized_governance_action(vote.clone(), &voter, &voter);
        ledger
            .apply_signed_governance_action(&signed_vote, Height(2))
            .expect("first credential use should apply");

        let duplicate_vote = GovernanceAction::vote(
            voter_address,
            Amount(1),
            Nonce(2),
            proposal.id,
            VoteChoice::No,
            VoteAuthorization::BoundCredential { issuer_id },
        );
        let signed_duplicate_vote =
            authorized_governance_action(duplicate_vote.clone(), &voter, &voter);
        let error = ledger
            .apply_signed_governance_action(&signed_duplicate_vote, Height(2))
            .unwrap_err();
        assert_eq!(
            error,
            LedgerError::InvalidTransaction(TransactionError::DuplicateGovernanceCredential)
        );
        assert_eq!(
            ledger.governance_vote_tally(&proposal.id),
            Some(GovernanceVoteTally {
                yes: 1,
                no: 0,
                abstain: 0,
            })
        );

        let finalize = GovernanceAction::finalize_proposal(
            issuer_controller_address,
            Amount(1),
            Nonce(3),
            proposal.id,
        );
        let signed_finalize =
            authorized_governance_action(finalize.clone(), &issuer_controller, &issuer_controller);
        ledger
            .apply_signed_governance_action(&signed_finalize, Height(11))
            .expect("proposal finalization should apply");
        assert_eq!(
            ledger.governance_proposal_outcome(&proposal.id),
            Some(crate::governance::ProposalOutcome::Accepted)
        );

        let execute =
            GovernanceAction::execute_proposal(voter_address, Amount(1), Nonce(2), proposal.id);
        let signed_execute = authorized_governance_action(execute.clone(), &voter, &voter);
        ledger
            .apply_signed_governance_action(&signed_execute, Height(12))
            .expect("accepted proposal execution receipt should apply");
        assert_eq!(
            ledger
                .governance_proposal_execution(&proposal.id)
                .map(|execution| execution.executor),
            Some(voter_address)
        );
    }

    #[test]
    fn offchain_credential_can_bind_and_revoke_onchain_subject() {
        let issuer = generate_keypair();
        let issuer_controller = generate_keypair();
        let issuer_controller_address = dual_address_from_public_keys(
            &issuer_controller.public_key,
            &issuer_controller.public_key,
        );
        let credential_key = generate_keypair();
        let voter = generate_keypair();
        let voter_address = dual_address_from_public_keys(&voter.public_key, &voter.public_key);
        let credential = GovernanceCredential::unsigned_file(
            issuer.public_key,
            credential_key.public_key,
            GovernanceActionType::ProposalVote,
        );
        let credential = credential.clone().with_issuer_signature(sign(
            &issuer.secret_key,
            &credential.issuer_signing_bytes().unwrap(),
        ));

        let mut ledger = Ledger::new();
        ledger
            .create_account_with_authorization(
                issuer_controller_address,
                issuer_controller.public_key,
                Amount(100),
            )
            .unwrap();
        ledger
            .create_account_with_authorization(voter_address, voter.public_key, Amount(10))
            .unwrap();

        let register_issuer = GovernanceAction::register_issuer(
            issuer_controller_address,
            Amount(1),
            Nonce(0),
            issuer.public_key,
            hash_bytes(b"issuer-profile-v2"),
            b"ipfs://issuer-profile-v2".to_vec(),
            hash_bytes(b"issuer-fee-policy-v2"),
            b"ipfs://issuer-fee-policy-v2".to_vec(),
            Amount(10),
            Height(100),
        );
        ledger
            .apply_signed_governance_action(
                &authorized_governance_action(
                    register_issuer,
                    &issuer_controller,
                    &issuer_controller,
                ),
                Height(1),
            )
            .unwrap();
        let issuer_id = ledger
            .governance_issuer_by_key(&issuer.public_key)
            .unwrap()
            .id;
        ledger.governance.approve_issuer(issuer_id).unwrap();

        let bind_use = GovernanceCredentialUse::new(
            credential.clone(),
            crate::governance::bind_credential_context_id(
                voter_address,
                GovernanceActionType::ProposalVote,
            )
            .unwrap(),
            voter_address,
            &credential_key.secret_key,
        )
        .unwrap();
        let bind = GovernanceAction::bind_credential(voter_address, Amount(1), Nonce(0), bind_use);
        ledger
            .apply_signed_governance_action(
                &authorized_governance_action(bind, &voter, &voter),
                Height(2),
            )
            .unwrap();

        let bound_credential = credential.clone().bound_to(voter_address);
        assert_eq!(
            ledger.governance_credential(voter_address, &GovernanceActionType::ProposalVote),
            Some(&bound_credential)
        );

        let revoke = GovernanceAction::revoke_credential(
            voter_address,
            Amount(1),
            Nonce(1),
            GovernanceActionType::ProposalVote,
        );
        ledger
            .apply_signed_governance_action(
                &authorized_governance_action(revoke, &voter, &voter),
                Height(3),
            )
            .unwrap();
        assert_eq!(
            ledger.governance_credential(voter_address, &GovernanceActionType::ProposalVote),
            None
        );
    }

    #[test]
    fn coin_power_vote_locks_balance_and_can_be_increased() {
        let voter = generate_keypair();
        let voter_address = dual_address_from_public_keys(&voter.public_key, &voter.public_key);
        let miner = generate_keypair();
        let miner_address = dual_address_from_public_keys(&miner.public_key, &miner.public_key);
        let mut ledger = Ledger::new();
        ledger
            .create_account_with_authorization(voter_address, voter.public_key, Amount(200 * XPQ))
            .unwrap();
        ledger
            .create_account_with_authorization(miner_address, miner.public_key, Amount(10))
            .unwrap();

        let proposal = Proposal::new(
            voter_address,
            GovernanceActionType::ParameterPoll,
            b"coin power vote".to_vec(),
            hash_bytes(b"coin-power-v1"),
            Vec::new(),
            None,
            Vec::new(),
            ProposalVotingMode::CoinPower,
            ProposalRules {
                quorum: 50,
                yes_threshold_bps: 5_001,
            },
            Height(1),
            Height(10),
        )
        .unwrap();
        let create = GovernanceAction::create_proposal(
            voter_address,
            Amount(1),
            Nonce(0),
            proposal.clone(),
            MIN_PROPOSAL_BOND,
            ProposalCreationAuthorization::Coin,
        );
        ledger
            .apply_signed_governance_action(
                &authorized_governance_action(create, &voter, &voter),
                Height(1),
            )
            .unwrap();
        assert_eq!(
            ledger.governance_vote_tally(&proposal.id),
            Some(GovernanceVoteTally {
                yes: 0,
                no: 0,
                abstain: 0,
            })
        );
        assert_eq!(
            ledger
                .account(&voter_address)
                .map(|account| account.locked_balance_at(Height(10))),
            Some(MIN_PROPOSAL_BOND)
        );

        let first_vote = GovernanceAction::vote(
            voter_address,
            Amount(1),
            Nonce(1),
            proposal.id,
            VoteChoice::Yes,
            VoteAuthorization::CoinPower {
                amount: Amount(40 * XPQ),
            },
        );
        ledger
            .apply_signed_governance_action(
                &authorized_governance_action(first_vote, &voter, &voter),
                Height(2),
            )
            .unwrap();

        let blocked_transaction = single_output_transaction(
            voter_address,
            miner_address,
            Amount(60 * XPQ),
            Amount(1),
            Nonce(2),
        );
        let blocked_payload = blocked_transaction.signing_bytes().unwrap();
        let blocked_transfer = SignedTransaction::new_authorized(
            blocked_transaction,
            voter.public_key,
            sign(&voter.secret_key, &blocked_payload),
            voter.public_key,
            sign(&voter.secret_key, &blocked_payload),
        );
        assert_eq!(
            ledger.apply_signed_transaction(&blocked_transfer),
            Err(LedgerError::InsufficientBalance)
        );

        let second_vote = GovernanceAction::vote(
            voter_address,
            Amount(1),
            Nonce(2),
            proposal.id,
            VoteChoice::Yes,
            VoteAuthorization::CoinPower {
                amount: Amount(20 * XPQ),
            },
        );
        ledger
            .apply_signed_governance_action(
                &authorized_governance_action(second_vote, &voter, &voter),
                Height(3),
            )
            .unwrap();

        assert_eq!(
            ledger.governance_vote_tally(&proposal.id),
            Some(GovernanceVoteTally {
                yes: 60 * XPQ,
                no: 0,
                abstain: 0,
            })
        );
        assert_eq!(
            ledger
                .account(&voter_address)
                .map(|account| account.locked_balance_at(Height(10))),
            Some(Amount(MIN_PROPOSAL_BOND.0 + 60 * XPQ))
        );
        assert_eq!(
            ledger
                .account(&voter_address)
                .map(|account| account.locked_balance_at(Height(11))),
            Some(Amount(0))
        );
    }

    #[test]
    fn issuer_requires_accepted_governance_approval() {
        let controller = generate_keypair();
        let controller_address =
            dual_address_from_public_keys(&controller.public_key, &controller.public_key);
        let issuer = generate_keypair();
        let voter = generate_keypair();
        let voter_address = dual_address_from_public_keys(&voter.public_key, &voter.public_key);
        let mut ledger = Ledger::new();
        ledger
            .create_account_with_authorization(
                controller_address,
                controller.public_key,
                Amount(100),
            )
            .unwrap();
        ledger
            .create_account_with_authorization(voter_address, voter.public_key, Amount(200 * XPQ))
            .unwrap();

        let register = GovernanceAction::register_issuer(
            controller_address,
            Amount(1),
            Nonce(0),
            issuer.public_key,
            hash_bytes(b"kyc-provider"),
            b"ipfs://kyc-provider".to_vec(),
            hash_bytes(b"kyc-fees"),
            b"ipfs://kyc-fees".to_vec(),
            Amount(10),
            Height(100),
        );
        ledger
            .apply_signed_governance_action(
                &authorized_governance_action(register, &controller, &controller),
                Height(1),
            )
            .unwrap();
        let issuer_id = ledger
            .governance_issuer_by_key(&issuer.public_key)
            .unwrap()
            .id;
        assert!(
            ledger
                .governance
                .active_issuer_by_key(&issuer.public_key)
                .is_none()
        );

        let approval = Proposal::new(
            voter_address,
            GovernanceActionType::ApproveIssuer,
            b"approve kyc issuer".to_vec(),
            hash_bytes(b"approve-issuer"),
            Vec::new(),
            None,
            Vec::new(),
            ProposalVotingMode::CoinPower,
            ProposalRules::default(),
            Height(2),
            Height(3),
        )
        .unwrap();
        let create = GovernanceAction::create_proposal(
            voter_address,
            Amount(1),
            Nonce(0),
            approval.clone(),
            MIN_PROPOSAL_BOND,
            ProposalCreationAuthorization::Coin,
        );
        ledger
            .apply_signed_governance_action(
                &authorized_governance_action(create, &voter, &voter),
                Height(2),
            )
            .unwrap();
        let vote = GovernanceAction::vote(
            voter_address,
            Amount(1),
            Nonce(1),
            approval.id,
            VoteChoice::Yes,
            VoteAuthorization::CoinPower { amount: Amount(10) },
        );
        ledger
            .apply_signed_governance_action(
                &authorized_governance_action(vote, &voter, &voter),
                Height(2),
            )
            .unwrap();
        let finalize =
            GovernanceAction::finalize_proposal(voter_address, Amount(1), Nonce(2), approval.id);
        ledger
            .apply_signed_governance_action(
                &authorized_governance_action(finalize, &voter, &voter),
                Height(4),
            )
            .unwrap();
        let approve = GovernanceAction::approve_issuer(
            voter_address,
            Amount(1),
            Nonce(3),
            approval.id,
            issuer_id,
        );
        ledger
            .apply_signed_governance_action(
                &authorized_governance_action(approve, &voter, &voter),
                Height(5),
            )
            .unwrap();

        assert!(
            ledger
                .governance
                .active_issuer_by_key(&issuer.public_key)
                .is_some()
        );
    }
}
