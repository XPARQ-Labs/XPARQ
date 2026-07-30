//! Consensus state for governance issuers, proposals, votes, and credential nullifiers.

use crate::block::BlockHeight;
use crate::consensus::supply::Amount;
use crate::crypto::{Address, HashDomain, StateRoot, domain_hash};
use crate::error::LedgerError;
use crate::governance::{
    CredentialNullifier, GOVERNANCE_BASIS_POINTS, GovernanceActionType, GovernanceCredential,
    GovernanceIssuer, GovernanceIssuerId, GovernanceIssuerStatus, Proposal, ProposalExecution,
    ProposalId, ProposalOutcome, VoteChoice,
};
use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct GovernanceVoteTally {
    pub yes: u64,
    pub no: u64,
    pub abstain: u64,
}

impl GovernanceVoteTally {
    pub fn record(&mut self, choice: VoteChoice, power: u64) -> Result<(), LedgerError> {
        let counter = match choice {
            VoteChoice::Yes => &mut self.yes,
            VoteChoice::No => &mut self.no,
            VoteChoice::Abstain => &mut self.abstain,
        };
        *counter = counter
            .checked_add(power)
            .ok_or(LedgerError::SupplyOverflow)?;
        Ok(())
    }

    pub fn total(self) -> u64 {
        self.yes
            .saturating_add(self.no)
            .saturating_add(self.abstain)
    }

    pub fn outcome_for(self, proposal: &Proposal) -> ProposalOutcome {
        if self.total() < proposal.rules.quorum {
            return ProposalOutcome::Rejected;
        }
        let decisive_votes = self.yes.saturating_add(self.no);
        if decisive_votes == 0 {
            return ProposalOutcome::Rejected;
        }
        let yes_bps = (self.yes as u128)
            .saturating_mul(GOVERNANCE_BASIS_POINTS as u128)
            .checked_div(decisive_votes as u128)
            .unwrap_or(0);
        if yes_bps >= proposal.rules.yes_threshold_bps as u128 {
            ProposalOutcome::Accepted
        } else {
            ProposalOutcome::Rejected
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct GovernanceState {
    pub issuers: BTreeMap<GovernanceIssuerId, GovernanceIssuer>,
    pub proposals: BTreeMap<ProposalId, Proposal>,
    pub votes: BTreeMap<ProposalId, GovernanceVoteTally>,
    pub outcomes: BTreeMap<ProposalId, ProposalOutcome>,
    pub executions: BTreeMap<ProposalId, ProposalExecution>,
    pub credentials: BTreeMap<(Address, GovernanceActionType), GovernanceCredential>,
    pub used_nullifiers: BTreeMap<ProposalId, BTreeSet<CredentialNullifier>>,
    pub coin_power_votes: BTreeMap<(ProposalId, Address), Amount>,
}

impl GovernanceState {
    pub fn issuer(&self, issuer_id: &GovernanceIssuerId) -> Option<&GovernanceIssuer> {
        self.issuers.get(issuer_id)
    }

    pub fn issuer_by_key(
        &self,
        issuer_public_key: &crate::crypto::PublicKey,
    ) -> Option<&GovernanceIssuer> {
        self.issuers
            .values()
            .find(|issuer| issuer.issuer_public_key == *issuer_public_key)
    }

    pub fn active_issuer_by_key(
        &self,
        issuer_public_key: &crate::crypto::PublicKey,
    ) -> Option<&GovernanceIssuer> {
        self.issuer_by_key(issuer_public_key)
            .filter(|issuer| issuer.status == GovernanceIssuerStatus::Active)
    }

    pub fn proposal(&self, proposal_id: &ProposalId) -> Option<&Proposal> {
        self.proposals.get(proposal_id)
    }

    pub fn vote_tally(&self, proposal_id: &ProposalId) -> Option<GovernanceVoteTally> {
        self.votes.get(proposal_id).copied()
    }

    pub fn proposal_outcome(&self, proposal_id: &ProposalId) -> Option<ProposalOutcome> {
        self.outcomes.get(proposal_id).copied()
    }

    pub fn proposal_execution(&self, proposal_id: &ProposalId) -> Option<ProposalExecution> {
        self.executions.get(proposal_id).copied()
    }

    pub fn credential(
        &self,
        subject: Address,
        credential_type: &GovernanceActionType,
    ) -> Option<&GovernanceCredential> {
        self.credentials.get(&(subject, credential_type.clone()))
    }

    pub fn nullifier_used(
        &self,
        proposal_id: &ProposalId,
        nullifier: &CredentialNullifier,
    ) -> bool {
        self.used_nullifiers
            .get(proposal_id)
            .is_some_and(|used| used.contains(nullifier))
    }

    pub fn insert_issuer(&mut self, issuer: GovernanceIssuer) -> Result<(), LedgerError> {
        if self.issuer_by_key(&issuer.issuer_public_key).is_some()
            || self.issuers.contains_key(&issuer.id)
        {
            return Err(LedgerError::DuplicateGovernanceIssuer);
        }
        self.issuers.insert(issuer.id, issuer);
        Ok(())
    }

    pub fn approve_issuer(&mut self, issuer_id: GovernanceIssuerId) -> Result<(), LedgerError> {
        let issuer = self
            .issuers
            .get_mut(&issuer_id)
            .ok_or(LedgerError::UnknownGovernanceIssuer)?;
        if issuer.status == GovernanceIssuerStatus::Revoked {
            return Err(LedgerError::UnknownGovernanceIssuer);
        }
        issuer.status = GovernanceIssuerStatus::Active;
        Ok(())
    }

    pub fn insert_proposal(&mut self, proposal: Proposal) -> Result<(), LedgerError> {
        if self.proposals.contains_key(&proposal.id) {
            return Err(LedgerError::DuplicateGovernanceProposal);
        }
        self.votes.entry(proposal.id).or_default();
        self.proposals.insert(proposal.id, proposal);
        Ok(())
    }

    pub fn insert_credential(
        &mut self,
        credential: GovernanceCredential,
    ) -> Result<(), LedgerError> {
        let issuer = self
            .active_issuer_by_key(&credential.issuer_public_key)
            .ok_or(LedgerError::UnknownGovernanceIssuer)?;
        let subject = credential.subject.ok_or(LedgerError::InvalidTransaction(
            crate::transaction::TransactionError::InvalidGovernanceCredential,
        ))?;
        let key = (subject, credential.credential_type.clone());
        if self.credentials.contains_key(&key) {
            return Err(LedgerError::InvalidTransaction(
                crate::transaction::TransactionError::DuplicateGovernanceCredential,
            ));
        }
        if issuer.issuer_public_key != credential.issuer_public_key {
            return Err(LedgerError::UnknownGovernanceIssuer);
        }
        self.credentials.insert(key, credential);
        Ok(())
    }

    pub fn revoke_credential(
        &mut self,
        subject: Address,
        credential_type: &GovernanceActionType,
    ) -> Result<GovernanceCredential, LedgerError> {
        self.credentials
            .remove(&(subject, credential_type.clone()))
            .ok_or(LedgerError::InvalidTransaction(
                crate::transaction::TransactionError::InvalidGovernanceCredential,
            ))
    }

    pub fn finalize_proposal(
        &mut self,
        proposal_id: ProposalId,
    ) -> Result<ProposalOutcome, LedgerError> {
        if self.outcomes.contains_key(&proposal_id) {
            return Err(LedgerError::DuplicateGovernanceProposalFinalization);
        }
        let proposal = self
            .proposals
            .get(&proposal_id)
            .ok_or(LedgerError::UnknownGovernanceProposal)?;
        let tally = self.votes.get(&proposal_id).copied().unwrap_or_default();
        let outcome = tally.outcome_for(proposal);
        self.outcomes.insert(proposal_id, outcome);
        Ok(outcome)
    }

    pub fn execute_proposal(
        &mut self,
        proposal_id: ProposalId,
        executor: Address,
        executed_at: BlockHeight,
    ) -> Result<ProposalExecution, LedgerError> {
        if self.executions.contains_key(&proposal_id) {
            return Err(LedgerError::DuplicateGovernanceProposalExecution);
        }
        if self.outcomes.get(&proposal_id) != Some(&ProposalOutcome::Accepted) {
            return Err(LedgerError::GovernanceProposalNotAccepted);
        }
        let execution = ProposalExecution {
            proposal_id,
            executor,
            executed_at,
        };
        self.executions.insert(proposal_id, execution);
        Ok(execution)
    }

    pub fn record_vote(
        &mut self,
        proposal_id: ProposalId,
        nullifier: CredentialNullifier,
        choice: VoteChoice,
    ) -> Result<(), LedgerError> {
        self.record_credential_use(proposal_id, nullifier)?;
        self.votes.entry(proposal_id).or_default().record(choice, 1)
    }

    pub fn record_coin_power_vote(
        &mut self,
        proposal_id: ProposalId,
        voter: Address,
        amount: Amount,
        choice: VoteChoice,
    ) -> Result<(), LedgerError> {
        let entry = self
            .coin_power_votes
            .entry((proposal_id, voter))
            .or_insert(Amount(0));
        entry.0 = entry
            .0
            .checked_add(amount.0)
            .ok_or(LedgerError::SupplyOverflow)?;
        self.votes
            .entry(proposal_id)
            .or_default()
            .record(choice, amount.0)
    }

    pub fn record_credential_use(
        &mut self,
        proposal_id: ProposalId,
        nullifier: CredentialNullifier,
    ) -> Result<(), LedgerError> {
        if self.nullifier_used(&proposal_id, &nullifier) {
            return Err(LedgerError::InvalidTransaction(
                crate::transaction::TransactionError::DuplicateGovernanceCredential,
            ));
        }
        self.used_nullifiers
            .entry(proposal_id)
            .or_default()
            .insert(nullifier);
        Ok(())
    }

    pub fn consensus_root(&self) -> Result<StateRoot, crate::error::CodecError> {
        Ok(StateRoot(
            domain_hash(
                HashDomain::GovernanceState,
                &crate::codec::canonical_bytes(self)?,
            )
            .0,
        ))
    }
}
