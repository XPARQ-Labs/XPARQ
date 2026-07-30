use crate::crypto::{HashDomain, StateRoot, domain_hash};
use crate::governance::{CredentialNullifier, GovernanceContextId, GovernanceCredentialUse};
use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CredentialUseState {
    used_nullifiers: BTreeMap<GovernanceContextId, BTreeSet<CredentialNullifier>>,
}

impl CredentialUseState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn nullifier_used(
        &self,
        context_id: &GovernanceContextId,
        nullifier: &CredentialNullifier,
    ) -> bool {
        self.used_nullifiers
            .get(context_id)
            .is_some_and(|used| used.contains(nullifier))
    }

    pub fn record_use(
        &mut self,
        credential_use: &GovernanceCredentialUse,
    ) -> Result<(), CredentialUseStateError> {
        let used = self
            .used_nullifiers
            .entry(credential_use.context_id)
            .or_default();
        if !used.insert(credential_use.nullifier) {
            return Err(CredentialUseStateError::DuplicateCredentialUse);
        }
        Ok(())
    }

    pub fn consensus_root(&self) -> Result<StateRoot, crate::error::CodecError> {
        Ok(StateRoot(
            domain_hash(
                HashDomain::CredentialUseState,
                &crate::codec::canonical_bytes(&self.used_nullifiers)?,
            )
            .0,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialUseStateError {
    DuplicateCredentialUse,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{PublicKey, Signature};
    use crate::governance::{GovernanceActionType, GovernanceCredential};

    #[test]
    fn credential_use_state_rejects_duplicate_context_nullifier() {
        let credential = GovernanceCredential {
            version: crate::governance::GOVERNANCE_CREDENTIAL_VERSION,
            subject: Some(crate::crypto::Address([7; crate::crypto::ADDRESS_SIZE])),
            issuer_public_key: PublicKey([1; crate::crypto::PUBLIC_KEY_SIZE]),
            credential_public_key: PublicKey([2; crate::crypto::PUBLIC_KEY_SIZE]),
            credential_type: GovernanceActionType::SignalSupport,
            issuer_signature: Signature([3; crate::crypto::SIGNATURE_SIZE]),
        };
        let credential_use = GovernanceCredentialUse {
            credential,
            context_id: crate::crypto::Hash([4; crate::crypto::HASH_SIZE]),
            nullifier: crate::crypto::Hash([5; crate::crypto::HASH_SIZE]),
            authorized_signer: crate::crypto::Address([7; crate::crypto::ADDRESS_SIZE]),
            credential_signature: Signature([6; crate::crypto::SIGNATURE_SIZE]),
        };
        let mut state = CredentialUseState::new();

        assert!(state.record_use(&credential_use).is_ok());
        assert_eq!(
            state.record_use(&credential_use),
            Err(CredentialUseStateError::DuplicateCredentialUse)
        );
    }
}
