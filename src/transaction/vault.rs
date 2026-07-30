use crate::codec::canonical_bytes;
use crate::crypto::{
    Address, PublicKey, Signature, dual_address_from_public_keys, verify_dual_parallel,
};
use crate::error::TransactionError;
use crate::state::{VaultClaim, VaultError};
use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::BTreeSet;

const VAULT_CLAIM_SIGNATURE_DOMAIN: &[u8] = b"PAQUS_SHARKSPHERE_VAULT_CLAIM_V1";

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct VaultApproval {
    pub owner_public_key: PublicKey,
    pub auth_public_key: PublicKey,
    pub signature: Signature,
    pub auth_signature: Signature,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignedVaultClaim {
    /// The encoded approvals field must be empty before verification. Verified
    /// claimant addresses are derived from `signatures`, never trusted input.
    pub claim: VaultClaim,
    pub signatures: Vec<VaultApproval>,
}

impl SignedVaultClaim {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, crate::error::CodecError> {
        let payload = canonical_bytes(&(
            self.claim.vault_id,
            self.claim.minter,
            self.claim.recipient,
            self.claim.amount,
            self.claim.nonce,
        ))?;
        super::chain_bound_signing_bytes(VAULT_CLAIM_SIGNATURE_DOMAIN, payload)
    }

    pub fn verify(self) -> Result<VaultClaim, VaultAuthorizationError> {
        if !self.claim.approvals.is_empty() || self.signatures.is_empty() {
            return Err(VaultAuthorizationError::UntrustedApprovalList);
        }
        let payload = self
            .signing_bytes()
            .map_err(|_| VaultAuthorizationError::Encoding)?;
        let mut approvals = BTreeSet::new();
        for approval in self.signatures {
            let address = dual_address_from_public_keys(
                &approval.owner_public_key,
                &approval.auth_public_key,
            );
            if !approvals.insert(address) {
                return Err(VaultAuthorizationError::DuplicateApproval);
            }
            let (owner_valid, auth_valid) = verify_dual_parallel(
                &approval.owner_public_key,
                &approval.auth_public_key,
                &payload,
                &approval.signature,
                &approval.auth_signature,
            );
            if !owner_valid || !auth_valid {
                return Err(VaultAuthorizationError::InvalidSignature);
            }
        }
        let mut claim = self.claim;
        claim.approvals = approvals.into_iter().collect();
        Ok(claim)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultAuthorizationError {
    Encoding,
    UntrustedApprovalList,
    DuplicateApproval,
    InvalidSignature,
}

impl From<VaultAuthorizationError> for TransactionError {
    fn from(error: VaultAuthorizationError) -> Self {
        match error {
            VaultAuthorizationError::Encoding => TransactionError::InvalidWitnessEncoding,
            VaultAuthorizationError::UntrustedApprovalList
            | VaultAuthorizationError::DuplicateApproval
            | VaultAuthorizationError::InvalidSignature => TransactionError::InvalidSignature,
        }
    }
}

impl From<VaultAuthorizationError> for VaultError {
    fn from(error: VaultAuthorizationError) -> Self {
        match error {
            VaultAuthorizationError::Encoding => VaultError::Encoding,
            VaultAuthorizationError::UntrustedApprovalList
            | VaultAuthorizationError::DuplicateApproval
            | VaultAuthorizationError::InvalidSignature => VaultError::UnauthorizedApproval,
        }
    }
}

pub fn claimant_address(approval: &VaultApproval) -> Address {
    dual_address_from_public_keys(&approval.owner_public_key, &approval.auth_public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::supply::Amount;
    use crate::crypto::{generate_keypair, sign};
    use crate::state::VaultId;

    #[test]
    fn verifies_multiple_dual_signature_approvals() {
        let owner_a = generate_keypair();
        let auth_a = generate_keypair();
        let owner_b = generate_keypair();
        let auth_b = generate_keypair();
        let minter = dual_address_from_public_keys(&owner_a.public_key, &auth_a.public_key);
        let mut signed = SignedVaultClaim {
            claim: VaultClaim {
                vault_id: VaultId(crate::crypto::Hash([4; crate::crypto::HASH_SIZE])),
                minter,
                recipient: Some(Address([8; crate::crypto::ADDRESS_SIZE])),
                amount: Amount(10),
                nonce: 0,
                approvals: Vec::new(),
            },
            signatures: Vec::new(),
        };
        let payload = signed.signing_bytes().unwrap();
        signed.signatures = vec![
            VaultApproval {
                owner_public_key: owner_a.public_key,
                auth_public_key: auth_a.public_key,
                signature: sign(&owner_a.secret_key, &payload),
                auth_signature: sign(&auth_a.secret_key, &payload),
            },
            VaultApproval {
                owner_public_key: owner_b.public_key,
                auth_public_key: auth_b.public_key,
                signature: sign(&owner_b.secret_key, &payload),
                auth_signature: sign(&auth_b.secret_key, &payload),
            },
        ];
        let claim = signed.verify().unwrap();
        assert_eq!(claim.approvals.len(), 2);
        assert!(claim.approvals.contains(&minter));
    }
}
