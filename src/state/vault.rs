use crate::codec::{HashDomain, canonical_bytes, domain_hash};
use crate::consensus::supply::Amount;
use crate::crypto::{Address, Hash};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_VAULT_CLAIMANTS: usize = 32;
pub const MAX_VAULT_NAME_BYTES: usize = 64;
pub const MAX_VAULT_DESCRIPTION_BYTES: usize = 256;

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
pub struct VaultId(pub Hash);

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash,
)]
pub struct VaultMetadata {
    pub name: String,
    pub description: String,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash,
)]
pub struct VaultPolicy {
    /// Sorted, unique addresses allowed to initiate or approve a claim.
    pub claimants: Vec<Address>,
    /// Number of distinct claimant approvals required. `1` is single-signature.
    pub threshold: u8,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash,
)]
pub struct Vault {
    pub id: VaultId,
    pub creator: Address,
    pub metadata: VaultMetadata,
    pub policy: VaultPolicy,
    pub remaining: Amount,
    pub released: Amount,
    pub nonce: u64,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash,
)]
pub struct VaultClaim {
    pub vault_id: VaultId,
    pub minter: Address,
    /// `None` pays the minter; `Some` redirects the payout.
    pub recipient: Option<Address>,
    pub amount: Amount,
    pub nonce: u64,
    /// Signatures are verified by the transaction layer. State transition
    /// consumes the canonical, distinct signer addresses.
    pub approvals: Vec<Address>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultPayout {
    pub vault_id: VaultId,
    pub minter: Address,
    pub recipient: Address,
    pub amount: Amount,
    pub nonce: u64,
}

#[derive(
    Default, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq,
)]
pub struct VaultState {
    vaults: BTreeMap<VaultId, Vault>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultError {
    EmptyName,
    MetadataTooLarge,
    EmptyClaimants,
    TooManyClaimants,
    DuplicateClaimant,
    InvalidThreshold,
    ZeroFunding,
    VaultAlreadyExists,
    VaultNotFound,
    UnauthorizedMinter,
    UnauthorizedApproval,
    DuplicateApproval,
    InsufficientApprovals,
    InvalidNonce,
    ZeroAmount,
    InsufficientReserve,
    AmountOverflow,
    Encoding,
}

impl VaultMetadata {
    pub fn validate(&self) -> Result<(), VaultError> {
        if self.name.is_empty() {
            return Err(VaultError::EmptyName);
        }
        if self.name.len() > MAX_VAULT_NAME_BYTES
            || self.description.len() > MAX_VAULT_DESCRIPTION_BYTES
        {
            return Err(VaultError::MetadataTooLarge);
        }
        Ok(())
    }
}

impl VaultPolicy {
    pub fn new(mut claimants: Vec<Address>, threshold: Option<u8>) -> Result<Self, VaultError> {
        if claimants.is_empty() {
            return Err(VaultError::EmptyClaimants);
        }
        if claimants.len() > MAX_VAULT_CLAIMANTS {
            return Err(VaultError::TooManyClaimants);
        }
        claimants.sort_unstable();
        let original_len = claimants.len();
        claimants.dedup();
        if claimants.len() != original_len {
            return Err(VaultError::DuplicateClaimant);
        }
        let threshold = threshold.unwrap_or(1);
        if threshold == 0 || usize::from(threshold) > claimants.len() {
            return Err(VaultError::InvalidThreshold);
        }
        Ok(Self {
            claimants,
            threshold,
        })
    }

    pub fn permits(&self, claim: &VaultClaim) -> Result<(), VaultError> {
        if self.claimants.binary_search(&claim.minter).is_err() {
            return Err(VaultError::UnauthorizedMinter);
        }
        let mut seen = BTreeSet::new();
        for approval in &claim.approvals {
            if self.claimants.binary_search(approval).is_err() {
                return Err(VaultError::UnauthorizedApproval);
            }
            if !seen.insert(*approval) {
                return Err(VaultError::DuplicateApproval);
            }
        }
        if seen.len() < usize::from(self.threshold) {
            return Err(VaultError::InsufficientApprovals);
        }
        Ok(())
    }
}

impl Vault {
    pub fn new(
        creator: Address,
        creation_nonce: u64,
        metadata: VaultMetadata,
        policy: VaultPolicy,
        funding: Amount,
    ) -> Result<Self, VaultError> {
        metadata.validate()?;
        if funding.0 == 0 {
            return Err(VaultError::ZeroFunding);
        }
        let id = VaultId(domain_hash(
            HashDomain::Vault,
            &canonical_bytes(&(creator, creation_nonce, &metadata, &policy))
                .map_err(|_| VaultError::Encoding)?,
        ));
        Ok(Self {
            id,
            creator,
            metadata,
            policy,
            remaining: funding,
            released: Amount(0),
            nonce: 0,
        })
    }

    pub fn claim(&mut self, claim: &VaultClaim) -> Result<VaultPayout, VaultError> {
        if claim.vault_id != self.id {
            return Err(VaultError::VaultNotFound);
        }
        if claim.nonce != self.nonce {
            return Err(VaultError::InvalidNonce);
        }
        if claim.amount.0 == 0 {
            return Err(VaultError::ZeroAmount);
        }
        self.policy.permits(claim)?;
        if claim.amount.0 > self.remaining.0 {
            return Err(VaultError::InsufficientReserve);
        }
        let released = self
            .released
            .0
            .checked_add(claim.amount.0)
            .ok_or(VaultError::AmountOverflow)?;
        self.remaining.0 -= claim.amount.0;
        self.released.0 = released;
        self.nonce = self
            .nonce
            .checked_add(1)
            .ok_or(VaultError::AmountOverflow)?;
        Ok(VaultPayout {
            vault_id: self.id,
            minter: claim.minter,
            recipient: claim.recipient.unwrap_or(claim.minter),
            amount: claim.amount,
            nonce: claim.nonce,
        })
    }
}

impl VaultState {
    pub fn vault(&self, id: &VaultId) -> Option<&Vault> {
        self.vaults.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&VaultId, &Vault)> {
        self.vaults.iter()
    }

    pub fn create(&mut self, vault: Vault) -> Result<VaultId, VaultError> {
        if self.vaults.contains_key(&vault.id) {
            return Err(VaultError::VaultAlreadyExists);
        }
        let id = vault.id;
        self.vaults.insert(id, vault);
        Ok(id)
    }

    pub fn claim(&mut self, claim: &VaultClaim) -> Result<VaultPayout, VaultError> {
        self.vaults
            .get_mut(&claim.vault_id)
            .ok_or(VaultError::VaultNotFound)?
            .claim(claim)
    }

    pub fn reserved_supply(&self) -> Result<Amount, VaultError> {
        self.vaults
            .values()
            .try_fold(0_u64, |total, vault| {
                total
                    .checked_add(vault.remaining.0)
                    .ok_or(VaultError::AmountOverflow)
            })
            .map(Amount)
    }

    pub fn state_root(&self) -> Result<crate::crypto::StateRoot, VaultError> {
        canonical_bytes(&self.vaults)
            .map(|bytes| crate::crypto::StateRoot(domain_hash(HashDomain::VaultState, &bytes).0))
            .map_err(|_| VaultError::Encoding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(byte: u8) -> Address {
        Address([byte; crate::crypto::ADDRESS_SIZE])
    }

    fn vault(threshold: Option<u8>) -> Vault {
        Vault::new(
            address(9),
            0,
            VaultMetadata {
                name: "test vault".to_string(),
                description: "reserved test coins".to_string(),
            },
            VaultPolicy::new(vec![address(1), address(2), address(3)], threshold).unwrap(),
            Amount(1_000),
        )
        .unwrap()
    }

    #[test]
    fn single_signature_claim_can_pay_another_address() {
        let mut vault = vault(None);
        let payout = vault
            .claim(&VaultClaim {
                vault_id: vault.id,
                minter: address(1),
                recipient: Some(address(8)),
                amount: Amount(100),
                nonce: 0,
                approvals: vec![address(1)],
            })
            .unwrap();
        assert_eq!(payout.recipient, address(8));
        assert_eq!(vault.remaining, Amount(900));
        assert_eq!(vault.released, Amount(100));
        assert_eq!(vault.nonce, 1);
    }

    #[test]
    fn multisig_threshold_and_unique_approvals_are_enforced() {
        let mut vault = vault(Some(2));
        let claim = VaultClaim {
            vault_id: vault.id,
            minter: address(1),
            recipient: None,
            amount: Amount(100),
            nonce: 0,
            approvals: vec![address(1)],
        };
        assert_eq!(vault.claim(&claim), Err(VaultError::InsufficientApprovals));
        let mut claim = claim;
        claim.approvals.push(address(2));
        assert!(vault.claim(&claim).is_ok());
    }

    #[test]
    fn reserve_release_preserves_total_funding() {
        let mut vault = vault(Some(2));
        let initial = vault.remaining.0;
        vault
            .claim(&VaultClaim {
                vault_id: vault.id,
                minter: address(2),
                recipient: None,
                amount: Amount(400),
                nonce: 0,
                approvals: vec![address(1), address(2)],
            })
            .unwrap();
        assert_eq!(vault.remaining.0 + vault.released.0, initial);
    }

    #[test]
    fn ledger_moves_supply_between_account_and_vault_without_inflation() {
        let creator = address(9);
        let recipient = address(8);
        let mut ledger = crate::ledger::Ledger::new();
        ledger.create_account(creator, Amount(1_000)).unwrap();
        let supply_before = ledger.economic_supply().unwrap();
        let vault = Vault::new(
            creator,
            0,
            VaultMetadata {
                name: "treasury".to_string(),
                description: String::new(),
            },
            VaultPolicy::new(vec![creator], None).unwrap(),
            Amount(600),
        )
        .unwrap();
        let id = ledger
            .create_vault_from_account(vault, crate::block::Height(0))
            .unwrap();
        assert_eq!(ledger.economic_supply().unwrap(), supply_before);
        ledger
            .apply_verified_vault_claim(
                &VaultClaim {
                    vault_id: id,
                    minter: creator,
                    recipient: Some(recipient),
                    amount: Amount(250),
                    nonce: 0,
                    approvals: vec![creator],
                },
                crate::block::Height(0),
            )
            .unwrap();
        assert_eq!(ledger.economic_supply().unwrap(), supply_before);
        assert_eq!(ledger.vaults.vault(&id).unwrap().remaining, Amount(350));
    }
}
