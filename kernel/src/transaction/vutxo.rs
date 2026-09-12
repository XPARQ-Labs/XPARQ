use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};

use crypto::{
    AccountSignature, Address, HASH_SIZE, HashDomain, PublicKey, VAULT_ENVELOPE_PAYLOAD_SIZE,
    canonical_bytes, domain, kem::KemCiphertext,
};

use crate::{
    native::{
        asset::{AssetOutput, AssetShare, Contract, Share, ensure_nonzero_asset_amount},
        coin::{CoinOutput, XPQ, Zeno},
    },
    transaction::{ChainContext, IntentError, SpendCommitment},
};

// -----------------------------------------------------------------------------
// Vault ID
// -----------------------------------------------------------------------------

/// Canonical identifier of a Vault UTXO.
///
/// A vault has its own identifier because it may contain either
/// native XPQ or a native asset.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct VaultId([u8; HASH_SIZE]);

impl VaultId {
    pub const ZERO: Self = Self([0; HASH_SIZE]);

    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; HASH_SIZE] {
        self.0
    }

    pub fn derive(commitment: SpendCommitment, output_index: u32) -> Self {
        let bytes =
            canonical_bytes(&(commitment, output_index)).expect("vault output identifier encoding");
        Self(domain(HashDomain::VaultOutput, &bytes).into_bytes())
    }
}

// -----------------------------------------------------------------------------
// Vault value
// -----------------------------------------------------------------------------

/// Public value contained by a Vault UTXO.
///
/// vUTXO hides ownership, not value.
///
/// Coin amount remains public.
/// Asset identity and amount also remain public.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum VaultValue {
    Coin(Zeno),
    Asset(AssetShare),
}

impl VaultValue {
    pub const fn coin(amount: Zeno) -> Self {
        Self::Coin(amount)
    }

    pub const fn asset(share: AssetShare) -> Self {
        Self::Asset(share)
    }

    pub const fn as_coin(&self) -> Option<Zeno> {
        match self {
            Self::Coin(amount) => Some(*amount),
            Self::Asset(_) => None,
        }
    }

    pub const fn as_asset(&self) -> Option<&AssetShare> {
        match self {
            Self::Coin(_) => None,
            Self::Asset(share) => Some(share),
        }
    }

    pub const fn is_coin(&self) -> bool {
        matches!(self, Self::Coin(_))
    }

    pub const fn is_asset(&self) -> bool {
        matches!(self, Self::Asset(_))
    }

    pub fn validate(&self) -> Result<(), IntentError> {
        match self {
            Self::Coin(amount) => {
                if amount.is_zero() {
                    return Err(IntentError::ZeroAmount);
                }
            }

            Self::Asset(share) => {
                ensure_nonzero_asset_amount(share.amount).map_err(|_| IntentError::InvalidVault)?;
            }
        }

        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Vault lock
// -----------------------------------------------------------------------------

/// Recipient-hiding ownership commitment.
///
/// Conceptually:
///
///     lock = H(spend_public_key || opening)
///
/// The actual construction and verification of this commitment belongs
/// to consensus validation.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct VaultLock([u8; HASH_SIZE]);

impl VaultLock {
    pub const ZERO: Self = Self([0; HASH_SIZE]);

    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; HASH_SIZE] {
        self.0
    }

    pub fn derive(public_key: &PublicKey, opening: &[u8; HASH_SIZE]) -> Self {
        let bytes = canonical_bytes(&(public_key, opening)).expect("vault lock encoding");
        Self(domain(HashDomain::VaultLock, &bytes).into_bytes())
    }
}

// -----------------------------------------------------------------------------
// Vault envelope
// -----------------------------------------------------------------------------

/// Encrypted recipient notification.
///
/// `kem_ciphertext` allows the intended recipient to derive the shared
/// secret.
///
/// `encrypted_payload` contains recipient-specific vault data encrypted
/// by the wallet / crypto layer.
///
/// The transaction and ledger layers treat the payload as opaque bytes.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VaultEnvelope {
    kem_ciphertext: KemCiphertext,
    encrypted_payload: Vec<u8>,
}

impl VaultEnvelope {
    pub fn new(kem_ciphertext: KemCiphertext, encrypted_payload: Vec<u8>) -> Self {
        Self {
            kem_ciphertext,
            encrypted_payload,
        }
    }

    pub const fn kem_ciphertext(&self) -> &KemCiphertext {
        &self.kem_ciphertext
    }

    pub fn encrypted_payload(&self) -> &[u8] {
        &self.encrypted_payload
    }

    pub fn into_parts(self) -> (KemCiphertext, Vec<u8>) {
        (self.kem_ciphertext, self.encrypted_payload)
    }
}

// -----------------------------------------------------------------------------
// Vault output
// -----------------------------------------------------------------------------

/// A newly-created Vault UTXO.
///
/// No recipient `Address` is stored.
///
/// Ownership is represented by `lock`, while `envelope` lets the intended
/// recipient discover and recover the private vault metadata.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VaultOutput {
    pub value: VaultValue,
    pub lock: VaultLock,
    pub envelope: VaultEnvelope,
}

impl VaultOutput {
    pub fn new(
        value: VaultValue,
        lock: VaultLock,
        envelope: VaultEnvelope,
    ) -> Result<Self, IntentError> {
        value.validate()?;

        Ok(Self {
            value,
            lock,
            envelope,
        })
    }

    pub fn validate(&self) -> Result<(), IntentError> {
        self.value.validate()?;
        if self.envelope.encrypted_payload().len() != VAULT_ENVELOPE_PAYLOAD_SIZE {
            return Err(IntentError::InvalidVault);
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Lock source
// -----------------------------------------------------------------------------

/// Transparent source used to create new vaults.
///
/// Creating a vault is account-authorized because the source is still
/// an ordinary XPQ or asset UTXO.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum VaultSource {
    Coin { inputs: Vec<XPQ> },

    Asset { asset: Contract, inputs: Vec<Share> },
}

// -----------------------------------------------------------------------------
// Vault lock intent
// -----------------------------------------------------------------------------

/// Converts ordinary account-owned value into one or more vUTXOs.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VaultLockIntent {
    pub signer: Address,
    pub source: VaultSource,
    pub outputs: Vec<VaultOutput>,
}

impl VaultLockIntent {
    pub fn new(
        signer: Address,
        source: VaultSource,
        outputs: Vec<VaultOutput>,
    ) -> Result<Self, IntentError> {
        let intent = Self {
            signer,
            source,
            outputs,
        };

        intent.validate()?;

        Ok(intent)
    }

    pub fn validate(&self) -> Result<(), IntentError> {
        if self.outputs.is_empty() {
            return Err(IntentError::EmptyOutputs);
        }

        for output in &self.outputs {
            output.validate()?;
        }

        match &self.source {
            VaultSource::Coin { inputs } => {
                if inputs.is_empty() {
                    return Err(IntentError::EmptyInputs);
                }

                let mut unique = BTreeSet::new();

                if inputs.iter().any(|id| !unique.insert(*id)) {
                    return Err(IntentError::DuplicateInput);
                }

                if self.outputs.iter().any(|output| !output.value.is_coin()) {
                    return Err(IntentError::InvalidVault);
                }
            }

            VaultSource::Asset { asset, inputs } => {
                if inputs.is_empty() {
                    return Err(IntentError::EmptyInputs);
                }

                let mut unique = BTreeSet::new();

                if inputs.iter().any(|id| !unique.insert(*id)) {
                    return Err(IntentError::DuplicateInput);
                }

                for output in &self.outputs {
                    match output.value {
                        VaultValue::Asset(share) if share.asset == *asset => {}

                        _ => {
                            return Err(IntentError::InvalidVault);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn signing_bytes(&self, chain: ChainContext) -> Result<Vec<u8>, IntentError> {
        self.validate()?;

        canonical_bytes(&(chain.genesis_hash, self)).map_err(|_| IntentError::Encoding)
    }

    pub fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        let bytes = self.signing_bytes(chain)?;

        Ok(SpendCommitment::from_bytes(
            domain(HashDomain::VaultIntent, &bytes).into_bytes(),
        ))
    }
}

// -----------------------------------------------------------------------------
// Vault spend output
// -----------------------------------------------------------------------------

/// Destination of value consumed from one or more vUTXOs.
///
/// A vault may remain private by producing another vault, or return
/// to the transparent XPQ / asset UTXO model.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum VaultSpendOutput {
    Vault(VaultOutput),
    Coin(CoinOutput),
    Asset(AssetOutput),
}

impl VaultSpendOutput {
    pub fn validate(&self) -> Result<(), IntentError> {
        match self {
            Self::Vault(output) => output.validate(),

            Self::Coin(output) => {
                if output.amount.is_zero() {
                    return Err(IntentError::ZeroAmount);
                }

                Ok(())
            }

            Self::Asset(output) => {
                ensure_nonzero_asset_amount(output.amount).map_err(|_| IntentError::InvalidVault)
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Vault spend intent
// -----------------------------------------------------------------------------

/// Consumes existing vUTXOs.
///
/// Structural validation only verifies the transaction shape.
///
/// Monetary conservation and compatibility between input values and
/// outputs must be checked against canonical ledger state.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VaultSpendIntent {
    pub inputs: Vec<VaultId>,
    pub outputs: Vec<VaultSpendOutput>,
}

impl VaultSpendIntent {
    pub fn new(inputs: Vec<VaultId>, outputs: Vec<VaultSpendOutput>) -> Result<Self, IntentError> {
        let intent = Self { inputs, outputs };

        intent.validate()?;

        Ok(intent)
    }

    pub fn validate(&self) -> Result<(), IntentError> {
        if self.inputs.is_empty() {
            return Err(IntentError::EmptyInputs);
        }

        if self.outputs.is_empty() {
            return Err(IntentError::EmptyOutputs);
        }

        let mut unique = BTreeSet::new();

        if self.inputs.iter().any(|id| !unique.insert(*id)) {
            return Err(IntentError::DuplicateInput);
        }

        for output in &self.outputs {
            output.validate()?;
        }

        Ok(())
    }

    pub fn signing_bytes(&self, chain: ChainContext) -> Result<Vec<u8>, IntentError> {
        self.validate()?;

        canonical_bytes(&(chain.genesis_hash, self)).map_err(|_| IntentError::Encoding)
    }

    pub fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        let bytes = self.signing_bytes(chain)?;

        Ok(SpendCommitment::from_bytes(
            domain(HashDomain::VaultIntent, &bytes).into_bytes(),
        ))
    }
}

// -----------------------------------------------------------------------------
// Vault authorization
// -----------------------------------------------------------------------------

/// Ownership witness for one consumed Vault UTXO.
///
/// Consensus must verify:
///
/// 1. `vault` exists.
/// 2. `H(public_key || opening)` matches that vault's `VaultLock`.
/// 3. `signature` verifies the complete `VaultSpendIntent` commitment.
///
/// A separate authorization is used for each input so a transaction may
/// consume vaults controlled by different keys.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VaultAuthorization {
    pub vault: VaultId,
    pub public_key: PublicKey,
    pub opening: [u8; HASH_SIZE],
    pub signature: AccountSignature,
}

impl VaultAuthorization {
    pub const fn vault(&self) -> VaultId {
        self.vault
    }

    pub const fn opening(&self) -> &[u8; HASH_SIZE] {
        &self.opening
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AuthorizedVaultLockTransaction {
    pub lock: crate::transaction::AuthorizedAccountIntent<VaultLockIntent>,
    pub payment:
        Option<crate::transaction::AuthorizedAccountIntent<crate::transaction::SpendIntent>>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AuthorizedVaultSpendTransaction {
    pub spend: VaultSpendIntent,
    pub authorizations: Vec<VaultAuthorization>,
    pub payment:
        Option<crate::transaction::AuthorizedAccountIntent<crate::transaction::SpendIntent>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{Signature, SigningSeed};

    #[test]
    fn vault_lock_binds_public_key_and_opening() {
        let first_key = SigningSeed::new(Signature::MlDsa44, [1; 32]).public_key();
        let second_key = SigningSeed::new(Signature::MlDsa44, [2; 32]).public_key();

        assert_ne!(
            VaultLock::derive(&first_key, &[3; 32]),
            VaultLock::derive(&first_key, &[4; 32])
        );
        assert_ne!(
            VaultLock::derive(&first_key, &[3; 32]),
            VaultLock::derive(&second_key, &[3; 32])
        );
    }

    #[test]
    fn vault_id_binds_commitment_and_output_index() {
        let commitment = SpendCommitment::from_bytes([7; HASH_SIZE]);
        assert_ne!(
            VaultId::derive(commitment, 0),
            VaultId::derive(commitment, 1)
        );
        assert_ne!(VaultId::derive(commitment, 0), VaultId::ZERO);
    }
}
