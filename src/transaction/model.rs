use crate::block::{BlockHeight, Height, Nonce};
use crate::codec::{signed_transaction_bytes, transaction_bytes, transaction_hash};
use crate::consensus::supply::Amount;
use crate::crypto::{Address, PublicKey, Signature};
use crate::crypto::{TransactionHash, WitnessTransactionHash};
use crate::crypto::{address_from_public_key, dual_address_from_public_keys, verify};
pub use crate::error::TransactionError;
use crate::genesis::CURRENT_CHAIN_PARAMS;
use crate::governance::{
    GovernanceCredentialUse, SignedGovernanceAction, validate_attached_credentials,
};
use borsh::{BorshDeserialize, BorshSerialize};
use static_assertions::const_assert;

use super::qcash::{self, SignedQCashTransaction};

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SignedProtocolTransaction {
    Transfer(Box<SignedTransaction>),
    QCash(Box<SignedQCashTransaction>),
    Governance(Box<SignedGovernanceAction>),
}

// Keep unified transaction containers pointer-sized per variant. This prevents
// a block or mempool vector from reserving the largest protocol payload inline.
const_assert!(std::mem::size_of::<SignedProtocolTransaction>() <= 2 * std::mem::size_of::<usize>());

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransactionFamily {
    Transfer,
    QCash,
    Governance,
}

/// Maximum canonical unified envelope size.
pub const MAX_PROTOCOL_TRANSACTION_SIZE: usize = qcash::MAX_QCASH_TX_SIZE + MAX_TX_SIZE + 1;
const_assert!(MAX_TX_SIZE <= qcash::MAX_QCASH_TX_SIZE);

impl SignedProtocolTransaction {
    pub fn witness(&self) -> &Witness {
        match self {
            Self::Transfer(tx) => &tx.witness,
            Self::QCash(tx) => &tx.witness,
            Self::Governance(tx) => &tx.witness,
        }
    }

    pub fn witness_mut(&mut self) -> &mut Witness {
        match self {
            Self::Transfer(tx) => &mut tx.witness,
            Self::QCash(tx) => &mut tx.witness,
            Self::Governance(tx) => &mut tx.witness,
        }
    }

    pub fn witness_public_keys_all(&self) -> Vec<&PublicKey> {
        let witness = self.witness();
        if witness.carries_registration_keys() {
            vec![&witness.public_key, &witness.auth_public_key]
        } else {
            Vec::new()
        }
    }

    pub fn family(&self) -> TransactionFamily {
        match self {
            Self::Transfer(_) => TransactionFamily::Transfer,
            Self::QCash(_) => TransactionFamily::QCash,
            Self::Governance(_) => TransactionFamily::Governance,
        }
    }

    pub fn hash(&self) -> Result<TransactionHash, crate::error::CodecError> {
        match self {
            Self::Transfer(tx) => tx.hash(),
            Self::QCash(tx) => tx.hash(),
            Self::Governance(tx) => tx.hash(),
        }
    }

    /// Commits to the family, payload, public keys, signatures, and approvals.
    pub fn wtxid(&self) -> Result<WitnessTransactionHash, crate::error::CodecError> {
        crate::codec::signed_protocol_transaction_hash(self)
    }

    /// Unified envelope size without public keys, signatures, or approvals.
    pub fn stripped_size(&self) -> Result<usize, crate::error::CodecError> {
        Ok(1 + match self {
            Self::Transfer(tx) => tx.transaction.to_bytes()?.len(),
            Self::QCash(tx) => tx.transaction.to_bytes()?.len(),
            Self::Governance(tx) => tx.action.to_bytes()?.len(),
        })
    }

    pub fn witness_size(&self) -> Result<usize, crate::error::CodecError> {
        Ok(self.to_bytes()?.len().saturating_sub(self.stripped_size()?))
    }

    pub fn weight(&self) -> Result<usize, crate::error::CodecError> {
        Ok(self
            .stripped_size()?
            .saturating_mul(crate::block::WITNESS_SCALE_FACTOR)
            .saturating_add(self.witness_size()?))
    }

    pub fn virtual_size(&self) -> Result<usize, crate::error::CodecError> {
        Ok(self
            .weight()?
            .saturating_add(crate::block::WITNESS_SCALE_FACTOR - 1)
            / crate::block::WITNESS_SCALE_FACTOR)
    }

    pub fn signer(&self) -> Address {
        match self {
            Self::Transfer(tx) => tx.transaction.from,
            Self::QCash(tx) => tx.transaction.signer,
            Self::Governance(tx) => tx.action.signer,
        }
    }

    pub fn nonce(&self) -> AccountNonce {
        match self {
            Self::Transfer(tx) => tx.transaction.nonce,
            Self::QCash(tx) => tx.transaction.nonce,
            Self::Governance(tx) => tx.action.nonce,
        }
    }

    pub fn fee(&self) -> Amount {
        match self {
            Self::Transfer(tx) => tx.transaction.fee,
            Self::QCash(tx) => tx.transaction.fee,
            Self::Governance(tx) => tx.action.fee,
        }
    }

    pub fn validity(&self) -> ValidityWindow {
        match self {
            Self::Transfer(tx) => tx.transaction.validity,
            Self::QCash(tx) => tx.transaction.validity,
            Self::Governance(tx) => tx.action.validity,
        }
    }

    /// Returns every public key carried by the transaction witness.
    ///
    /// This is an inspection API; callers must still run normal transaction
    /// validation before trusting the key or its derived address.
    pub fn witness_public_keys(&self) -> Vec<&PublicKey> {
        self.witness_public_keys_all()
    }

    /// Returns the envelope's single witness public key.
    pub fn single_witness_public_key(&self) -> Option<&PublicKey> {
        self.witness()
            .carries_registration_keys()
            .then_some(&self.witness().public_key)
    }

    /// Derives signer addresses from all public keys carried by the witness.
    pub fn witness_addresses(&self) -> Vec<Address> {
        self.witness_public_keys()
            .into_iter()
            .map(address_from_public_key)
            .collect()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::CodecError> {
        crate::codec::signed_protocol_transaction_bytes(self)
    }

    pub fn validate_with_account_authorization(
        &self,
        account: &crate::state::Account,
        height: BlockHeight,
    ) -> Result<Option<(PublicKey, PublicKey)>, TransactionError> {
        if let Some(authorization) = &account.authorization {
            if self.witness().carries_registration_keys() {
                if self.witness().public_key != authorization.owner_public_key
                    || self.witness().auth_public_key != authorization.auth_public_key
                {
                    return Err(TransactionError::SenderAddressMismatch);
                }
                match self {
                    Self::Transfer(tx) => tx.validate_signed_for_height(height)?,
                    Self::QCash(tx) => tx.validate_signed_for_height(height)?,
                    Self::Governance(tx) => tx.validate_signed_for_height(height)?,
                }
            } else {
                match self {
                    Self::Transfer(tx) => tx.validate_stored_keys_for_height(
                        height,
                        &authorization.owner_public_key,
                        &authorization.auth_public_key,
                    )?,
                    Self::QCash(tx) => tx.validate_stored_keys_for_height(
                        height,
                        &authorization.owner_public_key,
                        &authorization.auth_public_key,
                    )?,
                    Self::Governance(tx) => tx.validate_stored_keys_for_height(
                        height,
                        &authorization.owner_public_key,
                        &authorization.auth_public_key,
                    )?,
                }
            }
            Ok(None)
        } else {
            match self {
                Self::Transfer(tx) => tx.validate_signed_for_height(height)?,
                Self::QCash(tx) => tx.validate_signed_for_height(height)?,
                Self::Governance(tx) => tx.validate_signed_for_height(height)?,
            }
            let witness = self.witness();
            Ok(Some((witness.public_key, witness.auth_public_key)))
        }
    }

    pub fn validate_envelope_for_height(
        &self,
        height: BlockHeight,
    ) -> Result<(), TransactionError> {
        self.witness().validate_shape()?;
        if self.to_bytes()?.len() > MAX_PROTOCOL_TRANSACTION_SIZE {
            return Err(TransactionError::TransactionTooLarge);
        }
        match self {
            Self::Transfer(tx) if tx.witness.carries_registration_keys() => {
                tx.validate_signed_for_height(height)
            }
            Self::QCash(tx) if tx.witness.carries_registration_keys() => {
                tx.validate_signed_for_height(height)
            }
            Self::Governance(tx) if tx.witness.carries_registration_keys() => {
                tx.validate_signed_for_height(height)
            }
            Self::Transfer(tx) => tx.transaction.validate_for_height(height),
            Self::QCash(tx) => tx.transaction.validate_for_height(height),
            Self::Governance(tx) => tx.action.validate_for_height(height),
        }
    }
}

impl From<SignedTransaction> for SignedProtocolTransaction {
    fn from(transaction: SignedTransaction) -> Self {
        Self::Transfer(Box::new(transaction))
    }
}
impl From<SignedQCashTransaction> for SignedProtocolTransaction {
    fn from(transaction: SignedQCashTransaction) -> Self {
        Self::QCash(Box::new(transaction))
    }
}
impl From<SignedGovernanceAction> for SignedProtocolTransaction {
    fn from(transaction: SignedGovernanceAction) -> Self {
        Self::Governance(Box::new(transaction))
    }
}
pub const MAX_TX_SIZE: usize = 24 * 1024;

pub type AccountNonce = Nonce;
pub type TransactionHeight = Height;

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ValidityWindow {
    pub valid_from: BlockHeight,
    pub valid_until: BlockHeight,
}

impl Default for ValidityWindow {
    fn default() -> Self {
        Self::UNBOUNDED
    }
}

impl ValidityWindow {
    pub const UNBOUNDED: Self = Self {
        valid_from: Height(0),
        valid_until: Height(u64::MAX),
    };

    pub fn new(
        valid_from: BlockHeight,
        valid_until: BlockHeight,
    ) -> Result<Self, TransactionError> {
        let window = Self {
            valid_from,
            valid_until,
        };
        window.validate()?;
        Ok(window)
    }

    pub fn validate(self) -> Result<(), TransactionError> {
        if self.valid_from.0 > self.valid_until.0 {
            return Err(TransactionError::InvalidValidityWindow);
        }
        Ok(())
    }

    pub fn validate_at(self, height: BlockHeight) -> Result<(), TransactionError> {
        self.validate()?;
        if height.0 < self.valid_from.0 {
            return Err(TransactionError::NotYetValid);
        }
        if height.0 > self.valid_until.0 {
            return Err(TransactionError::ValidityExpired);
        }
        Ok(())
    }
}

const TRANSACTION_SIGNATURE_DOMAIN: &[u8] = b"PAQUS_SHARKSPHERE_TX_V1";

#[derive(BorshSerialize)]
struct TransactionSigningContext {
    chain_id: u32,
    protocol_version: u8,
    genesis_hash: [u8; crate::crypto::HASH_SIZE],
    payload: Vec<u8>,
}

pub(crate) fn chain_bound_signing_bytes(
    domain: &[u8],
    payload: Vec<u8>,
) -> Result<Vec<u8>, crate::error::CodecError> {
    let context = TransactionSigningContext {
        chain_id: CURRENT_CHAIN_PARAMS.chain_id,
        protocol_version: CURRENT_CHAIN_PARAMS.protocol_version,
        genesis_hash: CURRENT_CHAIN_PARAMS.genesis.hash,
        payload,
    };
    let context_bytes = crate::codec::canonical_bytes(&context)?;
    let mut bytes = Vec::with_capacity(domain.len() + context_bytes.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&context_bytes);
    Ok(bytes)
}
pub const TRANSACTION_VERSION: u8 = 1;
pub const MAX_BATCH_OUTPUTS: usize = 64;

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransferOutput {
    pub to: Address,
    pub amount: Amount,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Transaction {
    pub version: u8,
    pub from: Address,
    pub outputs: Vec<TransferOutput>,
    pub fee: Amount,
    pub nonce: AccountNonce,
    pub timestamp: u64,
    pub validity: ValidityWindow,
    pub credential_uses: Vec<GovernanceCredentialUse>,
}

impl Transaction {
    pub fn new(
        from: Address,
        outputs: Vec<TransferOutput>,
        fee: Amount,
        nonce: AccountNonce,
    ) -> Self {
        Self::new_at(from, outputs, fee, nonce, 0)
    }

    pub fn new_at(
        from: Address,
        outputs: Vec<TransferOutput>,
        fee: Amount,
        nonce: AccountNonce,
        timestamp: u64,
    ) -> Self {
        Self {
            version: TRANSACTION_VERSION,
            from,
            outputs,
            fee,
            nonce,
            timestamp,
            validity: ValidityWindow::UNBOUNDED,
            credential_uses: Vec::new(),
        }
    }

    pub fn with_validity_window(mut self, validity: ValidityWindow) -> Self {
        self.validity = validity;
        self
    }

    pub fn outputs(&self) -> impl Iterator<Item = TransferOutput> + '_ {
        self.outputs.iter().copied()
    }

    pub fn total_amount(&self) -> Result<Amount, TransactionError> {
        self.outputs()
            .try_fold(0_u64, |total, output| total.checked_add(output.amount.0))
            .map(Amount)
            .ok_or(TransactionError::AmountOverflow)
    }

    pub fn validate(&self) -> Result<(), TransactionError> {
        if self.version != TRANSACTION_VERSION {
            return Err(TransactionError::UnsupportedVersion);
        }
        if self.outputs.is_empty() {
            return Err(TransactionError::EmptyOutputs);
        }
        if self.outputs.len() > MAX_BATCH_OUTPUTS {
            return Err(TransactionError::TooManyOutputs);
        }
        let mut recipients = std::collections::BTreeSet::new();
        for output in self.outputs() {
            if output.amount.0 == 0 {
                return Err(TransactionError::ZeroAmount);
            }
            if output.to == self.from {
                return Err(TransactionError::SameSenderAndRecipient);
            }
            if !recipients.insert(output.to) {
                return Err(TransactionError::DuplicateRecipient);
            }
        }
        self.total_amount()?;
        self.validity.validate()?;
        validate_attached_credentials(&self.credential_uses, self.from)
    }

    pub fn validate_for_height(
        &self,
        height: crate::block::BlockHeight,
    ) -> Result<(), TransactionError> {
        self.validate()?;
        self.validity.validate_at(height)
    }

    /// Validates structure while accepting a caller timestamp for API symmetry.
    ///
    /// Transfer transaction time validity is height-based through
    /// `ValidityWindow`; `timestamp` is signed metadata and is not a mempool
    /// or consensus clock bound here.
    pub fn validate_at(&self, _now: u64) -> Result<(), TransactionError> {
        self.validate()
    }

    /// Validates structure at a block height. The timestamp parameter is kept
    /// for call-site symmetry with block-level validation; transfer validity is
    /// height-based.
    pub fn validate_at_height(
        &self,
        _now: u64,
        height: crate::block::BlockHeight,
    ) -> Result<(), TransactionError> {
        self.validate_for_height(height)
    }

    pub fn hash(&self) -> Result<TransactionHash, crate::error::CodecError> {
        transaction_hash(self)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::CodecError> {
        transaction_bytes(self)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, crate::error::CodecError> {
        chain_bound_signing_bytes(TRANSACTION_SIGNATURE_DOMAIN, self.to_bytes()?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Witness {
    pub public_key: PublicKey,
    pub auth_public_key: PublicKey,
    pub signature: Signature,
    pub auth_signature: Signature,
}

impl Witness {
    const REGISTER_KEYS_TAG: u8 = 0;
    const STORED_KEYS_TAG: u8 = 1;

    pub fn new(public_key: PublicKey, signature: Signature) -> Self {
        Self {
            public_key,
            auth_public_key: PublicKey([0; crate::crypto::PUBLIC_KEY_SIZE]),
            signature,
            auth_signature: Signature([0; crate::crypto::SIGNATURE_SIZE]),
        }
    }

    pub fn new_authorized(
        public_key: PublicKey,
        signature: Signature,
        auth_public_key: PublicKey,
        auth_signature: Signature,
    ) -> Self {
        Self {
            public_key,
            auth_public_key,
            signature,
            auth_signature,
        }
    }

    pub fn new_stored(signature: Signature, auth_signature: Signature) -> Self {
        Self {
            public_key: PublicKey([0; crate::crypto::PUBLIC_KEY_SIZE]),
            auth_public_key: PublicKey([0; crate::crypto::PUBLIC_KEY_SIZE]),
            signature,
            auth_signature,
        }
    }

    pub fn carries_registration_keys(&self) -> bool {
        let owner = self.public_key.0.iter().any(|byte| *byte != 0);
        let auth = self.auth_public_key.0.iter().any(|byte| *byte != 0);
        owner && auth
    }

    pub fn uses_stored_keys(&self) -> bool {
        self.public_key.0.iter().all(|byte| *byte == 0)
            && self.auth_public_key.0.iter().all(|byte| *byte == 0)
    }

    pub fn validate_shape(&self) -> Result<(), TransactionError> {
        if !self.carries_registration_keys() && !self.uses_stored_keys() {
            return Err(TransactionError::EmptyPublicKey);
        }
        if self.signature.0.iter().all(|byte| *byte == 0) {
            return Err(TransactionError::EmptySignature);
        }
        if self.auth_signature.0.iter().all(|byte| *byte == 0) {
            return Err(TransactionError::EmptyAuthorizationSignature);
        }
        Ok(())
    }
}

impl BorshSerialize for Witness {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        if self.carries_registration_keys() {
            Self::REGISTER_KEYS_TAG.serialize(writer)?;
            self.public_key.serialize(writer)?;
            self.auth_public_key.serialize(writer)?;
        } else if self.uses_stored_keys() {
            Self::STORED_KEYS_TAG.serialize(writer)?;
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "witness must carry both public keys or neither",
            ));
        }
        self.signature.serialize(writer)?;
        self.auth_signature.serialize(writer)
    }
}

impl BorshDeserialize for Witness {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let tag = u8::deserialize_reader(reader)?;
        let (public_key, auth_public_key) = match tag {
            Self::REGISTER_KEYS_TAG => (
                PublicKey::deserialize_reader(reader)?,
                PublicKey::deserialize_reader(reader)?,
            ),
            Self::STORED_KEYS_TAG => (
                PublicKey([0; crate::crypto::PUBLIC_KEY_SIZE]),
                PublicKey([0; crate::crypto::PUBLIC_KEY_SIZE]),
            ),
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unsupported witness key mode",
                ));
            }
        };
        Ok(Self {
            public_key,
            auth_public_key,
            signature: Signature::deserialize_reader(reader)?,
            auth_signature: Signature::deserialize_reader(reader)?,
        })
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignedTransaction {
    pub transaction: Transaction,
    pub witness: Witness,
}

impl SignedTransaction {
    pub fn new(transaction: Transaction, public_key: PublicKey, signature: Signature) -> Self {
        Self {
            transaction,
            witness: Witness::new(public_key, signature),
        }
    }

    pub fn new_authorized(
        transaction: Transaction,
        public_key: PublicKey,
        signature: Signature,
        auth_public_key: PublicKey,
        auth_signature: Signature,
    ) -> Self {
        Self {
            transaction,
            witness: Witness::new_authorized(
                public_key,
                signature,
                auth_public_key,
                auth_signature,
            ),
        }
    }

    pub fn new_stored_authorized(
        transaction: Transaction,
        signature: Signature,
        auth_signature: Signature,
    ) -> Self {
        Self {
            transaction,
            witness: Witness::new_stored(signature, auth_signature),
        }
    }

    pub fn validate(&self) -> Result<(), TransactionError> {
        self.transaction.validate()?;
        self.validate_witness_and_size()
    }

    pub fn validate_for_height(
        &self,
        height: crate::block::BlockHeight,
    ) -> Result<(), TransactionError> {
        self.transaction.validate_for_height(height)?;
        self.validate_witness_and_size()
    }

    pub fn validate_at(&self, now: u64) -> Result<(), TransactionError> {
        self.validate_at_height(now, crate::block::Height(0))
    }

    pub fn validate_at_height(
        &self,
        now: u64,
        height: crate::block::BlockHeight,
    ) -> Result<(), TransactionError> {
        self.transaction.validate_at_height(now, height)?;
        self.validate_witness_and_size()
    }

    fn validate_witness_and_size(&self) -> Result<(), TransactionError> {
        if self.serialized_size()? > MAX_TX_SIZE {
            return Err(TransactionError::TransactionTooLarge);
        }
        // Cheap sentinel checks only; full key/signature validity is enforced
        // by `verify_signature`.
        if !self.witness.carries_registration_keys() && !self.witness.uses_stored_keys() {
            return Err(TransactionError::EmptyPublicKey);
        }
        if self.witness.signature.0.iter().all(|byte| *byte == 0) {
            return Err(TransactionError::EmptySignature);
        }
        if self.witness.auth_signature.0.iter().all(|byte| *byte == 0) {
            return Err(TransactionError::EmptyAuthorizationSignature);
        }
        Ok(())
    }

    pub fn verify_signature(&self) -> Result<(), TransactionError> {
        let payload_bytes = self.transaction.signing_bytes()?;

        if verify(
            &self.witness.public_key,
            &payload_bytes,
            &self.witness.signature,
        ) {
            Ok(())
        } else {
            Err(TransactionError::InvalidSignature)
        }
    }

    pub fn verify_authorization(
        &self,
        auth_public_key: &PublicKey,
    ) -> Result<(), TransactionError> {
        let payload_bytes = self.transaction.signing_bytes()?;
        if verify(
            auth_public_key,
            &payload_bytes,
            &self.witness.auth_signature,
        ) {
            Ok(())
        } else {
            Err(TransactionError::InvalidAuthorizationSignature)
        }
    }

    pub fn sender_address(&self, auth_public_key: &PublicKey) -> Address {
        dual_address_from_public_keys(&self.witness.public_key, auth_public_key)
    }

    fn validate_dual_authorization(&self) -> Result<(), TransactionError> {
        if !self.witness.carries_registration_keys() {
            return Err(TransactionError::EmptyPublicKey);
        }
        if self.sender_address(&self.witness.auth_public_key) != self.transaction.from {
            return Err(TransactionError::SenderAddressMismatch);
        }
        let payload = self.transaction.signing_bytes()?;
        let (owner_valid, auth_valid) = crate::crypto::verify_dual_parallel(
            &self.witness.public_key,
            &self.witness.auth_public_key,
            &payload,
            &self.witness.signature,
            &self.witness.auth_signature,
        );
        if !owner_valid {
            return Err(TransactionError::InvalidSignature);
        }
        if !auth_valid {
            return Err(TransactionError::InvalidAuthorizationSignature);
        }
        Ok(())
    }

    pub fn validate_signed(&self) -> Result<(), TransactionError> {
        self.validate()?;
        self.validate_dual_authorization()
    }

    pub fn validate_signed_for_height(
        &self,
        height: crate::block::BlockHeight,
    ) -> Result<(), TransactionError> {
        self.validate_for_height(height)?;

        self.validate_dual_authorization()
    }

    pub fn validate_stored_keys_for_height(
        &self,
        height: crate::block::BlockHeight,
        owner_public_key: &PublicKey,
        auth_public_key: &PublicKey,
    ) -> Result<(), TransactionError> {
        self.validate_for_height(height)?;
        self.validate_witness_and_size()?;
        if !self.witness.uses_stored_keys() {
            return Err(TransactionError::InvalidAuthorizationSignature);
        }
        let payload_bytes = self.transaction.signing_bytes()?;
        let (owner_valid, auth_valid) = crate::crypto::verify_dual_parallel(
            owner_public_key,
            auth_public_key,
            &payload_bytes,
            &self.witness.signature,
            &self.witness.auth_signature,
        );
        if !owner_valid {
            return Err(TransactionError::InvalidSignature);
        }
        if !auth_valid {
            return Err(TransactionError::InvalidAuthorizationSignature);
        }
        Ok(())
    }

    pub fn validate_signed_at(&self, now: u64) -> Result<(), TransactionError> {
        self.validate_signed_at_height(now, crate::block::Height(0))
    }

    pub fn validate_signed_at_height(
        &self,
        now: u64,
        height: crate::block::BlockHeight,
    ) -> Result<(), TransactionError> {
        self.validate_at_height(now, height)?;

        self.validate_dual_authorization()
    }

    pub fn hash(&self) -> Result<TransactionHash, crate::error::CodecError> {
        self.txid()
    }

    pub fn txid(&self) -> Result<TransactionHash, crate::error::CodecError> {
        self.transaction.hash()
    }

    pub fn wtxid(&self) -> Result<WitnessTransactionHash, crate::error::CodecError> {
        SignedProtocolTransaction::from(self.clone()).wtxid()
    }

    pub fn stripped_size(&self) -> Result<usize, crate::error::CodecError> {
        Ok(self.transaction.to_bytes()?.len())
    }

    pub fn witness_size(&self) -> Result<usize, crate::error::CodecError> {
        Ok(self
            .serialized_size()?
            .saturating_sub(self.stripped_size()?))
    }

    pub fn weight(&self) -> Result<usize, crate::error::CodecError> {
        Ok(self
            .stripped_size()?
            .saturating_mul(crate::block::WITNESS_SCALE_FACTOR)
            .saturating_add(self.witness_size()?))
    }

    pub fn virtual_size(&self) -> Result<usize, crate::error::CodecError> {
        Ok(self
            .weight()?
            .saturating_add(crate::block::WITNESS_SCALE_FACTOR - 1)
            / crate::block::WITNESS_SCALE_FACTOR)
    }

    pub fn transaction_hash(&self) -> Result<TransactionHash, crate::error::CodecError> {
        self.txid()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::CodecError> {
        signed_transaction_bytes(self)
    }

    pub fn serialized_size(&self) -> Result<usize, crate::error::CodecError> {
        Ok(self.to_bytes()?.len())
    }
}

#[cfg(test)]
mod transfer_output_tests {
    use super::*;

    fn output(byte: u8) -> TransferOutput {
        TransferOutput {
            to: Address([byte; crate::crypto::ADDRESS_SIZE]),
            amount: Amount(1),
        }
    }

    #[test]
    fn transfer_requires_between_one_and_max_outputs() {
        let sender = Address([0xff; crate::crypto::ADDRESS_SIZE]);
        assert_eq!(
            Transaction::new(sender, Vec::new(), Amount(0), Nonce(0)).validate(),
            Err(TransactionError::EmptyOutputs)
        );
        assert_eq!(
            Transaction::new(sender, vec![output(1)], Amount(0), Nonce(0)).validate(),
            Ok(())
        );
        assert_eq!(
            Transaction::new(
                sender,
                (1..=MAX_BATCH_OUTPUTS + 1)
                    .map(|index| output(index as u8))
                    .collect(),
                Amount(0),
                Nonce(0),
            )
            .validate(),
            Err(TransactionError::TooManyOutputs)
        );
    }
}
