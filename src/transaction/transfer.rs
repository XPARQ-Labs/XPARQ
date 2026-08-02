use crate::block::{BlockHeight, Height};
use crate::codec::{signed_transaction_bytes, transaction_bytes, transaction_hash};
use crate::consensus::supply::Amount;
use crate::crypto::{Address, PublicKey, Signature};
use crate::crypto::{Hash, HashDomain, TransactionHash, domain_hash};
use crate::crypto::{dual_address_from_public_keys, verify};
pub use crate::error::TransactionError;
use crate::genesis::CURRENT_CHAIN_PARAMS;
use borsh::{BorshDeserialize, BorshSerialize};

pub const MAX_TX_SIZE: usize = 24 * 1024;

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

#[derive(
    BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub enum OutputTarget {
    Address(Address),
    BlockMiner,
}

impl OutputTarget {
    pub fn address(self) -> Option<Address> {
        match self {
            Self::Address(address) => Some(address),
            Self::BlockMiner => None,
        }
    }
}

impl From<Address> for OutputTarget {
    fn from(address: Address) -> Self {
        Self::Address(address)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransferOutput {
    pub to: OutputTarget,
    pub amount: Amount,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Transaction {
    pub version: u8,
    pub from: Address,
    pub outputs: Vec<TransferOutput>,
    pub last_state: Hash,
    pub validity: ValidityWindow,
}

impl Transaction {
    pub fn new(from: Address, outputs: Vec<TransferOutput>) -> Self {
        Self {
            version: TRANSACTION_VERSION,
            from,
            outputs,
            last_state: Hash::ZERO,
            validity: ValidityWindow::UNBOUNDED,
        }
    }

    pub fn with_last_state(mut self, last_state: Hash) -> Self {
        self.last_state = last_state;
        self
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
            if output.to == OutputTarget::Address(self.from) {
                return Err(TransactionError::SameSenderAndRecipient);
            }
            if !recipients.insert(output.to) {
                return Err(TransactionError::DuplicateRecipient);
            }
        }
        self.total_amount()?;
        self.validity.validate()
    }

    pub fn validate_for_height(
        &self,
        height: crate::block::BlockHeight,
    ) -> Result<(), TransactionError> {
        self.validate()?;
        self.validity.validate_at(height)
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
pub struct AuthorizationProof {
    pub public_key: PublicKey,
    pub auth_public_key: PublicKey,
    pub signature: Signature,
    pub auth_signature: Signature,
}

impl AuthorizationProof {
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

    pub fn hash_with_transaction(
        &self,
        applied_tx_hash: Hash,
    ) -> Result<Hash, crate::error::CodecError> {
        #[derive(BorshSerialize)]
        struct AuthorizationProofHashPayload {
            applied_tx_hash: Hash,
            authorization_proof: AuthorizationProof,
        }

        let payload = AuthorizationProofHashPayload {
            applied_tx_hash,
            authorization_proof: self.clone(),
        };
        Ok(domain_hash(
            HashDomain::AuthorizationProof,
            &crate::codec::canonical_bytes(&payload)?,
        ))
    }
}

impl BorshSerialize for AuthorizationProof {
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
                "authorization_proof must carry both public keys or neither",
            ));
        }
        self.signature.serialize(writer)?;
        self.auth_signature.serialize(writer)
    }
}

impl BorshDeserialize for AuthorizationProof {
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
                    "unsupported authorization_proof key mode",
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
    pub authorization_proof: AuthorizationProof,
}

impl SignedTransaction {
    pub fn new(transaction: Transaction, public_key: PublicKey, signature: Signature) -> Self {
        Self {
            transaction,
            authorization_proof: AuthorizationProof::new(public_key, signature),
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
            authorization_proof: AuthorizationProof::new_authorized(
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
            authorization_proof: AuthorizationProof::new_stored(signature, auth_signature),
        }
    }

    pub fn validate(&self) -> Result<(), TransactionError> {
        self.transaction.validate()?;
        self.validate_authorization_proof_and_size()
    }

    pub fn validate_for_height(
        &self,
        height: crate::block::BlockHeight,
    ) -> Result<(), TransactionError> {
        self.transaction.validate_for_height(height)?;
        self.validate_authorization_proof_and_size()
    }

    fn validate_authorization_proof_and_size(&self) -> Result<(), TransactionError> {
        if self.serialized_size()? > MAX_TX_SIZE {
            return Err(TransactionError::TransactionTooLarge);
        }
        // Cheap sentinel checks only; full key/signature validity is enforced
        // by `verify_signature`.
        if !self.authorization_proof.carries_registration_keys()
            && !self.authorization_proof.uses_stored_keys()
        {
            return Err(TransactionError::EmptyPublicKey);
        }
        if self
            .authorization_proof
            .signature
            .0
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(TransactionError::EmptySignature);
        }
        if self
            .authorization_proof
            .auth_signature
            .0
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(TransactionError::EmptyAuthorizationSignature);
        }
        Ok(())
    }

    pub fn verify_signature(&self) -> Result<(), TransactionError> {
        let payload_bytes = self.transaction.signing_bytes()?;

        if verify(
            &self.authorization_proof.public_key,
            &payload_bytes,
            &self.authorization_proof.signature,
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
            &self.authorization_proof.auth_signature,
        ) {
            Ok(())
        } else {
            Err(TransactionError::InvalidAuthorizationSignature)
        }
    }

    pub fn sender_address(&self, auth_public_key: &PublicKey) -> Address {
        dual_address_from_public_keys(&self.authorization_proof.public_key, auth_public_key)
    }

    fn validate_dual_authorization(&self) -> Result<(), TransactionError> {
        if !self.authorization_proof.carries_registration_keys() {
            return Err(TransactionError::EmptyPublicKey);
        }
        if self.sender_address(&self.authorization_proof.auth_public_key) != self.transaction.from {
            return Err(TransactionError::SenderAddressMismatch);
        }
        let payload = self.transaction.signing_bytes()?;
        let (owner_valid, auth_valid) = crate::crypto::verify_dual_parallel(
            &self.authorization_proof.public_key,
            &self.authorization_proof.auth_public_key,
            &payload,
            &self.authorization_proof.signature,
            &self.authorization_proof.auth_signature,
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
        self.validate_authorization_proof_and_size()?;
        if !self.authorization_proof.uses_stored_keys() {
            return Err(TransactionError::InvalidAuthorizationSignature);
        }
        let payload_bytes = self.transaction.signing_bytes()?;
        let (owner_valid, auth_valid) = crate::crypto::verify_dual_parallel(
            owner_public_key,
            auth_public_key,
            &payload_bytes,
            &self.authorization_proof.signature,
            &self.authorization_proof.auth_signature,
        );
        if !owner_valid {
            return Err(TransactionError::InvalidSignature);
        }
        if !auth_valid {
            return Err(TransactionError::InvalidAuthorizationSignature);
        }
        Ok(())
    }

    pub fn hash(&self) -> Result<TransactionHash, crate::error::CodecError> {
        self.txid()
    }

    pub fn txid(&self) -> Result<TransactionHash, crate::error::CodecError> {
        self.transaction.hash()
    }

    pub fn stripped_size(&self) -> Result<usize, crate::error::CodecError> {
        Ok(self.transaction.to_bytes()?.len())
    }

    pub fn authorization_proof_size(&self) -> Result<usize, crate::error::CodecError> {
        Ok(self
            .serialized_size()?
            .saturating_sub(self.stripped_size()?))
    }

    pub fn weight(&self) -> Result<usize, crate::error::CodecError> {
        self.serialized_size()
    }

    pub fn virtual_size(&self) -> Result<usize, crate::error::CodecError> {
        self.serialized_size()
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
            to: (Address([byte; crate::crypto::ADDRESS_SIZE])).into(),
            amount: Amount(1),
        }
    }

    #[test]
    fn stored_authorized_single_output_size_is_explicit() {
        let transaction = Transaction::new(
            Address([0xff; crate::crypto::ADDRESS_SIZE]),
            vec![output(1)],
        );
        let signed = SignedTransaction::new_stored_authorized(
            transaction,
            Signature([1; crate::crypto::SIGNATURE_SIZE]),
            Signature([2; crate::crypto::SIGNATURE_SIZE]),
        );

        assert_eq!(signed.stripped_size().unwrap(), 102);
        assert_eq!(
            signed.authorization_proof_size().unwrap(),
            1 + (2 * crate::crypto::SIGNATURE_SIZE)
        );
        assert_eq!(signed.serialized_size().unwrap(), 4_943);
    }

    #[test]
    fn transfer_requires_between_one_and_max_outputs() {
        let sender = Address([0xff; crate::crypto::ADDRESS_SIZE]);
        assert_eq!(
            Transaction::new(sender, Vec::new()).validate(),
            Err(TransactionError::EmptyOutputs)
        );
        assert_eq!(Transaction::new(sender, vec![output(1)]).validate(), Ok(()));
        assert_eq!(
            Transaction::new(
                sender,
                (1..=MAX_BATCH_OUTPUTS + 1)
                    .map(|index| output(index as u8))
                    .collect(),
            )
            .validate(),
            Err(TransactionError::TooManyOutputs)
        );
    }

    #[test]
    fn authorization_proof_hash_is_bound_to_transaction_hash() {
        let proof = AuthorizationProof::new_authorized(
            PublicKey([1; crate::crypto::PUBLIC_KEY_SIZE]),
            Signature([2; crate::crypto::SIGNATURE_SIZE]),
            PublicKey([3; crate::crypto::PUBLIC_KEY_SIZE]),
            Signature([4; crate::crypto::SIGNATURE_SIZE]),
        );
        let other_proof = AuthorizationProof::new_authorized(
            PublicKey([1; crate::crypto::PUBLIC_KEY_SIZE]),
            Signature([5; crate::crypto::SIGNATURE_SIZE]),
            PublicKey([3; crate::crypto::PUBLIC_KEY_SIZE]),
            Signature([4; crate::crypto::SIGNATURE_SIZE]),
        );

        assert_ne!(
            proof
                .hash_with_transaction(Hash([9; crate::crypto::HASH_SIZE]))
                .unwrap(),
            proof
                .hash_with_transaction(Hash([8; crate::crypto::HASH_SIZE]))
                .unwrap()
        );
        assert_ne!(
            proof
                .hash_with_transaction(Hash([9; crate::crypto::HASH_SIZE]))
                .unwrap(),
            other_proof
                .hash_with_transaction(Hash([9; crate::crypto::HASH_SIZE]))
                .unwrap()
        );
    }
}
