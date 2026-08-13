use crate::block::{BlockHeight, Height};
use crate::codec::{signed_transaction_bytes, transaction_bytes, transaction_hash};
use crate::consensus::supply::Amount;
use crate::crypto::{Address, PublicKey, Signature};
use crate::crypto::{Hash, HashDomain, TransactionHash, domain_hash};
use crate::crypto::{address_from_public_key, verify};
pub use crate::error::TransactionError;
use crate::genesis::CURRENT_CHAIN_PARAMS;
use crate::state::XpqCoinId;
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

const TRANSACTION_SIGNATURE_DOMAIN: &[u8] = b"XPARQ_SHARKSPHERE_TX_V1";

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
        genesis_hash: crate::genesis::genesis_hash_for_chain(CURRENT_CHAIN_PARAMS)?.0,
        payload,
    };
    let context_bytes = crate::codec::canonical_bytes(&context)?;
    let mut bytes = Vec::with_capacity(domain.len() + context_bytes.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&context_bytes);
    Ok(bytes)
}
pub const TRANSACTION_VERSION: u8 = 1;

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

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct TransferOutput {
    pub to: OutputTarget,
    pub amount: Amount,
}

impl TransferOutput {
    pub fn new(to: impl Into<OutputTarget>, amount: Amount) -> Self {
        Self {
            to: to.into(),
            amount,
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Transfer {
    pub version: u8,
    pub from: Address,
    pub inputs: Vec<XpqCoinId>,
    pub outputs: Vec<TransferOutput>,
    pub validity: ValidityWindow,
}

impl Transfer {
    pub fn new(
        from: Address,
        inputs: Vec<XpqCoinId>,
        to: impl Into<OutputTarget>,
        amount: Amount,
    ) -> Self {
        Self {
            version: TRANSACTION_VERSION,
            from,
            inputs,
            outputs: vec![TransferOutput::new(to, amount)],
            validity: ValidityWindow::UNBOUNDED,
        }
    }

    pub fn from_outputs(
        from: Address,
        inputs: Vec<XpqCoinId>,
        outputs: Vec<TransferOutput>,
    ) -> Self {
        Self {
            version: TRANSACTION_VERSION,
            from,
            inputs,
            outputs,
            validity: ValidityWindow::UNBOUNDED,
        }
    }

    pub fn with_output(mut self, output: TransferOutput) -> Self {
        self.outputs.push(output);
        self
    }

    pub fn with_validity_window(mut self, validity: ValidityWindow) -> Self {
        self.validity = validity;
        self
    }

    pub fn validate(&self) -> Result<(), TransactionError> {
        if self.version != TRANSACTION_VERSION {
            return Err(TransactionError::UnsupportedVersion);
        }
        if self.inputs.is_empty() {
            return Err(TransactionError::EmptyInputs);
        }
        if self.outputs.is_empty() {
            return Err(TransactionError::EmptyOutputs);
        }
        if self.outputs.iter().any(|output| output.amount.0 == 0) {
            return Err(TransactionError::ZeroAmount);
        }
        let mut inputs = std::collections::BTreeSet::new();
        if self.inputs.iter().any(|input| !inputs.insert(*input)) {
            return Err(TransactionError::DuplicateInput);
        }
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
    pub signature: Signature,
}

impl AuthorizationProof {
    const REGISTER_KEYS_TAG: u8 = 0;
    const STORED_KEYS_TAG: u8 = 1;

    pub fn new(public_key: PublicKey, signature: Signature) -> Self {
        Self {
            public_key,
            signature,
        }
    }

    pub fn new_stored(signature: Signature) -> Self {
        Self {
            public_key: PublicKey([0; crate::crypto::PUBLIC_KEY_SIZE]),
            signature,
        }
    }

    pub fn carries_registration_keys(&self) -> bool {
        self.public_key.0.iter().any(|byte| *byte != 0)
    }

    pub fn uses_stored_keys(&self) -> bool {
        self.public_key.0.iter().all(|byte| *byte == 0)
    }

    pub fn validate_shape(&self) -> Result<(), TransactionError> {
        if !self.carries_registration_keys() && !self.uses_stored_keys() {
            return Err(TransactionError::EmptyPublicKey);
        }
        if self.signature.0.iter().all(|byte| *byte == 0) {
            return Err(TransactionError::EmptySignature);
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
        } else if self.uses_stored_keys() {
            Self::STORED_KEYS_TAG.serialize(writer)?;
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "authorization proof must carry one public key or use the stored key",
            ));
        }
        self.signature.serialize(writer)
    }
}

impl BorshDeserialize for AuthorizationProof {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let tag = u8::deserialize_reader(reader)?;
        let public_key = match tag {
            Self::REGISTER_KEYS_TAG => PublicKey::deserialize_reader(reader)?,
            Self::STORED_KEYS_TAG => PublicKey([0; crate::crypto::PUBLIC_KEY_SIZE]),
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unsupported authorization_proof key mode",
                ));
            }
        };
        Ok(Self {
            public_key,
            signature: Signature::deserialize_reader(reader)?,
        })
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignedTransfer {
    pub transaction: Transfer,
    pub authorization_proof: AuthorizationProof,
}

impl SignedTransfer {
    pub fn new(transaction: Transfer, public_key: PublicKey, signature: Signature) -> Self {
        Self {
            transaction,
            authorization_proof: AuthorizationProof::new(public_key, signature),
        }
    }

    pub fn new_stored(transaction: Transfer, signature: Signature) -> Self {
        Self {
            transaction,
            authorization_proof: AuthorizationProof::new_stored(signature),
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

    pub fn sender_address(&self) -> Address {
        address_from_public_key(&self.authorization_proof.public_key)
    }

    fn validate_registration_signature_at_height(
        &self,
        _height: crate::block::BlockHeight,
    ) -> Result<(), TransactionError> {
        if !self.authorization_proof.carries_registration_keys() {
            return Err(TransactionError::EmptyPublicKey);
        }
        if self.sender_address() != self.transaction.from {
            return Err(TransactionError::SenderAddressMismatch);
        }
        let payload = self.transaction.signing_bytes()?;
        if !verify(
            &self.authorization_proof.public_key,
            &payload,
            &self.authorization_proof.signature,
        ) {
            return Err(TransactionError::InvalidSignature);
        }
        Ok(())
    }

    pub fn validate_signed(&self) -> Result<(), TransactionError> {
        self.validate()?;
        self.validate_registration_signature_at_height(crate::block::Height(0))
    }

    pub fn validate_signed_for_height(
        &self,
        height: crate::block::BlockHeight,
    ) -> Result<(), TransactionError> {
        self.validate_for_height(height)?;

        self.validate_registration_signature_at_height(height)
    }

    pub fn validate_stored_keys_for_height(
        &self,
        height: crate::block::BlockHeight,
        public_key: &PublicKey,
    ) -> Result<(), TransactionError> {
        self.validate_for_height(height)?;
        self.validate_authorization_proof_and_size()?;
        if !self.authorization_proof.uses_stored_keys() {
            return Err(TransactionError::InvalidAuthorizationProofEncoding);
        }
        let payload_bytes = self.transaction.signing_bytes()?;
        if !verify(
            public_key,
            &payload_bytes,
            &self.authorization_proof.signature,
        ) {
            return Err(TransactionError::InvalidSignature);
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
mod transfer_tests {
    use super::*;

    #[test]
    fn stored_authorized_single_transfer_size_is_explicit() {
        let transaction = Transfer::new(
            Address([0xff; crate::crypto::ADDRESS_SIZE]),
            vec![XpqCoinId([7; crate::crypto::HASH_SIZE])],
            Address([1; crate::crypto::ADDRESS_SIZE]),
            Amount(1),
        );
        let signed =
            SignedTransfer::new_stored(transaction, Signature([1; crate::crypto::SIGNATURE_SIZE]));

        assert!(signed.stripped_size().unwrap() > 74);
        assert_eq!(
            signed.authorization_proof_size().unwrap(),
            1 + crate::crypto::SIGNATURE_SIZE
        );
        assert!(signed.serialized_size().unwrap() > signed.stripped_size().unwrap());
    }

    #[test]
    fn transfer_requires_inputs_outputs_and_positive_amount() {
        let sender = Address([0xff; crate::crypto::ADDRESS_SIZE]);
        assert_eq!(
            Transfer::new(
                sender,
                vec![XpqCoinId([1; crate::crypto::HASH_SIZE])],
                Address([1; crate::crypto::ADDRESS_SIZE]),
                Amount(0),
            )
            .validate(),
            Err(TransactionError::ZeroAmount)
        );
        assert_eq!(
            Transfer::new(
                sender,
                vec![XpqCoinId([1; crate::crypto::HASH_SIZE])],
                Address([1; crate::crypto::ADDRESS_SIZE]),
                Amount(1),
            )
            .validate(),
            Ok(())
        );
        assert_eq!(
            Transfer::new(
                sender,
                vec![XpqCoinId([1; crate::crypto::HASH_SIZE])],
                sender,
                Amount(1),
            )
            .validate(),
            Ok(())
        );
    }

    #[test]
    fn authorization_proof_hash_is_bound_to_transaction_hash() {
        let proof = AuthorizationProof::new(
            PublicKey([1; crate::crypto::PUBLIC_KEY_SIZE]),
            Signature([2; crate::crypto::SIGNATURE_SIZE]),
        );
        let other_proof = AuthorizationProof::new(
            PublicKey([1; crate::crypto::PUBLIC_KEY_SIZE]),
            Signature([5; crate::crypto::SIGNATURE_SIZE]),
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
