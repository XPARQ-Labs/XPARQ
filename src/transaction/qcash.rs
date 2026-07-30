use super::{AccountNonce, ValidityWindow, Witness, chain_bound_signing_bytes};
use crate::block::BlockHeight;
use crate::codec::canonical_bytes;
use crate::consensus::supply::Amount;
use crate::crypto::{
    Address, HashDomain, PublicKey, Signature, TransactionHash, domain_hash,
    dual_address_from_public_keys, verify,
};
use crate::error::TransactionError;
use crate::governance::{GovernanceCredentialUse, validate_attached_credentials};
use crate::qcash::{QCashCoinFile, QCashDepositMetadata, QCashError, QCashWithdrawMetadata};
use borsh::{BorshDeserialize, BorshSerialize};

pub const QCASH_TRANSACTION_VERSION: u8 = 1;
/// QCash carries one or more post-quantum coin authorizations in addition to
/// the transaction witness, so it needs a dedicated bounded envelope.
pub const MAX_QCASH_TX_SIZE: usize = 64 * 1024;
const QCASH_SIGNATURE_DOMAIN: &[u8] = b"PAQUS_SHARKSPHERE_QCASH_TX_V1";

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum QCashTransactionKind {
    Withdraw {
        amount: Amount,
        metadata: QCashWithdrawMetadata,
    },
    Deposit {
        recipient: Address,
        metadata: QCashDepositMetadata,
    },
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct QCashTransaction {
    pub version: u8,
    pub signer: Address,
    pub fee: Amount,
    pub nonce: AccountNonce,
    pub timestamp: u64,
    pub kind: QCashTransactionKind,
    pub validity: ValidityWindow,
    pub credential_uses: Vec<GovernanceCredentialUse>,
}

#[derive(BorshSerialize)]
struct DepositTransactionCommitmentInput {
    version: u8,
    coin_id: [u8; 32],
    denomination: crate::qcash::QCashDenomination,
    spend_public_key: PublicKey,
}

#[derive(BorshSerialize)]
struct DepositTransactionCommitmentPayload {
    version: u8,
    signer: Address,
    recipient: Address,
    fee: Amount,
    nonce: AccountNonce,
    timestamp: u64,
    validity: ValidityWindow,
    inputs: Vec<DepositTransactionCommitmentInput>,
}

impl QCashTransaction {
    pub fn withdraw(
        signer: Address,
        amount: Amount,
        fee: Amount,
        nonce: AccountNonce,
        metadata: QCashWithdrawMetadata,
    ) -> Self {
        Self {
            version: QCASH_TRANSACTION_VERSION,
            signer,
            fee,
            nonce,
            timestamp: 0,
            kind: QCashTransactionKind::Withdraw { amount, metadata },
            validity: ValidityWindow::UNBOUNDED,
            credential_uses: Vec::new(),
        }
    }

    pub fn deposit(
        signer: Address,
        recipient: Address,
        fee: Amount,
        nonce: AccountNonce,
        metadata: QCashDepositMetadata,
    ) -> Self {
        Self {
            version: QCASH_TRANSACTION_VERSION,
            signer,
            fee,
            nonce,
            timestamp: 0,
            kind: QCashTransactionKind::Deposit {
                recipient,
                metadata,
            },
            validity: ValidityWindow::UNBOUNDED,
            credential_uses: Vec::new(),
        }
    }

    pub fn deposit_from_files(
        signer: Address,
        recipient: Address,
        fee: Amount,
        nonce: AccountNonce,
        files: &[QCashCoinFile],
    ) -> Result<Self, QCashError> {
        Self::deposit_from_files_at(signer, recipient, fee, nonce, 0, files)
    }

    pub fn deposit_from_files_at(
        signer: Address,
        recipient: Address,
        fee: Amount,
        nonce: AccountNonce,
        timestamp: u64,
        files: &[QCashCoinFile],
    ) -> Result<Self, QCashError> {
        let placeholder_inputs = files
            .iter()
            .map(|file| file.deposit_input_for_transaction(recipient, [0; 32]))
            .collect::<Result<Vec<_>, _>>()?;
        let mut transaction = Self::deposit(
            signer,
            recipient,
            fee,
            nonce,
            QCashDepositMetadata::from_inputs(placeholder_inputs)?,
        )
        .with_timestamp(timestamp);
        let commitment = transaction
            .deposit_transaction_commitment()
            .map_err(|_| QCashError::Serialization)?
            .ok_or(QCashError::InvalidCommitment)?;
        transaction.kind = QCashTransactionKind::Deposit {
            recipient,
            metadata: QCashDepositMetadata::new_for_transaction(files, recipient, commitment)?,
        };
        Ok(transaction)
    }

    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }
    pub fn with_validity_window(mut self, validity: ValidityWindow) -> Self {
        self.validity = validity;
        self
    }

    pub fn validate(&self) -> Result<(), TransactionError> {
        if self.version != QCASH_TRANSACTION_VERSION {
            return Err(TransactionError::UnsupportedVersion);
        }
        match &self.kind {
            QCashTransactionKind::Withdraw { amount, metadata } => {
                if amount.0 == 0 {
                    return Err(TransactionError::ZeroAmount);
                }
                metadata
                    .validate_amount(*amount)
                    .map_err(|_| TransactionError::InvalidQCashMetadata)?;
            }
            QCashTransactionKind::Deposit {
                recipient,
                metadata,
            } => {
                metadata
                    .validate_authorizations_for_transaction(
                        *recipient,
                        self.deposit_transaction_commitment()?
                            .ok_or(TransactionError::InvalidQCashMetadata)?,
                    )
                    .map_err(|_| TransactionError::InvalidQCashMetadata)?;
                if *recipient == Address([0; 20]) {
                    return Err(TransactionError::InvalidQCashRecipient);
                }
            }
        }
        self.validity.validate()?;
        validate_attached_credentials(&self.credential_uses, self.signer)
    }

    pub fn validate_for_height(&self, height: BlockHeight) -> Result<(), TransactionError> {
        self.validate()?;
        self.validity.validate_at(height)
    }

    pub fn amount(&self) -> Result<Amount, TransactionError> {
        match &self.kind {
            QCashTransactionKind::Withdraw { amount, .. } => Ok(*amount),
            QCashTransactionKind::Deposit { metadata, .. } => metadata
                .amount()
                .map_err(|_| TransactionError::InvalidQCashMetadata),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::CodecError> {
        canonical_bytes(self)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, crate::error::CodecError> {
        chain_bound_signing_bytes(QCASH_SIGNATURE_DOMAIN, self.to_bytes()?)
    }

    pub fn hash(&self) -> Result<TransactionHash, crate::error::CodecError> {
        Ok(TransactionHash(
            domain_hash(HashDomain::Transaction, &self.to_bytes()?).0,
        ))
    }

    pub fn deposit_transaction_commitment(
        &self,
    ) -> Result<Option<[u8; 32]>, crate::error::CodecError> {
        let QCashTransactionKind::Deposit {
            recipient,
            metadata,
        } = &self.kind
        else {
            return Ok(None);
        };
        let payload = DepositTransactionCommitmentPayload {
            version: self.version,
            signer: self.signer,
            recipient: *recipient,
            fee: self.fee,
            nonce: self.nonce,
            timestamp: self.timestamp,
            validity: self.validity,
            inputs: metadata
                .inputs
                .iter()
                .map(|input| DepositTransactionCommitmentInput {
                    version: input.version,
                    coin_id: input.coin_id,
                    denomination: input.denomination,
                    spend_public_key: input.spend_public_key,
                })
                .collect(),
        };
        Ok(Some(
            domain_hash(
                HashDomain::QCashDepositTransaction,
                &canonical_bytes(&payload)?,
            )
            .0,
        ))
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignedQCashTransaction {
    pub transaction: QCashTransaction,
    pub witness: Witness,
}

impl SignedQCashTransaction {
    pub fn new(transaction: QCashTransaction, public_key: PublicKey, signature: Signature) -> Self {
        Self {
            transaction,
            witness: Witness::new(public_key, signature),
        }
    }

    pub fn new_authorized(
        transaction: QCashTransaction,
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
        transaction: QCashTransaction,
        signature: Signature,
        auth_signature: Signature,
    ) -> Self {
        Self {
            transaction,
            witness: Witness::new_stored(signature, auth_signature),
        }
    }

    pub fn validate_signed(&self) -> Result<(), TransactionError> {
        self.transaction.validate()?;
        if self.to_bytes()?.len() > MAX_QCASH_TX_SIZE {
            return Err(TransactionError::TransactionTooLarge);
        }
        if self.witness.public_key.0.iter().all(|byte| *byte == 0) {
            return Err(TransactionError::EmptyPublicKey);
        }
        if self.witness.signature.0.iter().all(|byte| *byte == 0) {
            return Err(TransactionError::EmptySignature);
        }
        if self.witness.auth_signature.0.iter().all(|byte| *byte == 0) {
            return Err(TransactionError::EmptyAuthorizationSignature);
        }
        if dual_address_from_public_keys(&self.witness.public_key, &self.witness.auth_public_key)
            != self.transaction.signer
        {
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

    pub fn validate_stored_keys_for_height(
        &self,
        height: crate::block::BlockHeight,
        owner_public_key: &PublicKey,
        auth_public_key: &PublicKey,
    ) -> Result<(), TransactionError> {
        self.transaction.validate_for_height(height)?;
        if self.to_bytes()?.len() > MAX_QCASH_TX_SIZE {
            return Err(TransactionError::TransactionTooLarge);
        }
        if !self.witness.uses_stored_keys() {
            return Err(TransactionError::InvalidAuthorizationSignature);
        }
        if self.witness.signature.0.iter().all(|byte| *byte == 0) {
            return Err(TransactionError::EmptySignature);
        }
        if self.witness.auth_signature.0.iter().all(|byte| *byte == 0) {
            return Err(TransactionError::EmptyAuthorizationSignature);
        }
        let payload = self.transaction.signing_bytes()?;
        let (owner_valid, auth_valid) = crate::crypto::verify_dual_parallel(
            owner_public_key,
            auth_public_key,
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

    pub fn verify_authorization(
        &self,
        auth_public_key: &PublicKey,
    ) -> Result<(), TransactionError> {
        if verify(
            auth_public_key,
            &self.transaction.signing_bytes()?,
            &self.witness.auth_signature,
        ) {
            Ok(())
        } else {
            Err(TransactionError::InvalidAuthorizationSignature)
        }
    }

    pub fn validate_signed_for_height(&self, height: BlockHeight) -> Result<(), TransactionError> {
        self.validate_signed()?;
        self.transaction.validity.validate_at(height)
    }

    pub fn hash(&self) -> Result<TransactionHash, crate::error::CodecError> {
        self.transaction.hash()
    }

    pub fn wtxid(&self) -> Result<crate::crypto::WitnessTransactionHash, crate::error::CodecError> {
        super::SignedProtocolTransaction::from(self.clone()).wtxid()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::CodecError> {
        canonical_bytes(self)
    }
}
