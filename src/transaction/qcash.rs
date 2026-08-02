use super::{AuthorizationProof, ValidityWindow, chain_bound_signing_bytes};
use crate::block::BlockHeight;
use crate::block::merkle::MerkleInclusionProof;
use crate::codec::canonical_bytes;
use crate::consensus::supply::Amount;
use crate::crypto::{
    Address, BlockHash, Hash, HashDomain, PublicKey, Signature, TransactionHash, domain_hash,
    dual_address_from_public_keys, verify,
};
use crate::error::TransactionError;
use crate::qcash::recovery::{BlockHeaderProof, RollbackProofError, verify_header_proof_chain};
use crate::qcash::{QCashCoinFile, QCashError, QCashRedeemMetadata, QCashWithdrawalMetadata};
use borsh::{BorshDeserialize, BorshSerialize};

pub const QCASH_TRANSACTION_VERSION: u8 = 1;
/// QCash carries one or more post-quantum coin authorizations in addition to
/// the transaction authorization proof, so it needs a dedicated bounded envelope.
pub const MAX_QCASH_TX_SIZE: usize = 64 * 1024;
const QCASH_SIGNATURE_DOMAIN: &[u8] = b"PAQUS_SHARKSPHERE_QCASH_TX_V1";

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum QCashTransactionKind {
    Withdraw {
        amount: Amount,
        metadata: QCashWithdrawalMetadata,
    },
    Redeem {
        recipient: Address,
        metadata: QCashRedeemMetadata,
    },
    RecoverRedeem {
        claimant: Address,
        metadata: QCashRedeemMetadata,
        orphan_tx_hash: TransactionHash,
        recovery_proof: Box<QCashRecoverRedeemProof>,
    },
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct QCashRecoverRedeemProof {
    pub orphan_redeem_tx: Box<SignedQCashTransaction>,
    pub orphan_block: BlockHeaderProof,
    pub orphan_tx_proof: MerkleInclusionProof,
    pub losing_branch: Vec<BlockHeaderProof>,
    pub canonical_branch: Vec<BlockHeaderProof>,
    pub common_ancestor: BlockHash,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct QCashTransaction {
    pub version: u8,
    pub signer: Address,
    pub last_state: Hash,
    pub kind: QCashTransactionKind,
    pub validity: ValidityWindow,
}

#[derive(BorshSerialize)]
struct RedeemTransactionCommitmentInput {
    version: u8,
    coin_id: [u8; 32],
    denomination: crate::qcash::QCashDenomination,
    redeem_public_key: PublicKey,
}

#[derive(BorshSerialize)]
struct RedeemTransactionCommitmentPayload {
    version: u8,
    signer: Address,
    recipient: Address,
    last_state: Hash,
    validity: ValidityWindow,
    inputs: Vec<RedeemTransactionCommitmentInput>,
}

impl QCashTransaction {
    pub fn withdraw(signer: Address, amount: Amount, metadata: QCashWithdrawalMetadata) -> Self {
        Self {
            version: QCASH_TRANSACTION_VERSION,
            signer,
            last_state: Hash::ZERO,
            kind: QCashTransactionKind::Withdraw { amount, metadata },
            validity: ValidityWindow::UNBOUNDED,
        }
    }

    pub fn redeem(signer: Address, recipient: Address, metadata: QCashRedeemMetadata) -> Self {
        Self {
            version: QCASH_TRANSACTION_VERSION,
            signer,
            last_state: Hash::ZERO,
            kind: QCashTransactionKind::Redeem {
                recipient,
                metadata,
            },
            validity: ValidityWindow::UNBOUNDED,
        }
    }

    pub fn recover_redeem(
        signer: Address,
        claimant: Address,
        metadata: QCashRedeemMetadata,
        orphan_tx_hash: TransactionHash,
        recovery_proof: QCashRecoverRedeemProof,
    ) -> Self {
        Self {
            version: QCASH_TRANSACTION_VERSION,
            signer,
            last_state: Hash::ZERO,
            kind: QCashTransactionKind::RecoverRedeem {
                claimant,
                metadata,
                orphan_tx_hash,
                recovery_proof: Box::new(recovery_proof),
            },
            validity: ValidityWindow::UNBOUNDED,
        }
    }

    pub fn redeem_from_files(
        signer: Address,
        recipient: Address,
        files: &[QCashCoinFile],
    ) -> Result<Self, QCashError> {
        Self::redeem_from_files_at(signer, recipient, files)
    }

    pub fn redeem_from_files_at(
        signer: Address,
        recipient: Address,
        files: &[QCashCoinFile],
    ) -> Result<Self, QCashError> {
        let placeholder_inputs = files
            .iter()
            .map(|file| file.redeem_input_for_transaction(recipient, [0; 32]))
            .collect::<Result<Vec<_>, _>>()?;
        let mut transaction = Self::redeem(
            signer,
            recipient,
            QCashRedeemMetadata::from_inputs(placeholder_inputs)?,
        );
        let commitment = transaction
            .redeem_transaction_commitment()
            .map_err(|_| QCashError::Serialization)?
            .ok_or(QCashError::InvalidCommitment)?;
        transaction.kind = QCashTransactionKind::Redeem {
            recipient,
            metadata: QCashRedeemMetadata::new_for_transaction(files, recipient, commitment)?,
        };
        Ok(transaction)
    }

    pub fn with_validity_window(mut self, validity: ValidityWindow) -> Self {
        self.validity = validity;
        self
    }

    pub fn with_last_state(mut self, last_state: Hash) -> Self {
        self.last_state = last_state;
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
            QCashTransactionKind::Redeem {
                recipient,
                metadata,
            } => {
                metadata
                    .validate_authorizations_for_transaction(
                        *recipient,
                        self.redeem_transaction_commitment()?
                            .ok_or(TransactionError::InvalidQCashMetadata)?,
                    )
                    .map_err(|_| TransactionError::InvalidQCashMetadata)?;
                if *recipient == Address([0; 20]) {
                    return Err(TransactionError::InvalidQCashRecipient);
                }
            }
            QCashTransactionKind::RecoverRedeem {
                claimant,
                metadata,
                orphan_tx_hash,
                recovery_proof,
            } => {
                metadata
                    .validate_authorizations_for_transaction(
                        *claimant,
                        self.redeem_transaction_commitment()?
                            .ok_or(TransactionError::InvalidQCashMetadata)?,
                    )
                    .map_err(|_| TransactionError::InvalidQCashMetadata)?;
                if *claimant == Address([0; 20]) {
                    return Err(TransactionError::InvalidQCashRecipient);
                }
                self.validate_recover_redeem_proof(
                    *claimant,
                    metadata,
                    *orphan_tx_hash,
                    recovery_proof,
                )?;
            }
        }
        self.validity.validate()
    }

    pub fn validate_for_height(&self, height: BlockHeight) -> Result<(), TransactionError> {
        self.validate()?;
        self.validity.validate_at(height)
    }

    pub fn amount(&self) -> Result<Amount, TransactionError> {
        match &self.kind {
            QCashTransactionKind::Withdraw { amount, .. } => Ok(*amount),
            QCashTransactionKind::Redeem { metadata, .. }
            | QCashTransactionKind::RecoverRedeem { metadata, .. } => metadata
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

    pub fn redeem_transaction_commitment(
        &self,
    ) -> Result<Option<[u8; 32]>, crate::error::CodecError> {
        let (recipient, metadata) = match &self.kind {
            QCashTransactionKind::Redeem {
                recipient,
                metadata,
            } => (*recipient, metadata),
            QCashTransactionKind::RecoverRedeem {
                claimant, metadata, ..
            } => (*claimant, metadata),
            QCashTransactionKind::Withdraw { .. } => return Ok(None),
        };
        let payload = RedeemTransactionCommitmentPayload {
            version: self.version,
            signer: self.signer,
            recipient,
            last_state: self.last_state,
            validity: self.validity,
            inputs: metadata
                .inputs
                .iter()
                .map(|input| RedeemTransactionCommitmentInput {
                    version: input.version,
                    coin_id: input.coin_id,
                    denomination: input.denomination,
                    redeem_public_key: input.redeem_public_key,
                })
                .collect(),
        };
        Ok(Some(
            domain_hash(
                HashDomain::QCashRedeemTransaction,
                &canonical_bytes(&payload)?,
            )
            .0,
        ))
    }

    fn validate_recover_redeem_proof(
        &self,
        claimant: Address,
        metadata: &QCashRedeemMetadata,
        orphan_tx_hash: TransactionHash,
        recovery_proof: &QCashRecoverRedeemProof,
    ) -> Result<(), TransactionError> {
        let orphan_tx = &recovery_proof.orphan_redeem_tx.transaction;
        let QCashTransactionKind::Redeem {
            recipient,
            metadata: orphan_metadata,
        } = &orphan_tx.kind
        else {
            return Err(TransactionError::InvalidQCashMetadata);
        };
        if *recipient != claimant || orphan_metadata != metadata {
            return Err(TransactionError::InvalidQCashMetadata);
        }
        if recovery_proof
            .orphan_redeem_tx
            .hash()
            .map_err(|_| TransactionError::InvalidQCashMetadata)?
            != orphan_tx_hash
        {
            return Err(TransactionError::InvalidQCashMetadata);
        }
        recovery_proof
            .orphan_redeem_tx
            .validate_signed_for_height(recovery_proof.orphan_block.header.height)?;
        if !recovery_proof.orphan_tx_proof.verify(
            orphan_tx_hash.as_hash(),
            recovery_proof.orphan_block.header.merkle_root.as_hash(),
            HashDomain::MerkleNode,
        ) {
            return Err(TransactionError::InvalidQCashMetadata);
        }
        let orphan_block_hash = recovery_proof
            .orphan_block
            .hash()
            .map_err(|_| TransactionError::InvalidQCashMetadata)?;
        let (losing_tip, losing_work) = verify_header_proof_chain(&recovery_proof.losing_branch)
            .map_err(recover_proof_error)?;
        let (canonical_tip, canonical_work) =
            verify_header_proof_chain(&recovery_proof.canonical_branch)
                .map_err(recover_proof_error)?;
        let shared_count = recovery_proof
            .losing_branch
            .iter()
            .zip(&recovery_proof.canonical_branch)
            .take_while(|(left, right)| left == right)
            .count();
        if shared_count == 0
            || shared_count == recovery_proof.losing_branch.len()
            || shared_count == recovery_proof.canonical_branch.len()
        {
            return Err(TransactionError::InvalidQCashMetadata);
        }
        let common_ancestor = recovery_proof.losing_branch[shared_count - 1]
            .hash()
            .map_err(|_| TransactionError::InvalidQCashMetadata)?;
        if common_ancestor != recovery_proof.common_ancestor {
            return Err(TransactionError::InvalidQCashMetadata);
        }
        if !recovery_proof.losing_branch[shared_count..]
            .iter()
            .any(|header| header.hash() == Ok(orphan_block_hash))
        {
            return Err(TransactionError::InvalidQCashMetadata);
        }
        if canonical_work < losing_work
            || (canonical_work == losing_work && canonical_tip >= losing_tip)
        {
            return Err(TransactionError::InvalidQCashMetadata);
        }
        Ok(())
    }
}

fn recover_proof_error(_error: RollbackProofError) -> TransactionError {
    TransactionError::InvalidQCashMetadata
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignedQCashTransaction {
    pub transaction: QCashTransaction,
    pub authorization_proof: AuthorizationProof,
}

impl SignedQCashTransaction {
    pub fn new(transaction: QCashTransaction, public_key: PublicKey, signature: Signature) -> Self {
        Self {
            transaction,
            authorization_proof: AuthorizationProof::new(public_key, signature),
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
            authorization_proof: AuthorizationProof::new_authorized(
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
            authorization_proof: AuthorizationProof::new_stored(signature, auth_signature),
        }
    }

    pub fn validate_signed(&self) -> Result<(), TransactionError> {
        self.transaction.validate()?;
        if self.to_bytes()?.len() > MAX_QCASH_TX_SIZE {
            return Err(TransactionError::TransactionTooLarge);
        }
        if self
            .authorization_proof
            .public_key
            .0
            .iter()
            .all(|byte| *byte == 0)
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
        if dual_address_from_public_keys(
            &self.authorization_proof.public_key,
            &self.authorization_proof.auth_public_key,
        ) != self.transaction.signer
        {
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
        if !self.authorization_proof.uses_stored_keys() {
            return Err(TransactionError::InvalidAuthorizationSignature);
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
        let payload = self.transaction.signing_bytes()?;
        let (owner_valid, auth_valid) = crate::crypto::verify_dual_parallel(
            owner_public_key,
            auth_public_key,
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

    pub fn verify_authorization(
        &self,
        auth_public_key: &PublicKey,
    ) -> Result<(), TransactionError> {
        if verify(
            auth_public_key,
            &self.transaction.signing_bytes()?,
            &self.authorization_proof.auth_signature,
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

    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::CodecError> {
        canonical_bytes(self)
    }
}
