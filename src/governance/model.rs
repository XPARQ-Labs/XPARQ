use crate::block::{BlockHeight, Height};
use crate::codec::canonical_bytes;
use crate::crypto::{
    Address, Hash, HashDomain, PublicKey, Signature, TransactionHash, WitnessTransactionHash,
    domain_hash, dual_address_from_public_keys, sign, verify,
};
use crate::error::TransactionError;
use crate::transaction::{AccountNonce, ValidityWindow, Witness, chain_bound_signing_bytes};
use borsh::{BorshDeserialize, BorshSerialize};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Key, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use static_assertions::const_assert;
use std::fmt;
use zeroize::Zeroizing;

pub const GOVERNANCE_CREDENTIAL_VERSION: u8 = 1;
pub const GOVERNANCE_CREDENTIAL_FILE_MAGIC: [u8; 4] = *b"PGD1";
pub const GOVERNANCE_CREDENTIAL_FILE_VERSION: u8 = 1;
pub const MAX_GOVERNANCE_CREDENTIAL_FILE_SIZE: usize = 16 * 1024;
pub const GOVERNANCE_CREDENTIAL_FILE_SALT_SIZE: usize = 16;
pub const GOVERNANCE_CREDENTIAL_FILE_NONCE_SIZE: usize = 24;
pub const GOVERNANCE_PROPOSAL_VERSION: u8 = 1;
pub const GOVERNANCE_ACTION_VERSION: u8 = 1;
pub const MAX_GOVERNANCE_TITLE_BYTES: usize = 128;
pub const MAX_GOVERNANCE_URI_BYTES: usize = 512;
pub const MAX_GOVERNANCE_METADATA_FIELD_BYTES: usize = 256;
pub const MAX_GOVERNANCE_ISSUER_METADATA_URI_BYTES: usize = 512;
pub const MAX_GOVERNANCE_ACTION_SIZE: usize = 32 * 1024;
pub const MAX_ATTACHED_CREDENTIALS: usize = 8;
pub const GOVERNANCE_BASIS_POINTS: u16 = 10_000;
pub const MIN_PROPOSAL_BOND: crate::consensus::supply::Amount =
    crate::consensus::supply::Amount(100 * crate::consensus::supply::XPQ);

const GOVERNANCE_ACTION_SIGNATURE_DOMAIN: &[u8] = b"PAQUS_SHARKSPHERE_GOVERNANCE_ACTION_V1";
const GOVERNANCE_CREDENTIAL_ISSUER_DOMAIN: &[u8] = b"PAQUS_SHARKSPHERE_GOVERNANCE_CREDENTIAL_V1";
const GOVERNANCE_CREDENTIAL_USE_DOMAIN: &[u8] = b"PAQUS_SHARKSPHERE_GOVERNANCE_CREDENTIAL_USE_V1";

pub type ProposalId = Hash;
pub type GovernanceIssuerId = Hash;
pub type GovernanceContextId = Hash;
pub type CredentialNullifier = Hash;

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
)]
pub enum VoteChoice {
    Abstain,
    Yes,
    No,
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
)]
pub enum ProposalOutcome {
    Accepted,
    Rejected,
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
)]
pub enum ProposalVotingMode {
    Credential,
    CoinPower,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProposalRules {
    pub quorum: u64,
    pub yes_threshold_bps: u16,
}

impl Default for ProposalRules {
    fn default() -> Self {
        Self {
            quorum: 1,
            yes_threshold_bps: 5_001,
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProposalExecution {
    pub proposal_id: ProposalId,
    pub executor: Address,
    pub executed_at: BlockHeight,
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub enum GovernanceActionType {
    ApproveIssuer,
    IssueCredential,
    BindCredential,
    RevokeCredential,
    ProposalVote,
    CreateProposal,
    SignalSupport,
    GrantVote,
    MilestoneApproval,
    ReleaseSignoff,
    MaintainerElection,
    ParameterPoll,
    EmergencySignal,
    TestnetRewardClaim,
    AirdropClaim,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct GovernanceIssuer {
    pub id: GovernanceIssuerId,
    pub controller: Address,
    pub issuer_public_key: PublicKey,
    pub metadata_hash: Hash,
    pub metadata_uri: Vec<u8>,
    pub fee_policy_hash: Hash,
    pub fee_policy_uri: Vec<u8>,
    pub bond_amount: crate::consensus::supply::Amount,
    pub bond_locked_until: BlockHeight,
    pub status: GovernanceIssuerStatus,
    pub registered_at: BlockHeight,
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
)]
pub enum GovernanceIssuerStatus {
    Pending,
    Active,
    Suspended,
    Revoked,
}

#[derive(BorshSerialize)]
struct GovernanceIssuerIdPayload {
    controller: Address,
    issuer_public_key: PublicKey,
    metadata_hash: Hash,
    metadata_uri: Vec<u8>,
    fee_policy_hash: Hash,
    fee_policy_uri: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct GovernanceCredential {
    pub version: u8,
    pub subject: Option<Address>,
    pub issuer_public_key: PublicKey,
    pub credential_public_key: PublicKey,
    pub credential_type: GovernanceActionType,
    pub issuer_signature: Signature,
}

#[derive(BorshSerialize)]
struct GovernanceCredentialPayload {
    version: u8,
    credential_public_key: PublicKey,
    credential_type: GovernanceActionType,
}

#[derive(BorshSerialize)]
struct GovernanceCredentialUsePayload {
    version: u8,
    context_id: GovernanceContextId,
    nullifier: CredentialNullifier,
    authorized_signer: Address,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct GovernanceCredentialUse {
    pub credential: GovernanceCredential,
    pub context_id: GovernanceContextId,
    pub nullifier: CredentialNullifier,
    pub authorized_signer: Address,
    pub credential_signature: Signature,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Hash)]
pub struct GovernanceCredentialFile {
    pub version: u8,
    pub credential: GovernanceCredential,
    pub credential_secret_key: crate::crypto::SecretKey,
}

impl fmt::Debug for GovernanceCredentialFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GovernanceCredentialFile")
            .field("version", &self.version)
            .field("credential", &self.credential)
            .field("credential_secret_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(BorshSerialize, BorshDeserialize)]
struct EncryptedGovernanceCredentialFile {
    magic: [u8; 4],
    version: u8,
    chain_id: u32,
    genesis_hash: [u8; crate::crypto::HASH_SIZE],
    salt: [u8; GOVERNANCE_CREDENTIAL_FILE_SALT_SIZE],
    nonce: [u8; GOVERNANCE_CREDENTIAL_FILE_NONCE_SIZE],
    ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernanceCredentialFileError {
    EmptyPassword,
    InvalidFormat,
    UnsupportedVersion,
    WrongChain,
    TooLarge,
    KeyMismatch,
    KeyDerivation,
    Encryption,
    Decryption,
}

impl fmt::Display for GovernanceCredentialFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyPassword => "credential-file password must not be empty",
            Self::InvalidFormat => "credential file has an invalid binary format",
            Self::UnsupportedVersion => "credential file version is unsupported",
            Self::WrongChain => "credential file belongs to a different chain",
            Self::TooLarge => "credential file exceeds the maximum size",
            Self::KeyMismatch => "credential secret key does not match its public key",
            Self::KeyDerivation => "credential-file key derivation failed",
            Self::Encryption => "credential file encryption failed",
            Self::Decryption => "credential file authentication or password is invalid",
        })
    }
}

impl std::error::Error for GovernanceCredentialFileError {}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProposalMetadata {
    pub category: Vec<u8>,
    pub repository_uri: Vec<u8>,
    pub issue_uri: Vec<u8>,
    pub milestone: Vec<u8>,
    pub budget: crate::consensus::supply::Amount,
    pub target_module: Vec<u8>,
    pub extra_uri: Vec<u8>,
    pub extra_hash: Hash,
}

impl Default for ProposalMetadata {
    fn default() -> Self {
        Self {
            category: Vec::new(),
            repository_uri: Vec::new(),
            issue_uri: Vec::new(),
            milestone: Vec::new(),
            budget: crate::consensus::supply::Amount(0),
            target_module: Vec::new(),
            extra_uri: Vec::new(),
            extra_hash: Hash([0; crate::crypto::HASH_SIZE]),
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Proposal {
    pub version: u8,
    pub id: ProposalId,
    pub proposer: Address,
    pub action_type: GovernanceActionType,
    pub title: Vec<u8>,
    pub document_hash: Hash,
    pub document_uri: Vec<u8>,
    pub metadata: Option<ProposalMetadata>,
    pub accepted_issuers: Vec<GovernanceIssuerId>,
    pub voting_mode: ProposalVotingMode,
    pub rules: ProposalRules,
    pub voting_start: BlockHeight,
    pub voting_end: BlockHeight,
}

#[derive(BorshSerialize)]
struct ProposalIdPayload {
    version: u8,
    proposer: Address,
    action_type: GovernanceActionType,
    title: Vec<u8>,
    document_hash: Hash,
    document_uri: Vec<u8>,
    metadata: Option<ProposalMetadata>,
    accepted_issuers: Vec<GovernanceIssuerId>,
    voting_mode: ProposalVotingMode,
    rules: ProposalRules,
    voting_start: BlockHeight,
    voting_end: BlockHeight,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum GovernanceActionKind {
    RegisterIssuer {
        issuer_public_key: Box<PublicKey>,
        metadata_hash: Hash,
        metadata_uri: Vec<u8>,
        fee_policy_hash: Hash,
        fee_policy_uri: Vec<u8>,
        bond_amount: crate::consensus::supply::Amount,
        bond_locked_until: BlockHeight,
    },
    ApproveIssuer {
        proposal_id: ProposalId,
        issuer_id: GovernanceIssuerId,
    },
    IssueCredential {
        credential: Box<GovernanceCredential>,
    },
    BindCredential {
        credential_use: Box<GovernanceCredentialUse>,
    },
    RevokeCredential {
        credential_type: GovernanceActionType,
    },
    CreateProposal {
        proposal: Box<Proposal>,
        bond_amount: crate::consensus::supply::Amount,
        authorization: Box<ProposalCreationAuthorization>,
    },
    Vote {
        proposal_id: ProposalId,
        choice: VoteChoice,
        authorization: Box<VoteAuthorization>,
    },
    FinalizeProposal {
        proposal_id: ProposalId,
    },
    ExecuteProposal {
        proposal_id: ProposalId,
    },
}

// Governance actions are stored inside larger signed protocol containers.
// Large cryptographic/proposal payloads must remain behind indirection.
const_assert!(std::mem::size_of::<GovernanceActionKind>() <= 256);

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ProposalCreationAuthorization {
    Credential(Box<GovernanceCredentialUse>),
    BoundCredential { issuer_id: GovernanceIssuerId },
    Coin,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum VoteAuthorization {
    Credential(Box<GovernanceCredentialUse>),
    BoundCredential {
        issuer_id: GovernanceIssuerId,
    },
    CoinPower {
        amount: crate::consensus::supply::Amount,
    },
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct GovernanceAction {
    pub version: u8,
    pub signer: Address,
    pub fee: crate::consensus::supply::Amount,
    pub nonce: AccountNonce,
    pub timestamp: u64,
    pub validity: ValidityWindow,
    pub credential_uses: Vec<GovernanceCredentialUse>,
    pub kind: GovernanceActionKind,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignedGovernanceAction {
    pub action: GovernanceAction,
    pub witness: Witness,
}

impl GovernanceCredential {
    pub fn unsigned(
        subject: Address,
        issuer_public_key: PublicKey,
        credential_public_key: PublicKey,
        credential_type: GovernanceActionType,
    ) -> Self {
        Self {
            version: GOVERNANCE_CREDENTIAL_VERSION,
            subject: Some(subject),
            issuer_public_key,
            credential_public_key,
            credential_type,
            issuer_signature: Signature([0; crate::crypto::SIGNATURE_SIZE]),
        }
    }

    pub fn unsigned_file(
        issuer_public_key: PublicKey,
        credential_public_key: PublicKey,
        credential_type: GovernanceActionType,
    ) -> Self {
        Self {
            version: GOVERNANCE_CREDENTIAL_VERSION,
            subject: None,
            issuer_public_key,
            credential_public_key,
            credential_type,
            issuer_signature: Signature([0; crate::crypto::SIGNATURE_SIZE]),
        }
    }

    pub fn bound_to(mut self, subject: Address) -> Self {
        self.subject = Some(subject);
        self
    }

    pub fn issuer_signing_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let payload = GovernanceCredentialPayload {
            version: self.version,
            credential_public_key: self.credential_public_key,
            credential_type: self.credential_type.clone(),
        };
        let payload = canonical_bytes(&payload)?;
        let mut bytes =
            Vec::with_capacity(GOVERNANCE_CREDENTIAL_ISSUER_DOMAIN.len() + payload.len());
        bytes.extend_from_slice(GOVERNANCE_CREDENTIAL_ISSUER_DOMAIN);
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    pub fn with_issuer_signature(mut self, issuer_signature: Signature) -> Self {
        self.issuer_signature = issuer_signature;
        self
    }

    pub fn validate(&self) -> Result<(), TransactionError> {
        if self.version != GOVERNANCE_CREDENTIAL_VERSION {
            return Err(TransactionError::UnsupportedVersion);
        }
        if self.issuer_public_key.0.iter().all(|byte| *byte == 0)
            || self.credential_public_key.0.iter().all(|byte| *byte == 0)
        {
            return Err(TransactionError::EmptyPublicKey);
        }
        if self
            .subject
            .is_some_and(|subject| subject == Address([0; crate::crypto::ADDRESS_SIZE]))
        {
            return Err(TransactionError::SenderAddressMismatch);
        }
        if self.issuer_signature.0.iter().all(|byte| *byte == 0) {
            return Err(TransactionError::EmptySignature);
        }
        if !verify(
            &self.issuer_public_key,
            &self.issuer_signing_bytes()?,
            &self.issuer_signature,
        ) {
            return Err(TransactionError::InvalidSignature);
        }
        Ok(())
    }
}

impl GovernanceCredentialUse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        credential: GovernanceCredential,
        context_id: GovernanceContextId,
        authorized_signer: Address,
        credential_secret_key: &crate::crypto::SecretKey,
    ) -> Result<Self, TransactionError> {
        if authorized_signer == Address::ZERO {
            return Err(TransactionError::SenderAddressMismatch);
        }
        let nullifier = credential_nullifier(&credential.credential_public_key, context_id)?;
        let payload = credential_use_signing_bytes(context_id, nullifier, authorized_signer)?;
        let credential_signature = sign(credential_secret_key, &payload);
        Ok(Self {
            credential,
            context_id,
            nullifier,
            authorized_signer,
            credential_signature,
        })
    }

    pub fn validate_for_context(
        &self,
        expected_context_id: GovernanceContextId,
        expected_credential_type: GovernanceActionType,
        expected_signer: Address,
    ) -> Result<(), TransactionError> {
        self.credential.validate()?;
        if self.credential.credential_type != expected_credential_type {
            return Err(TransactionError::InvalidGovernanceCredential);
        }
        if self.context_id != expected_context_id || self.authorized_signer != expected_signer {
            return Err(TransactionError::InvalidGovernanceCredential);
        }
        if self.nullifier
            != credential_nullifier(&self.credential.credential_public_key, self.context_id)?
        {
            return Err(TransactionError::InvalidGovernanceCredential);
        }
        if self.credential_signature.0.iter().all(|byte| *byte == 0) {
            return Err(TransactionError::EmptySignature);
        }
        if !verify(
            &self.credential.credential_public_key,
            &credential_use_signing_bytes(self.context_id, self.nullifier, self.authorized_signer)?,
            &self.credential_signature,
        ) {
            return Err(TransactionError::InvalidSignature);
        }
        Ok(())
    }

    pub fn validate_attached(&self) -> Result<(), TransactionError> {
        self.credential.validate()?;
        if self.nullifier
            != credential_nullifier(&self.credential.credential_public_key, self.context_id)?
            || self.authorized_signer == Address::ZERO
        {
            return Err(TransactionError::InvalidGovernanceCredential);
        }
        if self.credential_signature.0.iter().all(|byte| *byte == 0) {
            return Err(TransactionError::EmptySignature);
        }
        if !verify(
            &self.credential.credential_public_key,
            &credential_use_signing_bytes(self.context_id, self.nullifier, self.authorized_signer)?,
            &self.credential_signature,
        ) {
            return Err(TransactionError::InvalidSignature);
        }
        Ok(())
    }
}

impl GovernanceCredentialFile {
    pub fn new(
        credential: GovernanceCredential,
        credential_secret_key: crate::crypto::SecretKey,
    ) -> Result<Self, TransactionError> {
        credential.validate()?;
        if crate::crypto::derive_public_key(&credential_secret_key)
            != credential.credential_public_key
        {
            return Err(TransactionError::InvalidGovernanceCredential);
        }
        Ok(Self {
            version: GOVERNANCE_CREDENTIAL_FILE_VERSION,
            credential,
            credential_secret_key,
        })
    }

    pub fn validate(&self) -> Result<(), GovernanceCredentialFileError> {
        if self.version != GOVERNANCE_CREDENTIAL_FILE_VERSION {
            return Err(GovernanceCredentialFileError::UnsupportedVersion);
        }
        self.credential
            .validate()
            .map_err(|_| GovernanceCredentialFileError::InvalidFormat)?;
        if crate::crypto::derive_public_key(&self.credential_secret_key)
            != self.credential.credential_public_key
        {
            return Err(GovernanceCredentialFileError::KeyMismatch);
        }
        Ok(())
    }
}

fn credential_file_aad(
    magic: [u8; 4],
    version: u8,
    chain_id: u32,
    genesis_hash: [u8; crate::crypto::HASH_SIZE],
    salt: [u8; GOVERNANCE_CREDENTIAL_FILE_SALT_SIZE],
    nonce: [u8; GOVERNANCE_CREDENTIAL_FILE_NONCE_SIZE],
) -> Result<Vec<u8>, GovernanceCredentialFileError> {
    canonical_bytes(&(magic, version, chain_id, genesis_hash, salt, nonce))
        .map_err(|_| GovernanceCredentialFileError::InvalidFormat)
}

pub fn encode_governance_credential_file(
    credential_file: &GovernanceCredentialFile,
    password: &[u8],
) -> Result<Vec<u8>, GovernanceCredentialFileError> {
    if password.is_empty() {
        return Err(GovernanceCredentialFileError::EmptyPassword);
    }
    credential_file.validate()?;

    let mut salt = [0_u8; GOVERNANCE_CREDENTIAL_FILE_SALT_SIZE];
    let mut nonce = [0_u8; GOVERNANCE_CREDENTIAL_FILE_NONCE_SIZE];
    getrandom::fill(&mut salt).map_err(|_| GovernanceCredentialFileError::Encryption)?;
    getrandom::fill(&mut nonce).map_err(|_| GovernanceCredentialFileError::Encryption)?;

    let key = crate::crypto::credential_file_key_from_password(password, &salt)
        .map_err(|_| GovernanceCredentialFileError::KeyDerivation)?;
    let cipher_key = Key::<XChaCha20Poly1305>::from(*key);
    let cipher = XChaCha20Poly1305::new(&cipher_key);
    let cipher_nonce = XNonce::from(nonce);
    let plaintext = Zeroizing::new(
        canonical_bytes(credential_file)
            .map_err(|_| GovernanceCredentialFileError::InvalidFormat)?,
    );
    let params = crate::genesis::CURRENT_CHAIN_PARAMS;
    let aad = credential_file_aad(
        GOVERNANCE_CREDENTIAL_FILE_MAGIC,
        GOVERNANCE_CREDENTIAL_FILE_VERSION,
        params.chain_id,
        params.genesis.hash,
        salt,
        nonce,
    )?;
    let ciphertext = cipher
        .encrypt(
            &cipher_nonce,
            Payload {
                msg: plaintext.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| GovernanceCredentialFileError::Encryption)?;
    let envelope = EncryptedGovernanceCredentialFile {
        magic: GOVERNANCE_CREDENTIAL_FILE_MAGIC,
        version: GOVERNANCE_CREDENTIAL_FILE_VERSION,
        chain_id: params.chain_id,
        genesis_hash: params.genesis.hash,
        salt,
        nonce,
        ciphertext,
    };
    let encoded =
        canonical_bytes(&envelope).map_err(|_| GovernanceCredentialFileError::InvalidFormat)?;
    if encoded.len() > MAX_GOVERNANCE_CREDENTIAL_FILE_SIZE {
        return Err(GovernanceCredentialFileError::TooLarge);
    }
    Ok(encoded)
}

pub fn decode_governance_credential_file(
    bytes: &[u8],
    password: &[u8],
) -> Result<GovernanceCredentialFile, GovernanceCredentialFileError> {
    if password.is_empty() {
        return Err(GovernanceCredentialFileError::EmptyPassword);
    }
    if bytes.len() > MAX_GOVERNANCE_CREDENTIAL_FILE_SIZE {
        return Err(GovernanceCredentialFileError::TooLarge);
    }
    let envelope: EncryptedGovernanceCredentialFile = crate::codec::canonical_deserialize(bytes)
        .map_err(|_| GovernanceCredentialFileError::InvalidFormat)?;
    if envelope.magic != GOVERNANCE_CREDENTIAL_FILE_MAGIC {
        return Err(GovernanceCredentialFileError::InvalidFormat);
    }
    if envelope.version != GOVERNANCE_CREDENTIAL_FILE_VERSION {
        return Err(GovernanceCredentialFileError::UnsupportedVersion);
    }
    let params = crate::genesis::CURRENT_CHAIN_PARAMS;
    if envelope.chain_id != params.chain_id || envelope.genesis_hash != params.genesis.hash {
        return Err(GovernanceCredentialFileError::WrongChain);
    }
    if envelope.ciphertext.len() > MAX_GOVERNANCE_CREDENTIAL_FILE_SIZE {
        return Err(GovernanceCredentialFileError::TooLarge);
    }
    let key = crate::crypto::credential_file_key_from_password(password, &envelope.salt)
        .map_err(|_| GovernanceCredentialFileError::KeyDerivation)?;
    let cipher_key = Key::<XChaCha20Poly1305>::from(*key);
    let cipher = XChaCha20Poly1305::new(&cipher_key);
    let cipher_nonce = XNonce::from(envelope.nonce);
    let aad = credential_file_aad(
        envelope.magic,
        envelope.version,
        envelope.chain_id,
        envelope.genesis_hash,
        envelope.salt,
        envelope.nonce,
    )?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &cipher_nonce,
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| GovernanceCredentialFileError::Decryption)?,
    );
    let credential_file: GovernanceCredentialFile = crate::codec::canonical_deserialize(&plaintext)
        .map_err(|_| GovernanceCredentialFileError::InvalidFormat)?;
    credential_file.validate()?;
    Ok(credential_file)
}

pub fn validate_attached_credentials(
    credential_uses: &[GovernanceCredentialUse],
    expected_signer: Address,
) -> Result<(), TransactionError> {
    if credential_uses.len() > MAX_ATTACHED_CREDENTIALS {
        return Err(TransactionError::TooManyCredentials);
    }
    for credential_use in credential_uses {
        if credential_use.authorized_signer != expected_signer {
            return Err(TransactionError::InvalidGovernanceCredential);
        }
        credential_use.validate_attached()?;
    }
    Ok(())
}

impl Proposal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposer: Address,
        action_type: GovernanceActionType,
        title: Vec<u8>,
        document_hash: Hash,
        document_uri: Vec<u8>,
        metadata: Option<ProposalMetadata>,
        accepted_issuers: Vec<GovernanceIssuerId>,
        voting_mode: ProposalVotingMode,
        rules: ProposalRules,
        voting_start: BlockHeight,
        voting_end: BlockHeight,
    ) -> Result<Self, TransactionError> {
        let mut proposal = Self {
            version: GOVERNANCE_PROPOSAL_VERSION,
            id: Hash([0; crate::crypto::HASH_SIZE]),
            proposer,
            action_type,
            title,
            document_hash,
            document_uri,
            metadata,
            accepted_issuers,
            voting_mode,
            rules,
            voting_start,
            voting_end,
        };
        proposal.validate_without_id()?;
        proposal.id = proposal.calculate_id()?;
        Ok(proposal)
    }

    pub fn calculate_id(&self) -> Result<ProposalId, TransactionError> {
        let payload = ProposalIdPayload {
            version: self.version,
            proposer: self.proposer,
            action_type: self.action_type.clone(),
            title: self.title.clone(),
            document_hash: self.document_hash,
            document_uri: self.document_uri.clone(),
            metadata: self.metadata.clone(),
            accepted_issuers: self.accepted_issuers.clone(),
            voting_mode: self.voting_mode,
            rules: self.rules,
            voting_start: self.voting_start,
            voting_end: self.voting_end,
        };
        Ok(domain_hash(
            HashDomain::GovernanceProposal,
            &canonical_bytes(&payload)?,
        ))
    }

    pub fn validate(&self) -> Result<(), TransactionError> {
        self.validate_without_id()?;
        if self.id != self.calculate_id()? {
            return Err(TransactionError::InvalidGovernanceProposal);
        }
        Ok(())
    }

    pub fn is_active_at(&self, height: BlockHeight) -> bool {
        self.voting_start.0 <= height.0 && height.0 <= self.voting_end.0
    }

    fn validate_without_id(&self) -> Result<(), TransactionError> {
        if self.version != GOVERNANCE_PROPOSAL_VERSION {
            return Err(TransactionError::UnsupportedVersion);
        }
        if self.proposer == Address([0; crate::crypto::ADDRESS_SIZE]) {
            return Err(TransactionError::InvalidGovernanceProposal);
        }
        if self.title.is_empty() || self.title.len() > MAX_GOVERNANCE_TITLE_BYTES {
            return Err(TransactionError::InvalidGovernanceProposal);
        }
        if self.document_uri.len() > MAX_GOVERNANCE_URI_BYTES {
            return Err(TransactionError::InvalidGovernanceProposal);
        }
        if let Some(metadata) = &self.metadata {
            metadata.validate()?;
        }
        if self.voting_mode == ProposalVotingMode::Credential && self.accepted_issuers.is_empty() {
            return Err(TransactionError::InvalidGovernanceProposal);
        }
        if self
            .accepted_issuers
            .windows(2)
            .any(|window| window[0] >= window[1])
        {
            return Err(TransactionError::InvalidGovernanceProposal);
        }
        self.rules.validate()?;
        if self.voting_start.0 > self.voting_end.0 {
            return Err(TransactionError::InvalidGovernanceProposal);
        }
        Ok(())
    }
}

impl ProposalRules {
    pub fn validate(&self) -> Result<(), TransactionError> {
        if self.yes_threshold_bps == 0 || self.yes_threshold_bps > GOVERNANCE_BASIS_POINTS {
            return Err(TransactionError::InvalidGovernanceProposal);
        }
        Ok(())
    }
}

impl ProposalMetadata {
    pub fn validate(&self) -> Result<(), TransactionError> {
        let fields = [
            &self.category,
            &self.repository_uri,
            &self.issue_uri,
            &self.milestone,
            &self.target_module,
            &self.extra_uri,
        ];
        if fields
            .iter()
            .any(|field| field.len() > MAX_GOVERNANCE_METADATA_FIELD_BYTES)
        {
            return Err(TransactionError::InvalidGovernanceProposal);
        }
        Ok(())
    }
}

impl GovernanceIssuer {
    #[allow(clippy::too_many_arguments)]
    pub fn new_registered(
        controller: Address,
        issuer_public_key: PublicKey,
        metadata_hash: Hash,
        metadata_uri: Vec<u8>,
        fee_policy_hash: Hash,
        fee_policy_uri: Vec<u8>,
        bond_amount: crate::consensus::supply::Amount,
        bond_locked_until: BlockHeight,
        registered_at: BlockHeight,
    ) -> Result<Self, TransactionError> {
        let mut issuer = Self {
            id: Hash([0; crate::crypto::HASH_SIZE]),
            controller,
            issuer_public_key,
            metadata_hash,
            metadata_uri,
            fee_policy_hash,
            fee_policy_uri,
            bond_amount,
            bond_locked_until,
            status: GovernanceIssuerStatus::Pending,
            registered_at,
        };
        issuer.validate_without_id()?;
        issuer.id = issuer.calculate_id()?;
        Ok(issuer)
    }

    pub fn calculate_id(&self) -> Result<GovernanceIssuerId, TransactionError> {
        let payload = GovernanceIssuerIdPayload {
            controller: self.controller,
            issuer_public_key: self.issuer_public_key,
            metadata_hash: self.metadata_hash,
            metadata_uri: self.metadata_uri.clone(),
            fee_policy_hash: self.fee_policy_hash,
            fee_policy_uri: self.fee_policy_uri.clone(),
        };
        Ok(domain_hash(
            HashDomain::GovernanceIssuer,
            &canonical_bytes(&payload)?,
        ))
    }

    pub fn validate(&self) -> Result<(), TransactionError> {
        self.validate_without_id()?;
        if self.id != self.calculate_id()? {
            return Err(TransactionError::InvalidGovernanceCredential);
        }
        Ok(())
    }

    fn validate_without_id(&self) -> Result<(), TransactionError> {
        if self.controller == Address([0; crate::crypto::ADDRESS_SIZE]) {
            return Err(TransactionError::SenderAddressMismatch);
        }
        if self.issuer_public_key.0.iter().all(|byte| *byte == 0) {
            return Err(TransactionError::EmptyPublicKey);
        }
        if self.metadata_uri.len() > MAX_GOVERNANCE_ISSUER_METADATA_URI_BYTES {
            return Err(TransactionError::InvalidGovernanceCredential);
        }
        if self.fee_policy_uri.len() > MAX_GOVERNANCE_ISSUER_METADATA_URI_BYTES {
            return Err(TransactionError::InvalidGovernanceCredential);
        }
        if self.bond_amount.0 == 0 || self.bond_locked_until.0 <= self.registered_at.0 {
            return Err(TransactionError::InvalidGovernanceCredential);
        }
        Ok(())
    }
}

impl GovernanceAction {
    #[allow(clippy::too_many_arguments)]
    pub fn register_issuer(
        signer: Address,
        fee: crate::consensus::supply::Amount,
        nonce: AccountNonce,
        issuer_public_key: PublicKey,
        metadata_hash: Hash,
        metadata_uri: Vec<u8>,
        fee_policy_hash: Hash,
        fee_policy_uri: Vec<u8>,
        bond_amount: crate::consensus::supply::Amount,
        bond_locked_until: BlockHeight,
    ) -> Self {
        Self {
            version: GOVERNANCE_ACTION_VERSION,
            signer,
            fee,
            nonce,
            timestamp: 0,
            validity: ValidityWindow::UNBOUNDED,
            credential_uses: Vec::new(),
            kind: GovernanceActionKind::RegisterIssuer {
                issuer_public_key: Box::new(issuer_public_key),
                metadata_hash,
                metadata_uri,
                fee_policy_hash,
                fee_policy_uri,
                bond_amount,
                bond_locked_until,
            },
        }
    }

    pub fn approve_issuer(
        signer: Address,
        fee: crate::consensus::supply::Amount,
        nonce: AccountNonce,
        proposal_id: ProposalId,
        issuer_id: GovernanceIssuerId,
    ) -> Self {
        Self {
            version: GOVERNANCE_ACTION_VERSION,
            signer,
            fee,
            nonce,
            timestamp: 0,
            validity: ValidityWindow::UNBOUNDED,
            credential_uses: Vec::new(),
            kind: GovernanceActionKind::ApproveIssuer {
                proposal_id,
                issuer_id,
            },
        }
    }

    pub fn issue_credential(
        signer: Address,
        fee: crate::consensus::supply::Amount,
        nonce: AccountNonce,
        credential: GovernanceCredential,
    ) -> Self {
        Self {
            version: GOVERNANCE_ACTION_VERSION,
            signer,
            fee,
            nonce,
            timestamp: 0,
            validity: ValidityWindow::UNBOUNDED,
            credential_uses: Vec::new(),
            kind: GovernanceActionKind::IssueCredential {
                credential: Box::new(credential),
            },
        }
    }

    pub fn bind_credential(
        signer: Address,
        fee: crate::consensus::supply::Amount,
        nonce: AccountNonce,
        credential_use: GovernanceCredentialUse,
    ) -> Self {
        Self {
            version: GOVERNANCE_ACTION_VERSION,
            signer,
            fee,
            nonce,
            timestamp: 0,
            validity: ValidityWindow::UNBOUNDED,
            credential_uses: Vec::new(),
            kind: GovernanceActionKind::BindCredential {
                credential_use: Box::new(credential_use),
            },
        }
    }

    pub fn revoke_credential(
        signer: Address,
        fee: crate::consensus::supply::Amount,
        nonce: AccountNonce,
        credential_type: GovernanceActionType,
    ) -> Self {
        Self {
            version: GOVERNANCE_ACTION_VERSION,
            signer,
            fee,
            nonce,
            timestamp: 0,
            validity: ValidityWindow::UNBOUNDED,
            credential_uses: Vec::new(),
            kind: GovernanceActionKind::RevokeCredential { credential_type },
        }
    }

    pub fn create_proposal(
        signer: Address,
        fee: crate::consensus::supply::Amount,
        nonce: AccountNonce,
        proposal: Proposal,
        bond_amount: crate::consensus::supply::Amount,
        authorization: ProposalCreationAuthorization,
    ) -> Self {
        Self {
            version: GOVERNANCE_ACTION_VERSION,
            signer,
            fee,
            nonce,
            timestamp: 0,
            validity: ValidityWindow::UNBOUNDED,
            credential_uses: Vec::new(),
            kind: GovernanceActionKind::CreateProposal {
                proposal: Box::new(proposal),
                bond_amount,
                authorization: Box::new(authorization),
            },
        }
    }

    pub fn vote(
        signer: Address,
        fee: crate::consensus::supply::Amount,
        nonce: AccountNonce,
        proposal_id: ProposalId,
        choice: VoteChoice,
        authorization: VoteAuthorization,
    ) -> Self {
        Self {
            version: GOVERNANCE_ACTION_VERSION,
            signer,
            fee,
            nonce,
            timestamp: 0,
            validity: ValidityWindow::UNBOUNDED,
            credential_uses: Vec::new(),
            kind: GovernanceActionKind::Vote {
                proposal_id,
                choice,
                authorization: Box::new(authorization),
            },
        }
    }

    pub fn finalize_proposal(
        signer: Address,
        fee: crate::consensus::supply::Amount,
        nonce: AccountNonce,
        proposal_id: ProposalId,
    ) -> Self {
        Self {
            version: GOVERNANCE_ACTION_VERSION,
            signer,
            fee,
            nonce,
            timestamp: 0,
            validity: ValidityWindow::UNBOUNDED,
            credential_uses: Vec::new(),
            kind: GovernanceActionKind::FinalizeProposal { proposal_id },
        }
    }

    pub fn execute_proposal(
        signer: Address,
        fee: crate::consensus::supply::Amount,
        nonce: AccountNonce,
        proposal_id: ProposalId,
    ) -> Self {
        Self {
            version: GOVERNANCE_ACTION_VERSION,
            signer,
            fee,
            nonce,
            timestamp: 0,
            validity: ValidityWindow::UNBOUNDED,
            credential_uses: Vec::new(),
            kind: GovernanceActionKind::ExecuteProposal { proposal_id },
        }
    }

    pub fn validate_for_height(&self, height: BlockHeight) -> Result<(), TransactionError> {
        if self.version != GOVERNANCE_ACTION_VERSION {
            return Err(TransactionError::UnsupportedVersion);
        }
        if self.signer == Address([0; crate::crypto::ADDRESS_SIZE]) {
            return Err(TransactionError::SenderAddressMismatch);
        }
        self.validity.validate_at(height)?;
        validate_attached_credentials(&self.credential_uses, self.signer)?;
        match &self.kind {
            GovernanceActionKind::RegisterIssuer {
                issuer_public_key,
                metadata_hash,
                metadata_uri,
                fee_policy_hash,
                fee_policy_uri,
                bond_amount,
                bond_locked_until,
            } => {
                GovernanceIssuer::new_registered(
                    self.signer,
                    **issuer_public_key,
                    *metadata_hash,
                    metadata_uri.clone(),
                    *fee_policy_hash,
                    fee_policy_uri.clone(),
                    *bond_amount,
                    *bond_locked_until,
                    height,
                )?;
                Ok(())
            }
            GovernanceActionKind::ApproveIssuer { .. } => Ok(()),
            GovernanceActionKind::IssueCredential { credential } => {
                credential.validate()?;
                if credential.subject.is_none() {
                    return Err(TransactionError::InvalidGovernanceCredential);
                }
                Ok(())
            }
            GovernanceActionKind::BindCredential { credential_use } => credential_use
                .validate_for_context(
                    bind_credential_context_id(
                        self.signer,
                        credential_use.credential.credential_type.clone(),
                    )?,
                    credential_use.credential.credential_type.clone(),
                    self.signer,
                ),
            GovernanceActionKind::RevokeCredential { .. } => Ok(()),
            GovernanceActionKind::CreateProposal {
                proposal,
                bond_amount,
                authorization,
            } => {
                if proposal.proposer != self.signer {
                    return Err(TransactionError::InvalidGovernanceProposal);
                }
                if bond_amount.0 < MIN_PROPOSAL_BOND.0 {
                    return Err(TransactionError::InvalidGovernanceProposal);
                }
                proposal.validate()?;
                match authorization.as_ref() {
                    ProposalCreationAuthorization::Credential(credential_use) => credential_use
                        .validate_for_context(
                            proposal_create_context_id(proposal.id)?,
                            GovernanceActionType::CreateProposal,
                            self.signer,
                        ),
                    ProposalCreationAuthorization::BoundCredential { issuer_id } => {
                        if !proposal.accepted_issuers.contains(issuer_id) {
                            return Err(TransactionError::InvalidGovernanceProposal);
                        }
                        Ok(())
                    }
                    ProposalCreationAuthorization::Coin => Ok(()),
                }
            }
            GovernanceActionKind::Vote {
                proposal_id,
                authorization,
                ..
            } => match authorization.as_ref() {
                VoteAuthorization::Credential(credential_use) => credential_use
                    .validate_for_context(
                        vote_context_id(*proposal_id)?,
                        GovernanceActionType::ProposalVote,
                        self.signer,
                    ),
                VoteAuthorization::BoundCredential { .. } => Ok(()),
                VoteAuthorization::CoinPower { amount } => {
                    if amount.0 == 0 {
                        return Err(TransactionError::ZeroAmount);
                    }
                    Ok(())
                }
            },
            GovernanceActionKind::FinalizeProposal { .. } => Ok(()),
            GovernanceActionKind::ExecuteProposal { .. } => Ok(()),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::CodecError> {
        canonical_bytes(self)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, crate::error::CodecError> {
        chain_bound_signing_bytes(GOVERNANCE_ACTION_SIGNATURE_DOMAIN, self.to_bytes()?)
    }

    pub fn hash(&self) -> Result<TransactionHash, crate::error::CodecError> {
        Ok(TransactionHash(
            domain_hash(HashDomain::Transaction, &self.to_bytes()?).0,
        ))
    }
}

impl SignedGovernanceAction {
    pub fn new(action: GovernanceAction, public_key: PublicKey, signature: Signature) -> Self {
        Self {
            action,
            witness: Witness::new(public_key, signature),
        }
    }

    pub fn new_authorized(
        action: GovernanceAction,
        public_key: PublicKey,
        signature: Signature,
        auth_public_key: PublicKey,
        auth_signature: Signature,
    ) -> Self {
        Self {
            action,
            witness: Witness::new_authorized(
                public_key,
                signature,
                auth_public_key,
                auth_signature,
            ),
        }
    }

    pub fn new_stored_authorized(
        action: GovernanceAction,
        signature: Signature,
        auth_signature: Signature,
    ) -> Self {
        Self {
            action,
            witness: Witness::new_stored(signature, auth_signature),
        }
    }

    pub fn validate_signed_for_height(&self, height: BlockHeight) -> Result<(), TransactionError> {
        self.action.validate_for_height(height)?;
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
            != self.action.signer
        {
            return Err(TransactionError::SenderAddressMismatch);
        }
        let payload = self.action.signing_bytes()?;
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
        height: BlockHeight,
        owner_public_key: &PublicKey,
        auth_public_key: &PublicKey,
    ) -> Result<(), TransactionError> {
        self.action.validate_for_height(height)?;
        if !self.witness.uses_stored_keys() {
            return Err(TransactionError::InvalidAuthorizationSignature);
        }
        if self.witness.signature.0.iter().all(|byte| *byte == 0) {
            return Err(TransactionError::EmptySignature);
        }
        if self.witness.auth_signature.0.iter().all(|byte| *byte == 0) {
            return Err(TransactionError::EmptyAuthorizationSignature);
        }
        let payload = self.action.signing_bytes()?;
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
            &self.action.signing_bytes()?,
            &self.witness.auth_signature,
        ) {
            Ok(())
        } else {
            Err(TransactionError::InvalidAuthorizationSignature)
        }
    }

    pub fn hash(&self) -> Result<TransactionHash, crate::error::CodecError> {
        self.action.hash()
    }

    pub fn wtxid(&self) -> Result<WitnessTransactionHash, crate::error::CodecError> {
        crate::transaction::SignedProtocolTransaction::from(self.clone()).wtxid()
    }

    pub fn stripped_size(&self) -> Result<usize, crate::error::CodecError> {
        Ok(self.action.to_bytes()?.len())
    }

    pub fn witness_size(&self) -> Result<usize, crate::error::CodecError> {
        Ok(self.to_bytes()?.len().saturating_sub(self.stripped_size()?))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::CodecError> {
        canonical_bytes(self)
    }
}

pub fn vote_context_id(proposal_id: ProposalId) -> Result<GovernanceContextId, TransactionError> {
    governance_context_id(
        GovernanceActionType::ProposalVote,
        proposal_id,
        Height(0),
        Height(0),
    )
}

pub fn proposal_create_context_id(
    proposal_id: ProposalId,
) -> Result<GovernanceContextId, TransactionError> {
    governance_context_id(
        GovernanceActionType::CreateProposal,
        proposal_id,
        Height(0),
        Height(0),
    )
}

pub fn governance_context_id(
    action_type: GovernanceActionType,
    target_id: Hash,
    window_start: BlockHeight,
    window_end: BlockHeight,
) -> Result<GovernanceContextId, TransactionError> {
    Ok(domain_hash(
        HashDomain::GovernanceContext,
        &canonical_bytes(&(action_type, target_id, window_start, window_end))?,
    ))
}

pub fn bind_credential_context_id(
    subject: Address,
    credential_type: GovernanceActionType,
) -> Result<GovernanceContextId, TransactionError> {
    Ok(domain_hash(
        HashDomain::GovernanceContext,
        &canonical_bytes(&(
            GovernanceActionType::BindCredential,
            subject,
            credential_type,
        ))?,
    ))
}

pub fn credential_nullifier(
    credential_public_key: &PublicKey,
    context_id: GovernanceContextId,
) -> Result<CredentialNullifier, TransactionError> {
    Ok(domain_hash(
        HashDomain::GovernanceNullifier,
        &canonical_bytes(&(credential_public_key, context_id))?,
    ))
}

fn credential_use_signing_bytes(
    context_id: GovernanceContextId,
    nullifier: CredentialNullifier,
    authorized_signer: Address,
) -> Result<Vec<u8>, TransactionError> {
    let payload = GovernanceCredentialUsePayload {
        version: GOVERNANCE_CREDENTIAL_VERSION,
        context_id,
        nullifier,
        authorized_signer,
    };
    let payload = canonical_bytes(&payload)?;
    let mut bytes = Vec::with_capacity(GOVERNANCE_CREDENTIAL_USE_DOMAIN.len() + payload.len());
    bytes.extend_from_slice(GOVERNANCE_CREDENTIAL_USE_DOMAIN);
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_metadata_rejects_oversized_fields() {
        let metadata = ProposalMetadata {
            category: vec![b'x'; MAX_GOVERNANCE_METADATA_FIELD_BYTES + 1],
            ..ProposalMetadata::default()
        };

        assert_eq!(
            metadata.validate(),
            Err(TransactionError::InvalidGovernanceProposal)
        );
    }

    fn credential_file_fixture() -> GovernanceCredentialFile {
        let issuer = crate::crypto::keypair_from_seed(&[41; 32]);
        let credential_key = crate::crypto::keypair_from_seed(&[42; 32]);
        let unsigned = GovernanceCredential::unsigned_file(
            issuer.public_key,
            credential_key.public_key,
            GovernanceActionType::ProposalVote,
        );
        let issuer_signature = crate::crypto::sign(
            &issuer.secret_key,
            &unsigned.issuer_signing_bytes().unwrap(),
        );
        GovernanceCredentialFile::new(
            unsigned.with_issuer_signature(issuer_signature),
            credential_key.secret_key,
        )
        .unwrap()
    }

    #[test]
    fn encrypted_credential_file_roundtrips_and_rejects_wrong_password() {
        let credential_file = credential_file_fixture();
        let encoded =
            encode_governance_credential_file(&credential_file, b"correct horse battery staple")
                .unwrap();
        assert!(encoded.len() <= MAX_GOVERNANCE_CREDENTIAL_FILE_SIZE);
        assert_eq!(
            decode_governance_credential_file(&encoded, b"correct horse battery staple").unwrap(),
            credential_file
        );
        assert_eq!(
            decode_governance_credential_file(&encoded, b"wrong password"),
            Err(GovernanceCredentialFileError::Decryption)
        );
    }

    #[test]
    fn credential_file_rejects_tampering_version_and_key_mismatch() {
        let credential_file = credential_file_fixture();
        let legacy_plaintext = canonical_bytes(&credential_file).unwrap();
        assert_eq!(
            decode_governance_credential_file(&legacy_plaintext, b"credential password"),
            Err(GovernanceCredentialFileError::InvalidFormat)
        );
        let mut encoded =
            encode_governance_credential_file(&credential_file, b"credential password").unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        assert_eq!(
            decode_governance_credential_file(&encoded, b"credential password"),
            Err(GovernanceCredentialFileError::Decryption)
        );

        let mut wrong_version = credential_file.clone();
        wrong_version.version = GOVERNANCE_CREDENTIAL_FILE_VERSION + 1;
        assert_eq!(
            wrong_version.validate(),
            Err(GovernanceCredentialFileError::UnsupportedVersion)
        );

        let wrong_key = crate::crypto::keypair_from_seed(&[43; 32]).secret_key;
        assert_eq!(
            GovernanceCredentialFile::new(credential_file.credential.clone(), wrong_key),
            Err(TransactionError::InvalidGovernanceCredential)
        );
    }

    #[test]
    fn secret_bearing_debug_output_is_redacted() {
        let credential_file = credential_file_fixture();
        let debug = format!("{credential_file:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&format!("{:?}", credential_file.credential_secret_key.0)));
        assert_eq!(
            format!("{:?}", credential_file.credential_secret_key),
            "SecretKey([REDACTED])"
        );
    }

    #[test]
    fn credential_use_signature_is_bound_to_authorized_signer() {
        let credential_file = credential_file_fixture();
        let signer = Address([11; crate::crypto::ADDRESS_SIZE]);
        let attacker = Address([12; crate::crypto::ADDRESS_SIZE]);
        let context = Hash([13; crate::crypto::HASH_SIZE]);
        let credential_use = GovernanceCredentialUse::new(
            credential_file.credential,
            context,
            signer,
            &credential_file.credential_secret_key,
        )
        .unwrap();

        assert!(credential_use.validate_attached().is_ok());
        assert_eq!(
            credential_use.validate_for_context(
                context,
                GovernanceActionType::ProposalVote,
                attacker,
            ),
            Err(TransactionError::InvalidGovernanceCredential)
        );

        let mut copied = credential_use;
        copied.authorized_signer = attacker;
        assert_eq!(
            copied.validate_attached(),
            Err(TransactionError::InvalidSignature)
        );
    }
}
