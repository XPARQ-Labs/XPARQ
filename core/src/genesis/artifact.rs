use crate::block::{Block, Height};
use crate::codec::{canonical_bytes, canonical_deserialize};
use crate::consensus::supply::{
    BASE_BLOCK_REWARD, BLOCK_REWARD_STEP, DECIMALS, MAX_BLOCK_REWARD, MIN_BLOCK_REWARD, UNIT, XPQ,
};
use crate::consensus::{
    DIFFICULTY_START, MIN_DIFFICULTY, WBDA_HIGH_UTILIZATION_PPM, WBDA_LOW_UTILIZATION_PPM,
    WBDA_WINDOW,
};
use crate::crypto::{BlockHash, Hash, HashDomain, domain_hash};
use crate::error::{CodecError, GenesisError};
use crate::genesis::{
    CURRENT_CHAIN_PARAMS, ChainParams, genesis_block_for_chain, genesis_hash_for_chain,
    genesis_ledger_for_chain,
};
use crate::ledger::{
    BLOCK_REWARD_MATURITY, CONFIRMATION_DEPTH, FINALITY_DEPTH, Ledger,
    QCASH_REDEEM_CREDIT_MATURITY, QCASH_REDEEM_DELAY, SparseStateTree, Work,
    calculate_protocol_state_root_from_roots,
};
use crate::qcash::recovery::ChainHeader;
use crate::state::{Account, BlockStateCommitment, QCashUtxoSet, XpqUtxoSet};
use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::BTreeMap;

pub const XPARQ_ARTIFACT_MAGIC: [u8; 5] = *b"XPARQ";
pub const XPARQ_ARTIFACT_VERSION: u8 = 1;
pub const MAX_XPARQ_ARTIFACT_SIZE: usize = 256 * 1024 * 1024;

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum XPARQArtifactKind {
    Genesis,
    Snapshot,
    Checkpoint,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct XPARQArtifact {
    pub magic: [u8; 5],
    pub version: u8,
    pub kind: XPARQArtifactKind,
    pub payload_hash: Hash,
    pub payload: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct ChainParamsArtifact {
    pub chain_name: String,
    pub patch_name: String,
    pub chain_id: u32,
    pub coin_name: String,
    pub unit_name: String,
    pub protocol_stage: String,
    pub protocol_version: u8,
    pub pow_algorithm: String,
    pub pow_memory_kib: u32,
    pub pow_iterations: u32,
    pub pow_lanes: u32,
    pub difficulty_algorithm: String,
    pub network_magic: [u8; 4],
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct ChainSpecArtifact {
    pub params: ChainParamsArtifact,
    pub genesis_nonce: u64,
    pub genesis_hash: [u8; crate::crypto::HASH_SIZE],
    pub block_version: u8,
    pub max_block_size: u64,
    pub max_block_weight: u64,
    pub max_block_decode_items: u64,
    pub min_difficulty: u32,
    pub difficulty_start: u32,
    pub wbda_window: u64,
    pub wbda_target_block_weight: u64,
    pub wbda_low_utilization_ppm: u64,
    pub wbda_high_utilization_ppm: u64,
    pub confirmation_depth: u32,
    pub finality_depth: u32,
    pub block_reward_maturity: u32,
    pub qcash_redeem_credit_maturity: u32,
    pub qcash_redeem_delay: u32,
    pub unit: u64,
    pub xpq: u64,
    pub decimals: u8,
    pub base_block_reward: u64,
    pub min_block_reward: u64,
    pub max_block_reward: u64,
    pub block_reward_step: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct GenesisArtifact {
    pub params: ChainParamsArtifact,
    pub chain_spec: ChainSpecArtifact,
    pub chain_spec_hash: Hash,
    pub block: Block,
    pub block_hash: BlockHash,
    pub state_commitment: BlockStateCommitment,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct SnapshotArtifact {
    pub params: ChainParamsArtifact,
    pub chain_spec_hash: Hash,
    pub height: Height,
    pub block_hash: BlockHash,
    pub state_commitment: BlockStateCommitment,
    pub accounts: BTreeMap<crate::crypto::Address, Account>,
    pub xpq_utxos: XpqUtxoSet,
    pub qcash_utxos: QCashUtxoSet,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct CheckpointArtifact {
    pub params: ChainParamsArtifact,
    pub chain_spec_hash: Hash,
    pub height: Height,
    pub block_hash: BlockHash,
    pub state_commitment: BlockStateCommitment,
    pub cumulative_work: Work,
    pub difficulty: u32,
    pub ancestor_hashes: Vec<BlockHash>,
}

/// A locally established trust boundary for snapshot/checkpoint validation.
///
/// The fields are intentionally private: untrusted artifact metadata must not
/// be promoted into a trust anchor. Remote bootstrap must first independently
/// verify its header/PoW chain and expose a separate audited constructor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactTrustAnchor {
    height: Height,
    block_hash: BlockHash,
    protocol_state_root: crate::crypto::StateRoot,
}

impl ArtifactTrustAnchor {
    /// Establishes a snapshot trust anchor from a complete, independently
    /// validated PoW header chain rooted at the configured genesis.
    ///
    /// A snapshot provider cannot choose the anchor: its height, block hash,
    /// and protocol state root are all taken from the validated tip header.
    pub fn from_verified_header_chain(
        headers: &[ChainHeader],
    ) -> Result<(Self, Work), crate::qcash::recovery::RollbackProofError> {
        let (block_hash, cumulative_work) = crate::qcash::recovery::verify_header_chain(headers)?;
        let tip = headers
            .last()
            .ok_or(crate::qcash::recovery::RollbackProofError::EmptyHeaderChain)?;
        let protocol_state_root = if tip.height == Height(0) {
            genesis_ledger_for_chain(CURRENT_CHAIN_PARAMS)
                .map_err(|_| crate::qcash::recovery::RollbackProofError::WrongGenesis)?
                .protocol_state_root()
                .map_err(|_| crate::qcash::recovery::RollbackProofError::WrongGenesis)?
        } else {
            tip.header.state_root
        };
        Ok((
            Self {
                height: tip.height,
                block_hash,
                protocol_state_root,
            },
            cumulative_work,
        ))
    }

    /// Verifies every candidate and selects the canonical tip by cumulative
    /// work, using the consensus hash tie-breaker when work is equal.
    pub fn select_best_verified_header_chain(
        candidates: &[Vec<ChainHeader>],
    ) -> Result<(usize, Self, Work), crate::qcash::recovery::RollbackProofError> {
        let mut best: Option<(usize, Self, Work)> = None;
        for (index, headers) in candidates.iter().enumerate() {
            let (anchor, work) = Self::from_verified_header_chain(headers)?;
            let replace = best.as_ref().is_none_or(|(_, current, current_work)| {
                work > *current_work
                    || (work == *current_work && anchor.block_hash < current.block_hash)
            });
            if replace {
                best = Some((index, anchor, work));
            }
        }
        best.ok_or(crate::qcash::recovery::RollbackProofError::EmptyHeaderChain)
    }

    pub fn from_validated_ledger_tip(ledger: &Ledger) -> Result<Self, GenesisError> {
        ledger.validate_supply()?;
        let commitment = ledger
            .tip_state_commitment()?
            .ok_or(GenesisError::InvalidStateCommitment)?;
        if ledger.tip_height() != Some(commitment.height)
            || ledger.tip_hash() != Some(commitment.block_hash)
            || !commitment.matches_protocol_root()?
        {
            return Err(GenesisError::InvalidStateCommitment);
        }
        if commitment.height != Height(0) {
            let tip = ledger
                .block(&commitment.height)
                .ok_or(GenesisError::InvalidStateCommitment)?;
            if tip.state_root() != commitment.protocol_state_root {
                return Err(GenesisError::InvalidStateCommitment);
            }
        }
        Ok(Self {
            height: commitment.height,
            block_hash: commitment.block_hash,
            protocol_state_root: commitment.protocol_state_root,
        })
    }

    pub fn height(self) -> Height {
        self.height
    }

    pub fn block_hash(self) -> BlockHash {
        self.block_hash
    }

    pub fn protocol_state_root(self) -> crate::crypto::StateRoot {
        self.protocol_state_root
    }

    fn validate_commitment(
        self,
        height: Height,
        block_hash: BlockHash,
        protocol_state_root: crate::crypto::StateRoot,
    ) -> Result<(), GenesisError> {
        if height != self.height
            || block_hash != self.block_hash
            || protocol_state_root != self.protocol_state_root
        {
            return Err(GenesisError::TrustAnchorMismatch);
        }
        Ok(())
    }
}

impl ChainParamsArtifact {
    pub fn from_chain_params(params: ChainParams) -> Result<Self, CodecError> {
        Ok(Self {
            chain_name: params.chain_name.to_owned(),
            patch_name: params.patch_name.to_owned(),
            chain_id: params.chain_id,
            coin_name: params.coin_name.to_owned(),
            unit_name: params.unit_name.to_owned(),
            protocol_stage: params.protocol_stage.to_owned(),
            protocol_version: params.protocol_version,
            pow_algorithm: params.pow_algorithm.to_owned(),
            pow_memory_kib: params.pow_memory_kib,
            pow_iterations: params.pow_iterations,
            pow_lanes: params.pow_lanes,
            difficulty_algorithm: params.difficulty_algorithm.to_owned(),
            network_magic: params.network_magic,
        })
    }

    pub fn matches_chain_params(&self, params: ChainParams) -> Result<bool, CodecError> {
        Ok(self == &Self::from_chain_params(params)?)
    }
}

impl ChainSpecArtifact {
    pub fn from_chain_params(params: ChainParams) -> Result<Self, CodecError> {
        Ok(Self {
            params: ChainParamsArtifact::from_chain_params(params)?,
            genesis_nonce: params.genesis.nonce,
            genesis_hash: genesis_hash_for_chain(params)?.0,
            block_version: crate::block::BLOCK_VERSION,
            max_block_size: crate::block::MAX_BLOCK_SIZE as u64,
            max_block_weight: crate::block::MAX_BLOCK_WEIGHT as u64,
            max_block_decode_items: crate::block::MAX_BLOCK_DECODE_ITEMS as u64,
            min_difficulty: MIN_DIFFICULTY,
            difficulty_start: DIFFICULTY_START,
            wbda_window: WBDA_WINDOW as u64,
            wbda_target_block_weight: crate::consensus::WBDA_TARGET_BLOCK_WEIGHT as u64,
            wbda_low_utilization_ppm: WBDA_LOW_UTILIZATION_PPM,
            wbda_high_utilization_ppm: WBDA_HIGH_UTILIZATION_PPM,
            confirmation_depth: CONFIRMATION_DEPTH,
            finality_depth: FINALITY_DEPTH,
            block_reward_maturity: BLOCK_REWARD_MATURITY,
            qcash_redeem_credit_maturity: QCASH_REDEEM_CREDIT_MATURITY,
            qcash_redeem_delay: QCASH_REDEEM_DELAY,
            unit: UNIT,
            xpq: XPQ,
            decimals: DECIMALS,
            base_block_reward: BASE_BLOCK_REWARD,
            min_block_reward: MIN_BLOCK_REWARD,
            max_block_reward: MAX_BLOCK_REWARD,
            block_reward_step: BLOCK_REWARD_STEP,
        })
    }

    pub fn matches_chain_params(&self, params: ChainParams) -> Result<bool, CodecError> {
        Ok(self == &Self::from_chain_params(params)?)
    }
}

impl XPARQArtifact {
    pub fn new(kind: XPARQArtifactKind, payload: Vec<u8>) -> Self {
        Self {
            magic: XPARQ_ARTIFACT_MAGIC,
            version: XPARQ_ARTIFACT_VERSION,
            kind,
            payload_hash: artifact_payload_hash(&payload),
            payload,
        }
    }

    pub fn validate_header(&self, kind: XPARQArtifactKind) -> Result<(), GenesisError> {
        if self.magic != XPARQ_ARTIFACT_MAGIC {
            return Err(GenesisError::InvalidArtifact);
        }
        if self.version != XPARQ_ARTIFACT_VERSION {
            return Err(GenesisError::InvalidArtifactVersion);
        }
        if self.kind != kind {
            return Err(GenesisError::InvalidArtifactKind);
        }
        if self.payload_hash != artifact_payload_hash(&self.payload) {
            return Err(GenesisError::InvalidPayloadHash);
        }
        Ok(())
    }
}

pub fn artifact_payload_hash(payload: &[u8]) -> Hash {
    domain_hash(HashDomain::XPARQArtifact, payload)
}

pub fn chain_spec_hash(spec: &ChainSpecArtifact) -> Result<Hash, CodecError> {
    Ok(domain_hash(HashDomain::ChainSpec, &canonical_bytes(spec)?))
}

pub fn current_chain_spec_artifact() -> Result<ChainSpecArtifact, CodecError> {
    ChainSpecArtifact::from_chain_params(CURRENT_CHAIN_PARAMS)
}

pub fn create_genesis_artifact() -> Result<GenesisArtifact, GenesisError> {
    create_genesis_artifact_for_chain(CURRENT_CHAIN_PARAMS)
}

pub fn create_genesis_artifact_for_chain(
    params: ChainParams,
) -> Result<GenesisArtifact, GenesisError> {
    let block = genesis_block_for_chain(params)?;
    let block_hash = block.hash()?;
    let ledger = genesis_ledger_for_chain(params)?;
    let state_commitment = ledger
        .tip_state_commitment()?
        .ok_or(GenesisError::InvalidStateCommitment)?;
    let chain_spec = ChainSpecArtifact::from_chain_params(params)?;
    let chain_spec_hash = chain_spec_hash(&chain_spec)?;
    Ok(GenesisArtifact {
        params: ChainParamsArtifact::from_chain_params(params)?,
        chain_spec,
        chain_spec_hash,
        block,
        block_hash,
        state_commitment,
    })
}

pub fn validate_genesis_artifact(artifact: &GenesisArtifact) -> Result<(), GenesisError> {
    if !artifact.params.matches_chain_params(CURRENT_CHAIN_PARAMS)? {
        return Err(GenesisError::InvalidNetwork);
    }
    if !artifact
        .chain_spec
        .matches_chain_params(CURRENT_CHAIN_PARAMS)?
        || artifact.chain_spec.params != artifact.params
        || artifact.chain_spec_hash != chain_spec_hash(&artifact.chain_spec)?
    {
        return Err(GenesisError::InvalidNetwork);
    }
    if artifact.block.height() != Height(0) {
        return Err(GenesisError::InvalidArtifact);
    }
    let found = artifact.block.hash()?;
    if found != artifact.block_hash {
        return Err(GenesisError::HashMismatch {
            expected: artifact.block_hash.0,
            found: found.0,
        });
    }
    let expected_genesis_hash = genesis_hash_for_chain(CURRENT_CHAIN_PARAMS)?.0;
    if artifact.block_hash.0 != expected_genesis_hash {
        return Err(GenesisError::HashMismatch {
            expected: expected_genesis_hash,
            found: artifact.block_hash.0,
        });
    }
    let expected = create_genesis_artifact()?;
    if artifact.state_commitment != expected.state_commitment {
        return Err(GenesisError::InvalidStateCommitment);
    }
    if artifact.state_commitment.height != Height(0)
        || artifact.state_commitment.block_hash != artifact.block_hash
        || !artifact.state_commitment.matches_protocol_root()?
    {
        return Err(GenesisError::InvalidStateCommitment);
    }
    Ok(())
}

pub fn encode_xparq_artifact(artifact: &XPARQArtifact) -> Result<Vec<u8>, CodecError> {
    canonical_bytes(artifact)
}

pub fn decode_xparq_artifact(bytes: &[u8]) -> Result<XPARQArtifact, CodecError> {
    if bytes.len() > MAX_XPARQ_ARTIFACT_SIZE {
        return Err(CodecError::DecodeFailed);
    }
    canonical_deserialize(bytes)
}

pub fn genesis_xparq_bytes() -> Result<Vec<u8>, GenesisError> {
    let genesis = create_genesis_artifact()?;
    let payload = canonical_bytes(&genesis)?;
    Ok(encode_xparq_artifact(&XPARQArtifact::new(
        XPARQArtifactKind::Genesis,
        payload,
    ))?)
}

pub fn decode_genesis_xparq(bytes: &[u8]) -> Result<GenesisArtifact, GenesisError> {
    let artifact = decode_xparq_artifact(bytes).map_err(|_| GenesisError::InvalidArtifact)?;
    artifact.validate_header(XPARQArtifactKind::Genesis)?;
    let genesis: GenesisArtifact =
        canonical_deserialize(&artifact.payload).map_err(|_| GenesisError::InvalidArtifact)?;
    validate_genesis_artifact(&genesis)?;
    Ok(genesis)
}

pub fn create_snapshot_artifact(ledger: &Ledger) -> Result<SnapshotArtifact, GenesisError> {
    let height = ledger
        .tip_height()
        .ok_or(GenesisError::InvalidStateCommitment)?;
    let block_hash = ledger
        .tip_hash()
        .ok_or(GenesisError::InvalidStateCommitment)?;
    let state_commitment = ledger
        .tip_state_commitment()?
        .ok_or(GenesisError::InvalidStateCommitment)?;
    Ok(SnapshotArtifact {
        params: ChainParamsArtifact::from_chain_params(CURRENT_CHAIN_PARAMS)?,
        chain_spec_hash: chain_spec_hash(&current_chain_spec_artifact()?)?,
        height,
        block_hash,
        state_commitment,
        accounts: ledger.accounts().clone(),
        xpq_utxos: ledger.xpq_utxos.clone(),
        qcash_utxos: ledger.qcash_utxos.clone(),
    })
}

/// Validates internal consistency only.
///
/// This does not authenticate the snapshot against the canonical PoW chain.
/// Use [`decode_snapshot_XPARQ`] with an [`ArtifactTrustAnchor`] before import.
pub fn validate_snapshot_artifact(snapshot: &SnapshotArtifact) -> Result<(), GenesisError> {
    if !snapshot.params.matches_chain_params(CURRENT_CHAIN_PARAMS)? {
        return Err(GenesisError::InvalidNetwork);
    }
    if snapshot.chain_spec_hash != chain_spec_hash(&current_chain_spec_artifact()?)? {
        return Err(GenesisError::InvalidNetwork);
    }
    if snapshot.state_commitment.height != snapshot.height
        || snapshot.state_commitment.block_hash != snapshot.block_hash
    {
        return Err(GenesisError::InvalidStateCommitment);
    }

    let account_state_root = SparseStateTree::from_accounts(&snapshot.accounts)?.root();
    let xpq_state_root = crate::crypto::StateRoot(
        snapshot
            .xpq_utxos
            .consensus_root()
            .map_err(|_| GenesisError::InvalidStateCommitment)?
            .0,
    );
    let qcash_state_root = crate::crypto::StateRoot(snapshot.qcash_utxos.consensus_root()?.0);
    let protocol_state_root = calculate_protocol_state_root_from_roots(
        account_state_root,
        xpq_state_root,
        qcash_state_root,
    )?;

    if snapshot.state_commitment.account_state_root != account_state_root
        || snapshot.state_commitment.xpq_state_root != xpq_state_root
        || snapshot.state_commitment.qcash_state_root != qcash_state_root
        || snapshot.state_commitment.protocol_state_root != protocol_state_root
        || !snapshot.state_commitment.matches_protocol_root()?
    {
        return Err(GenesisError::InvalidStateCommitment);
    }

    let xpq_supply = snapshot
        .xpq_utxos
        .total_value()
        .map_err(|_| GenesisError::InvalidStateCommitment)?
        .0;
    let qcash_supply = snapshot
        .qcash_utxos
        .total_value()
        .map_err(|_| GenesisError::InvalidStateCommitment)?
        .0;
    let economic_supply = xpq_supply
        .checked_add(qcash_supply)
        .ok_or(GenesisError::InvalidStateCommitment)?;
    // The authenticated header chain is required to validate dynamic epoch
    // issuance; internal snapshot validation can only check state consistency.
    let _ = economic_supply;

    Ok(())
}

pub fn snapshot_xparq_bytes(ledger: &Ledger) -> Result<Vec<u8>, GenesisError> {
    let snapshot = create_snapshot_artifact(ledger)?;
    let payload = canonical_bytes(&snapshot)?;
    Ok(encode_xparq_artifact(&XPARQArtifact::new(
        XPARQArtifactKind::Snapshot,
        payload,
    ))?)
}

/// Decodes a snapshot and binds it to independently validated local chain state.
///
/// There is deliberately no overload accepting a raw `BlockHash`: a hash read
/// from the artifact itself is not a trust anchor.
pub fn decode_snapshot_xparq(
    bytes: &[u8],
    trust_anchor: &ArtifactTrustAnchor,
) -> Result<SnapshotArtifact, GenesisError> {
    let artifact = decode_xparq_artifact(bytes).map_err(|_| GenesisError::InvalidArtifact)?;
    artifact.validate_header(XPARQArtifactKind::Snapshot)?;
    let snapshot: SnapshotArtifact =
        canonical_deserialize(&artifact.payload).map_err(|_| GenesisError::InvalidArtifact)?;
    validate_snapshot_artifact(&snapshot)?;
    trust_anchor.validate_commitment(
        snapshot.height,
        snapshot.block_hash,
        snapshot.state_commitment.protocol_state_root,
    )?;
    Ok(snapshot)
}

/// Builds a usable pruned ledger after independently authenticating both the
/// PoW header chain and every snapshot state commitment.
pub fn ledger_from_authenticated_snapshot(
    bytes: &[u8],
    headers: &[ChainHeader],
) -> Result<(Ledger, Work), GenesisError> {
    let (anchor, work) = ArtifactTrustAnchor::from_verified_header_chain(headers)
        .map_err(|_| GenesisError::InvalidArtifact)?;
    let snapshot = decode_snapshot_xparq(bytes, &anchor)?;
    let supply_headers = headers
        .iter()
        .map(|header| header.header.clone())
        .collect::<Vec<_>>();
    let expected_supply =
        crate::ledger::ledger::expected_issued_supply_from_headers(&supply_headers)
            .map_err(|_| GenesisError::InvalidStateCommitment)?;
    let snapshot_supply = snapshot
        .xpq_utxos
        .total_value()
        .ok()
        .and_then(|xpq| {
            snapshot
                .qcash_utxos
                .total_value()
                .ok()
                .and_then(|cash| xpq.0.checked_add(cash.0))
        })
        .ok_or(GenesisError::InvalidStateCommitment)?;
    if snapshot_supply != expected_supply.0 {
        return Err(GenesisError::InvalidStateCommitment);
    }
    let ledger = Ledger::from_snapshot_parts(
        snapshot.accounts,
        snapshot.xpq_utxos,
        snapshot.qcash_utxos,
        headers,
    )?;
    crate::ledger::validate_ledger_invariants(&ledger)
        .map_err(|_| GenesisError::InvalidStateCommitment)?;
    let commitment = ledger
        .tip_state_commitment()?
        .ok_or(GenesisError::InvalidStateCommitment)?;
    if commitment != snapshot.state_commitment {
        return Err(GenesisError::InvalidStateCommitment);
    }
    Ok((ledger, work))
}

pub fn create_checkpoint_artifact(
    ledger: &Ledger,
    cumulative_work: Work,
    ancestor_hashes: Vec<BlockHash>,
) -> Result<CheckpointArtifact, GenesisError> {
    let height = ledger
        .tip_height()
        .ok_or(GenesisError::InvalidStateCommitment)?;
    let block_hash = ledger
        .tip_hash()
        .ok_or(GenesisError::InvalidStateCommitment)?;
    let block = ledger
        .block(&height)
        .ok_or(GenesisError::InvalidStateCommitment)?;
    let state_commitment = ledger
        .tip_state_commitment()?
        .ok_or(GenesisError::InvalidStateCommitment)?;
    Ok(CheckpointArtifact {
        params: ChainParamsArtifact::from_chain_params(CURRENT_CHAIN_PARAMS)?,
        chain_spec_hash: chain_spec_hash(&current_chain_spec_artifact()?)?,
        height,
        block_hash,
        state_commitment,
        cumulative_work,
        difficulty: block.difficulty(),
        ancestor_hashes,
    })
}

/// Validates internal consistency only.
///
/// This does not prove that the claimed work belongs to the canonical chain.
/// Use [`decode_checkpoint_XPARQ`] with an [`ArtifactTrustAnchor`] before use.
pub fn validate_checkpoint_artifact(checkpoint: &CheckpointArtifact) -> Result<(), GenesisError> {
    if !checkpoint
        .params
        .matches_chain_params(CURRENT_CHAIN_PARAMS)?
    {
        return Err(GenesisError::InvalidNetwork);
    }
    if checkpoint.chain_spec_hash != chain_spec_hash(&current_chain_spec_artifact()?)? {
        return Err(GenesisError::InvalidNetwork);
    }
    if checkpoint.state_commitment.height != checkpoint.height
        || checkpoint.state_commitment.block_hash != checkpoint.block_hash
        || !checkpoint.state_commitment.matches_protocol_root()?
    {
        return Err(GenesisError::InvalidStateCommitment);
    }
    if checkpoint.height == Height(0) {
        let expected_genesis_hash = genesis_hash_for_chain(CURRENT_CHAIN_PARAMS)?.0;
        if checkpoint.block_hash.0 != expected_genesis_hash {
            return Err(GenesisError::HashMismatch {
                expected: expected_genesis_hash,
                found: checkpoint.block_hash.0,
            });
        }
    } else if checkpoint.cumulative_work == Work::ZERO {
        return Err(GenesisError::InvalidStateCommitment);
    }
    if checkpoint
        .ancestor_hashes
        .windows(2)
        .any(|window| window[0] == window[1])
    {
        return Err(GenesisError::InvalidArtifact);
    }
    Ok(())
}

pub fn checkpoint_xparq_bytes(
    ledger: &Ledger,
    cumulative_work: Work,
    ancestor_hashes: Vec<BlockHash>,
) -> Result<Vec<u8>, GenesisError> {
    let checkpoint = create_checkpoint_artifact(ledger, cumulative_work, ancestor_hashes)?;
    let payload = canonical_bytes(&checkpoint)?;
    Ok(encode_xparq_artifact(&XPARQArtifact::new(
        XPARQArtifactKind::Checkpoint,
        payload,
    ))?)
}

/// Decodes a checkpoint and binds it to independently validated local state.
///
/// Remote checkpoint sync remains intentionally unsupported until its
/// header/PoW-chain verifier can construct a separately audited trust anchor.
pub fn decode_checkpoint_xparq(
    bytes: &[u8],
    trust_anchor: &ArtifactTrustAnchor,
) -> Result<CheckpointArtifact, GenesisError> {
    let artifact = decode_xparq_artifact(bytes).map_err(|_| GenesisError::InvalidArtifact)?;
    artifact.validate_header(XPARQArtifactKind::Checkpoint)?;
    let checkpoint: CheckpointArtifact =
        canonical_deserialize(&artifact.payload).map_err(|_| GenesisError::InvalidArtifact)?;
    validate_checkpoint_artifact(&checkpoint)?;
    trust_anchor.validate_commitment(
        checkpoint.height,
        checkpoint.block_hash,
        checkpoint.state_commitment.protocol_state_root,
    )?;
    Ok(checkpoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_xparq_roundtrip_validates() {
        let bytes = genesis_xparq_bytes().unwrap();
        let decoded = decode_genesis_xparq(&bytes).unwrap();

        assert_eq!(decoded.block.height(), Height(0));
        assert_eq!(
            decoded.block_hash.0,
            genesis_hash_for_chain(CURRENT_CHAIN_PARAMS).unwrap().0
        );
        assert_eq!(decoded.chain_spec.params, decoded.params);
        assert_eq!(
            decoded.chain_spec_hash,
            chain_spec_hash(&decoded.chain_spec).unwrap()
        );
        assert!(decoded.state_commitment.matches_protocol_root().unwrap());
    }

    #[test]
    fn genesis_artifact_rejects_chain_spec_tampering() {
        let mut genesis = create_genesis_artifact().unwrap();
        genesis.chain_spec.max_block_size += 1;

        assert_eq!(
            validate_genesis_artifact(&genesis),
            Err(GenesisError::InvalidNetwork)
        );
    }

    #[test]
    fn genesis_xparq_rejects_payload_tampering() {
        let mut bytes = genesis_xparq_bytes().unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;

        assert_eq!(
            decode_genesis_xparq(&bytes),
            Err(GenesisError::InvalidPayloadHash)
        );
    }

    #[test]
    fn snapshot_xparq_roundtrip_validates() {
        let ledger = genesis_ledger_for_chain(CURRENT_CHAIN_PARAMS).unwrap();
        let bytes = snapshot_xparq_bytes(&ledger).unwrap();
        let anchor = ArtifactTrustAnchor::from_validated_ledger_tip(&ledger).unwrap();
        let decoded = decode_snapshot_xparq(&bytes, &anchor).unwrap();

        assert_eq!(decoded.height, Height(0));
        assert_eq!(
            decoded.block_hash.0,
            genesis_hash_for_chain(CURRENT_CHAIN_PARAMS).unwrap().0
        );
        assert_eq!(
            decoded.chain_spec_hash,
            chain_spec_hash(&current_chain_spec_artifact().unwrap()).unwrap()
        );
        assert_eq!(decoded.accounts, ledger.accounts().clone());
        assert!(decoded.state_commitment.matches_protocol_root().unwrap());
    }

    #[test]
    fn snapshot_requires_matching_validated_trust_anchor() {
        let ledger = genesis_ledger_for_chain(CURRENT_CHAIN_PARAMS).unwrap();
        let bytes = snapshot_xparq_bytes(&ledger).unwrap();
        let mut anchor = ArtifactTrustAnchor::from_validated_ledger_tip(&ledger).unwrap();
        anchor.block_hash = BlockHash([0x55; crate::crypto::HASH_SIZE]);
        assert!(matches!(
            decode_snapshot_xparq(&bytes, &anchor),
            Err(GenesisError::TrustAnchorMismatch)
        ));
    }

    #[test]
    fn snapshot_accepts_anchor_from_verified_genesis_headers() {
        let ledger = genesis_ledger_for_chain(CURRENT_CHAIN_PARAMS).unwrap();
        let bytes = snapshot_xparq_bytes(&ledger).unwrap();
        let headers = ledger
            .chain
            .blocks
            .values()
            .map(|block| ChainHeader::new(block.height(), block.header.clone()))
            .collect::<Vec<_>>();
        let (anchor, _work) = ArtifactTrustAnchor::from_verified_header_chain(&headers).unwrap();

        let snapshot = decode_snapshot_xparq(&bytes, &anchor).unwrap();
        assert_eq!(snapshot.height, Height(0));
    }

    #[test]
    fn header_anchor_rejects_chain_not_rooted_at_configured_genesis() {
        let ledger = genesis_ledger_for_chain(CURRENT_CHAIN_PARAMS).unwrap();
        let mut headers = ledger
            .chain
            .blocks
            .values()
            .map(|block| ChainHeader::new(block.height(), block.header.clone()))
            .collect::<Vec<_>>();
        headers[0].header.merkle_root.0[0] ^= 1;

        assert!(ArtifactTrustAnchor::from_verified_header_chain(&headers).is_err());
    }

    #[test]
    fn authenticated_snapshot_pins_reorg_boundary() {
        let ledger = genesis_ledger_for_chain(CURRENT_CHAIN_PARAMS).unwrap();
        let bytes = snapshot_xparq_bytes(&ledger).unwrap();
        let headers = ledger.chain.chain_headers().unwrap();
        let (mut restored, _) = ledger_from_authenticated_snapshot(&bytes, &headers).unwrap();

        assert_eq!(restored.chain.checkpoint_height, Some(Height(0)));
        assert!(
            restored
                .chain
                .remove_tip(restored.tip_hash().unwrap())
                .is_err()
        );
    }

    #[test]
    fn snapshot_artifact_rejects_chain_spec_hash_tampering() {
        let ledger = genesis_ledger_for_chain(CURRENT_CHAIN_PARAMS).unwrap();
        let mut snapshot = create_snapshot_artifact(&ledger).unwrap();
        snapshot.chain_spec_hash.0[0] ^= 1;

        assert_eq!(
            validate_snapshot_artifact(&snapshot),
            Err(GenesisError::InvalidNetwork)
        );
    }

    #[test]
    fn snapshot_xparq_rejects_state_tampering() {
        let ledger = genesis_ledger_for_chain(CURRENT_CHAIN_PARAMS).unwrap();
        let mut snapshot = create_snapshot_artifact(&ledger).unwrap();
        snapshot.state_commitment.protocol_state_root.0[0] ^= 1;

        assert_eq!(
            validate_snapshot_artifact(&snapshot),
            Err(GenesisError::InvalidStateCommitment)
        );
    }

    #[test]
    fn checkpoint_xparq_roundtrip_validates() {
        let ledger = genesis_ledger_for_chain(CURRENT_CHAIN_PARAMS).unwrap();
        let bytes = checkpoint_xparq_bytes(&ledger, Work::ZERO, Vec::new()).unwrap();
        let anchor = ArtifactTrustAnchor::from_validated_ledger_tip(&ledger).unwrap();
        let decoded = decode_checkpoint_xparq(&bytes, &anchor).unwrap();

        assert_eq!(decoded.height, Height(0));
        assert_eq!(
            decoded.block_hash.0,
            genesis_hash_for_chain(CURRENT_CHAIN_PARAMS).unwrap().0
        );
        assert_eq!(
            decoded.chain_spec_hash,
            chain_spec_hash(&current_chain_spec_artifact().unwrap()).unwrap()
        );
        assert_eq!(decoded.cumulative_work, Work::ZERO);
        assert!(decoded.state_commitment.matches_protocol_root().unwrap());
    }

    #[test]
    fn checkpoint_requires_matching_validated_trust_anchor() {
        let ledger = genesis_ledger_for_chain(CURRENT_CHAIN_PARAMS).unwrap();
        let bytes = checkpoint_xparq_bytes(&ledger, Work::ZERO, Vec::new()).unwrap();
        let mut anchor = ArtifactTrustAnchor::from_validated_ledger_tip(&ledger).unwrap();
        anchor.block_hash = BlockHash([0x66; crate::crypto::HASH_SIZE]);
        assert!(matches!(
            decode_checkpoint_xparq(&bytes, &anchor),
            Err(GenesisError::TrustAnchorMismatch)
        ));
    }

    #[test]
    fn checkpoint_xparq_rejects_payload_tampering() {
        let ledger = genesis_ledger_for_chain(CURRENT_CHAIN_PARAMS).unwrap();
        let mut bytes = checkpoint_xparq_bytes(&ledger, Work::ZERO, Vec::new()).unwrap();
        let anchor = ArtifactTrustAnchor::from_validated_ledger_tip(&ledger).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;

        assert_eq!(
            decode_checkpoint_xparq(&bytes, &anchor),
            Err(GenesisError::InvalidPayloadHash)
        );
    }
}
