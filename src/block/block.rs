use crate::codec::{HashDomain, block_bytes, block_header_hash, canonical_bytes, domain_hash};
use crate::consensus::supply::Amount;
use crate::consensus::{DIFFICULTY_START, MAX_FUTURE_TIME};
use crate::crypto::{Address, PublicKey, Signature};
use crate::crypto::{
    BlockHash, HASH_SIZE, Hash, MerkleHash, PreviousHash, StateRoot, TransactionHash,
    WitnessMerkleHash, WitnessTransactionHash,
};
pub use crate::error::BlockError;
use crate::governance::{GovernanceAction, SignedGovernanceAction};
use crate::transaction::{
    QCashTransaction, SignedProtocolTransaction, SignedQCashTransaction, SignedTransaction,
    Transaction, Witness,
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{Error as IoError, ErrorKind, Read, Write};

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
    PartialOrd,
    Ord,
    Hash,
)]
pub struct Height(pub u64);

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
    PartialOrd,
    Ord,
    Hash,
)]
pub struct Nonce(pub u64);

pub type BlockHeight = Height;
pub type BlockNonce = Nonce;

pub const MAX_BLOCK_SIZE: usize = 5 * 1024 * 1024;
pub const BLOCK_VERSION: u8 = 1;
/// Witness bytes receive no consensus fee/weight discount. Keeping this
/// factor explicit preserves the existing weight API while making weight and
/// virtual size equal to the complete serialized transaction size.
pub const WITNESS_SCALE_FACTOR: usize = 1;
pub const MAX_BLOCK_WEIGHT: usize = MAX_BLOCK_SIZE * WITNESS_SCALE_FACTOR;
/// A dual-signature transaction cannot practically fill more than this count
/// within `MAX_BLOCK_WEIGHT`. Keep this explicit so hostile length prefixes
/// cannot amplify a small wire message into multi-gigabyte allocations.
pub const MAX_BLOCK_DECODE_ITEMS: usize = 4_096;
pub const MAX_BLOCK_WITNESS_KEYS: usize = MAX_BLOCK_DECODE_ITEMS * 2;
pub const MAX_GENESIS_ALLOCATIONS: usize = 4_096;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlockHeader {
    pub version: u8,
    pub height: BlockHeight,
    pub previous_hash: PreviousHash,
    pub merkle_root: MerkleHash,
    pub witness_root: WitnessMerkleHash,
    pub state_root: StateRoot,
    pub chain_commitment: Hash,
    pub miner_address: Address,
    pub difficulty: u32,
    pub timestamp: u64,
    pub nonce: BlockNonce,
}

impl BlockHeader {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: BlockHeight,
        previous_hash: PreviousHash,
        merkle_root: MerkleHash,
        witness_root: WitnessMerkleHash,
        state_root: StateRoot,
        chain_commitment: Hash,
        miner_address: Address,
        difficulty: u32,
        timestamp: u64,
        nonce: BlockNonce,
    ) -> Self {
        Self {
            version: BLOCK_VERSION,
            height,
            previous_hash,
            merkle_root,
            witness_root,
            state_root,
            chain_commitment,
            miner_address,
            difficulty,
            timestamp,
            nonce,
        }
    }

    pub fn hash(&self) -> Result<BlockHash, crate::error::CodecError> {
        block_header_hash(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Block {
    pub header: BlockHeader,
    pub genesis_allocations: Vec<GenesisAllocation>,
    pub coinbase: Option<CoinbaseTransaction>,
    pub transactions: Vec<SignedProtocolTransaction>,
}

// Box indirection keeps the in-memory enum compact. Borsh serializes Box<T>
// transparently, preserving the canonical v1 bytes; the explicit 4,096-item
// decode cap independently bounds hostile count prefixes.
#[derive(BorshSerialize, BorshDeserialize)]
enum ProtocolPayload {
    Transfer(Box<Transaction>),
    QCash(Box<QCashTransaction>),
    Governance(Box<GovernanceAction>),
}

static_assertions::const_assert!(
    std::mem::size_of::<ProtocolPayload>() <= 2 * std::mem::size_of::<usize>()
);

/// Consensus encoding keeps the ordered payload list before its witness list.
impl BorshSerialize for Block {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        serialize_stripped_block(self, writer)?;
        let keys = witness_dictionary(self);
        BorshSerialize::serialize(&keys, writer)?;
        serialize_indexed_protocol_witnesses(&self.transactions, &keys, writer)
    }
}

pub(crate) fn serialize_stripped_block<W: Write>(
    block: &Block,
    writer: &mut W,
) -> std::io::Result<()> {
    block.header.serialize(writer)?;
    block.genesis_allocations.serialize(writer)?;
    block.coinbase.serialize(writer)?;
    let payloads = block
        .transactions
        .iter()
        .map(|tx| match tx {
            SignedProtocolTransaction::Transfer(tx) => {
                ProtocolPayload::Transfer(Box::new(tx.transaction.clone()))
            }
            SignedProtocolTransaction::QCash(tx) => {
                ProtocolPayload::QCash(Box::new(tx.transaction.clone()))
            }
            SignedProtocolTransaction::Governance(tx) => {
                ProtocolPayload::Governance(Box::new(tx.action.clone()))
            }
        })
        .collect::<Vec<_>>();
    payloads.serialize(writer)
}

impl BorshDeserialize for Block {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let header = BlockHeader::deserialize_reader(reader)?;
        let genesis_allocations =
            deserialize_limited_vec::<GenesisAllocation, _>(reader, MAX_GENESIS_ALLOCATIONS)?;
        let coinbase = Option::<CoinbaseTransaction>::deserialize_reader(reader)?;

        let payloads =
            deserialize_limited_vec::<ProtocolPayload, _>(reader, MAX_BLOCK_DECODE_ITEMS)?;

        let keys = deserialize_limited_vec::<PublicKey, _>(reader, MAX_BLOCK_WITNESS_KEYS)?;
        if keys
            .iter()
            .enumerate()
            .any(|(index, key)| keys[..index].contains(key))
        {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                "duplicate witness dictionary key",
            ));
        }
        let witnesses = decode_indexed_single_key_witnesses(reader, &keys, payloads.len())?;

        let block = Self {
            header,
            genesis_allocations,
            coinbase,
            transactions: zip_witnesses(payloads, witnesses, |payload, witness| match payload {
                ProtocolPayload::Transfer(transaction) => {
                    SignedProtocolTransaction::from(SignedTransaction {
                        transaction: *transaction,
                        witness,
                    })
                }
                ProtocolPayload::QCash(transaction) => {
                    SignedProtocolTransaction::from(SignedQCashTransaction {
                        transaction: *transaction,
                        witness,
                    })
                }
                ProtocolPayload::Governance(action) => {
                    SignedProtocolTransaction::from(SignedGovernanceAction {
                        action: *action,
                        witness,
                    })
                }
            })?,
        };
        if witness_dictionary(&block) != keys {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                "non-canonical witness dictionary",
            ));
        }
        Ok(block)
    }
}

#[derive(BorshSerialize, BorshDeserialize)]
struct IndexedWitness {
    key_indexes: Option<(u32, u32)>,
    signature: Signature,
    auth_signature: Signature,
}

fn witness_dictionary(block: &Block) -> Vec<PublicKey> {
    let mut keys = Vec::new();
    for transaction in &block.transactions {
        for key in transaction.witness_public_keys_all() {
            if !keys.contains(key) {
                keys.push(*key);
            }
        }
    }
    keys
}

fn witness_key_index(keys: &[PublicKey], key: &PublicKey) -> std::io::Result<u32> {
    keys.iter()
        .position(|candidate| candidate == key)
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "missing witness key"))
        .and_then(|index| {
            u32::try_from(index)
                .map_err(|_| IoError::new(ErrorKind::InvalidData, "too many witness keys"))
        })
}

fn serialize_indexed_protocol_witnesses<W>(
    values: &[SignedProtocolTransaction],
    keys: &[PublicKey],
    writer: &mut W,
) -> std::io::Result<()>
where
    W: Write,
{
    let indexed = values
        .iter()
        .map(|value| {
            let witness = value.witness();
            let key_indexes = if witness.carries_registration_keys() {
                Some((
                    witness_key_index(keys, &witness.public_key)?,
                    witness_key_index(keys, &witness.auth_public_key)?,
                ))
            } else if witness.uses_stored_keys() {
                None
            } else {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "witness must carry both public keys or neither",
                ));
            };
            Ok(IndexedWitness {
                key_indexes,
                signature: witness.signature,
                auth_signature: witness.auth_signature,
            })
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    indexed.serialize(writer)
}

fn decode_indexed_single_key_witnesses<R: Read>(
    reader: &mut R,
    keys: &[PublicKey],
    limit: usize,
) -> std::io::Result<Vec<Witness>> {
    deserialize_limited_vec::<IndexedWitness, _>(reader, limit)?
        .into_iter()
        .map(|indexed| {
            let (public_key, auth_public_key) = match indexed.key_indexes {
                Some((key_index, auth_key_index)) => (
                    keys.get(key_index as usize).copied().ok_or_else(|| {
                        IoError::new(ErrorKind::InvalidData, "witness key index out of range")
                    })?,
                    keys.get(auth_key_index as usize).copied().ok_or_else(|| {
                        IoError::new(
                            ErrorKind::InvalidData,
                            "witness auth key index out of range",
                        )
                    })?,
                ),
                None => (
                    PublicKey([0; crate::crypto::PUBLIC_KEY_SIZE]),
                    PublicKey([0; crate::crypto::PUBLIC_KEY_SIZE]),
                ),
            };
            Ok(Witness {
                public_key,
                auth_public_key,
                signature: indexed.signature,
                auth_signature: indexed.auth_signature,
            })
        })
        .collect()
}

fn deserialize_limited_vec<T, R>(reader: &mut R, limit: usize) -> std::io::Result<Vec<T>>
where
    T: BorshDeserialize,
    R: Read,
{
    let length = u32::deserialize_reader(reader)? as usize;
    if length > limit {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "block section length exceeds limit",
        ));
    }

    // Never reserve the attacker-provided length up front. Large protocol
    // enums make wire-length-to-memory amplification otherwise severe.
    let mut values = Vec::new();
    values
        .try_reserve(length.min(64))
        .map_err(|_| IoError::new(ErrorKind::OutOfMemory, "block section allocation failed"))?;
    for _ in 0..length {
        values.push(T::deserialize_reader(reader)?);
    }
    Ok(values)
}

fn zip_witnesses<T, W, S, F>(
    transactions: Vec<T>,
    witnesses: Vec<W>,
    combine: F,
) -> std::io::Result<Vec<S>>
where
    F: Fn(T, W) -> S,
{
    if transactions.len() != witnesses.len() {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "transaction and witness section lengths differ",
        ));
    }
    Ok(transactions
        .into_iter()
        .zip(witnesses)
        .map(|(action, witness)| combine(action, witness))
        .collect())
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct GenesisAllocation {
    pub to: Address,
    pub amount: Amount,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct CoinbaseTransaction {
    pub to: Address,
    pub subsidy: Amount,
    pub fees: Amount,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinerRevenue {
    pub subsidy: Amount,
    pub fees: Amount,
}

impl GenesisAllocation {
    pub fn new(to: Address, amount: Amount) -> Self {
        Self { to, amount }
    }

    pub fn hash(&self) -> Result<Hash, crate::error::CodecError> {
        Ok(domain_hash(
            HashDomain::GenesisAllocation,
            &canonical_bytes(self)?,
        ))
    }
}

impl CoinbaseTransaction {
    pub fn new(to: Address, subsidy: Amount, fees: Amount) -> Self {
        Self { to, subsidy, fees }
    }

    pub fn total(&self) -> Amount {
        Amount(self.subsidy.0.saturating_add(self.fees.0))
    }

    pub fn checked_total(&self) -> Result<Amount, BlockError> {
        Ok(Amount(
            self.subsidy
                .0
                .checked_add(self.fees.0)
                .ok_or(BlockError::CoinbaseOverflow)?,
        ))
    }

    pub fn hash(&self) -> Result<Hash, crate::error::CodecError> {
        Ok(domain_hash(HashDomain::Coinbase, &canonical_bytes(self)?))
    }
}

impl Block {
    pub fn transfer_transactions(&self) -> impl Iterator<Item = &SignedTransaction> {
        self.transactions.iter().filter_map(|tx| match tx {
            SignedProtocolTransaction::Transfer(tx) => Some(tx.as_ref()),
            _ => None,
        })
    }

    pub fn qcash_transactions(&self) -> impl Iterator<Item = &SignedQCashTransaction> {
        self.transactions.iter().filter_map(|tx| match tx {
            SignedProtocolTransaction::QCash(tx) => Some(tx.as_ref()),
            _ => None,
        })
    }

    pub fn governance_actions(&self) -> impl Iterator<Item = &SignedGovernanceAction> {
        self.transactions.iter().filter_map(|tx| match tx {
            SignedProtocolTransaction::Governance(tx) => Some(tx.as_ref()),
            _ => None,
        })
    }

    pub fn genesis(
        miner_address: Address,
        timestamp: u64,
        allocations: Vec<GenesisAllocation>,
    ) -> Result<Self, crate::error::CodecError> {
        Self::genesis_with_chain_commitment(
            miner_address,
            timestamp,
            Hash([0; HASH_SIZE]),
            allocations,
        )
    }

    pub fn genesis_with_chain_commitment(
        miner_address: Address,
        timestamp: u64,
        chain_commitment: Hash,
        allocations: Vec<GenesisAllocation>,
    ) -> Result<Self, crate::error::CodecError> {
        Self::from_protocol_transactions_with_chain_commitment(
            Height(0),
            PreviousHash::ZERO,
            miner_address,
            DIFFICULTY_START,
            timestamp,
            Nonce(0),
            chain_commitment,
            allocations,
            None,
            vec![],
        )
    }

    /// Constructs a block from one consensus-ordered protocol transaction list.
    #[allow(clippy::too_many_arguments)]
    pub fn from_protocol_transactions(
        height: BlockHeight,
        previous_hash: impl Into<PreviousHash>,
        miner_address: Address,
        difficulty: u32,
        timestamp: u64,
        nonce: BlockNonce,
        genesis_allocations: Vec<GenesisAllocation>,
        coinbase: Option<CoinbaseTransaction>,
        transactions: Vec<SignedProtocolTransaction>,
    ) -> Result<Self, crate::error::CodecError> {
        Self::from_protocol_transactions_with_chain_commitment(
            height,
            previous_hash,
            miner_address,
            difficulty,
            timestamp,
            nonce,
            Hash([0; HASH_SIZE]),
            genesis_allocations,
            coinbase,
            transactions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_protocol_transactions_with_chain_commitment(
        height: BlockHeight,
        previous_hash: impl Into<PreviousHash>,
        miner_address: Address,
        difficulty: u32,
        timestamp: u64,
        nonce: BlockNonce,
        chain_commitment: Hash,
        genesis_allocations: Vec<GenesisAllocation>,
        coinbase: Option<CoinbaseTransaction>,
        transactions: Vec<SignedProtocolTransaction>,
    ) -> Result<Self, crate::error::CodecError> {
        let previous_hash = previous_hash.into();
        let merkle_root =
            calculate_merkle_root(&genesis_allocations, coinbase.as_ref(), &transactions)?;
        let witness_root = calculate_witness_merkle_root(&transactions)?;
        let state_root = StateRoot::ZERO;
        Ok(Self {
            header: BlockHeader::new(
                height,
                previous_hash,
                merkle_root,
                witness_root,
                state_root,
                chain_commitment,
                miner_address,
                difficulty,
                timestamp,
                nonce,
            ),
            genesis_allocations,
            coinbase,
            transactions,
        })
    }

    pub fn validate_at(&self, now: u64) -> Result<(), BlockError> {
        self.validate_structure()?;
        if self.header.timestamp > now.saturating_add(MAX_FUTURE_TIME as u64) {
            return Err(BlockError::FutureTimestamp);
        }
        Ok(())
    }

    /// Validates deterministic block-local rules only. Wall-clock acceptance
    /// must call `validate_at` with an independently obtained current time.
    pub fn validate_structure(&self) -> Result<(), BlockError> {
        if self.header.version != BLOCK_VERSION {
            return Err(BlockError::UnsupportedVersion);
        }

        if self.is_genesis() {
            if self.coinbase.is_some() {
                return Err(BlockError::UnexpectedCoinbase);
            }
            if self.transaction_count() != 0 {
                return Err(BlockError::InvalidTransaction);
            }
            // Mainnet is a consensus-enforced fair launch. An empty allocation
            // list is required, rather than merely relying on the canonical
            // builder to happen to produce no premine.
            #[cfg(feature = "mainnet")]
            if !self.genesis_allocations.is_empty() {
                return Err(BlockError::InvalidGenesisAllocation);
            }
        } else if self.coinbase.is_none() {
            return Err(BlockError::MissingCoinbase);
        } else if !self.genesis_allocations.is_empty() {
            return Err(BlockError::UnexpectedGenesisAllocation);
        }

        if self.transaction_count() > MAX_BLOCK_DECODE_ITEMS {
            return Err(BlockError::TooManyTransactions);
        }
        if self.genesis_allocations.len() > MAX_GENESIS_ALLOCATIONS {
            return Err(BlockError::InvalidGenesisAllocation);
        }

        if has_duplicate_transactions(&self.transactions)? {
            return Err(BlockError::DuplicateTransaction);
        }

        self.checked_total_fees()?;
        if let Some(coinbase) = &self.coinbase {
            coinbase.checked_total()?;
        }

        if self.stripped_size()? > MAX_BLOCK_SIZE {
            return Err(BlockError::BlockTooLarge);
        }
        if self.weight()? > MAX_BLOCK_WEIGHT {
            return Err(BlockError::BlockTooHeavy);
        }

        if !signed_transactions_are_valid_for_height(&self.transactions, self.height()) {
            return Err(BlockError::InvalidTransaction);
        }

        if let Some(coinbase) = &self.coinbase
            && (coinbase.to != self.header.miner_address
                || coinbase.fees != self.checked_total_fees()?)
        {
            return Err(BlockError::InvalidCoinbase);
        }

        if self
            .genesis_allocations
            .iter()
            .any(|allocation| allocation.amount.0 == 0)
        {
            return Err(BlockError::InvalidGenesisAllocation);
        }

        if self.header.merkle_root
            != calculate_merkle_root(
                &self.genesis_allocations,
                self.coinbase.as_ref(),
                &self.transactions,
            )?
        {
            return Err(BlockError::InvalidMerkleRoot);
        }

        if self.header.witness_root != self.calculate_witness_merkle_root()? {
            return Err(BlockError::InvalidWitnessRoot);
        }

        Ok(())
    }

    pub fn hash(&self) -> Result<BlockHash, crate::error::CodecError> {
        self.header.hash()
    }

    pub fn height(&self) -> BlockHeight {
        self.header.height
    }

    pub fn previous_hash(&self) -> PreviousHash {
        self.header.previous_hash
    }

    pub fn miner_address(&self) -> Address {
        self.header.miner_address
    }

    pub fn state_root(&self) -> StateRoot {
        self.header.state_root
    }

    pub fn set_state_root(&mut self, state_root: impl Into<StateRoot>) {
        self.header.state_root = state_root.into();
    }

    pub fn difficulty(&self) -> u32 {
        self.header.difficulty
    }

    pub fn timestamp(&self) -> u64 {
        self.header.timestamp
    }

    pub fn total_fees(&self) -> Amount {
        self.checked_total_fees().unwrap_or(Amount(u64::MAX))
    }

    pub fn checked_total_fees(&self) -> Result<Amount, BlockError> {
        checked_fees(&self.transactions)
    }

    pub fn miner_revenue(&self, subsidy: Amount) -> MinerRevenue {
        MinerRevenue {
            subsidy,
            fees: self.total_fees(),
        }
    }

    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    pub fn is_genesis(&self) -> bool {
        self.header.height.0 == 0 && self.header.previous_hash == Hash([0; HASH_SIZE])
    }

    pub fn serialized_size(&self) -> Result<usize, crate::error::CodecError> {
        Ok(self.to_bytes()?.len())
    }

    /// Size of the header and transaction payload sections, excluding witness sections.
    pub fn stripped_size(&self) -> Result<usize, crate::error::CodecError> {
        Ok(crate::codec::stripped_block_bytes(self)?.len())
    }

    /// Size of the six witness sections, including their canonical length prefixes.
    pub fn witness_size(&self) -> Result<usize, crate::error::CodecError> {
        Ok(self
            .serialized_size()?
            .saturating_sub(self.stripped_size()?))
    }

    pub fn weight(&self) -> Result<usize, crate::error::CodecError> {
        Ok(self
            .stripped_size()?
            .saturating_mul(WITNESS_SCALE_FACTOR)
            .saturating_add(self.witness_size()?))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::CodecError> {
        block_bytes(self)
    }

    pub fn calculate_merkle_root(&self) -> Result<MerkleHash, crate::error::CodecError> {
        calculate_merkle_root(
            &self.genesis_allocations,
            self.coinbase.as_ref(),
            &self.transactions,
        )
    }

    pub fn calculate_witness_merkle_root(
        &self,
    ) -> Result<WitnessMerkleHash, crate::error::CodecError> {
        calculate_witness_merkle_root(&self.transactions)
    }

    pub fn transaction_inclusion_proofs(
        &self,
        transaction_index: usize,
    ) -> Result<
        (
            crate::block::merkle::MerkleInclusionProof,
            crate::block::merkle::MerkleInclusionProof,
        ),
        crate::error::CodecError,
    > {
        if transaction_index >= self.transactions.len() {
            return Err(crate::error::CodecError::InvalidBlock);
        }
        let mut transaction_leaves = Vec::with_capacity(
            self.genesis_allocations.len()
                + usize::from(self.coinbase.is_some())
                + self.transactions.len(),
        );
        for allocation in &self.genesis_allocations {
            transaction_leaves.push(allocation.hash()?);
        }
        if let Some(coinbase) = &self.coinbase {
            transaction_leaves.push(coinbase.hash()?);
        }
        transaction_leaves.extend(
            self.transactions
                .iter()
                .map(|transaction| transaction.hash().map(TransactionHash::as_hash))
                .collect::<Result<Vec<_>, _>>()?,
        );
        let leaf_index = self.genesis_allocations.len()
            + usize::from(self.coinbase.is_some())
            + transaction_index;
        let transaction_proof = crate::block::merkle::MerkleInclusionProof::create(
            &transaction_leaves,
            leaf_index,
            HashDomain::MerkleNode,
        )
        .ok_or(crate::error::CodecError::InvalidBlock)?;

        let witness_leaves = self
            .transactions
            .iter()
            .map(|transaction| transaction.wtxid().map(WitnessTransactionHash::as_hash))
            .collect::<Result<Vec<_>, _>>()?;
        let witness_proof = crate::block::merkle::MerkleInclusionProof::create(
            &witness_leaves,
            transaction_index,
            HashDomain::WitnessMerkleNode,
        )
        .ok_or(crate::error::CodecError::InvalidBlock)?;
        Ok((transaction_proof, witness_proof))
    }

    pub fn refresh_merkle_root(&mut self) -> Result<(), crate::error::CodecError> {
        self.refresh_commitments()
    }

    pub fn refresh_commitments(&mut self) -> Result<(), crate::error::CodecError> {
        self.header.merkle_root = self.calculate_merkle_root()?;
        self.header.witness_root = self.calculate_witness_merkle_root()?;
        Ok(())
    }

    pub fn push_transaction(
        &mut self,
        transaction: SignedTransaction,
    ) -> Result<(), crate::error::CodecError> {
        self.transactions
            .push(SignedProtocolTransaction::from(transaction));
        if let Ok(fees) = self.checked_total_fees()
            && let Some(coinbase) = &mut self.coinbase
        {
            coinbase.fees = fees;
        }
        self.refresh_merkle_root()
    }
}

fn calculate_merkle_root(
    genesis_allocations: &[GenesisAllocation],
    coinbase: Option<&CoinbaseTransaction>,
    transactions: &[SignedProtocolTransaction],
) -> Result<MerkleHash, crate::error::CodecError> {
    if genesis_allocations.is_empty() && coinbase.is_none() && transactions.is_empty() {
        return Ok(MerkleHash::ZERO);
    }

    let mut hashes = Vec::with_capacity(
        genesis_allocations.len() + usize::from(coinbase.is_some()) + transactions.len(),
    );
    for allocation in genesis_allocations {
        hashes.push(allocation.hash()?);
    }
    if let Some(coinbase) = coinbase {
        hashes.push(coinbase.hash()?);
    }
    for transaction in transactions {
        hashes.push(transaction.hash()?.as_hash());
    }

    while hashes.len() > 1 {
        hashes = merkle_parent_level(hashes, HashDomain::MerkleNode);
    }

    Ok(MerkleHash(hashes[0].0))
}

fn merkle_parent_level(hashes: Vec<Hash>, domain: HashDomain) -> Vec<Hash> {
    let mut parents = Vec::with_capacity(hashes.len().div_ceil(2));
    let mut pairs = hashes.chunks_exact(2);
    for pair in &mut pairs {
        let mut bytes = Vec::with_capacity(HASH_SIZE * 2);
        bytes.extend_from_slice(&pair[0].0);
        bytes.extend_from_slice(&pair[1].0);
        parents.push(domain_hash(domain, &bytes));
    }
    if let [last] = pairs.remainder() {
        parents.push(*last);
    }
    parents
}

fn calculate_witness_merkle_root(
    transactions: &[SignedProtocolTransaction],
) -> Result<WitnessMerkleHash, crate::error::CodecError> {
    let mut hashes = transactions
        .iter()
        .map(|tx| tx.wtxid().map(WitnessTransactionHash::as_hash))
        .collect::<Result<Vec<_>, _>>()?;

    if hashes.is_empty() {
        return Ok(WitnessMerkleHash::ZERO);
    }

    while hashes.len() > 1 {
        hashes = merkle_parent_level(hashes, HashDomain::WitnessMerkleNode);
    }

    Ok(WitnessMerkleHash(hashes[0].0))
}

fn has_duplicate_transactions(
    transactions: &[SignedProtocolTransaction],
) -> Result<bool, crate::error::CodecError> {
    let mut seen = HashSet::with_capacity(transactions.len());
    for transaction in transactions {
        if !seen.insert(transaction.hash()?.as_hash()) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn checked_fees(transactions: &[SignedProtocolTransaction]) -> Result<Amount, BlockError> {
    transactions
        .iter()
        .map(|tx| tx.fee().0)
        .try_fold(0u64, |total, fee| total.checked_add(fee))
        .map(Amount)
        .ok_or(BlockError::FeeOverflow)
}

fn signed_transactions_are_valid_for_height(
    transactions: &[SignedProtocolTransaction],
    height: BlockHeight,
) -> bool {
    transactions
        .iter()
        .all(|tx| tx.validate_envelope_for_height(height).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::TransferOutput;
    use std::io::Cursor;

    fn invalid_signed_transfer(nonce: u64) -> SignedTransaction {
        let public_key = PublicKey([1; crate::crypto::PUBLIC_KEY_SIZE]);
        let auth_public_key = PublicKey([2; crate::crypto::PUBLIC_KEY_SIZE]);
        let transaction = Transaction::new(
            crate::crypto::address_from_public_key(&public_key),
            vec![TransferOutput {
                to: Address([3; crate::crypto::ADDRESS_SIZE]),
                amount: Amount(1),
            }],
            Amount(0),
            Nonce(nonce),
        );
        SignedTransaction::new_authorized(
            transaction,
            public_key,
            Signature([1; crate::crypto::SIGNATURE_SIZE]),
            auth_public_key,
            Signature([2; crate::crypto::SIGNATURE_SIZE]),
        )
    }

    #[test]
    fn block_validation_is_not_capped_at_500_transactions() {
        let transactions: Vec<SignedTransaction> = (0..501).map(invalid_signed_transfer).collect();
        let miner = Address([4; crate::crypto::ADDRESS_SIZE]);
        let block = Block::from_protocol_transactions(
            Height(1),
            PreviousHash([9; HASH_SIZE]),
            miner,
            DIFFICULTY_START,
            1,
            Nonce(0),
            Vec::new(),
            Some(CoinbaseTransaction::new(miner, Amount(0), Amount(0))),
            transactions.into_iter().map(Into::into).collect(),
        )
        .unwrap();

        assert_eq!(
            block.validate_structure(),
            Err(BlockError::InvalidTransaction)
        );
    }

    #[test]
    fn hostile_section_length_fails_without_full_preallocation() {
        let mut encoded_length = Cursor::new((MAX_BLOCK_DECODE_ITEMS as u32).to_le_bytes());
        assert!(
            deserialize_limited_vec::<ProtocolPayload, _>(
                &mut encoded_length,
                MAX_BLOCK_DECODE_ITEMS
            )
            .is_err()
        );

        let mut excessive = Cursor::new(((MAX_BLOCK_DECODE_ITEMS + 1) as u32).to_le_bytes());
        assert!(
            deserialize_limited_vec::<ProtocolPayload, _>(&mut excessive, MAX_BLOCK_DECODE_ITEMS)
                .is_err()
        );
    }

    #[test]
    fn explicit_time_validation_rejects_future_block() {
        let block = crate::genesis::genesis_block().unwrap();
        let now = block.timestamp().saturating_sub(MAX_FUTURE_TIME as u64 + 1);
        assert_eq!(block.validate_at(now), Err(BlockError::FutureTimestamp));
    }
}
