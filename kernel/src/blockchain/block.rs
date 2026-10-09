use std::{
    collections::HashSet,
    io::{Error as IoError, ErrorKind, Read, Write},
    sync::Arc,
};

use borsh::{BorshDeserialize, BorshSerialize};

use crypto::{
    BlockHash, Hash, HashDomain, MerkleHash, PreviousHash, ProgramId, StateRoot, canonical_bytes,
    domain,
};

use crate::{
    blockchain::merkle::{MerkleInclusionProof, merkle_root},
    common::{Height, Nonce},
    error::{BlockError, CodecError},
    monetary::coin::Zeno,
    operation::BlockOperation,
};

pub const MAX_BLOCK_SIZE: usize = 2 * 1024 * 1024;
pub const MAX_BLOCK_OPERATIONS: usize = 4096;
pub const MAX_OPERATION_SIZE: usize = MAX_BLOCK_SIZE;
pub const GENESIS_TARGET_BITS: u32 = 0x207f_ffff;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Header {
    pub previous_hash: PreviousHash,
    pub merkle_root: MerkleHash,
    pub state_root: StateRoot,
    pub target_bits: u32,
    /// Canonical serialized block size plus any ledger execution reservation.
    pub block_weight: u32,
    pub nonce: Nonce,
}

impl Header {
    pub const fn new(
        previous_hash: PreviousHash,
        merkle_root: MerkleHash,
        state_root: StateRoot,
        target_bits: u32,
        block_weight: u32,
        nonce: Nonce,
    ) -> Self {
        Self {
            previous_hash,
            merkle_root,
            state_root,
            target_bits,
            block_weight,
            nonce,
        }
    }

    pub fn hash(&self) -> Result<BlockHash, CodecError> {
        block_header_hash(self)
    }
}

#[derive(BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub struct Body {
    pub emission: Option<Emission>,
    pub operations: Vec<BlockOperation>,
}

#[derive(BorshSerialize, Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: Header,
    pub height: Height,
    /// Clones share the payload; body_mut isolates a writer before mutation.
    pub body: Arc<Body>,
}

// Bounded decoding avoids trusting a serialized Vec length before the block-size
// limit and block-local invariants have been checked.
impl BorshDeserialize for Block {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let header = Header::deserialize_reader(reader)?;
        let height = Height::deserialize_reader(reader)?;
        let emission = Option::<Emission>::deserialize_reader(reader)?;
        let operations = deserialize_block_operations(reader)?;

        Ok(Self {
            header,
            height,
            body: Arc::new(Body {
                emission,
                operations,
            }),
        })
    }
}

fn deserialize_block_operations<R: Read>(reader: &mut R) -> std::io::Result<Vec<BlockOperation>> {
    let length = u32::deserialize_reader(reader)? as usize;

    if length > MAX_BLOCK_OPERATIONS {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "block operation count exceeds limit",
        ));
    }

    let mut operations = Vec::new();

    operations
        .try_reserve(length.min(64))
        .map_err(|_| IoError::new(ErrorKind::OutOfMemory, "block allocation failed"))?;

    for _ in 0..length {
        let mut limited = OperationReader {
            inner: reader,
            remaining: MAX_OPERATION_SIZE,
        };

        operations.push(BlockOperation::deserialize_reader(&mut limited)?);
    }

    Ok(operations)
}

struct OperationReader<'a, R> {
    inner: &'a mut R,
    remaining: usize,
}

impl<R: Read> Read for OperationReader<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 && !bytes.is_empty() {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                "operation exceeds size limit",
            ));
        }

        let allowed = bytes.len().min(self.remaining);
        let read = self.inner.read(&mut bytes[..allowed])?;
        self.remaining -= read;
        Ok(read)
    }
}

struct CappedCounter {
    count: usize,
    maximum: usize,
}

impl Write for CappedCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self
            .count
            .checked_add(bytes.len())
            .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "block exceeds size limit"))?;

        if next > self.maximum {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                "block exceeds size limit",
            ));
        }

        self.count = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Emission {
    pub to: ProgramId,
    pub subsidy: Zeno,
}

impl Emission {
    pub const fn new(to: ProgramId, subsidy: Zeno) -> Self {
        Self { to, subsidy }
    }

    pub fn hash(&self) -> Result<Hash, CodecError> {
        let bytes = canonical_bytes(self).map_err(|_| CodecError::EncodeFailed)?;
        Ok(domain(HashDomain::Emission, &bytes))
    }
}

impl Block {
    pub fn emission(&self) -> Option<&Emission> {
        self.body.emission.as_ref()
    }

    pub fn operations(&self) -> &[BlockOperation] {
        &self.body.operations
    }

    /// Compatibility accessor retained for callers that still use coinbase naming.
    pub fn coinbase(&self) -> Option<&Emission> {
        self.emission()
    }

    pub fn genesis() -> Result<Self, CodecError> {
        Self::from_protocol_operations(
            Height(0),
            PreviousHash::ZERO,
            GENESIS_TARGET_BITS,
            Nonce(0),
            None,
            vec![],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_protocol_operations(
        height: Height,
        previous_hash: impl Into<PreviousHash>,
        target_bits: u32,
        nonce: Nonce,
        emission: Option<Emission>,
        operations: Vec<BlockOperation>,
    ) -> Result<Self, CodecError> {
        let previous_hash = previous_hash.into();
        let merkle_root = calculate_merkle_root(emission.as_ref(), &operations)?;

        let mut block = Self {
            header: Header::new(
                previous_hash,
                merkle_root,
                StateRoot::ZERO,
                target_bits,
                0,
                nonce,
            ),
            height,
            body: Arc::new(Body {
                emission,
                operations,
            }),
        };

        block.refresh_block_weight()?;
        Ok(block)
    }

    /// Validates only deterministic rules that depend on the block itself.
    /// Signatures, values, state burn, and state root execution remain
    /// consensus/ledger responsibilities.
    pub fn validate_structure(&self) -> Result<(), BlockError> {
        if self.body.operations.len() > MAX_BLOCK_OPERATIONS {
            return Err(BlockError::InvalidOperation);
        }

        if self.is_genesis() {
            if self.body.emission.is_some() {
                return Err(BlockError::UnexpectedEmission);
            }

            if self.operation_count() != 0 {
                return Err(BlockError::InvalidOperation);
            }
        } else if self.body.emission.is_none() {
            return Err(BlockError::MissingEmission);
        }

        if !operations_are_structurally_valid(&self.body.operations) {
            return Err(BlockError::InvalidOperation);
        }

        if self.header.block_weight as usize > MAX_BLOCK_SIZE {
            return Err(BlockError::BlockTooHeavy);
        }

        let mut counter = CappedCounter {
            count: 0,
            maximum: MAX_BLOCK_SIZE,
        };

        self.serialize(&mut counter)
            .map_err(|_| BlockError::BlockTooHeavy)?;

        let serialized_weight = counter.count;
        if (self.header.block_weight as usize) < serialized_weight {
            return Err(BlockError::InvalidBlockWeight);
        }

        if self.body.operations.iter().any(|operation| {
            crypto::canonical_length(operation)
                .map_or(true, |size| size > MAX_OPERATION_SIZE as u64)
        }) {
            return Err(BlockError::InvalidOperation);
        }

        if has_duplicate_operations(&self.body.operations)? {
            return Err(BlockError::DuplicateOperation);
        }

        if self.header.merkle_root
            != calculate_merkle_root(self.body.emission.as_ref(), &self.body.operations)?
        {
            return Err(BlockError::InvalidMerkleRoot);
        }

        Ok(())
    }

    pub fn hash(&self) -> Result<BlockHash, CodecError> {
        self.header.hash()
    }

    pub const fn height(&self) -> Height {
        self.height
    }

    pub const fn previous_hash(&self) -> PreviousHash {
        self.header.previous_hash
    }

    pub fn miner_program_id(&self) -> ProgramId {
        self.body
            .emission
            .as_ref()
            .map(|emission| emission.to)
            .unwrap_or(ProgramId([0; crypto::PROGRAM_ID_SIZE]))
    }

    pub const fn state_root(&self) -> StateRoot {
        self.header.state_root
    }

    pub fn set_state_root(&mut self, state_root: impl Into<StateRoot>) {
        self.header.state_root = state_root.into();
    }

    pub fn set_block_weight(&mut self, block_weight: u32) {
        self.header.block_weight = block_weight;
    }

    pub const fn target_bits(&self) -> u32 {
        self.header.target_bits
    }

    pub const fn block_weight(&self) -> u32 {
        self.header.block_weight
    }

    pub fn operation_count(&self) -> usize {
        self.body.operations.len()
    }

    pub fn is_genesis(&self) -> bool {
        self.height.0 == 0
    }

    pub fn serialized_size(&self) -> Result<usize, CodecError> {
        Ok(self.to_bytes()?.len())
    }

    pub fn weight(&self) -> Result<usize, CodecError> {
        self.serialized_size()
    }

    pub fn refresh_block_weight(&mut self) -> Result<(), CodecError> {
        self.header.block_weight = 0;
        let weight = self.weight()?;
        self.header.block_weight = u32::try_from(weight).map_err(|_| CodecError::EncodeFailed)?;
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, CodecError> {
        block_bytes(self)
    }

    pub fn calculate_merkle_root(&self) -> Result<MerkleHash, CodecError> {
        calculate_merkle_root(self.body.emission.as_ref(), &self.body.operations)
    }

    pub fn operation_inclusion_proof(
        &self,
        operation_index: usize,
    ) -> Result<MerkleInclusionProof, CodecError> {
        if operation_index >= self.body.operations.len() {
            return Err(CodecError::InvalidBlock);
        }

        let leaves = merkle_leaves(self.body.emission.as_ref(), &self.body.operations)?;
        let leaf_index = usize::from(self.body.emission.is_some()) + operation_index;

        MerkleInclusionProof::create(&leaves, leaf_index, HashDomain::MerkleNode)
            .ok_or(CodecError::InvalidBlock)
    }

    /// Backward-compatible plural name retained temporarily.
    pub fn operation_inclusion_proofs(
        &self,
        operation_index: usize,
    ) -> Result<MerkleInclusionProof, CodecError> {
        self.operation_inclusion_proof(operation_index)
    }

    pub fn refresh_merkle_root(&mut self) -> Result<(), CodecError> {
        self.refresh_commitments()
    }

    pub fn refresh_commitments(&mut self) -> Result<(), CodecError> {
        self.header.merkle_root = self.calculate_merkle_root()?;
        self.refresh_block_weight()?;
        Ok(())
    }

    /// Mutate a private body, preserving any cloned block or ledger view.
    pub fn body_mut(&mut self) -> &mut Body {
        Arc::make_mut(&mut self.body)
    }

    pub fn push_operation(&mut self, operation: BlockOperation) -> Result<(), CodecError> {
        self.body_mut().operations.push(operation);
        self.refresh_commitments()
    }
}

fn merkle_leaves(
    emission: Option<&Emission>,
    operations: &[BlockOperation],
) -> Result<Vec<Hash>, CodecError> {
    let mut leaves = Vec::with_capacity(usize::from(emission.is_some()) + operations.len());

    if let Some(emission) = emission {
        leaves.push(emission.hash()?);
    }

    for operation in operations {
        leaves.push(operation.id()?);
    }

    Ok(leaves)
}

fn calculate_merkle_root(
    emission: Option<&Emission>,
    operations: &[BlockOperation],
) -> Result<MerkleHash, CodecError> {
    if emission.is_none() && operations.is_empty() {
        return Ok(MerkleHash::ZERO);
    }

    let leaves = merkle_leaves(emission, operations)?;
    merkle_root(&leaves, HashDomain::MerkleNode)
        .map(|root| MerkleHash(root.into_bytes()))
        .ok_or(CodecError::InvalidBlock)
}

fn has_duplicate_operations(operations: &[BlockOperation]) -> Result<bool, CodecError> {
    let mut seen = HashSet::with_capacity(operations.len());

    for operation in operations {
        if !seen.insert(operation.id()?) {
            return Ok(true);
        }
    }

    Ok(false)
}

fn operations_are_structurally_valid(operations: &[BlockOperation]) -> bool {
    operations
        .iter()
        .all(|operation| operation.validate_structure().is_ok())
}

pub fn block_header_bytes(header: &Header) -> Result<Vec<u8>, CodecError> {
    canonical_bytes(header).map_err(|_| CodecError::EncodeFailed)
}

pub fn block_bytes(block: &Block) -> Result<Vec<u8>, CodecError> {
    canonical_bytes(block).map_err(|_| CodecError::EncodeFailed)
}

pub fn block_header_hash(header: &Header) -> Result<BlockHash, CodecError> {
    Ok(BlockHash(
        domain(HashDomain::Header, &block_header_bytes(header)?).into_bytes(),
    ))
}

pub fn decode_block(bytes: &[u8]) -> Result<Block, CodecError> {
    if bytes.len() > MAX_BLOCK_SIZE {
        return Err(CodecError::InvalidBlock);
    }

    let block = Block::try_from_slice(bytes).map_err(|_| CodecError::InvalidBlock)?;
    block
        .validate_structure()
        .map_err(|_| CodecError::InvalidBlock)?;
    Ok(block)
}

#[cfg(test)]
mod p3e_replay_tests {
    use super::*;

    use crypto::{AccountSignatureScheme, SigningSeed, program_id_from_public_key};

    use crate::{
        common::ChainContext,
        monetary::coin::{CoinOutput, CoinShare, Zeno},
        program::{
            AccountAuthorization, AuthorizedProgramInvocation, CoinTransition,
            program_invocation_commitment,
        },
    };

    fn duplicate_fixture() -> BlockOperation {
        let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([0x51; 32]));

        let signer = program_id_from_public_key(&seed.public_key()).unwrap();
        let chain = ChainContext::new([0x71; crypto::HASH_SIZE]);

        let intent = CoinTransition::coin(
            signer,
            vec![CoinShare::from_bytes([0x31; crypto::HASH_SIZE])],
            vec![CoinOutput::new(signer, Zeno::from_zeno(1))],
        )
        .expect("valid structural spend fixture");

        let call = crate::program::system::coin_program::transfer_call();
        let commitment = program_invocation_commitment(signer, &call, &intent, chain)
            .expect("authorization commitment");

        BlockOperation::ProgramCall(Box::new(AuthorizedProgramInvocation {
            signer,
            call,
            payment: intent,
            authorization: AccountAuthorization {
                salt: [0; 32],
                public_key: seed.public_key(),
                signature: seed.sign(commitment.as_bytes()),
            },
        }))
    }

    #[test]
    fn duplicate_operation_id_is_rejected_by_block_structure() {
        let operation = duplicate_fixture();

        assert_eq!(operation.id().unwrap(), operation.clone().id().unwrap());

        let miner = ProgramId([0x22; crypto::PROGRAM_ID_SIZE]);

        let block = Block::from_protocol_operations(
            Height(1),
            PreviousHash::ZERO,
            GENESIS_TARGET_BITS,
            Nonce(0),
            Some(Emission::new(miner, Zeno::from_zeno(1))),
            vec![operation.clone(), operation],
        )
        .expect("block construction itself may contain duplicate operations");

        assert!(matches!(
            block.validate_structure(),
            Err(BlockError::DuplicateOperation)
        ));
    }

    #[test]
    fn oversized_block_operation_count_prefix_is_rejected() {
        let mut bytes = Block::genesis().unwrap().to_bytes().unwrap();
        let count = bytes.len() - 4;
        bytes[count..].copy_from_slice(&((MAX_BLOCK_OPERATIONS + 1) as u32).to_le_bytes());
        assert!(decode_block(&bytes).is_err());
    }

    #[test]
    fn block_size_counter_stops_before_exceeding_cap() {
        let mut counter = CappedCounter {
            count: 0,
            maximum: 4,
        };

        counter.write_all(&[1, 2, 3, 4]).unwrap();
        assert!(counter.write_all(&[5]).is_err());
        assert_eq!(counter.count, 4);
    }
}
