use crate::runtime::network::compact::{CompactBlock, IndexedBlockTransaction};
use crate::runtime::params::{CURRENT_CHAIN_PARAMS, P2P_WIRE_FORMAT_VERSION};
use borsh::{BorshDeserialize, BorshSerialize};
use xparq::block::{Block, BlockHeight};
use xparq::crypto::{ADDRESS_SIZE, BlockHash, Hash, TransactionHash};
use xparq::ledger::ChainHeader;
use xparq::transaction::SignedProtocolTransaction;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    pub address: String,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct TipInfo {
    pub height: BlockHeight,
    pub hash: BlockHash,
    pub work: [u64; 8],
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct VersionInfo {
    pub protocol_version: u8,
    pub p2p_wire_format_version: u8,
    pub address_size: u16,
    pub chain_id: u32,
    pub chain_name: String,
    pub protocol_stage: String,
    pub pow_algorithm: String,
    pub difficulty_algorithm: String,
    pub network_magic: [u8; 4],
    pub tip: Option<TipInfo>,
}

impl VersionInfo {
    pub fn local(tip: Option<TipInfo>) -> Self {
        Self {
            protocol_version: CURRENT_CHAIN_PARAMS.protocol_version,
            p2p_wire_format_version: P2P_WIRE_FORMAT_VERSION,
            address_size: ADDRESS_SIZE as u16,
            chain_id: CURRENT_CHAIN_PARAMS.chain_id,
            chain_name: CURRENT_CHAIN_PARAMS.chain_name.to_string(),
            protocol_stage: CURRENT_CHAIN_PARAMS.protocol_stage.to_string(),
            pow_algorithm: CURRENT_CHAIN_PARAMS.pow_algorithm.to_string(),
            difficulty_algorithm: CURRENT_CHAIN_PARAMS.difficulty_algorithm.to_string(),
            network_magic: CURRENT_CHAIN_PARAMS.network_magic,
            tip,
        }
    }

    pub fn validate_compatibility(&self) -> Result<(), RejectReason> {
        if self.network_magic != CURRENT_CHAIN_PARAMS.network_magic {
            return Err(RejectReason::NetworkMismatch);
        }
        if self.chain_id != CURRENT_CHAIN_PARAMS.chain_id
            || self.chain_name != CURRENT_CHAIN_PARAMS.chain_name
            || self.protocol_stage != CURRENT_CHAIN_PARAMS.protocol_stage
        {
            return Err(RejectReason::ChainMismatch);
        }
        if self.protocol_version != CURRENT_CHAIN_PARAMS.protocol_version {
            return Err(RejectReason::ProtocolVersionMismatch);
        }
        if self.p2p_wire_format_version != P2P_WIRE_FORMAT_VERSION {
            return Err(RejectReason::ProtocolVersionMismatch);
        }
        if self.address_size != ADDRESS_SIZE as u16 {
            return Err(RejectReason::ConsensusMismatch);
        }
        if self.pow_algorithm != CURRENT_CHAIN_PARAMS.pow_algorithm
            || self.difficulty_algorithm != CURRENT_CHAIN_PARAMS.difficulty_algorithm
        {
            return Err(RejectReason::ConsensusMismatch);
        }
        Ok(())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum RejectReason {
    ProtocolVersionMismatch,
    ChainMismatch,
    NetworkMismatch,
    ConsensusMismatch,
    InvalidMessage,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum InventoryItem {
    Block(BlockHash),
    Transaction(TransactionHash),
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotCompression {
    None,
    Rle,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // Boxing would alter the public message construction API.
pub enum NetworkMessage {
    Version(VersionInfo),
    VerAck(VersionInfo),
    Reject {
        reason: RejectReason,
        message: String,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    GetTip,
    Tip(TipInfo),
    GetBlockByHeight {
        height: BlockHeight,
    },
    GetBlocksByHeightRange {
        start: BlockHeight,
        limit: u32,
    },
    GetBlockHeadersByHeightRange {
        start: BlockHeight,
        limit: u32,
    },
    GetCommonAncestor {
        locator: Vec<BlockHash>,
    },
    CommonAncestor(Option<TipInfo>),
    GetBlockByHash {
        hash: BlockHash,
    },
    Block(Block),
    Blocks(Vec<Block>),
    BlockHeaders(Vec<ChainHeader>),
    GetSnapshotManifest {
        height: BlockHeight,
        block_hash: BlockHash,
    },
    SnapshotManifest {
        height: BlockHeight,
        block_hash: BlockHash,
        size: u64,
        content_hash: Hash,
        chunk_size: u32,
    },
    GetSnapshotChunk {
        height: BlockHeight,
        block_hash: BlockHash,
        offset: u64,
        length: u32,
    },
    SnapshotChunk {
        height: BlockHeight,
        block_hash: BlockHash,
        offset: u64,
        compression: SnapshotCompression,
        uncompressed_length: u32,
        bytes: Vec<u8>,
    },
    Inventory(Vec<InventoryItem>),
    GetData(Vec<InventoryItem>),
    Transaction(SignedProtocolTransaction),
    Transactions(Vec<SignedProtocolTransaction>),
    GetMempoolInventory,
    ReconcileMempool {
        epoch: u64,
        short_ids: Vec<u64>,
    },
    GetPeers,
    Peers(Vec<PeerInfo>),
    CompactBlock(CompactBlock),
    GetCompactBlockTransactions {
        block_hash: BlockHash,
        indexes: Vec<u32>,
    },
    CompactBlockTransactions {
        block_hash: BlockHash,
        transactions: Vec<IndexedBlockTransaction>,
    },
}
