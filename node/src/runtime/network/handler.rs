use crate::runtime::network::error::NetworkError;
use crate::runtime::network::message::{
    InventoryItem, NetworkMessage, RejectReason, TipInfo, VersionInfo,
};
use crate::runtime::network::{
    CompactBlockReconstruction, IndexedBlockTransaction, MAX_COMPACT_MISSING_TRANSACTIONS,
};
use crate::runtime::node::Node;
use crate::runtime::params::MAX_NETWORK_MESSAGE_SIZE;
use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
use xparq::block::Height;
use xparq::crypto::{HashDomain, TransactionHash, domain_hash};

const MAX_RANGE_RESPONSE_ITEMS: u32 = 64;
const RANGE_RESPONSE_HEADROOM: usize = 64 * 1024;
pub const SNAPSHOT_CHUNK_SIZE: u32 = 4 * 1024 * 1024;
pub const MAX_RECONCILE_SHORT_IDS: usize = xparq::block::MAX_BLOCK_DECODE_ITEMS;
pub const RECONCILE_BUCKETS: u64 = 16;

pub fn reconcile_short_id(epoch: u64, hash: TransactionHash) -> u64 {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(b"xparq_MEMPOOL_RECONCILE_V1");
    bytes.extend_from_slice(&epoch.to_le_bytes());
    bytes.extend_from_slice(&hash.0);
    let digest = domain_hash(HashDomain::Raw, &bytes);
    u64::from_le_bytes(digest.0[..8].try_into().expect("fixed hash prefix"))
}

pub fn handle_message(
    node: &mut Node,
    message: NetworkMessage,
) -> Result<Option<NetworkMessage>, NetworkError> {
    match message {
        NetworkMessage::Version(version) => match version.validate_compatibility() {
            Ok(()) => Ok(Some(NetworkMessage::VerAck(local_version(node)))),
            Err(reason) => Ok(Some(NetworkMessage::Reject {
                reason,
                message: "incompatible peer version".to_string(),
            })),
        },
        NetworkMessage::VerAck(_) => Ok(None),
        NetworkMessage::Reject { .. } => Ok(None),
        NetworkMessage::Ping { nonce } => Ok(Some(NetworkMessage::Pong { nonce })),
        NetworkMessage::Pong { .. } => Ok(None),
        NetworkMessage::GetTip => Ok(local_tip(node).map(NetworkMessage::Tip)),
        NetworkMessage::Tip(_) => Ok(None),
        NetworkMessage::GetBlockByHeight { height } => Ok(node
            .ledger
            .block(&height)
            .cloned()
            .map(NetworkMessage::Block)),
        NetworkMessage::GetBlocksByHeightRange { start, limit } => {
            let limit = limit.min(MAX_RANGE_RESPONSE_ITEMS);
            let byte_budget = MAX_NETWORK_MESSAGE_SIZE.saturating_sub(RANGE_RESPONSE_HEADROOM);
            let mut encoded_bytes = 0_usize;
            let mut blocks = Vec::new();
            for height in (start.0..start.0.saturating_add(limit as u64)).map(Height) {
                let Some(block) = node.ledger.block(&height) else {
                    break;
                };
                let block_size = borsh::to_vec(block)?.len();
                if block_size > byte_budget {
                    return Err(NetworkError::MessageTooLarge);
                }
                if !blocks.is_empty() && encoded_bytes.saturating_add(block_size) > byte_budget {
                    break;
                }
                encoded_bytes = encoded_bytes.saturating_add(block_size);
                blocks.push(block.clone());
            }
            Ok(Some(NetworkMessage::Blocks(blocks)))
        }
        NetworkMessage::GetBlockHeadersByHeightRange { start, limit } => {
            let limit = limit.min(MAX_RANGE_RESPONSE_ITEMS);
            let headers = (start.0..start.0.saturating_add(limit as u64))
                .map(Height)
                .map_while(|height| {
                    let header = node.ledger.chain.header(&height)?.clone();
                    Some(xparq::qcash::recovery::ChainHeader::new(height, header))
                })
                .collect::<Vec<_>>();
            Ok(Some(NetworkMessage::BlockHeaders(headers)))
        }
        NetworkMessage::GetCommonAncestor { locator } => {
            let ancestor = locator.into_iter().find_map(|hash| {
                let indexed = node.fork_choice.get(&hash)?;
                Some(TipInfo {
                    height: indexed.height,
                    hash,
                    work: indexed.cumulative_work.to_be_limbs(),
                })
            });
            Ok(Some(NetworkMessage::CommonAncestor(ancestor)))
        }
        NetworkMessage::CommonAncestor(_) => Ok(None),
        NetworkMessage::GetBlockByHash { hash } => Ok(node
            .cache
            .block_by_hash(&hash)
            .cloned()
            .map(NetworkMessage::Block)
            .or_else(|| {
                Some(NetworkMessage::Reject {
                    reason: RejectReason::InvalidMessage,
                    message: format!("block not found: {}", hex::encode(hash.0)),
                })
            })),
        NetworkMessage::Block(block) => {
            node.apply_block(block)?;
            Ok(None)
        }
        NetworkMessage::Blocks(blocks) => {
            for block in blocks {
                node.apply_block(block)?;
            }
            Ok(None)
        }
        NetworkMessage::BlockHeaders(_) => Ok(None),
        NetworkMessage::GetSnapshotManifest { height, block_hash } => {
            if node.tip_height() != Some(height) || node.tip_hash() != Some(block_hash) {
                return Ok(Some(NetworkMessage::Reject {
                    reason: RejectReason::InvalidMessage,
                    message: "snapshot checkpoint is not the current canonical tip".to_string(),
                }));
            }
            let bytes = node.snapshot_bytes()?;
            Ok(Some(NetworkMessage::SnapshotManifest {
                height,
                block_hash,
                size: bytes.len() as u64,
                content_hash: xparq::genesis::artifact_payload_hash(bytes),
                chunk_size: SNAPSHOT_CHUNK_SIZE,
            }))
        }
        NetworkMessage::SnapshotManifest { .. } => Ok(None),
        NetworkMessage::GetSnapshotChunk {
            height,
            block_hash,
            offset,
            length,
        } => {
            if length == 0
                || length > SNAPSHOT_CHUNK_SIZE
                || node.tip_height() != Some(height)
                || node.tip_hash() != Some(block_hash)
            {
                return Ok(Some(NetworkMessage::Reject {
                    reason: RejectReason::InvalidMessage,
                    message: "invalid snapshot chunk request".to_string(),
                }));
            }
            let bytes = node.snapshot_bytes()?;
            let start = usize::try_from(offset).unwrap_or(usize::MAX);
            let end = start.saturating_add(length as usize).min(bytes.len());
            if start >= bytes.len() {
                return Ok(Some(NetworkMessage::Reject {
                    reason: RejectReason::InvalidMessage,
                    message: "snapshot chunk offset is out of range".to_string(),
                }));
            }
            let chunk = &bytes[start..end];
            let (compression, compressed) = crate::snapshot::compress_chunk(chunk);
            Ok(Some(NetworkMessage::SnapshotChunk {
                height,
                block_hash,
                offset,
                compression,
                uncompressed_length: chunk.len() as u32,
                bytes: compressed,
            }))
        }
        NetworkMessage::SnapshotChunk { .. } => Ok(None),
        NetworkMessage::Inventory(items) => {
            let missing = items
                .into_iter()
                .filter(|item| match item {
                    InventoryItem::Block(hash) => node.cache.block_by_hash(hash).is_none(),
                    InventoryItem::Transaction(hash) => !node.mempool.contains(hash),
                })
                .collect::<Vec<_>>();
            if missing.is_empty() {
                Ok(None)
            } else {
                Ok(Some(NetworkMessage::GetData(missing)))
            }
        }
        NetworkMessage::GetData(items) => {
            let mut blocks = Vec::new();
            let mut transactions = Vec::new();
            for item in items {
                match item {
                    InventoryItem::Block(hash) => {
                        if let Some(block) = node.cache.block_by_hash(&hash).cloned() {
                            blocks.push(block);
                        }
                    }
                    InventoryItem::Transaction(hash) => {
                        if let Some(transaction) = node.mempool.get(&hash).cloned() {
                            transactions.push(transaction);
                        }
                    }
                }
            }
            if !blocks.is_empty() {
                return Ok(Some(NetworkMessage::Blocks(blocks)));
            }
            if !transactions.is_empty() {
                return Ok(Some(NetworkMessage::Transactions(transactions)));
            }
            Ok(None)
        }
        NetworkMessage::Transaction(transaction) => {
            if let Ok(hash) = transaction.hash()
                && node.mempool.contains(&hash)
            {
                crate::runtime::network::metrics::NETWORK_METRICS
                    .duplicate_transactions
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(None);
            }
            node.submit_protocol_transaction(transaction)?;
            Ok(None)
        }
        NetworkMessage::Transactions(transactions) => {
            for transaction in transactions {
                if let Ok(hash) = transaction.hash()
                    && node.mempool.contains(&hash)
                {
                    crate::runtime::network::metrics::NETWORK_METRICS
                        .duplicate_transactions
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                node.submit_protocol_transaction(transaction)?;
            }
            Ok(None)
        }
        NetworkMessage::GetMempoolInventory => Ok(Some(NetworkMessage::Inventory(
            node.mempool
                .transactions()
                .map(|transaction| {
                    transaction
                        .hash()
                        .map(InventoryItem::Transaction)
                        .map_err(crate::runtime::node::NodeError::from)
                })
                .collect::<Result<Vec<_>, _>>()?,
        ))),
        NetworkMessage::ReconcileMempool { epoch, short_ids } => {
            if short_ids.len() > MAX_RECONCILE_SHORT_IDS
                || short_ids.iter().copied().collect::<BTreeSet<_>>().len() != short_ids.len()
            {
                return Ok(Some(NetworkMessage::Reject {
                    reason: RejectReason::InvalidMessage,
                    message: "invalid mempool reconciliation set".to_string(),
                }));
            }
            let remote = short_ids.into_iter().collect::<BTreeSet<_>>();
            let mut missing = Vec::new();
            for transaction in node.mempool.transactions() {
                let hash = transaction
                    .hash()
                    .map_err(crate::runtime::node::NodeError::from)?;
                let short_id = reconcile_short_id(epoch, hash);
                if short_id % RECONCILE_BUCKETS == epoch % RECONCILE_BUCKETS
                    && !remote.contains(&short_id)
                {
                    missing.push(transaction.clone());
                }
            }
            Ok(Some(NetworkMessage::Transactions(missing)))
        }
        NetworkMessage::GetPeers => Ok(Some(NetworkMessage::Peers(vec![]))),
        NetworkMessage::Peers(_) => Ok(None),
        NetworkMessage::CompactBlock(compact) => {
            let block_hash = match compact.block_hash() {
                Ok(hash) => hash,
                Err(_) => {
                    return Ok(Some(NetworkMessage::Reject {
                        reason: RejectReason::InvalidMessage,
                        message: "compact block header is invalid".to_string(),
                    }));
                }
            };
            if node.cache.block_by_hash(&block_hash).is_some() {
                return Ok(None);
            }
            match compact.reconstruct(&node.mempool, &[]) {
                Ok(CompactBlockReconstruction::Complete(block)) => {
                    node.apply_block(*block)?;
                    Ok(None)
                }
                Ok(CompactBlockReconstruction::Missing(indexes)) => {
                    node.stage_compact_block(block_hash, compact);
                    Ok(Some(NetworkMessage::GetCompactBlockTransactions {
                        block_hash,
                        indexes,
                    }))
                }
                Err(_) => Ok(Some(NetworkMessage::GetBlockByHash { hash: block_hash })),
            }
        }
        NetworkMessage::GetCompactBlockTransactions {
            block_hash,
            indexes,
        } => {
            if indexes.len() > MAX_COMPACT_MISSING_TRANSACTIONS {
                return Ok(Some(NetworkMessage::Reject {
                    reason: RejectReason::InvalidMessage,
                    message: "too many compact block transaction indexes".to_string(),
                }));
            }
            let mut seen = std::collections::BTreeSet::new();
            if indexes.iter().any(|index| !seen.insert(*index)) {
                return Ok(Some(NetworkMessage::Reject {
                    reason: RejectReason::InvalidMessage,
                    message: "duplicate compact block transaction index".to_string(),
                }));
            }
            let Some(block) = node.cache.block_by_hash(&block_hash) else {
                return Ok(Some(NetworkMessage::Reject {
                    reason: RejectReason::InvalidMessage,
                    message: "compact block is unavailable".to_string(),
                }));
            };
            let mut transactions = Vec::with_capacity(indexes.len());
            for index in indexes {
                let Some(transaction) = usize::try_from(index)
                    .ok()
                    .and_then(|index| block.transactions().get(index))
                else {
                    return Ok(Some(NetworkMessage::Reject {
                        reason: RejectReason::InvalidMessage,
                        message: "compact block transaction index is invalid".to_string(),
                    }));
                };
                transactions.push(IndexedBlockTransaction {
                    index,
                    transaction: transaction.clone(),
                });
            }
            Ok(Some(NetworkMessage::CompactBlockTransactions {
                block_hash,
                transactions,
            }))
        }
        NetworkMessage::CompactBlockTransactions {
            block_hash,
            transactions,
        } => {
            let Some(compact) = node.take_compact_block(&block_hash) else {
                return Ok(Some(NetworkMessage::GetBlockByHash { hash: block_hash }));
            };
            match compact.reconstruct(&node.mempool, &transactions) {
                Ok(CompactBlockReconstruction::Complete(block)) => {
                    node.apply_block(*block)?;
                    Ok(None)
                }
                Ok(CompactBlockReconstruction::Missing(_)) | Err(_) => {
                    Ok(Some(NetworkMessage::GetBlockByHash { hash: block_hash }))
                }
            }
        }
    }
}

fn local_version(node: &Node) -> VersionInfo {
    VersionInfo::local(local_tip(node))
}

fn local_tip(node: &Node) -> Option<TipInfo> {
    Some(TipInfo {
        height: node.tip_height()?,
        hash: node.tip_hash()?,
        work: node.tip_work()?,
    })
}

#[cfg(test)]
mod reconciliation_tests {
    use super::*;

    #[test]
    fn reconciliation_short_ids_are_epoch_separated() {
        let hash = TransactionHash([7; xparq::crypto::HASH_SIZE]);
        assert_eq!(reconcile_short_id(10, hash), reconcile_short_id(10, hash));
        assert_ne!(reconcile_short_id(10, hash), reconcile_short_id(11, hash));
    }
}
