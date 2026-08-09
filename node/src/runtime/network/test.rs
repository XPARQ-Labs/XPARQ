use super::{
    CompactBlock, InventoryItem, NetworkEnvelope, NetworkError, NetworkMessage, PeerInfo,
    RejectReason, TipInfo, VersionInfo, handle_message, read_message, write_message,
};
use crate::runtime::node::Node;
use crate::runtime::params::BASE_FEE;
use crate::runtime::params::MAX_NETWORK_MESSAGE_SIZE;
use crate::test_support::BlockTestExt;
use xparq::block::{Block, Height, Nonce};
use xparq::consensus::supply::Amount;
use xparq::consensus::{Consensus, ConsensusConfig};
use xparq::crypto::{
    Address, BlockHash, HASH_SIZE, Hash, TransactionHash, dual_address_from_public_keys,
    generate_keypair, sign,
};
use xparq::ledger::Ledger;
use xparq::transaction::{SignedTransaction, Transaction};
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

fn address(byte: u8) -> Address {
    Address([byte; 20])
}

fn block() -> Block {
    let mut block = Block::new(
        Height(0),
        Hash([0; HASH_SIZE]),
        Address([9; 20]),
        1_700_000_000,
        Nonce(0),
        vec![],
    );
    let consensus = Consensus::with_default_config();
    while consensus.validate_proof_of_work(&block).is_err() {
        block.header.nonce = Nonce(block.header.nonce.0.saturating_add(1));
    }
    block
}

#[test]
fn roundtrips_ping_message() {
    let envelope = NetworkMessage::Ping { nonce: 7 }.to_envelope();
    let bytes = envelope.to_bytes().unwrap();

    assert_eq!(NetworkEnvelope::from_bytes(&bytes).unwrap(), envelope);
}

#[test]
fn roundtrips_tip_and_block_messages() {
    let block = block();
    let tip = NetworkMessage::Tip(TipInfo {
        height: block.height(),
        hash: block.hash().unwrap(),
        work: [1; 8],
    })
    .to_envelope();
    let block_message = NetworkMessage::Block(block).to_envelope();

    assert_eq!(
        NetworkEnvelope::from_bytes(&tip.to_bytes().unwrap()).unwrap(),
        tip
    );
    assert_eq!(
        NetworkEnvelope::from_bytes(&block_message.to_bytes().unwrap()).unwrap(),
        block_message
    );
}

#[test]
fn roundtrips_compact_block_message() {
    let compact = CompactBlock::from_block(&block()).unwrap();
    let envelope = NetworkMessage::CompactBlock(compact).to_envelope();

    assert_eq!(
        NetworkEnvelope::from_bytes(&envelope.to_bytes().unwrap()).unwrap(),
        envelope
    );
}

#[test]
fn handler_returns_only_requested_compact_block_transactions() {
    let mut node = test_node_with_genesis();
    let transaction = signed_transaction_to(address(4), 7, 0);
    let block = Block::new(
        Height(1),
        node.tip_hash().unwrap(),
        address(9),
        1_700_000_100,
        Nonce(1),
        vec![transaction.clone()],
    );
    let block_hash = block.hash().unwrap();
    node.cache.insert_block(block).unwrap();

    let response = handle_message(
        &mut node,
        NetworkMessage::GetCompactBlockTransactions {
            block_hash,
            indexes: vec![0],
        },
    )
    .unwrap();
    let Some(NetworkMessage::CompactBlockTransactions {
        block_hash: returned_hash,
        transactions,
    }) = response
    else {
        panic!("expected compact block transactions");
    };
    assert_eq!(returned_hash, block_hash);
    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].index, 0);
    assert_eq!(
        transactions[0].transaction,
        xparq::transaction::SignedProtocolTransaction::from(transaction)
    );
}

#[test]
fn handler_requests_only_transactions_missing_from_compact_block() {
    let mut node = test_node_with_genesis();
    let transaction = signed_transaction_to(address(5), 8, 0);
    let block = Block::new(
        Height(1),
        node.tip_hash().unwrap(),
        address(9),
        1_700_000_101,
        Nonce(2),
        vec![transaction],
    );
    let block_hash = block.hash().unwrap();
    let compact = CompactBlock::from_block(&block).unwrap();

    assert_eq!(
        handle_message(&mut node, NetworkMessage::CompactBlock(compact)).unwrap(),
        Some(NetworkMessage::GetCompactBlockTransactions {
            block_hash,
            indexes: vec![0],
        })
    );
}

#[test]
fn roundtrips_peer_list() {
    let envelope = NetworkMessage::Peers(vec![PeerInfo {
        address: "127.0.0.1:5555".to_string(),
    }])
    .to_envelope();

    assert_eq!(
        NetworkEnvelope::from_bytes(&envelope.to_bytes().unwrap()).unwrap(),
        envelope
    );
}

#[test]
fn roundtrips_version_handshake_messages() {
    let version = VersionInfo::local(Some(TipInfo {
        height: Height(7),
        hash: Hash([7; HASH_SIZE]).into(),
        work: [7; 8],
    }));
    let messages = [
        NetworkMessage::Version(version.clone()),
        NetworkMessage::VerAck(version),
        NetworkMessage::Reject {
            reason: RejectReason::ProtocolVersionMismatch,
            message: "bad version".to_string(),
        },
    ];

    for message in messages {
        let envelope = message.to_envelope();
        assert_eq!(
            NetworkEnvelope::from_bytes(&envelope.to_bytes().unwrap()).unwrap(),
            envelope
        );
    }
}

#[test]
fn rejects_oversized_message_bytes() {
    let bytes = vec![0_u8; MAX_NETWORK_MESSAGE_SIZE + 1];

    assert!(matches!(
        NetworkEnvelope::from_bytes(&bytes),
        Err(NetworkError::MessageTooLarge)
    ));
}

#[test]
fn rejects_wrong_network_magic() {
    let mut envelope = NetworkMessage::GetTip.to_envelope();
    envelope.magic = [0, 0, 0, 0];
    let bytes = borsh::to_vec(&envelope).unwrap();

    assert!(matches!(
        NetworkEnvelope::from_bytes(&bytes),
        Err(NetworkError::Serialization(_))
    ));
}

#[test]
fn writes_and_reads_framed_message() {
    let envelope = NetworkMessage::Ping { nonce: 42 }.to_envelope();
    let mut bytes = Vec::new();

    write_message(&mut bytes, &envelope).unwrap();

    let mut cursor = Cursor::new(bytes);
    assert_eq!(read_message(&mut cursor).unwrap(), envelope);
}

#[test]
fn rejects_oversized_framed_message_length() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&((MAX_NETWORK_MESSAGE_SIZE as u32) + 1).to_be_bytes());

    let mut cursor = Cursor::new(bytes);

    assert!(matches!(
        read_message(&mut cursor),
        Err(NetworkError::MessageTooLarge)
    ));
}

#[test]
fn rejects_partial_framed_message() {
    let envelope = NetworkMessage::Pong { nonce: 7 }.to_envelope();
    let mut bytes = Vec::new();
    write_message(&mut bytes, &envelope).unwrap();
    bytes.pop();

    let mut cursor = Cursor::new(bytes);

    assert!(matches!(
        read_message(&mut cursor),
        Err(NetworkError::Io(_))
    ));
}

#[test]
fn handler_responds_to_ping_and_tip_requests() {
    let mut node = test_node_with_genesis();

    assert_eq!(
        handle_message(&mut node, NetworkMessage::Ping { nonce: 7 }).unwrap(),
        Some(NetworkMessage::Pong { nonce: 7 })
    );

    assert_eq!(
        handle_message(&mut node, NetworkMessage::GetTip).unwrap(),
        Some(NetworkMessage::Tip(TipInfo {
            height: Height(0),
            hash: node.tip_hash().unwrap(),
            work: node.tip_work().unwrap(),
        }))
    );
}

#[test]
fn handler_accepts_compatible_version_and_rejects_incompatible_version() {
    let mut node = test_node_with_genesis();
    let compatible = VersionInfo::local(None);

    assert!(matches!(
        handle_message(&mut node, NetworkMessage::Version(compatible)).unwrap(),
        Some(NetworkMessage::VerAck(_))
    ));

    let mut incompatible = VersionInfo::local(None);
    incompatible.protocol_version = incompatible.protocol_version.saturating_add(1);

    assert_eq!(
        handle_message(&mut node, NetworkMessage::Version(incompatible)).unwrap(),
        Some(NetworkMessage::Reject {
            reason: RejectReason::ProtocolVersionMismatch,
            message: "incompatible peer version".to_string()
        })
    );

    let mut incompatible_pow = VersionInfo::local(None);
    incompatible_pow.pow_algorithm = "different-pow".to_string();
    assert_eq!(
        handle_message(&mut node, NetworkMessage::Version(incompatible_pow)).unwrap(),
        Some(NetworkMessage::Reject {
            reason: RejectReason::ConsensusMismatch,
            message: "incompatible peer version".to_string()
        })
    );
}

#[test]
fn handler_returns_blocks_by_height_and_hash() {
    let mut node = test_node_with_genesis();
    let block = node.ledger.block(&Height(0)).unwrap().clone();

    assert_eq!(
        handle_message(
            &mut node,
            NetworkMessage::GetBlockByHeight { height: Height(0) }
        )
        .unwrap(),
        Some(NetworkMessage::Block(block.clone()))
    );
    assert_eq!(
        handle_message(
            &mut node,
            NetworkMessage::GetBlockByHash {
                hash: block.hash().unwrap()
            }
        )
        .unwrap(),
        Some(NetworkMessage::Block(block))
    );
}

#[test]
fn handler_returns_block_ranges_by_height() {
    let mut node = test_node_with_genesis();
    let block = node.ledger.block(&Height(0)).unwrap().clone();

    assert_eq!(
        handle_message(
            &mut node,
            NetworkMessage::GetBlocksByHeightRange {
                start: Height(0),
                limit: 32
            }
        )
        .unwrap(),
        Some(NetworkMessage::Blocks(vec![block]))
    );

    assert_eq!(
        handle_message(
            &mut node,
            NetworkMessage::GetBlocksByHeightRange {
                start: Height(1),
                limit: 32
            }
        )
        .unwrap(),
        Some(NetworkMessage::Blocks(vec![]))
    );
}

#[test]
fn handler_returns_block_header_ranges_by_height() {
    let mut node = test_node_with_genesis();
    let block = node.ledger.block(&Height(0)).unwrap().clone();

    assert_eq!(
        handle_message(
            &mut node,
            NetworkMessage::GetBlockHeadersByHeightRange {
                start: Height(0),
                limit: 32
            }
        )
        .unwrap(),
        Some(NetworkMessage::BlockHeaders(vec![block.header]))
    );
}

#[test]
fn handler_returns_common_ancestor_from_locator() {
    let mut node = test_node_with_genesis();
    let block = node.ledger.block(&Height(0)).unwrap().clone();

    assert_eq!(
        handle_message(
            &mut node,
            NetworkMessage::GetCommonAncestor {
                locator: vec![BlockHash([9; HASH_SIZE]), block.hash().unwrap()]
            }
        )
        .unwrap(),
        Some(NetworkMessage::CommonAncestor(Some(TipInfo {
            height: Height(0),
            hash: block.hash().unwrap(),
            work: node
                .fork_choice
                .get(&block.hash().unwrap())
                .unwrap()
                .cumulative_work
                .to_be_limbs(),
        })))
    );

    assert_eq!(
        handle_message(
            &mut node,
            NetworkMessage::GetCommonAncestor {
                locator: vec![BlockHash([9; HASH_SIZE])]
            }
        )
        .unwrap(),
        Some(NetworkMessage::CommonAncestor(None))
    );
}

#[test]
fn handler_requests_missing_inventory_data() {
    let mut node = test_node_with_genesis();
    let block = node.ledger.block(&Height(0)).unwrap().clone();

    assert_eq!(
        handle_message(
            &mut node,
            NetworkMessage::Inventory(vec![
                InventoryItem::Block(block.hash().unwrap()),
                InventoryItem::Transaction(TransactionHash([9; HASH_SIZE]))
            ])
        )
        .unwrap(),
        Some(NetworkMessage::GetData(vec![InventoryItem::Transaction(
            TransactionHash([9; HASH_SIZE])
        )]))
    );

    assert_eq!(
        handle_message(
            &mut node,
            NetworkMessage::Inventory(vec![InventoryItem::Block(BlockHash([9; HASH_SIZE]))])
        )
        .unwrap(),
        Some(NetworkMessage::GetData(vec![InventoryItem::Block(
            BlockHash([9; HASH_SIZE])
        )]))
    );
}

#[test]
fn handler_returns_mempool_inventory_and_data_by_hash() {
    let transaction = signed_transaction_to(address(2), 10, 0);
    let hash = transaction.hash().unwrap();
    let sender = transaction.transaction.from;
    let mut ledger = Ledger::new();
    ledger.create_account(sender, Amount(1_000_000)).unwrap();
    ledger.create_account(address(2), Amount(0)).unwrap();
    let mut node = Node::temporary(
        ledger,
        Consensus::new(ConsensusConfig::new(xparq::consensus::MIN_DIFFICULTY)).unwrap(),
    )
    .unwrap();
    node.submit_transaction(transaction.clone()).unwrap();

    assert_eq!(
        handle_message(&mut node, NetworkMessage::GetMempoolInventory).unwrap(),
        Some(NetworkMessage::Inventory(vec![InventoryItem::Transaction(
            hash
        )]))
    );
    assert_eq!(
        handle_message(
            &mut node,
            NetworkMessage::GetData(vec![InventoryItem::Transaction(hash)])
        )
        .unwrap(),
        Some(NetworkMessage::Transactions(vec![transaction.into()]))
    );
}

#[test]
fn handler_submits_transaction_to_node_mempool() {
    let transaction = signed_transaction_to(address(2), 10, 0);
    let hash = transaction.hash().unwrap();
    let sender = transaction.transaction.from;
    let mut ledger = Ledger::new();
    ledger.create_account(sender, Amount(1_000_000)).unwrap();
    ledger.create_account(address(2), Amount(0)).unwrap();
    let mut node = Node::temporary(
        ledger,
        Consensus::new(ConsensusConfig::new(xparq::consensus::MIN_DIFFICULTY)).unwrap(),
    )
    .unwrap();

    assert_eq!(
        handle_message(&mut node, NetworkMessage::Transaction(transaction.into())).unwrap(),
        None
    );
    assert!(node.mempool.contains(&hash));
}

#[test]
fn handler_serves_snapshot_manifest_and_bounded_chunks_for_exact_tip() {
    let ledger = xparq::genesis::genesis_ledger().unwrap();
    let mut node = Node::temporary(ledger, Consensus::with_default_config()).unwrap();
    let height = node.tip_height().unwrap();
    let block_hash = node.tip_hash().unwrap();

    let manifest = handle_message(
        &mut node,
        NetworkMessage::GetSnapshotManifest { height, block_hash },
    )
    .unwrap()
    .unwrap();
    let NetworkMessage::SnapshotManifest {
        size,
        content_hash,
        chunk_size,
        ..
    } = manifest
    else {
        panic!("expected snapshot manifest");
    };
    let chunk = handle_message(
        &mut node,
        NetworkMessage::GetSnapshotChunk {
            height,
            block_hash,
            offset: 0,
            length: chunk_size.min(size as u32),
        },
    )
    .unwrap()
    .unwrap();
    let NetworkMessage::SnapshotChunk { bytes, .. } = chunk else {
        panic!("expected snapshot chunk");
    };
    assert_eq!(bytes.len() as u64, size);
    assert_eq!(xparq::genesis::artifact_payload_hash(&bytes), content_hash);
}

#[test]
fn handler_rejects_snapshot_request_for_noncanonical_checkpoint() {
    let ledger = xparq::genesis::genesis_ledger().unwrap();
    let mut node = Node::temporary(ledger, Consensus::with_default_config()).unwrap();
    let height = node.tip_height().unwrap();
    let response = handle_message(
        &mut node,
        NetworkMessage::GetSnapshotManifest {
            height,
            block_hash: BlockHash([0x55; HASH_SIZE]),
        },
    )
    .unwrap();
    assert!(matches!(response, Some(NetworkMessage::Reject { .. })));
}

fn test_node_with_genesis() -> Node {
    let mut ledger = Ledger::new();
    let block = block();
    ledger.chain.insert_block(block).unwrap();
    Node::temporary(
        ledger,
        Consensus::new(ConsensusConfig::new(xparq::consensus::MIN_DIFFICULTY)).unwrap(),
    )
    .unwrap()
}

fn signed_transaction_to(to: Address, amount: u64, nonce: u64) -> SignedTransaction {
    let keypair = generate_keypair();
    let from = dual_address_from_public_keys(&keypair.public_key, &keypair.public_key);
    let template = Transaction::new(
        from,
        to,
        Amount(amount),
        nonce,
    );
    let template_signature = sign(&keypair.secret_key, &template.signing_bytes().unwrap());
    let template_auth_signature = sign(&keypair.secret_key, &template.signing_bytes().unwrap());
    let virtual_size = SignedTransaction::new_authorized(
        template,
        keypair.public_key,
        template_signature,
        keypair.public_key,
        template_auth_signature,
    )
    .virtual_size()
    .unwrap();
    let payload = Transaction::new(
        from,
        to,
        Amount(amount),
        nonce,
    );
    let signature = sign(&keypair.secret_key, &payload.signing_bytes().unwrap());
    let auth_signature = sign(&keypair.secret_key, &payload.signing_bytes().unwrap());
    SignedTransaction::new_authorized(
        payload,
        keypair.public_key,
        signature,
        keypair.public_key,
        auth_signature,
    )
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
