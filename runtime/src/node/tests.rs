use super::*;
use super::{explorer::*, gossip::*, mempool::*, protocol::*, rpc::*, state::*, util::*};

#[test]
fn embedded_api_documentation_is_valid_and_references_every_rpc_route() {
    let specification: serde_json::Value = serde_json::from_slice(OPENAPI_JSON).unwrap();
    assert_eq!(specification["openapi"], "3.1.0");
    for route in [
        "/status",
        "/fee-policy",
        "/blocks/latest",
        "/block/{height}",
        "/balance/{address}",
        "/account/{address}",
        "/asset/{asset}",
        "/asset/{asset}/balance/{address}",
        "/pools",
        "/pool/{pool}",
        "/pool/shares/{address}",
        "/explorer/address/{address}",
        "/explorer/transaction/{transaction_id}",
        "/transaction",
    ] {
        assert!(
            specification["paths"].get(route).is_some(),
            "missing {route}"
        );
    }
    assert!(
        API_DOCS_HTML
            .windows(b"/openapi.json".len())
            .any(|window| window == b"/openapi.json")
    );
}

#[test]
fn asset_transaction_projection_exposes_asset_and_action() {
    let chain = kernel::genesis::chain_context().unwrap();
    let seed =
        kernel::crypto::SigningSeed::new(kernel::crypto::Signature::MlDsa44, Box::new([0x51; 32]));
    let public_key = seed.public_key();
    let signer = kernel::crypto::address_from_public_key(&public_key);
    let asset_call = kernel::transaction::AssetIntent::new(
        kernel::transaction::AssetInstruction::Register {
            name: "Test Token".into(),
            decimals: 8,
            max_supply: kernel::native::asset::Unit::from_units(100_000_000_000_000_000_000_000),
            initial_mint: kernel::native::asset::Unit::from_units(1_000_000),
            mint_authority: signer,
            nonce: 0,
        },
        signer,
    );
    let signature = seed.sign(&asset_call.commitment(chain.genesis_hash).unwrap());
    let asset = asset_call.asset().unwrap().to_string();
    let transaction = kernel::transaction::AuthorizedAssetTransaction {
        call: kernel::transaction::AuthorizedAccountIntent {
            intent: asset_call,
            authorization: kernel::transaction::AccountAuthorization {
                public_key,
                signature,
            },
        },
        payment: kernel::transaction::AuthorizedAccountIntent {
            intent: kernel::transaction::SpendIntent {
                signer: Address::ZERO,
                spend: kernel::transaction::Spend::Coin {
                    inputs: vec![],
                    outputs: vec![],
                },
            },
            authorization: kernel::transaction::AccountAuthorization {
                public_key: seed.public_key(),
                signature: kernel::crypto::AccountSignature {
                    account: kernel::crypto::Signature::MlDsa44,
                    bytes: vec![],
                },
            },
        },
    };
    let response = asset_transaction_response(&transaction, Address::ZERO, Zeno::from_zeno(4_782));
    assert_eq!(response["asset"], asset);
    assert_eq!(response["asset_instruction"]["type"], "register");
    assert_eq!(response["miner_fee"], 0);
    assert_eq!(response["protocol_burn"], 4_782);
    assert_eq!(
        response["asset_instruction"]["max_supply"],
        "100000000000000000000000"
    );
}

#[test]
fn explorer_miner_fee_uses_block_miner_output() {
    let outputs = vec![CoinOutput {
        output: Recipient::BlockMiner,
        amount: Zeno::from_zeno(2_284),
    }];
    assert_eq!(miner_fee_from_outputs(&outputs).unwrap(), 2_284);
}

#[test]
fn account_projection_lists_asset_supply_and_creator_shares() {
    let seed =
        kernel::crypto::SigningSeed::new(kernel::crypto::Signature::MlDsa44, Box::new([0x61; 32]));
    let authority = kernel::crypto::address_from_public_key(&seed.public_key());
    let call = kernel::transaction::AssetIntent::new(
        kernel::transaction::AssetInstruction::Register {
            name: "Authority Asset".into(),
            decimals: 0,
            max_supply: kernel::native::asset::Unit::from_units(10),
            initial_mint: kernel::native::asset::Unit::from_units(4),
            mint_authority: authority,
            nonce: 0,
        },
        authority,
    );
    let mut ledger = Ledger::new();
    ledger
        .state
        .assets
        .apply(&mut ledger.state.utxos, &call, [0; 32])
        .unwrap();

    let assets = account_asset_balances(&ledger, authority).unwrap();
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0]["max_supply"], "10");
    assert_eq!(assets[0]["mint"], "4");
    assert!(assets[0].get("balance").is_none());
    assert_eq!(assets[0]["shares"].as_array().unwrap().len(), 1);
    assert_eq!(assets[0]["shares"][0]["amount"], "4");
    assert!(
        assets[0]["shares"][0]["share_id"].as_str().unwrap().len() == kernel::crypto::HASH_SIZE * 2
    );
}

#[test]
fn explorer_address_response_is_aggregate_only() {
    let ledger = kernel::genesis::genesis_ledger().unwrap();
    let response = explorer_address_response(
        &ledger,
        &[],
        Address([7; kernel::crypto::ADDRESS_SIZE]),
        true,
    )
    .unwrap();
    assert_eq!(response["balance"]["total"], 0);
    assert_eq!(response["activity_count"], 0);
    assert!(response.get("utxos").is_none());
}

#[test]
fn explorer_activity_reports_net_transfer_for_sender_and_recipient() {
    let mnemonic = wallet::encode_bip39_mnemonic(&[3; 16]).unwrap();
    let sender =
        wallet::account_wallet_from_bip39_mnemonic(&mnemonic, kernel::crypto::Signature::MlDsa44)
            .unwrap();
    let recipient = Address([4; kernel::crypto::ADDRESS_SIZE]);
    let miner = Address([5; kernel::crypto::ADDRESS_SIZE]);
    let intent = kernel::transaction::SpendIntent::coin(
        sender.address,
        vec![kernel::native::coin::XPQ::from_bytes(
            [6; kernel::native::coin::XPQ::SIZE],
        )],
        vec![
            CoinOutput::new(recipient, Zeno::from_zeno(10)),
            CoinOutput::new(sender.address, Zeno::from_zeno(5)),
        ],
    )
    .unwrap();
    let transaction =
        AuthorizedTransaction::Spend(Box::new(kernel::transaction::AuthorizedSpendTransaction {
            spend: sender.sign_account_intent(intent).unwrap(),
            payment: None,
        }));
    let genesis = genesis_block().unwrap();
    let block = Block::from_protocol_transactions(
        Height(1),
        genesis.hash().unwrap(),
        1,
        Nonce(0),
        Some(Emission::new(miner, Zeno::from_zeno(1))),
        vec![transaction.clone()],
    )
    .unwrap();

    let outgoing = address_transaction_activity(&transaction, sender.address, &block)
        .unwrap()
        .unwrap();
    assert_eq!(outgoing["direction"], "out");
    assert_eq!(outgoing["amount"], 10);
    assert_eq!(
        outgoing["size_bytes"],
        canonical_bytes(&transaction).unwrap().len()
    );
    let incoming = address_transaction_activity(&transaction, recipient, &block)
        .unwrap()
        .unwrap();
    assert_eq!(incoming["direction"], "in");
    assert_eq!(incoming["amount"], 10);
    assert!(
        address_transaction_activity(
            &transaction,
            Address([9; kernel::crypto::ADDRESS_SIZE]),
            &block,
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(
        parse_hash(&hex::encode(transaction.id().unwrap())).unwrap(),
        transaction.id().unwrap()
    );
}

fn read_test_http_request(parts: &[&[u8]]) -> Result<HttpRequest, String> {
    let bytes = parts.concat();
    read_http_request(&mut std::io::Cursor::new(bytes))
}

fn test_database(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "kernel-node-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

#[test]
fn handshake_rejects_a_different_wire_version() {
    let mut handshake = Handshake {
        magic: P2P_MAGIC,
        protocol_version: P2P_PROTOCOL_VERSION + 1,
        node_id: [1; 32],
        genesis_hash: EXPECTED_GENESIS_HASH.0,
        chain_spec_hash: chain_spec_hash().unwrap().0,
        capabilities: LOCAL_CAPABILITIES,
        tip_height: Height(0),
        tip_hash: EXPECTED_GENESIS_HASH.0,
        cumulative_work: [0; 8],
        cumulative_weight: 0,
    };
    assert!(
        validate_handshake(&handshake)
            .unwrap_err()
            .contains("unsupported P2P protocol version")
    );

    handshake.protocol_version = P2P_PROTOCOL_VERSION;
    assert!(validate_handshake(&handshake).is_ok());

    handshake.chain_spec_hash[0] ^= 1;
    assert!(
        validate_handshake(&handshake)
            .unwrap_err()
            .contains("chain specification")
    );
}

#[test]
fn discovered_peer_response_is_bounded() {
    let peers = (0..MAX_DISCOVERED_PEERS)
        .map(|index| format!("8.8.{}.{}:6677", index / 255, index % 255))
        .collect::<Vec<_>>();
    let encoded = canonical_bytes(&peers).unwrap();
    assert!(encoded.len() <= MAX_PEERS_RESPONSE_SIZE);
}

#[test]
fn rpc_request_reader_accepts_fragmented_binary_body() {
    let request = read_test_http_request(&[
        b"POST /transaction HTTP/1.1\r\nContent-Len",
        b"gth: 4\r\nConnection: close\r\n\r\n\x00\x01",
        b"\x02\x03",
    ])
    .unwrap();

    assert!(request.headers.starts_with("POST /transaction HTTP/1.1"));
    assert_eq!(request.body, [0, 1, 2, 3]);
}

#[test]
fn rpc_request_reader_rejects_ambiguous_or_oversized_framing() {
    let duplicate = read_test_http_request(&[
        b"POST /transaction HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
    ])
    .unwrap_err();
    assert!(duplicate.contains("duplicate RPC Content-Length"));

    let transfer = read_test_http_request(&[
        b"POST /transaction HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
    ])
    .unwrap_err();
    assert!(transfer.contains("Transfer-Encoding"));

    let oversized = format!(
        "POST /transaction HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
        MAX_STORED_TRANSACTION_SIZE + 1
    );
    let oversized = read_test_http_request(&[oversized.as_bytes()]).unwrap_err();
    assert!(oversized.contains("exceeds transaction size limit"));
}

#[test]
fn gossip_inventory_round_trips_and_rejects_excess_items_before_decode() {
    let inventory = GossipInventory {
        tip_height: Height(7),
        tip_hash: [3; 32],
        cumulative_work: Work::pow2(7).to_be_limbs(),
        cumulative_weight: 123,
        hash: vec![[4; 32], [5; 32]],
    };
    let encoded = canonical_bytes(&inventory).unwrap();
    let decoded = decode_gossip_inventory(&encoded).unwrap();
    assert_eq!(decoded.tip_height, inventory.tip_height);
    assert_eq!(decoded.tip_hash, inventory.tip_hash);
    assert_eq!(decoded.cumulative_work, inventory.cumulative_work);
    assert_eq!(decoded.cumulative_weight, inventory.cumulative_weight);
    assert_eq!(decoded.hash, inventory.hash);

    let mut oversized = encoded;
    oversized[112..116].copy_from_slice(&((MAX_GOSSIP_INVENTORY_ITEMS + 1) as u32).to_le_bytes());
    assert!(
        decode_gossip_inventory(&oversized)
            .unwrap_err()
            .contains("item count exceeds limit")
    );
}

#[test]
fn gossip_inventory_prefers_work_then_weight_then_smaller_tip_hash() {
    let inventory = |work, weight, tip_hash| GossipInventory {
        tip_height: Height(7),
        tip_hash,
        cumulative_work: Work::from_be_limbs(work).to_be_limbs(),
        cumulative_weight: weight,
        hash: Vec::new(),
    };
    let weaker = inventory([0, 0, 0, 0, 0, 0, 0, 7], 999, [1; 32]);
    let stronger = inventory([0, 0, 0, 0, 0, 0, 0, 8], 1, [9; 32]);
    assert!(inventory_preferred(&stronger, &weaker));

    let lighter = inventory([0, 0, 0, 0, 0, 0, 0, 8], 10, [1; 32]);
    let heavier = inventory([0, 0, 0, 0, 0, 0, 0, 8], 11, [9; 32]);
    assert!(inventory_preferred(&heavier, &lighter));

    let larger_hash = inventory([0, 0, 0, 0, 0, 0, 0, 8], 11, [9; 32]);
    let smaller_hash = inventory([0, 0, 0, 0, 0, 0, 0, 8], 11, [2; 32]);
    assert!(inventory_preferred(&smaller_hash, &larger_hash));
}

#[test]
fn redb_startup_round_trips_canonical_genesis() {
    let database = test_database("redb-roundtrip");
    let ledger = load_or_initialize_uncached(&database).unwrap();
    let recovered = load_existing(&database).unwrap();
    assert_eq!(recovered.tip_hash(), ledger.tip_hash());
    assert!(database.join("xparq.redb").is_file());
    fs::remove_dir_all(database).unwrap();
}

#[test]
fn startup_discards_invalid_redb_mempool_entries() {
    let database = test_database("corrupt-mempool");
    let ledger = load_or_initialize_uncached(&database).unwrap();
    crate::storage::replace_mempool(&database, &[vec![0xff, 0xff, 0xff]]).unwrap();

    recover_mempool(&database, &ledger).unwrap();

    assert!(read_mempool(&database).unwrap().is_empty());
    fs::remove_dir_all(database).unwrap();
}
