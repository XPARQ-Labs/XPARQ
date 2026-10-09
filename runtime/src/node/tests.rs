use super::mining::{MiningAttempt, mine_block_database};
use super::*;
use super::{
    chain_sync::*, explorer::*, gossip::*, index::*, mempool::*, protocol::*, rpc::*, state::*,
    util::*,
};

#[test]
fn genesis_rpc_preserves_block_hash_and_empty_transaction_hashes() {
    let ledger = kernel::genesis::genesis_ledger()
        .unwrap()
        .with_applications(extension::SystemApplications);
    let block = ledger.chain.block(&Height(0)).unwrap();
    let response = block_response(&ledger, block).unwrap();
    assert_eq!(response["hash"], hex::encode(block.hash().unwrap().0));
    assert_eq!(response["transaction_hashes"], serde_json::json!([]));
    assert_eq!(response["transactions"], 0);
    assert_eq!(
        latest_blocks_response(Path::new("unused-genesis-body-is-resident"), &ledger).unwrap()["blocks"]
            [0],
        response
    );
}

#[test]
fn embedded_api_documentation_is_valid_and_references_every_rpc_route() {
    let specification: serde_json::Value = serde_json::from_slice(OPENAPI_JSON).unwrap();
    assert_eq!(specification["openapi"], "3.1.0");
    for route in [
        "/status",
        "/fee-policy",
        "/blocks/latest",
        "/block/{height}",
        "/program/balance/{program_id}",
        "/program/account/{program_id}",
        "/program/coins/{program_id}",
        "/coin-origin/{share}",
        "/program/quote",
        "/program/state/{program_id}/{key}",
        "/program/deploy",
        "/program/deploy/quote",
        "/program/asset/{asset}",
        "/program/asset/{asset}/balance/{program_id}",
        "/explorer/program/{program_id}",
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
fn explorer_program_response_is_aggregate_only() {
    let ledger = kernel::genesis::genesis_ledger()
        .unwrap()
        .with_applications(extension::SystemApplications);
    let database = test_database("explorer-address-aggregate");
    let response = explorer_program_response(
        &database,
        &ledger,
        &[],
        ProgramId([7; kernel::crypto::PROGRAM_ID_SIZE]),
        true,
        DEFAULT_PROGRAM_ACTIVITY_LIMIT,
        None,
    )
    .unwrap();
    assert_eq!(response["balance"]["total"], 0);
    assert_eq!(response["activity_count"], 0);
    assert!(response.get("utxos").is_none());
}

#[test]
fn explorer_address_pagination_rebuilds_after_reorg() {
    let database = test_database("explorer-address-pagination-reorg");

    let mut ledger = kernel::genesis::genesis_ledger()
        .expect("genesis ledger")
        .with_applications(extension::SystemApplications);

    let miner = ProgramId([0x92; kernel::crypto::PROGRAM_ID_SIZE]);

    let target_bits = ledger
        .chain
        .block(&Height(0))
        .expect("genesis block")
        .target_bits();

    // Branch A: heights 1 -> 2 -> 3.
    for height in 1_u64..=3 {
        let block = Block::from_protocol_operations(
            Height(height),
            ledger.tip_hash().expect("branch A tip"),
            target_bits,
            Nonce(height),
            Some(Emission::new(miner, Zeno::from_zeno(1))),
            vec![],
        )
        .expect("construct branch A block");

        ledger
            .chain
            .insert_block(block)
            .expect("insert branch A block");
    }

    let page_a =
        program_activity_page(&database, &ledger, miner, None, 2).expect("read branch A page");

    assert_eq!(
        page_a.locations,
        vec![
            ActivityLocation::Emission { height: Height(3) },
            ActivityLocation::Emission { height: Height(2) },
        ],
    );

    // Remove branch A completely.
    for _ in 0..3 {
        let tip = ledger.tip_hash().expect("branch A tip");
        ledger.chain.remove_tip(tip).expect("remove branch A tip");
    }

    // Branch B: heights 1 -> 2 -> 3 -> 4.
    for height in 1_u64..=4 {
        let block = Block::from_protocol_operations(
            Height(height),
            ledger.tip_hash().expect("branch B tip"),
            target_bits,
            Nonce(100 + height),
            Some(Emission::new(miner, Zeno::from_zeno(1))),
            vec![],
        )
        .expect("construct branch B block");

        ledger
            .chain
            .insert_block(block)
            .expect("insert branch B block");
    }

    // Tip changed, so persistent activity index must rebuild.
    let page_b =
        program_activity_page(&database, &ledger, miner, None, 2).expect("read branch B page");

    assert_eq!(
        page_b.locations,
        vec![
            ActivityLocation::Emission { height: Height(4) },
            ActivityLocation::Emission { height: Height(3) },
        ],
    );

    let cursor = page_b.next_cursor.expect("branch B first page cursor");

    let page_b2 = program_activity_page(&database, &ledger, miner, Some(cursor), 2)
        .expect("read branch B second page");

    assert_eq!(
        page_b2.locations,
        vec![
            ActivityLocation::Emission { height: Height(2) },
            ActivityLocation::Emission { height: Height(1) },
        ],
    );

    assert_eq!(page_b2.next_cursor, None);
}

#[test]
fn explorer_address_pagination_advances_when_emissions_are_hidden() {
    let database = test_database("explorer-address-pagination-hidden-emissions");

    let mut ledger = kernel::genesis::genesis_ledger()
        .expect("genesis ledger")
        .with_applications(extension::SystemApplications);

    let miner = ProgramId([0x93; kernel::crypto::PROGRAM_ID_SIZE]);

    let target_bits = ledger
        .chain
        .block(&Height(0))
        .expect("genesis block")
        .target_bits();

    for height in 1_u64..=3 {
        let block = Block::from_protocol_operations(
            Height(height),
            ledger.tip_hash().expect("canonical tip"),
            target_bits,
            Nonce(height),
            Some(Emission::new(miner, Zeno::from_zeno(1))),
            vec![],
        )
        .expect("construct emission block");

        ledger
            .chain
            .insert_block(block)
            .expect("insert emission block");
    }

    let first = explorer_program_response(&database, &ledger, &[], miner, false, 2, None)
        .expect("first hidden-emission page");

    assert_eq!(first["activity_count"], 0);
    assert_eq!(first["emission_count"], 2);

    assert_eq!(
        first["activities"]
            .as_array()
            .expect("activities array")
            .len(),
        0,
    );

    let cursor_hex = first["next_cursor"]
        .as_str()
        .expect("first page has next cursor");

    let cursor_bytes = hex::decode(cursor_hex).expect("decode activity cursor");

    let cursor: [u8; crate::storage::PROGRAM_ACTIVITY_CURSOR_SIZE] = cursor_bytes
        .try_into()
        .expect("activity cursor has correct size");

    let second = explorer_program_response(&database, &ledger, &[], miner, false, 2, Some(cursor))
        .expect("second hidden-emission page");

    assert_eq!(second["activity_count"], 0);
    assert_eq!(second["emission_count"], 1);

    assert_eq!(
        second["activities"]
            .as_array()
            .expect("activities array")
            .len(),
        0,
    );

    assert!(second["next_cursor"].is_null());
}

#[test]
fn explorer_activity_reports_net_transfer_for_sender_and_recipient() {
    let mnemonic = wallet::encode_bip39_mnemonic(&[3; 16]).unwrap();
    let sender =
        wallet::account_wallet_from_bip39_mnemonic(&mnemonic, kernel::crypto::Signature::MlDsa44)
            .unwrap();
    let recipient = ProgramId([4; kernel::crypto::PROGRAM_ID_SIZE]);
    let miner = ProgramId([5; kernel::crypto::PROGRAM_ID_SIZE]);
    let intent = kernel::program::CoinTransition::coin(
        sender.program_id,
        vec![kernel::monetary::coin::CoinShare::from_bytes(
            [6; kernel::monetary::coin::CoinShare::SIZE],
        )],
        vec![
            CoinOutput::new(recipient, Zeno::from_zeno(10)),
            CoinOutput::new(sender.program_id, Zeno::from_zeno(5)),
        ],
    )
    .unwrap();
    let transaction =
        AuthorizedProgramEnvelope::Program(Box::new(sender.sign_xpq_transfer(intent).unwrap()));
    let genesis = genesis_block().unwrap();
    let block = Block::from_protocol_operations(
        Height(1),
        genesis.hash().unwrap(),
        1,
        Nonce(0),
        Some(Emission::new(miner, Zeno::from_zeno(1))),
        vec![transaction.clone().into()],
    )
    .unwrap();

    let outgoing = program_transaction_activity(&transaction, sender.program_id, &block)
        .unwrap()
        .unwrap();
    assert_eq!(outgoing["direction"], "out");
    assert_eq!(outgoing["amount"], 10);
    assert_eq!(
        outgoing["size_bytes"],
        canonical_bytes(&transaction).unwrap().len()
    );
    let incoming = program_transaction_activity(&transaction, recipient, &block)
        .unwrap()
        .unwrap();
    assert_eq!(incoming["direction"], "in");
    assert_eq!(incoming["amount"], 10);
    assert!(
        program_transaction_activity(
            &transaction,
            ProgramId([9; kernel::crypto::PROGRAM_ID_SIZE]),
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
fn failed_reorg_root_check_keeps_persisted_canonical_chain() {
    let database = test_database("failed-reorg-root");
    let _ = load_or_initialize_owned(&database).expect("initialize genesis");
    let miner = ProgramId([0xa1; kernel::crypto::PROGRAM_ID_SIZE]);
    let mut memory = new_pow_memory();
    assert!(matches!(
        mine_block_database(&database, miner, 0, 100, &mut memory).unwrap(),
        MiningAttempt::Mined
    ));

    let original_blocks = crate::storage::read_blocks(&database).unwrap();
    let canonical = load_or_initialize_owned(&database).unwrap();
    let original_tip = canonical.tip_hash().unwrap();

    let genesis = kernel::genesis::genesis_block().unwrap();
    let genesis_hash = genesis.hash().unwrap();
    let target_bits = expected_next_difficulty(&load_existing(&database).unwrap().chain).unwrap();
    let mut alternative_one = Block::from_protocol_operations(
        Height(1),
        genesis_hash,
        target_bits,
        Nonce(100),
        Some(Emission::new(
            miner,
            expected_emission_for_height(Height(1)),
        )),
        vec![],
    )
    .unwrap();
    // Mine the negative fixture so random PoW failure cannot mask root rejection.
    assert!(
        crate::miner::mine_range(
            &mut alternative_one,
            crate::miner::MiningRange {
                start_nonce: 0,
                attempts: 1000
            },
            &mut memory,
        )
        .unwrap()
        .is_some()
    );
    let alternative_two = Block::from_protocol_operations(
        Height(2),
        alternative_one.hash().unwrap(),
        target_bits,
        Nonce(101),
        Some(Emission::new(
            miner,
            expected_emission_for_height(Height(2)),
        )),
        vec![],
    )
    .unwrap();
    let sync = HeaderSyncResult {
        ancestor_height: Height(0),
        ancestor_hash: genesis_hash,
        headers: vec![
            kernel::consensus::HeaderAtHeight::new(Height(1), alternative_one.header.clone()),
            kernel::consensus::HeaderAtHeight::new(Height(2), alternative_two.header.clone()),
        ],
        peer_work: Work::MAX,
        peer_weight: u64::MAX,
        preferred: true,
    };

    let error = apply_verified_branch(&database, sync, vec![alternative_one, alternative_two])
        .expect_err("invalid alternative state root must abort reorg");
    assert!(error.contains("state root"), "{error}");
    assert_eq!(
        crate::storage::read_blocks(&database).unwrap(),
        original_blocks
    );
    assert_eq!(
        load_existing(&database).unwrap().tip_hash(),
        Some(original_tip)
    );
}

#[test]
fn failed_reorg_after_applying_alternative_block_keeps_database_and_cache() {
    let database = test_database("failed-reorg-after-apply");
    let _ = load_or_initialize_owned(&database).expect("initialize genesis");
    let mut memory = new_pow_memory();
    assert!(matches!(
        mine_block_database(
            &database,
            ProgramId([0xb1; kernel::crypto::PROGRAM_ID_SIZE]),
            0,
            100,
            &mut memory,
        )
        .unwrap(),
        MiningAttempt::Mined
    ));
    let stored_before = crate::storage::read_blocks(&database).unwrap();
    let canonical_before = load_or_initialize_owned(&database).unwrap();
    let original_tip = canonical_before.tip_hash();
    let original_root = canonical_before.state_root().unwrap();

    let mut alternative = kernel::genesis::genesis_ledger()
        .unwrap()
        .with_applications(extension::SystemApplications);
    let miner = ProgramId([0xb2; kernel::crypto::PROGRAM_ID_SIZE]);
    let mut first = Block::from_protocol_operations(
        Height(1),
        alternative.tip_hash().unwrap(),
        expected_next_difficulty(&alternative.chain).unwrap(),
        Nonce(0),
        Some(Emission::new(
            miner,
            expected_emission_for_height(Height(1)),
        )),
        vec![],
    )
    .unwrap();
    let (first_root, first_weight) = alternative.preview_block_commitments(&first).unwrap();
    first.set_state_root(first_root);
    first.set_block_weight(first_weight);
    assert!(
        crate::miner::mine_range(
            &mut first,
            crate::miner::MiningRange {
                start_nonce: 0,
                attempts: 100
            },
            &mut memory,
        )
        .unwrap()
        .is_some()
    );
    kernel::consensus::apply_block(&mut alternative, first.clone()).unwrap();

    let mut second = Block::from_protocol_operations(
        Height(2),
        alternative.tip_hash().unwrap(),
        expected_next_difficulty(&alternative.chain).unwrap(),
        Nonce(0),
        Some(Emission::new(
            miner,
            expected_emission_for_height(Height(2)),
        )),
        vec![],
    )
    .unwrap();
    let (correct_root, second_weight) = alternative.preview_block_commitments(&second).unwrap();
    assert_ne!(correct_root, kernel::crypto::StateRoot::ZERO);
    second.set_state_root(kernel::crypto::StateRoot::ZERO);
    second.set_block_weight(second_weight);
    assert!(
        crate::miner::mine_range(
            &mut second,
            crate::miner::MiningRange {
                start_nonce: 0,
                attempts: 100
            },
            &mut memory,
        )
        .unwrap()
        .is_some()
    );
    let sync = HeaderSyncResult {
        ancestor_height: Height(0),
        ancestor_hash: kernel::genesis::genesis_block().unwrap().hash().unwrap(),
        headers: vec![
            kernel::consensus::HeaderAtHeight::new(Height(1), first.header.clone()),
            kernel::consensus::HeaderAtHeight::new(Height(2), second.header.clone()),
        ],
        peer_work: Work::MAX,
        peer_weight: u64::MAX,
        preferred: true,
    };
    let read_error = apply_verified_branch_stream(
        &database,
        sync.clone(),
        [
            Ok(first.clone()),
            Err("simulated staging read failure".into()),
        ]
        .into_iter(),
    )
    .expect_err("staging read failed after a valid alternative block");
    assert!(read_error.contains("staging read failure"));
    assert_eq!(
        crate::storage::read_blocks(&database).unwrap(),
        stored_before
    );
    let cached = load_or_initialize_owned(&database).unwrap();
    assert_eq!(cached.tip_hash(), original_tip);
    assert_eq!(cached.state_root().unwrap(), original_root);
    let error = apply_verified_branch(&database, sync, vec![first, second])
        .expect_err("second alternative block has an invalid state root");
    assert!(error.contains("state root"), "{error}");
    assert_eq!(
        crate::storage::read_blocks(&database).unwrap(),
        stored_before
    );
    let cached = load_or_initialize_owned(&database).unwrap();
    assert_eq!(cached.tip_hash(), original_tip);
    assert_eq!(cached.state_root().unwrap(), original_root);
    assert_eq!(load_existing(&database).unwrap().tip_hash(), original_tip);
}

fn append_synthetic_header_block(ledger: &mut Ledger, miner: ProgramId) {
    let height = Height(
        ledger
            .tip_height()
            .expect("synthetic chain has genesis")
            .0
            .saturating_add(1),
    );

    let previous = ledger
        .tip_hash()
        .expect("synthetic chain has canonical tip");

    // Use a known-valid target encoding from genesis.
    // This test checks checkpoint accounting, not difficulty adjustment.
    let target_bits = ledger
        .chain
        .block(&Height(0))
        .expect("synthetic chain has genesis")
        .target_bits();

    let mut block = Block::from_protocol_operations(
        height,
        previous,
        target_bits,
        Nonce(0),
        Some(Emission::new(miner, Zeno::from_zeno(1))),
        Vec::new(),
    )
    .expect("construct synthetic block");

    // Make cumulative weight sensitive to skipped/double-counted blocks.
    block.set_block_weight(
        u32::try_from(height.0).expect("synthetic test height fits block weight"),
    );

    ledger
        .chain
        .insert_block(block)
        .expect("append synthetic canonical block");
}

fn sequential_header_metrics(ledger: &Ledger, target_height: Height) -> (Work, u64) {
    let mut cumulative_work = Work::ZERO;
    let mut cumulative_weight = 0_u64;

    for value in 1..=target_height.0 {
        let height = Height(value);

        let block = ledger
            .chain
            .block(&height)
            .expect("sequential test block exists");

        let block_work = kernel::consensus::block_work(block.target_bits())
            .expect("synthetic target bits are valid");

        cumulative_work = cumulative_work.saturating_add(block_work);

        cumulative_weight = cumulative_weight.saturating_add(u64::from(block.block_weight()));
    }

    (cumulative_work, cumulative_weight)
}

#[test]
fn checkpoint_state_matches_sequential_state_at_boundaries() {
    let mut ledger = kernel::genesis::genesis_ledger()
        .expect("genesis ledger")
        .with_applications(extension::SystemApplications);

    let miner = ProgramId([0x73; kernel::crypto::PROGRAM_ID_SIZE]);

    while ledger.tip_height() != Some(Height(512)) {
        append_synthetic_header_block(&mut ledger, miner);
    }

    let (checkpoints, total_work, total_weight) =
        build_header_state_checkpoints(&ledger).expect("build header checkpoints");

    assert_eq!(
        checkpoints
            .iter()
            .map(|checkpoint| checkpoint.height.0)
            .collect::<Vec<_>>(),
        vec![0, 256, 512],
    );

    let (expected_total_work, expected_total_weight) =
        sequential_header_metrics(&ledger, Height(512));

    assert_eq!(total_work, expected_total_work);
    assert_eq!(total_weight, expected_total_weight);

    for value in [0_u64, 1, 255, 256, 257, 511, 512] {
        let height = Height(value);

        let state = ledger_header_state_at_height(&ledger, &checkpoints, height)
            .expect("checkpoint header state");

        let (expected_work, expected_weight) = sequential_header_metrics(&ledger, height);

        assert_eq!(
            state.cumulative_work, expected_work,
            "cumulative work mismatch at height {value}",
        );

        assert_eq!(
            state.cumulative_weight, expected_weight,
            "cumulative weight mismatch at height {value}",
        );

        assert_eq!(state.height, height);

        assert_eq!(
            state.difficulty_anchor.height,
            if value == 0 { Height(0) } else { Height(1) },
            "difficulty anchor mismatch at height {value}",
        );

        if kernel::consensus::RECENT_HEADER_WINDOW > 0 {
            assert_eq!(
                state
                    .recent_headers
                    .last()
                    .expect("recent headers contain target")
                    .height,
                height,
            );
        }
    }
}

#[test]
fn explorer_tx_index_finds_canonical_transaction() {
    let database = test_database("tx-index");

    let mut ledger = kernel::genesis::genesis_ledger()
        .expect("genesis ledger")
        .with_applications(extension::SystemApplications);

    let mnemonic = wallet::encode_bip39_mnemonic(&[0x31; 16]).unwrap();

    let sender =
        wallet::account_wallet_from_bip39_mnemonic(&mnemonic, kernel::crypto::Signature::MlDsa44)
            .unwrap();

    let recipient = ProgramId([0x32; kernel::crypto::PROGRAM_ID_SIZE]);

    let miner = ProgramId([0x33; kernel::crypto::PROGRAM_ID_SIZE]);

    let intent = kernel::program::CoinTransition::coin(
        sender.program_id,
        vec![kernel::monetary::coin::CoinShare::from_bytes(
            [0x34; kernel::monetary::coin::CoinShare::SIZE],
        )],
        vec![CoinOutput::new(recipient, Zeno::from_zeno(10))],
    )
    .unwrap();

    let transaction =
        AuthorizedProgramEnvelope::Program(Box::new(sender.sign_xpq_transfer(intent).unwrap()));

    let transaction_hash = transaction.id().expect("transaction ID");

    let previous = ledger.tip_hash().expect("genesis tip");

    let target_bits = ledger
        .chain
        .block(&Height(0))
        .expect("genesis block")
        .target_bits();

    let block = Block::from_protocol_operations(
        Height(1),
        previous,
        target_bits,
        Nonce(0),
        Some(Emission::new(miner, Zeno::from_zeno(1))),
        vec![transaction.into()],
    )
    .expect("construct transaction block");

    ledger
        .chain
        .insert_block(block)
        .expect("insert transaction block");

    let location = transaction_location(&database, &ledger, transaction_hash)
        .expect("transaction index lookup")
        .expect("indexed transaction");

    assert_eq!(location.height, Height(1));
    assert_eq!(location.transaction_index, 0);

    crate::storage::clear_canonical_indexes_for_test(&database)
        .expect("clear persistent canonical indexes");

    assert_eq!(
        crate::storage::canonical_index_tip(&database).expect("read cleared canonical index tip"),
        None,
    );

    assert_eq!(
        crate::storage::read_transaction_location(&database, transaction_hash,)
            .expect("read cleared transaction index"),
        None,
    );

    // The next lookup must detect the missing marker and rebuild
    // BLOCK_HASH_INDEX and TX_INDEX from the canonical ledger.
    let rebuilt_location = transaction_location(&database, &ledger, transaction_hash)
        .expect("rebuild persistent transaction index")
        .expect("transaction after persistent index rebuild");

    assert_eq!(rebuilt_location.height, Height(1));
    assert_eq!(rebuilt_location.transaction_index, 0);

    let block = ledger.chain.block(&Height(1)).expect("canonical block 1");

    let block_hash = block.hash().expect("canonical block hash").0;

    assert_eq!(
        canonical_block_height(&database, &ledger, block_hash,)
            .expect("lookup rebuilt block hash index"),
        Some(Height(1)),
    );

    assert_eq!(
        crate::storage::canonical_index_tip(&database).expect("read rebuilt canonical index tip"),
        Some((Height(1).0, block_hash)),
    );

    assert!(
        transaction_location(&database, &ledger, [0xff; 32],)
            .expect("missing transaction lookup")
            .is_none()
    );
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
fn explorer_index_extends_after_canonical_append() {
    let database = test_database("explorer-index-append");

    let mut ledger = kernel::genesis::genesis_ledger()
        .expect("genesis ledger")
        .with_applications(extension::SystemApplications);

    let miner = ProgramId([0x41; kernel::crypto::PROGRAM_ID_SIZE]);

    let make_transaction = |seed_byte: u8, input_byte: u8, recipient_byte: u8| {
        let mnemonic = wallet::encode_bip39_mnemonic(&[seed_byte; 16]).unwrap();

        let sender = wallet::account_wallet_from_bip39_mnemonic(
            &mnemonic,
            kernel::crypto::Signature::MlDsa44,
        )
        .unwrap();

        let recipient = ProgramId([recipient_byte; kernel::crypto::PROGRAM_ID_SIZE]);

        let intent = kernel::program::CoinTransition::coin(
            sender.program_id,
            vec![kernel::monetary::coin::CoinShare::from_bytes(
                [input_byte; kernel::monetary::coin::CoinShare::SIZE],
            )],
            vec![CoinOutput::new(recipient, Zeno::from_zeno(10))],
        )
        .unwrap();

        AuthorizedProgramEnvelope::Program(Box::new(sender.sign_xpq_transfer(intent).unwrap()))
    };

    let transaction_one = make_transaction(0x42, 0x43, 0x44);

    let hash_one = transaction_one.id().expect("first transaction ID");

    let target_bits = ledger
        .chain
        .block(&Height(0))
        .expect("genesis block")
        .target_bits();

    let block_one = Block::from_protocol_operations(
        Height(1),
        ledger.tip_hash().expect("genesis tip"),
        target_bits,
        Nonce(0),
        Some(Emission::new(miner, Zeno::from_zeno(1))),
        vec![transaction_one.into()],
    )
    .expect("construct first block");

    ledger
        .chain
        .insert_block(block_one)
        .expect("insert first block");

    // First lookup builds the Explorer index through height 1.
    let first_location = transaction_location(&database, &ledger, hash_one)
        .expect("first index lookup")
        .expect("first transaction indexed");

    assert_eq!(first_location.height, Height(1));
    assert_eq!(first_location.transaction_index, 0);

    let transaction_two = make_transaction(0x45, 0x46, 0x47);

    let hash_two = transaction_two.id().expect("second transaction ID");

    let block_two = Block::from_protocol_operations(
        Height(2),
        ledger.tip_hash().expect("height-one tip"),
        target_bits,
        Nonce(0),
        Some(Emission::new(miner, Zeno::from_zeno(1))),
        vec![transaction_two.into()],
    )
    .expect("construct second block");

    ledger
        .chain
        .insert_block(block_two)
        .expect("insert second block");

    // This lookup should take the incremental extension path.
    let second_location = transaction_location(&database, &ledger, hash_two)
        .expect("second index lookup")
        .expect("second transaction indexed");

    assert_eq!(second_location.height, Height(2));
    assert_eq!(second_location.transaction_index, 0);

    // Existing entries must survive the extension.
    let first_location_after_append = transaction_location(&database, &ledger, hash_one)
        .expect("old transaction lookup after append")
        .expect("old transaction remains indexed");

    assert_eq!(first_location_after_append, first_location,);
}

#[test]
fn explorer_index_rebuilds_after_reorg_and_drops_orphan_transaction() {
    let database = test_database("explorer-index-reorg");

    let mut ledger = kernel::genesis::genesis_ledger()
        .expect("genesis ledger")
        .with_applications(extension::SystemApplications);

    let miner_a = ProgramId([0x51; kernel::crypto::PROGRAM_ID_SIZE]);

    let miner_b = ProgramId([0x52; kernel::crypto::PROGRAM_ID_SIZE]);

    let make_transaction = |seed_byte: u8, input_byte: u8, recipient_byte: u8| {
        let mnemonic = wallet::encode_bip39_mnemonic(&[seed_byte; 16]).unwrap();

        let sender = wallet::account_wallet_from_bip39_mnemonic(
            &mnemonic,
            kernel::crypto::Signature::MlDsa44,
        )
        .unwrap();

        let recipient = ProgramId([recipient_byte; kernel::crypto::PROGRAM_ID_SIZE]);

        let intent = kernel::program::CoinTransition::coin(
            sender.program_id,
            vec![kernel::monetary::coin::CoinShare::from_bytes(
                [input_byte; kernel::monetary::coin::CoinShare::SIZE],
            )],
            vec![CoinOutput::new(recipient, Zeno::from_zeno(10))],
        )
        .unwrap();

        AuthorizedProgramEnvelope::Program(Box::new(sender.sign_xpq_transfer(intent).unwrap()))
    };

    let target_bits = ledger
        .chain
        .block(&Height(0))
        .expect("genesis block")
        .target_bits();

    // Canonical branch A.
    let transaction_a = make_transaction(0x53, 0x54, 0x55);

    let hash_a = transaction_a.id().expect("branch A transaction ID");

    let block_a = Block::from_protocol_operations(
        Height(1),
        ledger.tip_hash().expect("genesis tip"),
        target_bits,
        Nonce(0),
        Some(Emission::new(miner_a, Zeno::from_zeno(1))),
        vec![transaction_a.into()],
    )
    .expect("construct branch A block");

    ledger
        .chain
        .insert_block(block_a)
        .expect("insert branch A block");

    // Build index against branch A.
    assert!(
        transaction_location(&database, &ledger, hash_a,)
            .expect("branch A lookup")
            .is_some()
    );

    let branch_a_tip = ledger.tip_hash().expect("branch A tip");

    ledger
        .chain
        .remove_tip(branch_a_tip)
        .expect("remove branch A tip");

    // Alternative branch B at the same height.
    let transaction_b = make_transaction(0x56, 0x57, 0x58);

    let hash_b = transaction_b.id().expect("branch B transaction ID");

    let block_b = Block::from_protocol_operations(
        Height(1),
        ledger.tip_hash().expect("genesis tip after reorg"),
        target_bits,
        Nonce(1),
        Some(Emission::new(miner_b, Zeno::from_zeno(1))),
        vec![transaction_b.into()],
    )
    .expect("construct branch B block");

    ledger
        .chain
        .insert_block(block_b)
        .expect("insert branch B block");

    // Tip height is still 1, but tip hash changed.
    // refresh_explorer_index() must rebuild, not extend.
    assert!(
        transaction_location(&database, &ledger, hash_a,)
            .expect("orphan transaction lookup")
            .is_none(),
        "orphan transaction remained in explorer index",
    );

    let location_b = transaction_location(&database, &ledger, hash_b)
        .expect("branch B lookup")
        .expect("branch B transaction indexed");

    assert_eq!(location_b.height, Height(1));
    assert_eq!(location_b.transaction_index, 0);
}

#[test]
fn explorer_program_index_rebuilds_after_reorg() {
    let database = test_database("explorer-address-index-reorg");

    let mut ledger = kernel::genesis::genesis_ledger()
        .expect("genesis ledger")
        .with_applications(extension::SystemApplications);

    let miner_a = ProgramId([0x61; kernel::crypto::PROGRAM_ID_SIZE]);
    let miner_b = ProgramId([0x62; kernel::crypto::PROGRAM_ID_SIZE]);

    let recipient_a = ProgramId([0x63; kernel::crypto::PROGRAM_ID_SIZE]);
    let recipient_b = ProgramId([0x64; kernel::crypto::PROGRAM_ID_SIZE]);

    let make_transaction = |seed_byte: u8, input_byte: u8, recipient: ProgramId| {
        let mnemonic = wallet::encode_bip39_mnemonic(&[seed_byte; 16]).unwrap();

        let sender = wallet::account_wallet_from_bip39_mnemonic(
            &mnemonic,
            kernel::crypto::Signature::MlDsa44,
        )
        .unwrap();

        let intent = kernel::program::CoinTransition::coin(
            sender.program_id,
            vec![kernel::monetary::coin::CoinShare::from_bytes(
                [input_byte; kernel::monetary::coin::CoinShare::SIZE],
            )],
            vec![CoinOutput::new(recipient, Zeno::from_zeno(10))],
        )
        .unwrap();

        AuthorizedProgramEnvelope::Program(Box::new(sender.sign_xpq_transfer(intent).unwrap()))
    };

    let target_bits = ledger
        .chain
        .block(&Height(0))
        .expect("genesis block")
        .target_bits();

    let transaction_a = make_transaction(0x65, 0x66, recipient_a);

    let block_a = Block::from_protocol_operations(
        Height(1),
        ledger.tip_hash().expect("genesis tip"),
        target_bits,
        Nonce(0),
        Some(Emission::new(miner_a, Zeno::from_zeno(1))),
        vec![transaction_a.into()],
    )
    .expect("construct branch A block");

    ledger
        .chain
        .insert_block(block_a)
        .expect("insert branch A block");

    let recipient_a_activities = program_activity_locations(&database, &ledger, recipient_a)
        .expect("branch A recipient activities");

    assert_eq!(
        recipient_a_activities,
        vec![ActivityLocation::Transaction {
            height: Height(1),
            transaction_index: 0,
        }],
    );

    let miner_a_activities =
        program_activity_locations(&database, &ledger, miner_a).expect("branch A miner activities");

    assert!(miner_a_activities.contains(&ActivityLocation::Emission { height: Height(1) },));

    let branch_a_tip = ledger.tip_hash().expect("branch A tip");

    ledger
        .chain
        .remove_tip(branch_a_tip)
        .expect("remove branch A tip");

    let transaction_b = make_transaction(0x67, 0x68, recipient_b);

    let block_b = Block::from_protocol_operations(
        Height(1),
        ledger.tip_hash().expect("genesis tip after reorg"),
        target_bits,
        Nonce(1),
        Some(Emission::new(miner_b, Zeno::from_zeno(1))),
        vec![transaction_b.into()],
    )
    .expect("construct branch B block");

    ledger
        .chain
        .insert_block(block_b)
        .expect("insert branch B block");

    assert!(
        program_activity_locations(&database, &ledger, recipient_a,)
            .expect("orphan recipient lookup")
            .is_empty(),
        "orphan recipient activity remained indexed",
    );

    assert!(
        program_activity_locations(&database, &ledger, miner_a,)
            .expect("orphan miner lookup")
            .is_empty(),
        "orphan emission remained indexed",
    );

    assert_eq!(
        program_activity_locations(&database, &ledger, recipient_b,)
            .expect("branch B recipient lookup"),
        vec![ActivityLocation::Transaction {
            height: Height(1),
            transaction_index: 0,
        }],
    );

    assert!(
        program_activity_locations(&database, &ledger, miner_b,)
            .expect("branch B miner lookup")
            .contains(&ActivityLocation::Emission { height: Height(1) },)
    );

    // Simulate missing/corrupted rebuildable persistent indexes.
    crate::storage::clear_canonical_indexes_for_test(&database)
        .expect("clear persistent canonical indexes");

    assert_eq!(
        crate::storage::canonical_index_tip(&database).expect("read cleared canonical index tip"),
        None,
    );

    assert!(
        crate::storage::read_program_activities(&database, recipient_b.0,)
            .expect("read cleared recipient activity index")
            .is_empty(),
    );

    assert!(
        crate::storage::read_program_activities(&database, miner_b.0,)
            .expect("read cleared miner activity index")
            .is_empty(),
    );

    // First address lookup must rebuild all persistent canonical indexes.
    let rebuilt_recipient = program_activity_locations(&database, &ledger, recipient_b)
        .expect("rebuild recipient address activity index");

    assert_eq!(
        rebuilt_recipient,
        vec![ActivityLocation::Transaction {
            height: Height(1),
            transaction_index: 0,
        }],
    );

    let rebuilt_miner = program_activity_locations(&database, &ledger, miner_b)
        .expect("lookup rebuilt miner activity index");

    assert!(rebuilt_miner.contains(&ActivityLocation::Emission { height: Height(1) },),);

    assert_eq!(
        crate::storage::canonical_index_tip(&database).expect("read rebuilt canonical index tip"),
        Some((
            ledger.tip_height().expect("canonical tip height").0,
            ledger.tip_hash().expect("canonical tip hash").0,
        )),
    );

    assert!(
        !crate::storage::read_program_activities(&database, recipient_b.0,)
            .expect("read rebuilt recipient activity index")
            .is_empty(),
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
fn explorer_address_pagination_uses_exclusive_cursor() {
    let database = test_database("explorer-address-pagination");

    let mut ledger = kernel::genesis::genesis_ledger()
        .expect("genesis ledger")
        .with_applications(extension::SystemApplications);

    let miner = ProgramId([0x91; kernel::crypto::PROGRAM_ID_SIZE]);

    let target_bits = ledger
        .chain
        .block(&Height(0))
        .expect("genesis block")
        .target_bits();

    for height in 1_u64..=5 {
        let block = Block::from_protocol_operations(
            Height(height),
            ledger.tip_hash().expect("canonical tip"),
            target_bits,
            Nonce(height),
            Some(Emission::new(miner, Zeno::from_zeno(1))),
            vec![],
        )
        .expect("construct pagination block");

        ledger
            .chain
            .insert_block(block)
            .expect("insert pagination block");
    }

    // Page 1: newest two activities.
    let page1 = program_activity_page(&database, &ledger, miner, None, 2)
        .expect("read first activity page");

    assert_eq!(
        page1.locations,
        vec![
            ActivityLocation::Emission { height: Height(5) },
            ActivityLocation::Emission { height: Height(4) },
        ],
    );

    let cursor1 = page1.next_cursor.expect("first page has next cursor");

    // Cursor must be exclusive: height 4 must not appear again.
    let page2 = program_activity_page(&database, &ledger, miner, Some(cursor1), 2)
        .expect("read second activity page");

    assert_eq!(
        page2.locations,
        vec![
            ActivityLocation::Emission { height: Height(3) },
            ActivityLocation::Emission { height: Height(2) },
        ],
    );

    let cursor2 = page2.next_cursor.expect("second page has next cursor");

    let page3 = program_activity_page(&database, &ledger, miner, Some(cursor2), 2)
        .expect("read final activity page");

    assert_eq!(
        page3.locations,
        vec![ActivityLocation::Emission { height: Height(1) }],
    );

    assert_eq!(page3.next_cursor, None);

    // Combined result proves there was no duplicate or skipped entry.
    let heights = page1
        .locations
        .iter()
        .chain(&page2.locations)
        .chain(&page3.locations)
        .map(|location| match location {
            ActivityLocation::Emission { height } => height.0,
            ActivityLocation::Transaction { .. } => {
                panic!("unexpected transaction activity")
            }
        })
        .collect::<Vec<_>>();

    assert_eq!(heights, vec![5, 4, 3, 2, 1]);
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
fn p2p_transaction_frame_rejects_oversized_length_before_body() {
    let error = validate_frame_length(
        MAX_STORED_TRANSACTION_SIZE + 2,
        MAX_STORED_TRANSACTION_SIZE + 1,
    )
    .unwrap_err();
    assert!(error.contains("outside allowed range"));
    assert!(
        validate_session_frame_length(MAX_STORED_TRANSACTION_SIZE + 2, SUBMIT_TRANSACTION_MESSAGE,)
            .is_err()
    );
    assert!(
        validate_session_frame_length(MAX_STORED_TRANSACTION_SIZE + 2, SUBMIT_BLOCK_MESSAGE,)
            .is_ok()
    );
}

#[test]
fn explorer_index_rebuilds_after_deep_reorg_to_longer_branch() {
    let database = test_database("explorer-index-deep-reorg");

    let mut ledger = kernel::genesis::genesis_ledger()
        .expect("genesis ledger")
        .with_applications(extension::SystemApplications);

    let miner = ProgramId([0x71; kernel::crypto::PROGRAM_ID_SIZE]);

    let make_transaction = |seed_byte: u8, input_byte: u8, recipient_byte: u8| {
        let mnemonic = wallet::encode_bip39_mnemonic(&[seed_byte; 16]).unwrap();

        let sender = wallet::account_wallet_from_bip39_mnemonic(
            &mnemonic,
            kernel::crypto::Signature::MlDsa44,
        )
        .unwrap();

        let recipient = ProgramId([recipient_byte; kernel::crypto::PROGRAM_ID_SIZE]);

        let intent = kernel::program::CoinTransition::coin(
            sender.program_id,
            vec![kernel::monetary::coin::CoinShare::from_bytes(
                [input_byte; kernel::monetary::coin::CoinShare::SIZE],
            )],
            vec![CoinOutput::new(recipient, Zeno::from_zeno(10))],
        )
        .unwrap();

        AuthorizedProgramEnvelope::Program(Box::new(sender.sign_xpq_transfer(intent).unwrap()))
    };

    let target_bits = ledger
        .chain
        .block(&Height(0))
        .expect("genesis block")
        .target_bits();

    // Branch A: heights 1 → 2.
    let transaction_a = make_transaction(0x72, 0x73, 0x74);

    let hash_a = transaction_a.id().expect("branch A transaction ID");

    let block_a1 = Block::from_protocol_operations(
        Height(1),
        ledger.tip_hash().expect("genesis tip"),
        target_bits,
        Nonce(0),
        Some(Emission::new(miner, Zeno::from_zeno(1))),
        vec![transaction_a.into()],
    )
    .expect("branch A height 1");

    ledger.chain.insert_block(block_a1).unwrap();

    let block_a2 = Block::from_protocol_operations(
        Height(2),
        ledger.tip_hash().expect("branch A height-one tip"),
        target_bits,
        Nonce(0),
        Some(Emission::new(miner, Zeno::from_zeno(1))),
        vec![],
    )
    .expect("branch A height 2");

    ledger.chain.insert_block(block_a2).unwrap();

    // Build index at branch A height 2.
    assert!(
        transaction_location(&database, &ledger, hash_a)
            .unwrap()
            .is_some()
    );

    // Roll back branch A completely.
    for _ in 0..2 {
        let tip = ledger.tip_hash().expect("branch A tip");
        ledger.chain.remove_tip(tip).unwrap();
    }

    // Branch B: heights 1 → 2 → 3.
    let transaction_b = make_transaction(0x75, 0x76, 0x77);

    let hash_b = transaction_b.id().expect("branch B transaction ID");

    let block_b1 = Block::from_protocol_operations(
        Height(1),
        ledger.tip_hash().expect("genesis tip"),
        target_bits,
        Nonce(1),
        Some(Emission::new(miner, Zeno::from_zeno(1))),
        vec![transaction_b.into()],
    )
    .expect("branch B height 1");

    ledger.chain.insert_block(block_b1).unwrap();

    for height in [2_u64, 3] {
        let block = Block::from_protocol_operations(
            Height(height),
            ledger.tip_hash().expect("branch B tip"),
            target_bits,
            Nonce(height),
            Some(Emission::new(miner, Zeno::from_zeno(1))),
            vec![],
        )
        .expect("branch B block");

        ledger.chain.insert_block(block).unwrap();
    }

    // New tip is higher than indexed tip, but old height-2 hash
    // is no longer canonical. Index must rebuild, not extend.
    assert!(
        transaction_location(&database, &ledger, hash_a)
            .unwrap()
            .is_none(),
        "orphan transaction survived deep reorg",
    );

    let location_b = transaction_location(&database, &ledger, hash_b)
        .unwrap()
        .expect("branch B transaction indexed");

    assert_eq!(location_b.height, Height(1));
    assert_eq!(location_b.transaction_index, 0);
}

#[test]
fn block_index_extends_and_rebuilds_after_reorg() {
    let database = test_database("block-index-reorg");

    let mut ledger = kernel::genesis::genesis_ledger()
        .expect("genesis ledger")
        .with_applications(extension::SystemApplications);

    let miner = ProgramId([0x81; kernel::crypto::PROGRAM_ID_SIZE]);

    let target_bits = ledger
        .chain
        .block(&Height(0))
        .expect("genesis block")
        .target_bits();

    let block_a1 = Block::from_protocol_operations(
        Height(1),
        ledger.tip_hash().expect("genesis tip"),
        target_bits,
        Nonce(1),
        Some(Emission::new(miner, Zeno::from_zeno(1))),
        vec![],
    )
    .expect("branch A block 1");

    let hash_a1 = block_a1.hash().expect("branch A hash 1").0;

    ledger
        .chain
        .insert_block(block_a1)
        .expect("insert branch A block 1");

    // Initial build.
    assert_eq!(
        canonical_block_height(&database, &ledger, hash_a1).unwrap(),
        Some(Height(1)),
    );

    let block_a2 = Block::from_protocol_operations(
        Height(2),
        ledger.tip_hash().expect("branch A tip"),
        target_bits,
        Nonce(2),
        Some(Emission::new(miner, Zeno::from_zeno(1))),
        vec![],
    )
    .expect("branch A block 2");

    let hash_a2 = block_a2.hash().expect("branch A hash 2").0;

    ledger
        .chain
        .insert_block(block_a2)
        .expect("insert branch A block 2");

    // Incremental extension.
    assert_eq!(
        canonical_block_height(&database, &ledger, hash_a2).unwrap(),
        Some(Height(2)),
    );

    // Remove branch A completely.
    for _ in 0..2 {
        let tip = ledger.tip_hash().expect("branch A tip");
        ledger.chain.remove_tip(tip).unwrap();
    }

    let block_b1 = Block::from_protocol_operations(
        Height(1),
        ledger.tip_hash().expect("genesis tip after rollback"),
        target_bits,
        Nonce(11),
        Some(Emission::new(miner, Zeno::from_zeno(1))),
        vec![],
    )
    .expect("branch B block 1");

    let hash_b1 = block_b1.hash().expect("branch B hash 1").0;

    ledger.chain.insert_block(block_b1).unwrap();

    for (height, nonce) in [(2_u64, 12_u64), (3_u64, 13_u64)] {
        let block = Block::from_protocol_operations(
            Height(height),
            ledger.tip_hash().expect("branch B tip"),
            target_bits,
            Nonce(nonce),
            Some(Emission::new(miner, Zeno::from_zeno(1))),
            vec![],
        )
        .expect("branch B block");

        ledger.chain.insert_block(block).unwrap();
    }

    // Old canonical hashes must disappear after rebuild.
    assert_eq!(
        canonical_block_height(&database, &ledger, hash_a1).unwrap(),
        None,
    );

    assert_eq!(
        canonical_block_height(&database, &ledger, hash_a2).unwrap(),
        None,
    );

    assert_eq!(
        canonical_block_height(&database, &ledger, hash_b1).unwrap(),
        Some(Height(1)),
    );
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
fn deploy_operation_is_mined_persisted_and_replayed() {
    use kernel::crypto::{AccountSignatureScheme, SigningSeed, program_id_from_public_key};
    use kernel::{
        consensus::quote_deploy_burn,
        operation::{AuthorizedDeployProgram, BlockOperation},
        program::{AccountAuthorization, CoinCharges, CoinTransition, DeployProgram},
    };
    let database = test_database("deploy-operation");
    let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([0x71; 32]));
    let owner = program_id_from_public_key(&seed.public_key()).unwrap();
    let mut memory = new_pow_memory();
    let mut nonce = 0;
    loop {
        match mine_block_database(&database, owner, nonce, 1_000_000, &mut memory).unwrap() {
            MiningAttempt::Mined => break,
            MiningAttempt::Exhausted { next } => nonce = next,
        }
    }
    let ledger = load_existing(&database).unwrap();
    let (input, coin) = ledger
        .state()
        .utxos()
        .coins()
        .find(|(_, coin)| coin.owner == kernel::common::Owner::Program(owner))
        .unwrap();
    let input_amount = coin.amount.as_zeno();
    let mut code = b"XPVM".to_vec();
    code.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0, 0]);
    code.push(1);
    code.extend_from_slice(&7i64.to_le_bytes());
    code.push(3);
    let deploy = DeployProgram {
        owner,
        nonce: 1,
        code: code.into(),
    };
    let chain = kernel::genesis::chain_context().unwrap();
    let height = Height(2);
    let fee = 100_000;
    let make = |burn: u64| {
        let payment = CoinTransition::coin_with_charges(
            owner,
            vec![input],
            vec![CoinOutput::new(
                owner,
                Zeno::from_zeno(input_amount - burn - fee),
            )],
            CoinCharges::new(Zeno::from_zeno(fee)),
        )
        .unwrap();
        let mut signed = AuthorizedDeployProgram {
            deploy: deploy.clone(),
            payment,
            authorization: AccountAuthorization {
                salt: [0; 32],
                public_key: seed.public_key(),
                signature: seed.sign(&[0; kernel::crypto::HASH_SIZE]),
            },
        };
        let commitment = signed.commitment(chain).unwrap();
        signed.authorization.signature = seed.sign(commitment.as_bytes());
        signed
    };
    let (_, burn) = quote_deploy_burn(&make(0), height, ledger.state()).unwrap();
    let signed = make(burn.as_zeno());
    let (program_id, exact_burn) = quote_deploy_burn(&signed, height, ledger.state()).unwrap();
    assert_eq!(exact_burn, burn);
    let operation = BlockOperation::DeployProgram(Box::new(signed));
    let operation_id = operation.id().unwrap().into_bytes();
    insert_pending_operation(&database, operation, false).unwrap();
    assert_eq!(read_pending_operations(&database).unwrap().len(), 1);
    let mut nonce = 0;
    loop {
        match mine_block_database(&database, owner, nonce, 1_000_000, &mut memory).unwrap() {
            MiningAttempt::Mined => break,
            MiningAttempt::Exhausted { next } => nonce = next,
        }
    }
    let replayed = load_existing(&database).unwrap();
    assert!(replayed.state().programs().contains(&program_id));
    assert!(
        replayed
            .chain
            .block(&Height(2))
            .unwrap()
            .operations()
            .iter()
            .any(|op| op.id().unwrap().into_bytes() == operation_id)
    );
    let response = block_response(&replayed, replayed.chain.block(&Height(2)).unwrap()).unwrap();
    assert_eq!(response["operations"], 1);
    assert_eq!(response["transactions"], 0);
    assert_eq!(response["operation_details"][0]["type"], "deploy_program");
    assert!(read_pending_operations(&database).unwrap().is_empty());
    let old_block = replayed.chain.block(&Height(2)).unwrap().clone();
    let expected_burns = replayed
        .program_call_protocol_burns_for_block(&old_block)
        .unwrap();
    let mut pruned = replayed.clone();
    super::journal::copy_receipt(&database, &database, &pruned, &old_block).unwrap();
    let mut next_block = super::mining::candidate_operation_block(&pruned, owner, vec![]).unwrap();
    crate::miner::mine_range(
        &mut next_block,
        crate::miner::MiningRange {
            start_nonce: 0,
            attempts: 1000,
        },
        &mut memory,
    )
    .unwrap()
    .unwrap();
    apply_block(&mut pruned, next_block.clone()).unwrap();
    persist_block_and_pending(&database, &next_block, &[]).unwrap();
    let blocked = test_database("journal-archive-blocked");
    fs::write(&blocked, b"not a database directory").unwrap();
    let root_before = pruned.state_root().unwrap();
    let journals_before = pruned.rollback_journal_heights().count();
    super::journal::prune_journals_with_window(&blocked, &mut pruned, 1).unwrap();
    assert_eq!(pruned.rollback_journal_heights().count(), journals_before);
    assert_eq!(pruned.state_root().unwrap(), root_before);
    fs::remove_file(blocked).unwrap();
    super::journal::prune_journals_with_window(&database, &mut pruned, 1).unwrap();
    assert!(
        pruned
            .program_call_protocol_burns_for_block(&old_block)
            .is_none()
    );
    assert_eq!(
        super::journal::protocol_burns(&database, &pruned, &old_block).unwrap(),
        expected_burns
    );
    assert_eq!(
        stored_block_response(&database, &pruned, &old_block).unwrap(),
        response
    );
    crate::snapshot::write(&database, &pruned).unwrap();
    let restored = load_existing(&database).unwrap();
    assert_eq!(restored.rollback_journal_heights().count(), 1);
    assert_eq!(
        stored_block_response(&database, &restored, &old_block).unwrap(),
        response
    );
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

#[test]
fn disk_body_eviction_preserves_headers_rpc_restart_and_deep_reorg() {
    let database = test_database("disk-body-eviction");
    let miner = ProgramId([0xd1; kernel::crypto::PROGRAM_ID_SIZE]);
    let mut memory = new_pow_memory();
    let mut canonical = kernel::genesis::genesis_ledger()
        .unwrap()
        .with_applications(extension::SystemApplications);
    fn extend(ledger: &mut Ledger, miner: ProgramId, memory: &mut PoWMemory) -> Block {
        let mut block = super::mining::candidate_operation_block(ledger, miner, vec![]).unwrap();
        assert!(
            crate::miner::mine_range(
                &mut block,
                crate::miner::MiningRange {
                    start_nonce: 0,
                    attempts: 1000,
                },
                memory
            )
            .unwrap()
            .is_some()
        );
        apply_block(ledger, block.clone()).unwrap();
        block
    }
    for _ in 0..3 {
        extend(&mut canonical, miner, &mut memory);
    }
    persist_chain_and_pending(&database, &canonical, &[]).unwrap();
    let pinned_reader = crate::storage::CanonicalBodyReader::new(&database).unwrap();
    let original_tip = canonical.tip_hash();
    let old = canonical.chain.block(&Height(1)).unwrap().clone();
    let expected = block_response(&canonical, &old).unwrap();
    let mut damaged = old.clone();
    damaged.body_mut().emission.as_mut().unwrap().to =
        ProgramId([0xff; kernel::crypto::PROGRAM_ID_SIZE]);
    assert!(
        decode_pinned_local_body(Height(1), &old.header, &block_bytes(&damaged).unwrap())
            .unwrap_err()
            .contains("Merkle commitment")
    );
    assert!(decode_pinned_local_body(Height(2), &old.header, &block_bytes(&old).unwrap()).is_err());
    let mut trailing = block_bytes(&old).unwrap();
    trailing.push(0);
    assert!(decode_pinned_local_body(Height(1), &old.header, &trailing).is_err());

    let headers = canonical.chain.chain_headers();
    canonical.chain.retain_recent_bodies(0, 0).unwrap();
    assert!(canonical.chain.block(&Height(1)).is_none());
    assert!(canonical.chain.block(&Height(2)).is_none());
    assert_eq!(canonical.chain.chain_headers(), headers);
    assert_eq!(canonical.chain.blocks().count(), 2); // Pinned genesis and tip.
    assert_eq!(
        canonical_block(&database, &canonical, Height(1)).unwrap(),
        old
    );
    assert_eq!(
        block_response(
            &canonical,
            &canonical_block(&database, &canonical, Height(1)).unwrap()
        )
        .unwrap(),
        expected
    );
    assert_eq!(
        latest_blocks_response(&database, &canonical).unwrap()["blocks"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    let checkpoints = build_header_state_checkpoints(&canonical).unwrap().0;
    assert_eq!(
        ledger_header_state_at_height(&canonical, &checkpoints, Height(1))
            .unwrap()
            .header,
        old.header
    );
    assert_eq!(
        ledger_header_locator(&canonical).unwrap().last().unwrap().0,
        EXPECTED_GENESIS_HASH.0
    );
    assert_eq!(
        expected_next_difficulty(&canonical.chain).unwrap(),
        old.target_bits()
    );
    assert_eq!(
        load_existing(&database).unwrap().state_root().unwrap(),
        canonical.state_root().unwrap()
    );
    update_ledger_cache(&database, canonical).unwrap();

    let mut alternative = kernel::genesis::genesis_ledger()
        .unwrap()
        .with_applications(extension::SystemApplications);
    let mut bodies = Vec::new();
    for _ in 0..4 {
        bodies.push(extend(
            &mut alternative,
            ProgramId([0xd2; kernel::crypto::PROGRAM_ID_SIZE]),
            &mut memory,
        ));
    }
    let (work, weight) = sequential_header_metrics(&alternative, Height(4));
    let sync = HeaderSyncResult {
        ancestor_height: Height(0),
        ancestor_hash: EXPECTED_GENESIS_HASH,
        headers: bodies
            .iter()
            .map(|block| {
                kernel::consensus::HeaderAtHeight::new(block.height(), block.header.clone())
            })
            .collect(),
        peer_work: work,
        peer_weight: weight,
        preferred: true,
    };
    assert_eq!(apply_verified_branch(&database, sync, bodies).unwrap(), 4);
    let replayed = load_existing(&database).unwrap();
    assert_eq!(replayed.tip_hash(), alternative.tip_hash());
    assert_eq!(
        replayed.state_root().unwrap(),
        alternative.state_root().unwrap()
    );
    assert_eq!(
        crate::storage::CanonicalBodyReader::new(&database)
            .unwrap()
            .count(),
        5
    );
    let pinned_tip = pinned_reader
        .map(|bytes| decode_block(&bytes.unwrap()).unwrap())
        .last()
        .unwrap();
    assert_eq!(Some(pinned_tip.hash().unwrap()), original_tip);
}

#[cfg(feature = "devnet")]
#[test]
fn scratch_recovery_replays_expired_journals_and_survives_restart() {
    let _test = super::recovery::RECOVERY_TEST_LOCK.lock().unwrap();
    let database = test_database("scratch-expired");
    let miner = ProgramId([0xd1; kernel::crypto::PROGRAM_ID_SIZE]);
    let mut memory = new_pow_memory();
    let mut canonical = kernel::genesis::genesis_ledger()
        .unwrap()
        .with_applications(extension::SystemApplications);
    fn extend(ledger: &mut Ledger, miner: ProgramId, memory: &mut PoWMemory) -> Block {
        let mut block = super::mining::candidate_operation_block(ledger, miner, vec![]).unwrap();
        assert!(
            crate::miner::mine_range(
                &mut block,
                crate::miner::MiningRange {
                    start_nonce: 0,
                    attempts: 1000,
                },
                memory
            )
            .unwrap()
            .is_some()
        );
        apply_block(ledger, block.clone()).unwrap();
        block
    }
    for _ in 0..3 {
        extend(&mut canonical, miner, &mut memory);
    }
    persist_chain_and_pending(&database, &canonical, &[]).unwrap();
    let pinned_reader = crate::storage::CanonicalBodyReader::new(&database).unwrap();
    let original_tip = canonical.tip_hash();
    canonical.discard_rollback_journals_before(Height(4));
    let captured = Arc::new(canonical.clone());
    update_ledger_cache(&database, canonical).unwrap();

    let mut alternative = kernel::genesis::genesis_ledger()
        .unwrap()
        .with_applications(extension::SystemApplications);
    let mut bodies = Vec::new();
    for _ in 0..4 {
        bodies.push(extend(
            &mut alternative,
            ProgramId([0xd2; kernel::crypto::PROGRAM_ID_SIZE]),
            &mut memory,
        ));
    }
    let (work, weight) = sequential_header_metrics(&alternative, Height(4));
    let sync = HeaderSyncResult {
        ancestor_height: Height(0),
        ancestor_hash: EXPECTED_GENESIS_HASH,
        headers: bodies
            .iter()
            .map(|block| {
                kernel::consensus::HeaderAtHeight::new(block.height(), block.header.clone())
            })
            .collect(),
        peer_work: work,
        peer_weight: weight,
        preferred: true,
    };
    let make_sync = || HeaderSyncResult {
        ancestor_height: sync.ancestor_height,
        ancestor_hash: sync.ancestor_hash,
        headers: sync.headers.clone(),
        peer_work: sync.peer_work,
        peer_weight: sync.peer_weight,
        preferred: true,
    };
    let mut forged = make_sync();
    forged.peer_work = Work::MAX;
    assert!(
        super::recovery::recover_branch(
            &database,
            captured.clone(),
            forged,
            bodies.clone().into_iter().map(Ok)
        )
        .unwrap_err()
        .contains("work does not match")
    );
    let before = crate::storage::read_blocks(&database).unwrap();
    let mut failed = bodies.iter().cloned().map(Ok).collect::<Vec<_>>();
    failed[2] = Err("simulated local download I/O failure".into());
    assert!(
        super::recovery::recover_branch(
            &database,
            captured.clone(),
            make_sync(),
            failed.into_iter()
        )
        .unwrap_err()
        .contains("simulated local download")
    );
    assert_eq!(crate::storage::read_blocks(&database).unwrap(), before);
    assert_eq!(
        load_or_initialize(&database).unwrap().tip_hash(),
        original_tip
    );
    assert_eq!(fs::read_dir(database.join("recovery")).unwrap().count(), 0);
    let mut bad = bodies.clone();
    bad[1].body_mut().emission.as_mut().unwrap().to = ProgramId::ZERO;
    assert!(
        super::recovery::recover_branch(
            &database,
            captured.clone(),
            make_sync(),
            bad.into_iter().map(Ok)
        )
        .is_err()
    );
    assert_eq!(crate::storage::read_blocks(&database).unwrap(), before);
    assert_eq!(
        load_or_initialize(&database).unwrap().tip_hash(),
        original_tip
    );
    assert_eq!(
        super::recovery::recover_branch(
            &database,
            captured.clone(),
            make_sync(),
            bodies.into_iter().map(Ok)
        )
        .unwrap(),
        4
    );
    assert_eq!(fs::read_dir(database.join("recovery")).unwrap().count(), 0);
    let replayed = load_existing(&database).unwrap();
    assert_eq!(replayed.tip_hash(), alternative.tip_hash());
    assert_eq!(
        replayed.state_root().unwrap(),
        alternative.state_root().unwrap()
    );
    assert_eq!(
        crate::storage::CanonicalBodyReader::new(&database)
            .unwrap()
            .count(),
        5
    );
    let pinned_tip = pinned_reader
        .map(|bytes| decode_block(&bytes.unwrap()).unwrap())
        .last()
        .unwrap();
    assert_eq!(Some(pinned_tip.hash().unwrap()), original_tip);
}

#[cfg(feature = "devnet")]
#[test]
fn scratch_recovery_uses_ancestor_snapshot_rechecks_work_and_rejects_invalid_state() {
    let _test = super::recovery::RECOVERY_TEST_LOCK.lock().unwrap();
    fn extend(ledger: &mut Ledger, miner: ProgramId, memory: &mut PoWMemory) -> Block {
        let mut block = super::mining::candidate_operation_block(ledger, miner, vec![]).unwrap();
        crate::miner::mine_range(
            &mut block,
            crate::miner::MiningRange {
                start_nonce: 0,
                attempts: 1000,
            },
            memory,
        )
        .unwrap()
        .unwrap();
        apply_block(ledger, block.clone()).unwrap();
        block
    }
    let database = test_database("scratch-snapshot-concurrent");
    let mut memory = new_pow_memory();
    let mut canonical = kernel::genesis::genesis_ledger()
        .unwrap()
        .with_applications(extension::SystemApplications);
    extend(&mut canonical, ProgramId::ZERO, &mut memory);
    let prefix = canonical.clone();
    for _ in 0..2 {
        extend(&mut canonical, ProgramId::ZERO, &mut memory);
    }
    persist_chain_and_pending(&database, &canonical, &[]).unwrap();
    crate::snapshot::write(&database, &prefix).unwrap();
    // A newer snapshot must never be used to start recovery below its tip.
    crate::snapshot::write(&database, &canonical).unwrap();
    canonical.discard_rollback_journals_before(Height(4));
    let captured = Arc::new(canonical.clone());
    update_ledger_cache(&database, canonical.clone()).unwrap();
    let mut alternative = prefix.clone();
    let bodies = (0..4)
        .map(|_| {
            extend(
                &mut alternative,
                ProgramId([0xe3; kernel::crypto::PROGRAM_ID_SIZE]),
                &mut memory,
            )
        })
        .collect::<Vec<_>>();
    let (work, weight) = sequential_header_metrics(&alternative, Height(5));
    let make_sync = |bodies: &[Block]| HeaderSyncResult {
        ancestor_height: Height(1),
        ancestor_hash: prefix.tip_hash().unwrap(),
        headers: bodies
            .iter()
            .map(|block| {
                kernel::consensus::HeaderAtHeight::new(block.height(), block.header.clone())
            })
            .collect(),
        peer_work: work,
        peer_weight: weight,
        preferred: true,
    };
    // A structurally committed, mined header with a wrong execution root is invalid.
    let mut invalid = bodies.clone();
    invalid.last_mut().unwrap().header.state_root = prefix.state_root().unwrap();
    crate::miner::mine_range(
        invalid.last_mut().unwrap(),
        crate::miner::MiningRange {
            start_nonce: 0,
            attempts: 1000,
        },
        &mut memory,
    )
    .unwrap()
    .unwrap();
    let original = crate::storage::read_blocks(&database).unwrap();
    assert!(
        super::recovery::recover_branch(
            &database,
            captured.clone(),
            make_sync(&invalid),
            invalid.clone().into_iter().map(Ok)
        )
        .unwrap_err()
        .contains("invalid recovery candidate")
    );
    assert!(
        super::recovery::recover_branch(
            &database,
            captured.clone(),
            make_sync(&invalid),
            invalid.clone().into_iter().map(Ok)
        )
        .unwrap_err()
        .contains("already validated")
    );
    assert_eq!(crate::storage::read_blocks(&database).unwrap(), original);
    // A concurrent canonical append happens while the recovery lock is held,
    // proving that replay does not hold the state mutation lock.
    let mut advanced = canonical;
    let appended = extend(&mut advanced, ProgramId::ZERO, &mut memory);
    let mut moved = false;
    let stream = bodies.iter().cloned().map(|block| {
        if !moved {
            let _mutation = state_mutation_lock().unwrap().lock().unwrap();
            persist_block_and_pending(&database, &appended, &[]).unwrap();
            update_ledger_cache(&database, advanced.clone()).unwrap();
            moved = true;
        }
        Ok(block)
    });
    assert_eq!(
        super::recovery::recover_branch(&database, captured.clone(), make_sync(&bodies), stream)
            .unwrap(),
        4
    );
    assert_eq!(
        load_or_initialize(&database).unwrap().tip_hash(),
        alternative.tip_hash()
    );
    assert_eq!(
        load_existing(&database).unwrap().tip_hash(),
        alternative.tip_hash()
    );
    assert_eq!(
        super::recovery::recover_branch(
            &database,
            Arc::new(advanced.clone()),
            make_sync(&bodies),
            bodies.clone().into_iter().map(Ok)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        load_existing(&database).unwrap().state_root().unwrap(),
        alternative.state_root().unwrap()
    );
    assert_eq!(
        crate::storage::canonical_index_tip(&database).unwrap(),
        Some((5, alternative.tip_hash().unwrap().0))
    );
    assert_eq!(fs::read_dir(database.join("recovery")).unwrap().count(), 0);
}

#[cfg(feature = "devnet")]
#[test]
fn production_pruning_bounds_journals_and_recovers_a_deeper_valid_fork() {
    let _test = super::recovery::RECOVERY_TEST_LOCK.lock().unwrap();
    fn extend(ledger: &mut Ledger, miner: ProgramId, memory: &mut PoWMemory) -> Block {
        let mut block = super::mining::candidate_operation_block(ledger, miner, vec![]).unwrap();
        crate::miner::mine_range(
            &mut block,
            crate::miner::MiningRange {
                start_nonce: 0,
                attempts: 1000,
            },
            memory,
        )
        .unwrap()
        .unwrap();
        apply_block(ledger, block.clone()).unwrap();
        block
    }
    let database = test_database("production-pruning-deep-fork");
    let mut memory = new_pow_memory();
    let mut canonical = kernel::genesis::genesis_ledger()
        .unwrap()
        .with_applications(extension::SystemApplications);
    persist_chain_and_pending(&database, &canonical, &[]).unwrap();
    let mut prefix = canonical.clone();
    for height in 1..=260 {
        let block = extend(&mut canonical, ProgramId::ZERO, &mut memory);
        persist_block_and_pending(&database, &block, &[]).unwrap();
        let root = canonical.state_root().unwrap();
        super::journal::prune_journals(&database, &mut canonical).unwrap();
        trim_body_cache(&mut canonical).unwrap();
        assert_eq!(canonical.state_root().unwrap(), root);
        assert!(canonical.rollback_journal_heights().count() <= 256);
        if height == 2 {
            prefix = canonical.clone();
        }
    }
    assert_eq!(canonical.rollback_journal_heights().next(), Some(Height(5)));
    assert!(canonical.can_rollback_to(Height(4)));
    assert!(!canonical.can_rollback_to(Height(3)));
    let mut shallow = canonical.clone();
    shallow.rollback_tip().unwrap();
    assert_eq!(shallow.tip_height(), Some(Height(259)));
    let old_tip = canonical.tip_hash();
    crate::snapshot::write(&database, &canonical).unwrap();
    let replayed = load_existing(&database).unwrap();
    assert_eq!(replayed.tip_hash(), old_tip);
    assert_eq!(replayed.rollback_journal_heights().count(), 256);
    let historical = canonical_block(&database, &replayed, Height(1)).unwrap();
    assert!(stored_block_response(&database, &replayed, &historical).is_ok());
    update_ledger_cache(&database, canonical).unwrap();
    let mut alternative = prefix;
    let bodies = (3..=261)
        .map(|_| {
            extend(
                &mut alternative,
                ProgramId([0xf4; kernel::crypto::PROGRAM_ID_SIZE]),
                &mut memory,
            )
        })
        .collect::<Vec<_>>();
    let (work, weight) = build_header_state_checkpoints(&alternative)
        .map(|(_, work, weight)| (work, weight))
        .unwrap();
    let sync = HeaderSyncResult {
        ancestor_height: Height(2),
        ancestor_hash: alternative
            .chain
            .header(&Height(2))
            .unwrap()
            .hash()
            .unwrap(),
        headers: bodies
            .iter()
            .map(|block| {
                kernel::consensus::HeaderAtHeight::new(block.height(), block.header.clone())
            })
            .collect(),
        peer_work: work,
        peer_weight: weight,
        preferred: true,
    };
    assert_eq!(apply_verified_branch(&database, sync, bodies).unwrap(), 259);
    let recovered = load_existing(&database).unwrap();
    assert_eq!(recovered.tip_hash(), alternative.tip_hash());
    assert_eq!(
        recovered.state_root().unwrap(),
        alternative.state_root().unwrap()
    );
    assert_eq!(recovered.rollback_journal_heights().count(), 256);
    assert!(!recovered.can_rollback_to(Height(2)));
    assert_eq!(
        crate::storage::CanonicalBodyReader::new(&database)
            .unwrap()
            .count(),
        262
    );
    assert_eq!(fs::read_dir(database.join("recovery")).unwrap().count(), 0);
}

#[cfg(feature = "devnet")]
#[test]
fn scratch_recovery_defers_if_concurrent_reorg_changes_common_ancestor() {
    let _test = super::recovery::RECOVERY_TEST_LOCK.lock().unwrap();
    fn extend(ledger: &mut Ledger, miner: ProgramId, memory: &mut PoWMemory) -> Block {
        let mut block = super::mining::candidate_operation_block(ledger, miner, vec![]).unwrap();
        crate::miner::mine_range(
            &mut block,
            crate::miner::MiningRange {
                start_nonce: 0,
                attempts: 1000,
            },
            memory,
        )
        .unwrap()
        .unwrap();
        apply_block(ledger, block.clone()).unwrap();
        block
    }
    let database = test_database("scratch-concurrent-ancestor-change");
    let mut memory = new_pow_memory();
    let mut canonical = kernel::genesis::genesis_ledger()
        .unwrap()
        .with_applications(extension::SystemApplications);
    extend(&mut canonical, ProgramId::ZERO, &mut memory);
    let prefix = canonical.clone();
    for _ in 0..2 {
        extend(&mut canonical, ProgramId::ZERO, &mut memory);
    }
    persist_chain_and_pending(&database, &canonical, &[]).unwrap();
    canonical.discard_rollback_journals_before(Height(4));
    let captured = Arc::new(canonical.clone());
    update_ledger_cache(&database, canonical).unwrap();
    let mut alternative = prefix.clone();
    let bodies = (0..3)
        .map(|_| {
            extend(
                &mut alternative,
                ProgramId([0xf5; kernel::crypto::PROGRAM_ID_SIZE]),
                &mut memory,
            )
        })
        .collect::<Vec<_>>();
    let (_, work, weight) = build_header_state_checkpoints(&alternative).unwrap();
    let sync = HeaderSyncResult {
        ancestor_height: Height(1),
        ancestor_hash: prefix.tip_hash().unwrap(),
        headers: bodies
            .iter()
            .map(|block| {
                kernel::consensus::HeaderAtHeight::new(block.height(), block.header.clone())
            })
            .collect(),
        peer_work: work,
        peer_weight: weight,
        preferred: true,
    };
    let mut replacement = kernel::genesis::genesis_ledger()
        .unwrap()
        .with_applications(extension::SystemApplications);
    for _ in 0..2 {
        extend(
            &mut replacement,
            ProgramId([0xf6; kernel::crypto::PROGRAM_ID_SIZE]),
            &mut memory,
        );
    }
    let mut moved = false;
    let stream = bodies.into_iter().map(|block| {
        if !moved {
            let _mutation = state_mutation_lock().unwrap().lock().unwrap();
            persist_chain_and_pending(&database, &replacement, &[]).unwrap();
            update_ledger_cache(&database, replacement.clone()).unwrap();
            moved = true;
        }
        Ok(block)
    });
    assert!(
        super::recovery::recover_branch(&database, captured, sync, stream)
            .unwrap_err()
            .contains("fork ancestor changed")
    );
    assert_eq!(
        load_existing(&database).unwrap().tip_hash(),
        replacement.tip_hash()
    );
    assert_eq!(fs::read_dir(database.join("recovery")).unwrap().count(), 0);
}

#[test]
fn chain_minimums_skip_low_claims_before_sending_header_requests() {
    use super::chain_minimums::{ChainMinimums, configure};
    let database = test_database("minimum-claims");
    let before = load_or_initialize(&database).unwrap();
    configure(
        &database,
        ChainMinimums {
            work: Work::pow2(70),
            weight: 100,
        },
    )
    .unwrap();
    let claim = cached_handshake(&database).unwrap();
    for (work, weight) in [(Work::pow2(69), u64::MAX), (Work::MAX, 99)] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let mut peer = claim.clone();
        peer.cumulative_work = work.to_be_limbs();
        peer.cumulative_weight = weight;
        let sync = synchronize_headers(&database, &mut client, &peer).unwrap();
        assert!(!sync.preferred);
        assert!(sync.headers.is_empty());
        drop(client);
        // No locator or header request was written, not even a frame prefix.
        assert_eq!(server.read(&mut [0]).unwrap(), 0);
    }
    assert_eq!(
        load_or_initialize(&database).unwrap().tip_hash(),
        before.tip_hash()
    );
    crate::storage::release_cached_database(&database);
    fs::remove_dir_all(database).unwrap();
}

#[test]
fn chain_minimums_do_not_trust_inflated_advertised_totals() {
    use super::chain_minimums::{ChainMinimums, configure};
    let database = test_database("minimum-inflated");
    load_or_initialize(&database).unwrap();
    configure(
        &database,
        ChainMinimums {
            work: Work::pow2(70),
            weight: 100,
        },
    )
    .unwrap();
    let mut peer = cached_handshake(&database).unwrap();
    peer.cumulative_work = Work::MAX.to_be_limbs();
    peer.cumulative_weight = u64::MAX;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let server = thread::spawn(move || {
        let (mut server, _) = listener.accept().unwrap();
        let _locator = read_frame(&mut server, 4096).unwrap();
        let mut complete = vec![HEADERS_COMPLETE_MESSAGE];
        complete.extend(EXPECTED_GENESIS_HASH.0);
        write_frame(&mut server, &complete).unwrap();
    });
    assert!(
        synchronize_headers(&database, &mut client, &peer)
            .err()
            .unwrap()
            .contains("does not match verified headers")
    );
    server.join().unwrap();
    assert_eq!(
        load_or_initialize(&database).unwrap().tip_height(),
        Some(Height(0))
    );
    crate::storage::release_cached_database(&database);
    fs::remove_dir_all(database).unwrap();
}

#[test]
fn chain_minimums_guard_branch_commit_and_unannounced_block_relay() {
    use super::chain_minimums::{ChainMinimums, configure};
    let database = test_database("minimum-commit");
    let parent = load_or_initialize_owned(&database).unwrap();
    let miner = ProgramId([0xc7; kernel::crypto::PROGRAM_ID_SIZE]);
    let source = test_database("minimum-commit-source");
    assert!(matches!(
        mine_block_database(&source, miner, 0, 100, &mut new_pow_memory()).unwrap(),
        MiningAttempt::Mined
    ));
    let block = load_or_initialize(&source)
        .unwrap()
        .chain
        .block(&Height(1))
        .unwrap()
        .clone();
    crate::storage::release_cached_database(&source);
    fs::remove_dir_all(source).unwrap();
    let (checkpoints, _, _) = build_header_state_checkpoints(&parent).unwrap();
    let ancestor = ledger_header_state_at_height(&parent, &checkpoints, Height(0)).unwrap();
    let header = kernel::consensus::HeaderAtHeight::new(Height(1), block.header.clone());
    let verified = kernel::consensus::advance_header_validation_state_with_memory(
        &ancestor,
        &[header.clone()],
        &mut new_pow_memory(),
    )
    .unwrap();
    let sync = HeaderSyncResult {
        ancestor_height: Height(0),
        ancestor_hash: EXPECTED_GENESIS_HASH,
        headers: vec![header],
        peer_work: verified.cumulative_work,
        peer_weight: verified.cumulative_weight,
        preferred: true,
    };
    for floor in [
        ChainMinimums {
            work: verified.cumulative_work.saturating_add(Work::pow2(0)),
            weight: 0,
        },
        ChainMinimums {
            work: Work::ZERO,
            weight: verified.cumulative_weight + 1,
        },
    ] {
        configure(&database, floor).unwrap();
        // The rejected branch must not even pull its body iterator.
        let bodies = std::iter::from_fn(|| -> Option<Result<Block, String>> {
            panic!("below-floor body was consumed")
        });
        assert_eq!(
            apply_verified_branch_stream(&database, sync.clone(), bodies).unwrap(),
            0
        );
        assert!(
            accept_relayed_block(&database, &block_bytes(&block).unwrap())
                .unwrap_err()
                .contains("below configured")
        );
        assert_eq!(
            load_or_initialize(&database).unwrap().tip_height(),
            Some(Height(0))
        );
    }
    configure(
        &database,
        ChainMinimums {
            work: verified.cumulative_work,
            weight: verified.cumulative_weight,
        },
    )
    .unwrap();
    assert_eq!(
        apply_verified_branch(&database, sync, vec![block]).unwrap(),
        1
    );
    assert_eq!(
        load_or_initialize(&database).unwrap().tip_height(),
        Some(Height(1))
    );
    crate::storage::release_cached_database(&database);
    fs::remove_dir_all(database).unwrap();
}

#[test]
fn program_storage_rpc_bounds_keys_and_reports_missing_entries() {
    let seed = kernel::crypto::SigningSeed::new(
        kernel::crypto::AccountSignatureScheme::MlDsa44,
        Box::new([0x73; 32]),
    );
    let owner = kernel::crypto::program_id_from_public_key(&seed.public_key()).unwrap();
    let mut ledger = kernel::genesis::genesis_ledger()
        .unwrap()
        .with_applications(extension::SystemApplications);
    let mut memory = new_pow_memory();
    let mut commit = |ledger: &mut Ledger, operations| {
        let height = Height(ledger.tip_height().unwrap().0 + 1);
        let mut block = Block::from_protocol_operations(
            height,
            ledger.tip_hash().unwrap(),
            expected_next_difficulty(&ledger.chain).unwrap(),
            Nonce(0),
            Some(Emission::new(owner, expected_emission_for_height(height))),
            operations,
        )
        .unwrap();
        let (root, weight) = ledger.preview_block_commitments(&block).unwrap();
        block.set_state_root(root);
        block.set_block_weight(weight);
        assert!(
            crate::miner::mine_range(
                &mut block,
                crate::miner::MiningRange {
                    start_nonce: 0,
                    attempts: 1_000_000
                },
                &mut memory,
            )
            .unwrap()
            .is_some()
        );
        kernel::consensus::apply_block(ledger, block).unwrap();
    };
    commit(&mut ledger, vec![]);
    let (input, coin) = ledger
        .state()
        .utxos()
        .coins_by_owner(kernel::common::Owner::Program(owner))
        .next()
        .unwrap();
    let amount = coin.amount.as_zeno();
    let mut code = b"XPVM".to_vec();
    code.extend([4, 1, 0, 1, 0, 0, 0, 0, 0]);
    code.push(1);
    code.extend(0u128.to_le_bytes());
    code.push(3);
    let deploy = kernel::program::DeployProgram {
        owner,
        nonce: 1,
        code: code.into(),
    };
    let chain = kernel::genesis::chain_context().unwrap();
    let make = |burn| {
        let payment = kernel::program::CoinTransition::coin(
            owner,
            vec![input],
            vec![kernel::monetary::coin::CoinOutput::new(
                owner,
                Zeno::from_zeno(amount - burn),
            )],
        )
        .unwrap();
        let mut signed = kernel::operation::AuthorizedDeployProgram {
            deploy: deploy.clone(),
            payment,
            authorization: kernel::program::AccountAuthorization {
                salt: [0; 32],
                public_key: seed.public_key(),
                signature: seed.sign(&[0; 32]),
            },
        };
        signed.authorization.signature = seed.sign(signed.commitment(chain).unwrap().as_bytes());
        signed
    };
    let (id, burn) =
        kernel::consensus::quote_deploy_burn(&make(0), Height(2), ledger.state()).unwrap();
    commit(
        &mut ledger,
        vec![kernel::operation::BlockOperation::DeployProgram(Box::new(
            make(burn.as_zeno()),
        ))],
    );
    let prefix = format!("/program/state/{}", hex::encode(id.into_bytes()));
    let response = explorer::program_state_response(&ledger, &format!("{prefix}/0102")).unwrap();
    assert_eq!(response["key"], "0102");
    assert!(response["value"].is_null());
    assert_eq!(response["height"], 2);
    for suffix in [
        "".into(),
        "zz".into(),
        "ab".repeat(129),
        "01/02".into(),
        "0".into(),
    ] {
        assert!(explorer::program_state_response(&ledger, &format!("{prefix}/{suffix}")).is_err());
    }
}
