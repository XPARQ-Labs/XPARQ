#![allow(dead_code)]

// Compile the storage and snapshot modules as a focused integration target.
// The node's older unit-test module is currently blocked by stale API fixtures.
#[path = "../src/miner.rs"]
mod miner;

#[test]
fn node_restarts_from_a_compact_snapshot() {
    use kernel::{
        block::{Block, Emission, block_bytes},
        common::{Height, Nonce},
        consensus::{
            apply_block, apply_genesis, expected_emission_for_height, expected_next_difficulty,
            new_pow_memory, validate_emission,
        },
        crypto::ProgramId,
        genesis::{EXPECTED_GENESIS_HASH, genesis_block},
        ledger::Ledger,
        monetary::coin::CoinShare,
    };

    let directory = std::env::temp_dir().join(format!(
        "xparq-snapshot-startup-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let genesis = genesis_block().unwrap();
    let mut ledger = Ledger::new().with_applications(extension::SystemApplications);
    apply_genesis(&mut ledger, genesis.clone(), EXPECTED_GENESIS_HASH).unwrap();
    let genesis_ledger = ledger.clone();
    let height = Height(1);
    let mut block = Block::from_protocol_operations(
        height,
        ledger.tip_hash().unwrap(),
        expected_next_difficulty(&ledger.chain).unwrap(),
        Nonce(0),
        Some(Emission::new(
            ProgramId::ZERO,
            expected_emission_for_height(height),
        )),
        vec![],
    )
    .unwrap();
    let (root, weight) = ledger.preview_block_commitments(&block).unwrap();
    block.set_state_root(root);
    block.set_block_weight(weight);
    assert!(
        miner::mine_range(
            &mut block,
            miner::MiningRange {
                start_nonce: 0,
                attempts: 100,
            },
            &mut new_pow_memory(),
        )
        .unwrap()
        .is_some()
    );
    apply_block(&mut ledger, block.clone()).unwrap();

    for block in [&genesis, &block] {
        storage::append_block_and_replace_mempool(
            &directory,
            &storage::StoredCanonicalBlock {
                height: block.height().0,
                hash: block.hash().unwrap().0,
                bytes: block_bytes(&block).unwrap(),
                transactions: vec![],
                activities: vec![],
            },
            &[],
        )
        .unwrap();
    }
    let emission_id =
        CoinShare::from_emission(&validate_emission(&block).unwrap().origin().into_bytes());
    assert_eq!(
        storage::read_coin_origin(&directory, emission_id).unwrap(),
        Some(storage::CoinOrigin {
            created_at: None,
            deploy_operation_id: None,
            created_in: height,
        })
    );
    let indexed = [&genesis, &block]
        .into_iter()
        .map(|block| storage::CanonicalIndexBlock {
            height: block.height().0,
            hash: block.hash().unwrap().0,
            bytes: block_bytes(block).unwrap(),
            transactions: vec![],
            activities: vec![],
        })
        .collect::<Vec<_>>();
    storage::rebuild_canonical_indexes_stream(&directory, || indexed.iter().cloned().map(Ok))
        .unwrap();
    assert_eq!(
        storage::read_coin_origin(&directory, emission_id).unwrap(),
        Some(storage::CoinOrigin {
            created_at: None,
            deploy_operation_id: None,
            created_in: height
        })
    );
    snapshot::write_after_large_sync(
        &directory,
        &genesis_ledger,
        snapshot::SNAPSHOT_INTERVAL as usize,
    )
    .unwrap();
    snapshot::write_after_large_sync(&directory, &ledger, snapshot::SNAPSHOT_INTERVAL as usize)
        .unwrap();
    // Measure both paths over identical, already admitted history. Counts prove
    // that the trusted path does not repeat the expensive historical PoW.
    let history = [genesis.clone(), block.clone()];
    let encoded_snapshot = kernel::crypto::canonical_bytes(&ledger.snapshot()).unwrap();
    let fresh_snapshot = || borsh::from_slice(&encoded_snapshot).unwrap();
    let (verified, full) = Ledger::from_snapshot_with_body_cache_measured(
        fresh_snapshot(),
        history.clone(),
        usize::MAX,
        usize::MAX,
    )
    .unwrap();
    let (trusted, fast) = Ledger::from_trusted_snapshot_with_body_cache_measured(
        fresh_snapshot(),
        history,
        usize::MAX,
        usize::MAX,
    )
    .unwrap();
    assert_eq!(verified, trusted);
    assert_eq!(trusted, ledger);
    assert_eq!(full.pow_checks, 1);
    assert_eq!(fast.pow_checks, 0);
    println!(
        "restore comparison: full_pow_ms={:.3} trusted_history_ms={:.3} supply_ms={:.3} root_ms={:.3}",
        full.proof_of_work.as_secs_f64() * 1000.0,
        fast.history.as_secs_f64() * 1000.0,
        fast.supply_audit.as_secs_f64() * 1000.0,
        fast.state_root.as_secs_f64() * 1000.0
    );
    // The storage module caches its last redb handle; switch it away before
    // opening the fixture in a separate node process.
    let spare = directory.with_extension("cache-release");
    storage::snapshots_descending(&spare).unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_node"))
        .arg("check")
        .arg(&directory)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let startup = String::from_utf8_lossy(&result.stdout);
    assert!(
        startup.contains("mode=trusted-local blocks=2 pow_checks=0"),
        "{startup}"
    );
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.contains("snapshot: loaded height=1"), "{output}");
    assert!(output.contains("height: 1"), "{output}");
    assert!(output.contains("database: valid"), "{output}");

    let full_check = std::process::Command::new(env!("CARGO_BIN_EXE_node"))
        .arg("check")
        .arg(&directory)
        .arg("--full")
        .output()
        .unwrap();
    assert!(
        full_check.status.success(),
        "{}",
        String::from_utf8_lossy(&full_check.stderr)
    );
    let full_output = String::from_utf8_lossy(&full_check.stdout);
    assert!(
        full_output.contains("database: full replay verified"),
        "{full_output}"
    );
    assert!(!full_output.contains("mode=trusted-local"), "{full_output}");

    // Simulate changing a structurally valid body without updating the local
    // validation record. The newest snapshot must not be trusted anymore.
    storage::release_cached_database(&directory);
    {
        let database = redb::Database::open(directory.join("xparq.redb")).unwrap();
        let transaction = database.begin_write().unwrap();
        {
            let mut table = transaction
                .open_table(redb::TableDefinition::<u64, &[u8]>::new("canonical_blocks"))
                .unwrap();
            let mut changed = block.clone();
            changed.header.nonce.0 += 1;
            let bytes = block_bytes(&changed).unwrap();
            table.insert(1, bytes.as_slice()).unwrap();
        }
        transaction.commit().unwrap();
    }
    let (fallback, next) = snapshot::load_streamed(&directory, usize::MAX, usize::MAX)
        .unwrap()
        .unwrap();
    assert_eq!(
        next, 1,
        "changed prefix must discard the height-one checkpoint"
    );
    assert_eq!(fallback, genesis_ledger);

    let replacement = Block::from_protocol_operations(
        height,
        genesis.hash().unwrap(),
        block.header.target_bits,
        Nonce(block.header.nonce.0 + 1),
        Some(Emission::new(
            ProgramId::from_bytes([1; kernel::crypto::PROGRAM_ID_SIZE]),
            expected_emission_for_height(height),
        )),
        vec![],
    )
    .unwrap();
    let replacement_id = CoinShare::from_emission(
        &validate_emission(&replacement)
            .unwrap()
            .origin()
            .into_bytes(),
    );
    let stored = [genesis, replacement]
        .into_iter()
        .map(|block| storage::StoredCanonicalBlock {
            height: block.height().0,
            hash: block.hash().unwrap().0,
            bytes: block_bytes(&block).unwrap(),
            transactions: vec![],
            activities: vec![],
        })
        .collect::<Vec<_>>();
    storage::replace_blocks_and_mempool_stream(&directory, || stored.iter().cloned().map(Ok), &[])
        .unwrap();
    assert_eq!(
        storage::read_coin_origin(&directory, emission_id).unwrap(),
        None
    );
    assert_eq!(
        storage::read_coin_origin(&directory, replacement_id).unwrap(),
        Some(storage::CoinOrigin {
            created_at: None,
            deploy_operation_id: None,
            created_in: height
        })
    );
    let retained = storage::snapshots_descending(&directory).unwrap();
    assert_eq!(
        retained
            .iter()
            .map(|(height, _)| *height)
            .collect::<Vec<_>>(),
        vec![0]
    );

    std::fs::remove_dir_all(directory).unwrap();
    std::fs::remove_dir_all(spare).unwrap();
}
#[path = "../src/snapshot.rs"]
mod snapshot;
#[path = "../src/storage.rs"]
mod storage;

#[test]
fn streaming_storage_failure_rolls_back_canonical_replacement() {
    use kernel::{block::block_bytes, genesis::genesis_block};
    let directory = std::env::temp_dir().join(format!(
        "xparq-stream-rollback-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let genesis = genesis_block().unwrap();
    let block = storage::StoredCanonicalBlock {
        height: 0,
        hash: genesis.hash().unwrap().0,
        bytes: block_bytes(&genesis).unwrap(),
        transactions: vec![],
        activities: vec![],
    };
    storage::replace_blocks_and_mempool_stream(
        &directory,
        || std::iter::once(Ok(block.clone())),
        &[],
    )
    .unwrap();
    let before = storage::read_blocks(&directory).unwrap();
    let passes = std::cell::Cell::new(0);
    let error = storage::replace_blocks_and_mempool_stream(
        &directory,
        || {
            passes.set(passes.get() + 1);
            let mut items = vec![Ok(block.clone())];
            if passes.get() == 3 {
                items.push(Err("simulated persistence read failure".to_owned()));
            }
            items.into_iter()
        },
        &[],
    )
    .unwrap_err();
    assert!(error.contains("simulated persistence read failure"));
    assert_eq!(storage::read_blocks(&directory).unwrap(), before);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn recovery_snapshot_publishes_atomically_with_canonical_indexes_and_mempool() {
    use kernel::{block::block_bytes, genesis::genesis_block};
    let directory = std::env::temp_dir().join(format!(
        "xparq-recovery-atomic-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let genesis = genesis_block().unwrap();
    let block = storage::StoredCanonicalBlock {
        height: 0,
        hash: genesis.hash().unwrap().0,
        bytes: block_bytes(&genesis).unwrap(),
        transactions: vec![],
        activities: vec![],
    };
    storage::replace_blocks_and_mempool_stream(
        &directory,
        || std::iter::once(Ok(block.clone())),
        &[],
    )
    .unwrap();
    // Storage treats snapshots as opaque local cache payloads; loading validates them.
    storage::put_snapshot(&directory, 0, b"previous local cache").unwrap();
    let bodies = storage::read_blocks(&directory).unwrap();
    let checkpoint = storage::snapshots_descending(&directory).unwrap();
    let indexes = storage::canonical_index_tip(&directory).unwrap();
    let pending = vec![b"pending cache bytes".to_vec()];
    assert!(
        storage::replace_blocks_mempool_and_snapshot_stream(
            &directory,
            || std::iter::once(Ok(block.clone())),
            &pending,
            Some((1, b"wrong-height cache"))
        )
        .unwrap_err()
        .contains("height does not match")
    );
    assert_eq!(storage::read_blocks(&directory).unwrap(), bodies);
    assert_eq!(
        storage::snapshots_descending(&directory).unwrap(),
        checkpoint
    );
    assert_eq!(storage::canonical_index_tip(&directory).unwrap(), indexes);
    assert!(storage::read_mempool(&directory).unwrap().is_empty());
    storage::replace_blocks_mempool_and_snapshot_stream(
        &directory,
        || std::iter::once(Ok(block.clone())),
        &pending,
        Some((0, b"recovered local cache")),
    )
    .unwrap();
    assert_eq!(storage::read_mempool(&directory).unwrap(), pending);
    assert_eq!(
        storage::snapshots_descending(&directory).unwrap(),
        vec![(0, b"recovered local cache".to_vec())]
    );
    assert_eq!(
        storage::canonical_index_tip(&directory).unwrap(),
        Some((0, block.hash))
    );
    std::fs::remove_dir_all(directory).unwrap();
}
