#[path = "../../benches/support/chain.rs"]
#[allow(dead_code)] // Shared fixture also contains the mixed-signature constructor.
mod chain;
#[path = "../src/storage.rs"]
#[allow(dead_code, unused_imports)] // Includes test-only imports under Cargo's bench cfg.
mod storage;
#[path = "../../benches/support/mod.rs"]
mod support;

use kernel::{
    blockchain::{Block, decode_block},
    common::Owner,
    consensus::{
        ApplyBlockState, apply_block_with_pow_memory, new_pow_memory,
        validate_block_for_apply_with_memory,
    },
    crypto::{
        AccountSignatureScheme, ChainContext, HashDomain, SigningSeed, StateRoot, canonical_bytes,
        canonical_decode, domain, program_id_from_public_key,
    },
    genesis::genesis_ledger,
    ledger::{Ledger, LedgerSnapshot},
    operation::BlockOperation,
};
use std::{
    collections::BTreeSet,
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use support::{Config, report, timed};

struct OwnedDatabase(PathBuf);
impl OwnedDatabase {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("xparq-sync-bench-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap(); // Never open or remove an existing/user database.
        Self(path)
    }
}
impl Drop for OwnedDatabase {
    fn drop(&mut self) {
        storage::release_cached_database(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn stored(block: &Block) -> storage::StoredCanonicalBlock {
    let mut transactions = Vec::new();
    let mut activities = BTreeSet::new();
    if let Some(emission) = block.emission() {
        activities.insert((emission.to.into_bytes(), None));
    }
    for (index, operation) in block.operations().iter().enumerate() {
        let BlockOperation::ProgramCall(tx) = operation else {
            panic!("unexpected fixture deploy")
        };
        transactions.push(
            kernel::program::AuthorizedProgramEnvelope::Program(tx.clone())
                .id()
                .unwrap(),
        );
        activities.insert((tx.signer.into_bytes(), Some(index as u64)));
        for output in tx.payment.coin_parts().unwrap().1 {
            let Owner::Program(owner) = output.output;
            activities.insert((owner.into_bytes(), Some(index as u64)));
        }
    }
    storage::StoredCanonicalBlock {
        height: block.height().0,
        hash: block.hash().unwrap().into_bytes(),
        bytes: block.to_bytes().unwrap(),
        transactions,
        activities: activities
            .into_iter()
            .map(
                |(program_id, transaction_index)| storage::StoredProgramActivity {
                    program_id,
                    transaction_index,
                },
            )
            .collect(),
    }
}

fn memory(label: &str) {
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status
            .lines()
            .filter(|line| line.starts_with("VmRSS:") || line.starts_with("VmHWM:"))
        {
            println!("# {label}: {line}");
        }
    }
}

fn main() {
    let config = Config::from_args();
    let database = OwnedDatabase::new();
    let mut ledger = genesis_ledger()
        .unwrap()
        .with_applications(extension::SystemApplications);
    let context = ChainContext::new(ledger.tip_hash().unwrap().into_bytes());
    let key = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([77; 32]));
    let owner = program_id_from_public_key(&key.public_key()).unwrap();
    let mut memory_buffer = new_pow_memory();
    let mut writes = Vec::new();
    let genesis = stored(ledger.chain.block(&kernel::common::Height(0)).unwrap());
    storage::append_block_and_replace_mempool(&database.0, &genesis, &[]).unwrap();
    let block = chain::candidate(&ledger, owner, vec![]);
    apply_block_with_pow_memory(&mut ledger, block.clone(), &mut memory_buffer).unwrap();
    let record = stored(&block);
    storage::append_block_and_replace_mempool(&database.0, &record, &[]).unwrap();
    println!(
        "# fixture: creating >= {} live UTXOs then {} additional valid blocks",
        config.state_utxos, config.blocks
    );
    let mut count = 1;
    while count < config.state_utxos {
        let (input, coin) = ledger
            .state
            .utxos
            .coins_by_owner(Owner::Program(owner))
            .max_by_key(|(_, coin)| coin.amount)
            .unwrap();
        let outputs = (config.state_utxos - count + 1).min(3800);
        let operation = chain::transfer(
            &key,
            input,
            coin.amount.as_zeno(),
            &vec![owner; outputs],
            context,
            false,
        );
        let block = chain::candidate(&ledger, owner, vec![operation]);
        apply_block_with_pow_memory(&mut ledger, block.clone(), &mut memory_buffer).unwrap();
        let record = stored(&block);
        let (_, ms) =
            timed(|| storage::append_block_and_replace_mempool(&database.0, &record, &[]).unwrap());
        writes.push(ms);
        count = ledger.state.utxos.len();
        println!("# fixture: height={}, UTXOs={count}", block.height().0);
    }
    for i in 0..config.blocks {
        let block = chain::candidate(&ledger, owner, vec![]);
        apply_block_with_pow_memory(&mut ledger, block.clone(), &mut memory_buffer).unwrap();
        let record = stored(&block);
        let (_, ms) =
            timed(|| storage::append_block_and_replace_mempool(&database.0, &record, &[]).unwrap());
        writes.push(ms);
        if i % 16 == 0 {
            println!("# fixture: additional block {i}/{}", config.blocks);
        }
    }
    ledger.state.audit_supply_invariants().unwrap();
    drop(memory_buffer);
    memory("fixture complete (includes mining setup)");
    report("history", "storage_append_per_block", &writes);
    let expected_root = ledger.state_root().unwrap();
    let expected_tip = ledger.tip_hash();
    let state_bytes = canonical_bytes(&ledger.state).unwrap();
    println!(
        "# fixture: tip={}, live_utxos={}, state_bytes={}",
        ledger.tip_height().unwrap().0,
        ledger.state.utxos.len(),
        state_bytes.len()
    );
    let mut rows: [Vec<f64>; 9] = std::array::from_fn(|_| Vec::new());
    for sample in 0..=config.samples {
        let (_, serialize_ms) = timed(|| canonical_bytes(&ledger.state).unwrap());
        let (hash, hash_ms) =
            timed(|| StateRoot(domain(HashDomain::ProtocolState, &state_bytes).into_bytes()));
        assert_eq!(hash, expected_root);
        let mut cold = ledger.clone();
        cold.state.root_cache = Default::default();
        let (root, root_ms) = timed(|| cold.state_root().unwrap());
        assert_eq!(root, expected_root);
        let (snapshot, snapshot_ms) = timed(|| canonical_bytes(&ledger.snapshot()).unwrap());
        let mut replay = genesis_ledger()
            .unwrap()
            .with_applications(extension::SystemApplications);
        let mut buffer = new_pow_memory();
        let mut reader = storage::CanonicalBodyReader::new(&database.0).unwrap();
        let mut read_ms = 0.;
        let mut admission_ms = 0.;
        let mut execution_ms = 0.;
        let (_, replay_ms) = timed(|| {
            loop {
                let (block, ms) = timed(|| {
                    reader
                        .next()
                        .map(|bytes| decode_block(&bytes.unwrap()).unwrap())
                });
                read_ms += ms;
                let Some(block) = block else { break };
                if block.is_genesis() {
                    assert_eq!(block.hash().unwrap(), replay.tip_hash().unwrap());
                    continue;
                }
                let (validated, ms) = timed(|| {
                    validate_block_for_apply_with_memory(&block, &replay.chain, &mut buffer)
                        .unwrap()
                });
                admission_ms += ms;
                let (_, ms) = timed(|| replay.commit_validated_block(validated).unwrap());
                execution_ms += ms;
            }
        });
        assert_eq!(replay.tip_hash(), expected_tip);
        assert_eq!(replay.state_root().unwrap(), expected_root);
        replay.state.audit_supply_invariants().unwrap();
        drop(buffer);
        drop(reader);
        drop(replay);
        let (restored, restore_ms) = timed(|| {
            let snapshot: LedgerSnapshot = canonical_decode(&snapshot).unwrap();
            let blocks = storage::CanonicalBodyReader::new(&database.0)
                .unwrap()
                .map(|bytes| decode_block(&bytes.unwrap()).unwrap());
            Ledger::from_snapshot_with_body_cache(snapshot, blocks, 256, usize::MAX).unwrap()
        });
        assert_eq!(restored.tip_hash(), expected_tip);
        assert_eq!(restored.state_root().unwrap(), expected_root);
        if sample != 0 {
            for (row, value) in rows.iter_mut().zip([
                serialize_ms,
                hash_ms,
                root_ms,
                snapshot_ms,
                read_ms,
                admission_ms,
                execution_ms,
                replay_ms,
                restore_ms,
            ]) {
                row.push(value);
            }
        }
        println!("# replay: sample {sample}/{} complete", config.samples);
        memory("replay sample complete");
    }
    for (operation, values) in [
        "serialize_state",
        "hash_preencoded_state",
        "cold_state_root",
        "serialize_snapshot",
        "read_and_decode_history",
        "admission_pow_history",
        "execute_commit_history",
        "replay_total",
        "snapshot_restore",
    ]
    .into_iter()
    .zip(&rows)
    {
        report("history", operation, values);
    }
}
