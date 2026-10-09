use std::{hint::black_box, time::Instant};

use kernel::{
    block::{Block, Emission, GENESIS_TARGET_BITS},
    blockchain::Chain,
    common::{Height, Nonce},
    consensus::{
        ConsensusError, PoWTarget, apply_block, apply_block_with_pow_memory, calculate_work,
        calculate_work_with_memory, expected_emission_for_height, expected_next_difficulty,
        new_pow_memory,
    },
    crypto::{PoWMemory, ProgramId, StateRoot, canonical_bytes},
    genesis::{genesis_block, genesis_ledger},
    ledger::{Ledger, LedgerError},
    monetary::coin::Zeno,
};

fn candidate(ledger: &Ledger) -> Block {
    let height = ledger.tip_height().unwrap().0 + 1;
    let mut block = Block::from_protocol_operations(
        Height(height),
        ledger.tip_hash().unwrap(),
        expected_next_difficulty(&ledger.chain).unwrap(),
        Nonce(0),
        Some(Emission::new(
            ProgramId([3; 32]),
            expected_emission_for_height(Height(height)),
        )),
        vec![],
    )
    .unwrap();
    let (root, weight) = ledger.preview_block_commitments(&block).unwrap();
    block.set_state_root(root);
    block.set_block_weight(weight);
    block
}

fn find_nonce(block: &mut Block, memory: &mut PoWMemory, valid: bool) {
    let target = PoWTarget::from_compact(block.target_bits()).unwrap();
    while target.meets(&calculate_work_with_memory(&block.header, memory).unwrap()) != valid {
        block.header.nonce.0 += 1;
    }
}

#[test]
fn reused_pow_buffer_matches_fresh_work_after_other_headers() {
    let first = genesis_block().unwrap().header;
    let mut second = first.clone();
    second.nonce.0 += 1;
    let mut memory = new_pow_memory();
    let first_hash = calculate_work(&first).unwrap();
    assert_eq!(
        calculate_work_with_memory(&first, &mut memory).unwrap(),
        first_hash
    );
    assert_eq!(
        calculate_work_with_memory(&second, &mut memory).unwrap(),
        calculate_work(&second).unwrap()
    );
    assert_eq!(
        calculate_work_with_memory(&first, &mut memory).unwrap(),
        first_hash
    );
    assert!(matches!(
        calculate_work_with_memory(&first, &mut PoWMemory::new(8)),
        Err(ConsensusError::InvalidPoWParameters)
    ));
}

#[test]
fn reusable_admission_matches_normal_admission_and_keeps_failures_atomic() {
    let mut regular = genesis_ledger().unwrap();
    let mut reused = regular.clone();
    let mut memory = new_pow_memory();
    for _ in 0..2 {
        let mut block = candidate(&regular);
        find_nonce(&mut block, &mut memory, true);
        apply_block(&mut regular, block.clone()).unwrap();
        apply_block_with_pow_memory(&mut reused, block, &mut memory).unwrap();
        assert_eq!(
            canonical_bytes(&regular).unwrap(),
            canonical_bytes(&reused).unwrap()
        );
    }
    let restored = Ledger::from_snapshot_with_body_cache(
        regular.snapshot(),
        regular.chain.blocks().cloned(),
        usize::MAX,
        usize::MAX,
    )
    .unwrap();
    assert_eq!(
        canonical_bytes(&restored).unwrap(),
        canonical_bytes(&regular).unwrap()
    );
    let mut bad_history: Vec<_> = regular.chain.blocks().cloned().collect();
    find_nonce(bad_history.last_mut().unwrap(), &mut memory, false);
    assert!(
        Ledger::from_snapshot_with_body_cache(
            regular.snapshot(),
            bad_history,
            usize::MAX,
            usize::MAX
        )
        .is_err()
    );
    let before = canonical_bytes(&reused).unwrap();
    let mut bad_pow = candidate(&reused);
    find_nonce(&mut bad_pow, &mut memory, false);
    assert!(matches!(
        apply_block_with_pow_memory(&mut reused, bad_pow.clone(), &mut memory),
        Err(LedgerError::Consensus(ConsensusError::InsufficientPoW))
    ));
    assert!(apply_block(&mut regular, bad_pow).is_err());
    assert_eq!(canonical_bytes(&reused).unwrap(), before);

    let mut bad_state = candidate(&reused);
    bad_state.set_state_root(StateRoot::ZERO);
    find_nonce(&mut bad_state, &mut memory, true);
    assert!(matches!(
        apply_block_with_pow_memory(&mut reused, bad_state, &mut memory),
        Err(LedgerError::InvalidStateRoot)
    ));
    assert_eq!(canonical_bytes(&reused).unwrap(), before);
    let block = candidate(&reused);
    assert!(apply_block_with_pow_memory(&mut reused, block, &mut PoWMemory::new(8)).is_err());
    assert_eq!(canonical_bytes(&reused).unwrap(), before);
    let mut empty = Ledger::new();
    assert!(
        apply_block_with_pow_memory(&mut empty, genesis_block().unwrap(), &mut memory).is_err()
    );
    assert_eq!(empty.tip_height(), None);
}

// Link-only fixtures below benchmark chain bookkeeping, not consensus validity.
fn next_link(chain: &Chain) -> Block {
    Block::from_protocol_operations(
        Height(chain.tip_height().unwrap().0 + 1),
        chain.tip_hash().unwrap(),
        GENESIS_TARGET_BITS,
        Nonce(0),
        Some(Emission::new(ProgramId([3; 32]), Zeno::ONE)),
        vec![],
    )
    .unwrap()
}

#[test]
fn rejected_chain_insertions_leave_history_and_tip_unchanged() {
    let mut chain = Chain::new();
    assert!(
        chain
            .insert_block(next_link(&genesis_ledger().unwrap().chain))
            .is_err()
    );
    assert_eq!(chain, Chain::new());
    let genesis = genesis_block().unwrap();
    chain.insert_block(genesis.clone()).unwrap();
    let before = chain.clone();
    assert!(chain.insert_block(genesis).is_err());
    assert_eq!(chain, before);
    let mut wrong = next_link(&chain);
    wrong.height = Height(2);
    assert!(chain.insert_block(wrong).is_err());
    assert_eq!(chain, before);
    let mut wrong = next_link(&chain);
    wrong.header.previous_hash.0 = [9; 32];
    assert!(chain.insert_block(wrong).is_err());
    assert_eq!(chain, before);
}

#[test]
#[ignore = "manual CPU microbenchmark; run in release mode with --nocapture"]
fn benchmark_chain_commit_and_pow_allocation() {
    for history in [1_000, 20_000] {
        let mut base = Chain::new();
        base.insert_block(genesis_block().unwrap()).unwrap();
        for _ in 0..history {
            base.insert_block(next_link(&base)).unwrap();
        }
        base.retain_recent_bodies(64 * 1024, 64).unwrap();
        let mut old = base.clone();
        let mut direct = base;
        let rounds = 128;
        let start = Instant::now();
        for _ in 0..rounds {
            let block = next_link(&old);
            let mut staged = old.clone();
            staged.insert_block(block).unwrap();
            old = staged;
            black_box(&old);
        }
        let cloned = start.elapsed();
        let start = Instant::now();
        for _ in 0..rounds {
            direct.insert_block(next_link(&direct)).unwrap();
            black_box(&direct);
        }
        let inserted = start.elapsed();
        assert_eq!(direct, old);
        println!(
            "history={history} rounds={rounds} clone_commit_ms={:.3} direct_commit_ms={:.3}",
            cloned.as_secs_f64() * 1000.0,
            inserted.as_secs_f64() * 1000.0
        );
    }
    let mut header = genesis_block().unwrap().header;
    let mut memory = new_pow_memory();
    let rounds = 8;
    let start = Instant::now();
    let mut fresh = Vec::new();
    for nonce in 0..rounds {
        header.nonce = Nonce(nonce);
        fresh.push(calculate_work(&header).unwrap());
    }
    let allocated = start.elapsed();
    let start = Instant::now();
    for nonce in 0..rounds {
        header.nonce = Nonce(nonce);
        assert_eq!(
            calculate_work_with_memory(&header, &mut memory).unwrap(),
            fresh[nonce as usize]
        );
    }
    let reused = start.elapsed();
    println!(
        "pow_rounds={rounds} fresh_buffer_ms={:.3} reused_buffer_ms={:.3}",
        allocated.as_secs_f64() * 1000.0,
        reused.as_secs_f64() * 1000.0
    );
}
