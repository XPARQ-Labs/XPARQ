#[path = "../../benches/support/mod.rs"]
mod support;

use kernel::crypto::program_id_from_public_key;
use kernel::{
    blockchain::MAX_BLOCK_SIZE,
    common::Owner,
    consensus::{apply_block_with_pow_memory, new_pow_memory},
};
use std::hint::black_box;
use support::{Config, report, timed};
#[path = "../../benches/support/chain.rs"]
mod chain;
use chain::{candidate, fixtures, transfer};

fn main() {
    let config = Config::from_args();
    println!("# setup: mining and signing fixtures outside timed region");
    let (baseline, keys, chain, miner) = fixtures(if config.signature_heavy { 14 } else { 1 });
    let mut cases = vec![("mixed_small", 1), ("mixed_near_limit_many_outputs", 3800)];
    if config.signature_heavy {
        cases.push(("mixed_near_limit_many_signatures", 1));
    }
    for (case, outputs_per_tx) in cases {
        let mut operations = Vec::new();
        for key in &keys {
            let owner = program_id_from_public_key(&key.public_key()).unwrap();
            let shares: Vec<_> = baseline
                .state()
                .utxos()
                .coins_by_owner(Owner::Program(owner))
                .take(if case == "mixed_near_limit_many_signatures" {
                    14
                } else {
                    1
                })
                .map(|(id, coin)| (id, coin.amount.as_zeno()))
                .collect();
            for (input, amount) in shares {
                operations.push(transfer(
                    key,
                    input,
                    amount,
                    &vec![owner; outputs_per_tx],
                    chain,
                    true,
                ));
            }
            println!("# {case}: fixture signed {} operations", operations.len());
        }
        let block = candidate(&baseline, miner, operations);
        let bytes = block.serialized_size().unwrap();
        let weight = block.header.block_weight as usize;
        assert!(bytes <= MAX_BLOCK_SIZE && weight <= MAX_BLOCK_SIZE);
        if outputs_per_tx > 1 || case == "mixed_near_limit_many_signatures" {
            assert!(bytes >= MAX_BLOCK_SIZE * 9 / 10);
        }
        println!(
            "# {case}: operations={}, outputs_per_tx={outputs_per_tx}, bytes={bytes}, weight={weight}, limit={MAX_BLOCK_SIZE}",
            block.operation_count()
        );
        let mut values = Vec::new();
        let mut memory = new_pow_memory();
        for sample in 0..=config.samples {
            // Reset state outside the timer; the normal admission/application
            // path inside includes PoW, authorization, execution and state root.
            let mut ledger = baseline.clone();
            let input = block.clone();
            let (_, ms) = timed(|| {
                apply_block_with_pow_memory(black_box(&mut ledger), black_box(input), &mut memory)
                    .unwrap()
            });
            assert_eq!(ledger.state_root().unwrap(), block.state_root());
            ledger.state().audit_coin_supply().unwrap();
            if sample != 0 {
                values.push(ms);
            }
            println!("# {case}: sample {sample}/{} complete", config.samples);
        }
        report(case, "apply_block_including_pow", &values);
    }
}
