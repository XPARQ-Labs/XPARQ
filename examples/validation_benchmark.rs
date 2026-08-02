use paqus::block::{Block, CoinbaseTransaction, GenesisAllocation, Height, Nonce};
use paqus::consensus::DIFFICULTY_START;
use paqus::consensus::supply::Amount;
use paqus::crypto::{
    Address, dual_address_from_public_keys, generate_keypair, sign, verify, verify_dual_parallel,
};
use paqus::ledger::{Chain, Ledger};
use paqus::state::Account;
use paqus::transaction::{SignedTransaction, Transaction};
use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::{Duration, Instant};

fn elapsed_per_item(elapsed: Duration, count: usize) -> f64 {
    elapsed.as_secs_f64() * 1_000_000.0 / count.max(1) as f64
}

fn benchmark_signature_pairs(count: usize) {
    let owner = generate_keypair();
    let auth = generate_keypair();
    let messages: Vec<Vec<u8>> = (0..count)
        .map(|index| format!("paqus-validation-benchmark-{index}").into_bytes())
        .collect();
    let signatures: Vec<_> = messages
        .iter()
        .map(|message| {
            (
                sign(&owner.secret_key, message),
                sign(&auth.secret_key, message),
            )
        })
        .collect();

    let started = Instant::now();
    for (message, (owner_signature, auth_signature)) in messages.iter().zip(&signatures) {
        black_box(verify(&owner.public_key, message, owner_signature));
        black_box(verify(&auth.public_key, message, auth_signature));
    }
    let sequential = started.elapsed();

    let started = Instant::now();
    for (message, (owner_signature, auth_signature)) in messages.iter().zip(&signatures) {
        black_box(verify_dual_parallel(
            &owner.public_key,
            &auth.public_key,
            message,
            owner_signature,
            auth_signature,
        ));
    }
    let parallel = started.elapsed();

    println!(
        "signature-pairs count={count} sequential={:.3}s ({:.1}us/tx) parallel={:.3}s ({:.1}us/tx) speedup={:.2}x",
        sequential.as_secs_f64(),
        elapsed_per_item(sequential, count),
        parallel.as_secs_f64(),
        elapsed_per_item(parallel, count),
        sequential.as_secs_f64() / parallel.as_secs_f64(),
    );
}

fn applicable_block(count: usize) -> Result<(Ledger, Block), String> {
    let owner = generate_keypair();
    let auth = generate_keypair();
    let sender = dual_address_from_public_keys(&owner.public_key, &auth.public_key);
    let miner = Address([9; 20]);
    let recipient = Address([3; 20]);
    let genesis = Block::genesis(
        miner,
        vec![GenesisAllocation {
            to: sender,
            amount: Amount((count as u64 + 1) * 3),
        }],
    )
    .unwrap();
    let genesis_hash = genesis.hash().unwrap();
    let mut accounts = BTreeMap::new();
    accounts.insert(sender, Account::new(sender, Amount((count as u64 + 1) * 3)));
    let mut chain = Chain::new();
    chain.insert_block(genesis).unwrap();
    let ledger = Ledger::from_accounts_and_chain(accounts, chain).unwrap();

    let transactions: Vec<SignedTransaction> = (0..count)
        .map(|index| {
            let transaction = Transaction::new(
                sender,
                vec![paqus::transaction::TransferOutput {
                    to: recipient.into(),
                    amount: Amount(1),
                }],
            )
            .with_last_state(ledger.account(&sender).unwrap().statement);
            let payload = transaction.signing_bytes().unwrap();
            let owner_signature = sign(&owner.secret_key, &payload);
            let auth_signature = sign(&auth.secret_key, &payload);
            if index == 0 {
                SignedTransaction::new_authorized(
                    transaction,
                    owner.public_key,
                    owner_signature,
                    auth.public_key,
                    auth_signature,
                )
            } else {
                SignedTransaction::new_stored_authorized(
                    transaction,
                    owner_signature,
                    auth_signature,
                )
            }
        })
        .collect();
    let coinbase = CoinbaseTransaction::new(miner, ledger.mintable_subsidy(Height(1)));
    let mut block = Block::from_protocol_transactions(
        Height(1),
        genesis_hash,
        miner,
        DIFFICULTY_START,
        Nonce(1),
        vec![],
        Some(coinbase),
        transactions.into_iter().map(Into::into).collect(),
    )
    .unwrap();
    let (_, execution) = ledger
        .execute_block(&block)
        .map_err(|error| error.to_string())?;
    block.set_state_root(execution.state_root_after);
    Ok((ledger, block))
}

fn benchmark_block_validation(count: usize) {
    let setup = Instant::now();
    let (ledger, block) = match applicable_block(count) {
        Ok(value) => value,
        Err(error) => {
            println!("block-validation count={count} skipped={error}");
            return;
        }
    };
    let setup = setup.elapsed();
    let started = Instant::now();
    black_box(ledger.execute_block(black_box(&block)).unwrap());
    let validation = started.elapsed();
    println!(
        "block-validation count={count} setup={:.3}s validation={:.3}s ({:.1}us/tx) throughput={:.2}tx/s",
        setup.as_secs_f64(),
        validation.as_secs_f64(),
        elapsed_per_item(validation, count),
        count as f64 / validation.as_secs_f64(),
    );
}

fn main() {
    let counts: Vec<usize> = std::env::args()
        .skip(1)
        .map(|value| value.parse().expect("counts must be positive integers"))
        .collect();
    let counts = if counts.is_empty() {
        vec![100, 500, 1_000, 4_096]
    } else {
        counts
    };
    println!(
        "Paqus validation benchmark; logical_cpus={}",
        std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
    );
    for count in counts {
        benchmark_signature_pairs(count);
        benchmark_block_validation(count);
    }
}
