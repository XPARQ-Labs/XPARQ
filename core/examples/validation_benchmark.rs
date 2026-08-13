use std::hint::black_box;
use std::time::{Duration, Instant};
use xparq::block::{Block, EmissionTransaction, Height, Nonce};
use xparq::consensus::DIFFICULTY_START;
use xparq::consensus::supply::Amount;
use xparq::crypto::{Address, address_from_public_key, generate_keypair, sign, verify};
use xparq::ledger::Ledger;
use xparq::transaction::{SignedTransfer, Transfer};

fn elapsed_per_item(elapsed: Duration, count: usize) -> f64 {
    elapsed.as_secs_f64() * 1_000_000.0 / count.max(1) as f64
}

fn benchmark_signatures(count: usize) {
    let owner = generate_keypair();
    let messages: Vec<Vec<u8>> = (0..count)
        .map(|index| format!("xparq-validation-benchmark-{index}").into_bytes())
        .collect();
    let signatures: Vec<_> = messages
        .iter()
        .map(|message| sign(&owner.secret_key, message))
        .collect();

    let started = Instant::now();
    for (message, signature) in messages.iter().zip(&signatures) {
        black_box(verify(&owner.public_key, message, signature));
    }
    let sequential = started.elapsed();

    println!(
        "signatures count={count} verify={:.3}s ({:.1}us/tx)",
        sequential.as_secs_f64(),
        elapsed_per_item(sequential, count),
    );
}

fn applicable_block(count: usize) -> Result<(Ledger, Block), String> {
    let owner = generate_keypair();
    let sender = address_from_public_key(&owner.public_key);
    let miner = Address([9; xparq::crypto::ADDRESS_SIZE]);
    let recipient = Address([3; xparq::crypto::ADDRESS_SIZE]);
    let genesis = Block::genesis().unwrap();
    let genesis_hash = genesis.hash().unwrap();
    let ledger = xparq::genesis::genesis_ledger().unwrap();

    let transactions: Vec<SignedTransfer> = (0..count)
        .map(|index| {
            let transaction = Transfer::new(
                sender,
                vec![xparq::state::XpqCoinId(
                    [index as u8; xparq::crypto::HASH_SIZE],
                )],
                recipient,
                Amount(1),
            );
            let payload = transaction.signing_bytes().unwrap();
            let owner_signature = sign(&owner.secret_key, &payload);
            if index == 0 {
                SignedTransfer::new(transaction, owner.public_key, owner_signature)
            } else {
                SignedTransfer::new_stored(transaction, owner_signature)
            }
        })
        .collect();
    let coinbase = EmissionTransaction::new(miner, ledger.mintable_subsidy(Height(1)).unwrap());
    let mut block = Block::from_protocol_transactions(
        Height(1),
        genesis_hash,
        DIFFICULTY_START,
        Nonce(1),
        Some(coinbase),
        transactions.into_iter().map(Into::into).collect(),
    )
    .unwrap();
    let execution = ledger
        .preview_candidate_block(&block)
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
    black_box(ledger.preview_candidate_block(black_box(&block)).unwrap());
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
        "xparq validation benchmark; logical_cpus={}",
        std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
    );
    for count in counts {
        benchmark_signatures(count);
        benchmark_block_validation(count);
    }
}
