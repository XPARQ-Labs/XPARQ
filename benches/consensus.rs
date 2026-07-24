use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use paqus::block::{Block, Height, MAX_BLOCK_SIZE, Nonce};
use paqus::codec::{
    block_bytes, decode_block, decode_protocol_event, decode_signed_protocol_transaction_at,
    decode_transaction, protocol_event_bytes, signed_transaction_bytes, transaction_bytes,
};
use paqus::consensus::supply::{Amount, XPQ};
use paqus::crypto::{
    Address, BlockHash, HASH_SIZE, Hash, HashDomain, address_from_public_key, cached_verifying_key,
    domain_hash, generate_keypair, sign, verify,
};
use paqus::ledger::{
    Ledger, SparseStateTree, calculate_state_root, create_account_state_proof,
    verify_account_state_proof,
};
use paqus::ledger::{fork_choice::ForkChoice, plan_reorg};
use paqus::qcash::{
    CashCoinFile, DepositCashMetadata, QCashOutput, decode_cash_coin_file, encode_cash_coin_file,
};
use paqus::qcash::{CashDenomination, WithdrawCashMetadata, cash_coin_commitment};
use paqus::state::Account;
use paqus::transaction::{
    MAX_TX_SIZE, QCashTransaction, SignedProtocolTransaction, SignedQCashTransaction,
    SignedTransaction, Transaction,
};
use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::Duration;

const TIMESTAMP: u64 = 1_700_000_000;

fn signed_transfer(nonce: u64) -> SignedTransaction {
    let keypair = generate_keypair();
    let transaction = Transaction::new_at(
        address_from_public_key(&keypair.public_key),
        Address([2; 20]),
        Amount(100),
        Amount(2),
        Nonce(nonce),
        TIMESTAMP + 1,
    );
    let signature = sign(&keypair.secret_key, &transaction.signing_bytes());
    SignedTransaction::new(transaction, keypair.public_key, signature)
}

fn benchmark_block(transaction_count: usize) -> Block {
    let transaction = signed_transfer(0);
    Block::new(
        Height(1),
        Hash([7; HASH_SIZE]),
        Address([9; 20]),
        TIMESTAMP + 1,
        Nonce(42),
        vec![transaction; transaction_count],
    )
}

fn applicable_transfer_block() -> (Ledger, Block) {
    let keypair = generate_keypair();
    let sender = address_from_public_key(&keypair.public_key);
    let recipient = Address([3; 20]);
    let genesis = Block::genesis(Address([9; 20]), TIMESTAMP, vec![]);
    let genesis_hash = genesis.hash();
    let mut ledger = Ledger::new();
    ledger.apply_block(genesis).unwrap();
    ledger.create_account(sender, Amount(10_000)).unwrap();

    let transaction = Transaction::new_at(
        sender,
        recipient,
        Amount(100),
        Amount(2),
        Nonce(0),
        TIMESTAMP + 1,
    );
    let signature = sign(&keypair.secret_key, &transaction.signing_bytes());
    let signed = SignedTransaction::new(transaction, keypair.public_key, signature);
    let mut block = Block::new(
        Height(1),
        genesis_hash,
        Address([9; 20]),
        TIMESTAMP + 1,
        Nonce(1),
        vec![signed],
    );
    block.set_state_root(ledger.state_root_after_block(&block).unwrap());
    (ledger, block)
}

fn applicable_multi_transfer_block(transaction_count: usize) -> (Ledger, Block) {
    let keypair = generate_keypair();
    let sender = address_from_public_key(&keypair.public_key);
    let recipient = Address([3; 20]);
    let genesis = Block::genesis(Address([9; 20]), TIMESTAMP, vec![]);
    let genesis_hash = genesis.hash();
    let mut ledger = Ledger::new();
    ledger.apply_block(genesis).unwrap();
    ledger.create_account(sender, Amount(1_000_000)).unwrap();

    let transactions = (0..transaction_count)
        .map(|index| {
            let transaction = Transaction::new_at(
                sender,
                recipient,
                Amount(100),
                Amount(2),
                Nonce(index as u64),
                TIMESTAMP + 1,
            );
            let signature = sign(&keypair.secret_key, &transaction.signing_bytes());
            SignedTransaction::new(transaction, keypair.public_key, signature)
        })
        .collect();
    let mut block = Block::new(
        Height(1),
        genesis_hash,
        Address([9; 20]),
        TIMESTAMP + 1,
        Nonce(1),
        transactions,
    );
    block.set_state_root(ledger.state_root_after_block(&block).unwrap());
    (ledger, block)
}

fn late_invalid_nonce_block(transaction_count: usize) -> (Ledger, Block) {
    let keypair = generate_keypair();
    let sender = address_from_public_key(&keypair.public_key);
    let recipient = Address([3; 20]);
    let genesis = Block::genesis(Address([9; 20]), TIMESTAMP, vec![]);
    let genesis_hash = genesis.hash();
    let mut ledger = Ledger::new();
    ledger.apply_block(genesis).unwrap();
    ledger.create_account(sender, Amount(1_000_000)).unwrap();

    let transactions = (0..transaction_count)
        .map(|index| {
            let nonce = if index + 1 == transaction_count {
                transaction_count as u64 + 7
            } else {
                index as u64
            };
            let transaction = Transaction::new_at(
                sender,
                recipient,
                Amount(100),
                Amount(2),
                Nonce(nonce),
                TIMESTAMP + 1,
            );
            let signature = sign(&keypair.secret_key, &transaction.signing_bytes());
            SignedTransaction::new(transaction, keypair.public_key, signature)
        })
        .collect();
    let mut block = Block::new(
        Height(1),
        genesis_hash,
        Address([9; 20]),
        TIMESTAMP + 1,
        Nonce(1),
        transactions,
    );
    // Non-zero lets execution reach state validation; the nonce error occurs first.
    block.set_state_root(Hash([1; HASH_SIZE]));
    (ledger, block)
}

fn competing_transfer_blocks() -> (Ledger, Ledger, ForkChoice, Block) {
    let keypair = generate_keypair();
    let sender = address_from_public_key(&keypair.public_key);
    let miner = Address([9; 20]);
    let genesis = Block::genesis(miner, TIMESTAMP, vec![]);
    let mut baseline = Ledger::new();
    baseline.apply_block(genesis.clone()).unwrap();
    baseline.create_account(sender, Amount(10_000)).unwrap();

    let make_block = |recipient: Address, block_nonce: u64| {
        let transaction = Transaction::new_at(
            sender,
            recipient,
            Amount(100),
            Amount(2),
            Nonce(0),
            TIMESTAMP + 1,
        );
        let signature = sign(&keypair.secret_key, &transaction.signing_bytes());
        let signed = SignedTransaction::new(transaction, keypair.public_key, signature);
        let mut block = Block::new(
            Height(1),
            genesis.hash(),
            miner,
            TIMESTAMP + 1,
            Nonce(block_nonce),
            vec![signed],
        );
        block.set_state_root(baseline.state_root_after_block(&block).unwrap());
        block
    };

    let active_block = make_block(Address([3; 20]), 1);
    let competing_block = make_block(Address([4; 20]), 2);
    let mut active = baseline.clone();
    active.apply_block(active_block.clone()).unwrap();
    let mut fork_choice = ForkChoice::new();
    fork_choice.insert_block(genesis).unwrap();
    fork_choice.insert_block(active_block).unwrap();
    fork_choice.insert_block(competing_block.clone()).unwrap();

    (baseline, active, fork_choice, competing_block)
}

fn two_block_competing_branches() -> (Ledger, ForkChoice, BlockHash, Vec<BlockHash>) {
    let keypair = generate_keypair();
    let sender = address_from_public_key(&keypair.public_key);
    let miner = Address([9; 20]);
    let genesis = Block::genesis(miner, TIMESTAMP, vec![]);
    let mut baseline = Ledger::new();
    baseline.apply_block(genesis.clone()).unwrap();
    baseline.create_account(sender, Amount(10_000)).unwrap();

    let make_next = |ledger: &Ledger,
                     previous: BlockHash,
                     height: u64,
                     recipient: Address,
                     block_nonce: u64| {
        let transaction = Transaction::new_at(
            sender,
            recipient,
            Amount(100),
            Amount(2),
            Nonce(height - 1),
            TIMESTAMP + height,
        );
        let signature = sign(&keypair.secret_key, &transaction.signing_bytes());
        let signed = SignedTransaction::new(transaction, keypair.public_key, signature);
        let mut block = Block::new(
            Height(height),
            previous,
            miner,
            TIMESTAMP + height,
            Nonce(block_nonce),
            vec![signed],
        );
        block.set_state_root(ledger.state_root_after_block(&block).unwrap());
        block
    };

    let mut active = baseline.clone();
    let active_one = make_next(&active, genesis.hash(), 1, Address([3; 20]), 1);
    active.apply_block(active_one.clone()).unwrap();
    let active_two = make_next(&active, active_one.hash(), 2, Address([3; 20]), 2);
    active.apply_block(active_two.clone()).unwrap();

    let mut competing = baseline;
    let competing_one = make_next(&competing, genesis.hash(), 1, Address([4; 20]), 11);
    competing.apply_block(competing_one.clone()).unwrap();
    let competing_two = make_next(&competing, competing_one.hash(), 2, Address([4; 20]), 12);

    let rollback_hashes = vec![active_two.hash(), active_one.hash()];
    let mut fork_choice = ForkChoice::new();
    for block in [
        genesis,
        active_one,
        active_two.clone(),
        competing_one,
        competing_two.clone(),
    ] {
        fork_choice.insert_block(block).unwrap();
    }
    (active, fork_choice, competing_two.hash(), rollback_hashes)
}

fn applicable_mixed_family_block() -> (Ledger, Block) {
    let transfer_key = generate_keypair();
    let qcash_key = generate_keypair();

    let transfer_sender = address_from_public_key(&transfer_key.public_key);
    let qcash_owner = address_from_public_key(&qcash_key.public_key);
    let miner = Address([99; 20]);
    let height = Height(1);
    let anchor = Block::new(
        Height(height.0 - 1),
        Hash([0; HASH_SIZE]),
        miner,
        TIMESTAMP,
        Nonce(0),
        vec![],
    );
    let anchor_hash = anchor.hash();
    let mut ledger = Ledger::new();
    ledger.chain.blocks.insert(anchor.height(), anchor);
    ledger.chain.tip_height = Some(Height(height.0 - 1));
    ledger.chain.tip_hash = Some(anchor_hash);
    ledger
        .create_account(transfer_sender, Amount(1_000))
        .unwrap();
    ledger.create_account(qcash_owner, Amount(2 * XPQ)).unwrap();

    let transfer = Transaction::new_at(
        transfer_sender,
        Address([21; 20]),
        Amount(100),
        Amount(2),
        Nonce(0),
        TIMESTAMP + 1,
    );
    let signed_transfer = SignedTransaction::new(
        transfer.clone(),
        transfer_key.public_key,
        sign(&transfer_key.secret_key, &transfer.signing_bytes()),
    );

    let qcash = QCashTransaction::withdraw(
        qcash_owner,
        Amount(XPQ),
        Amount(3),
        Nonce(0),
        WithdrawCashMetadata::with_denominations(
            Amount(XPQ),
            &[CashDenomination::One],
            &[cash_coin_commitment(&[31; 32])],
        )
        .unwrap(),
    )
    .with_timestamp(TIMESTAMP + 1);
    let signed_qcash = SignedQCashTransaction::new(
        qcash.clone(),
        qcash_key.public_key,
        sign(&qcash_key.secret_key, &qcash.signing_bytes()),
    );
    let mut block = Block::with_all_transactions(
        height,
        anchor_hash,
        miner,
        1,
        TIMESTAMP + 1,
        Nonce(1),
        vec![signed_transfer],
        vec![signed_qcash],
    )
    .unwrap();
    block.coinbase.as_mut().unwrap().fees = block.checked_total_fees().unwrap();
    block.refresh_merkle_root();
    block.set_state_root(ledger.state_root_after_block(&block).unwrap());
    (ledger, block)
}

fn crypto_operations(c: &mut Criterion) {
    let keypair = generate_keypair();
    let message = transaction_bytes(&signed_transfer(0).transaction);
    let signature = sign(&keypair.secret_key, &message);
    let cached_key = cached_verifying_key(&keypair.public_key);
    let mut group = c.benchmark_group("crypto_operations");

    group.bench_function("ml_dsa_87_keypair", |b| {
        b.iter(|| black_box(generate_keypair()))
    });
    group.bench_function("ml_dsa_87_sign", |b| {
        b.iter(|| black_box(sign(&keypair.secret_key, black_box(&message))))
    });
    group.bench_function("ml_dsa_87_verify", |b| {
        b.iter(|| black_box(verify(&keypair.public_key, black_box(&message), &signature)))
    });
    group.bench_function("ml_dsa_87_verify_cached_key", |b| {
        b.iter(|| {
            cached_key.verify(black_box(&message), &signature).unwrap();
            black_box(())
        })
    });
    group.bench_function("sha3_256_domain_hash", |b| {
        b.iter(|| black_box(domain_hash(HashDomain::Transaction, black_box(&message))))
    });
    group.finish();
}

fn qcash_file_operations(c: &mut Criterion) {
    let opening_secret = [0x42; 32];
    let output = QCashOutput {
        coin_index: 0,
        denomination: CashDenomination::OneHundred,
        commitment: cash_coin_commitment(&opening_secret),
    };
    let file = CashCoinFile::new(
        paqus::crypto::TransactionHash([0x24; HASH_SIZE]),
        &output,
        opening_secret,
    )
    .unwrap();
    let encoded = encode_cash_coin_file(&file).unwrap();
    let recipient = Address([0x52; 20]);
    let transaction_commitment = [0x99; 32];
    let deposit = DepositCashMetadata::new_for_transaction(
        std::slice::from_ref(&file),
        recipient,
        transaction_commitment,
    )
    .unwrap();
    let mut group = c.benchmark_group("qcash_file_operations");
    group.throughput(Throughput::Bytes(encoded.len() as u64));

    group.bench_function("derive_coin_commitment", |b| {
        b.iter(|| black_box(cash_coin_commitment(black_box(&opening_secret))))
    });
    group.bench_function("encode_bearer_file", |b| {
        b.iter(|| black_box(encode_cash_coin_file(black_box(&file)).unwrap()))
    });
    group.bench_function("decode_and_checksum_bearer_file", |b| {
        b.iter(|| black_box(decode_cash_coin_file(black_box(&encoded)).unwrap()))
    });
    group.throughput(Throughput::Elements(1));
    group.bench_function("create_deposit_authorization", |b| {
        b.iter(|| {
            black_box(
                black_box(&file)
                    .deposit_input_for_transaction(
                        black_box(recipient),
                        black_box(transaction_commitment),
                    )
                    .unwrap(),
            )
        })
    });
    group.bench_function("verify_deposit_authorization", |b| {
        b.iter(|| {
            black_box(&deposit)
                .validate_authorizations_for_transaction(
                    black_box(recipient),
                    black_box(transaction_commitment),
                )
                .unwrap();
            black_box(())
        })
    });
    group.finish();
}

fn protocol_event_operations(c: &mut Criterion) {
    let (baseline, block) = applicable_mixed_family_block();
    let block_hash = block.hash();
    let mut applied = baseline;
    applied.apply_block(block).unwrap();
    let events = applied.events_for_block(&block_hash).to_vec();
    let event = events.first().unwrap().clone();
    let event_id = event.id();
    let encoded = protocol_event_bytes(&event);
    let mut group = c.benchmark_group("protocol_event_operations");

    group.throughput(Throughput::Bytes(encoded.len() as u64));
    group.bench_function("encode_event", |b| {
        b.iter(|| black_box(protocol_event_bytes(black_box(&event))))
    });
    group.bench_function("decode_and_validate_event", |b| {
        b.iter(|| black_box(decode_protocol_event(black_box(&encoded)).unwrap()))
    });
    group.bench_function("derive_event_id", |b| {
        b.iter(|| black_box(black_box(&event).id()))
    });
    group.throughput(Throughput::Elements(events.len() as u64));
    group.bench_function("encode_mixed_family_event_batch", |b| {
        b.iter(|| {
            black_box(
                black_box(&events)
                    .iter()
                    .map(protocol_event_bytes)
                    .collect::<Vec<_>>(),
            )
        })
    });
    group.throughput(Throughput::Elements(1));
    group.bench_function("lookup_event_by_id", |b| {
        b.iter(|| black_box(black_box(&applied).event(black_box(event_id)).unwrap()))
    });
    group.finish();
}

fn protocol_envelope_operations(c: &mut Criterion) {
    let (_ledger, block) = applicable_mixed_family_block();
    let height = block.height();
    let timestamp = block.timestamp();
    let envelopes = [
        (
            "transfer",
            SignedProtocolTransaction::Transfer(block.transactions[0].clone()),
        ),
        (
            "qcash",
            SignedProtocolTransaction::QCash(block.qcash_transactions[0].clone()),
        ),
    ];
    let mut group = c.benchmark_group("protocol_envelope_operations");

    for (family, envelope) in envelopes {
        let encoded = envelope.to_bytes();
        group.throughput(Throughput::Bytes(encoded.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("encode", family),
            &envelope,
            |b, envelope| b.iter(|| black_box(black_box(envelope).to_bytes())),
        );
        group.bench_with_input(
            BenchmarkId::new("decode_and_validate", family),
            &encoded,
            |b, encoded| {
                b.iter(|| {
                    black_box(
                        decode_signed_protocol_transaction_at(
                            black_box(encoded),
                            height,
                            timestamp,
                            (),
                        )
                        .unwrap(),
                    )
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("wtxid", family),
            &envelope,
            |b, envelope| b.iter(|| black_box(black_box(envelope).wtxid())),
        );
    }
    group.finish();
}

fn canonical_codec(c: &mut Criterion) {
    let block = benchmark_block(32);
    let encoded = block_bytes(&block);
    let mut group = c.benchmark_group("canonical_codec");
    group.throughput(Throughput::Bytes(encoded.len() as u64));
    group.bench_function("encode_block_32_txs", |b| {
        b.iter(|| black_box(block_bytes(black_box(&block))))
    });
    group.bench_function("decode_and_validate_block_32_txs", |b| {
        b.iter(|| black_box(decode_block(black_box(&encoded)).unwrap()))
    });
    group.finish();
}

fn decoder_rejection(c: &mut Criterion) {
    let valid_transaction = Transaction::new_at(
        Address([1; 20]),
        Address([2; 20]),
        Amount(1),
        Amount(0),
        Nonce(0),
        TIMESTAMP,
    );
    let mut trailing_transaction = transaction_bytes(&valid_transaction);
    trailing_transaction.push(0);
    let oversized_transaction = vec![0_u8; MAX_TX_SIZE + 1];
    let oversized_block = vec![0_u8; MAX_BLOCK_SIZE + 1];
    let length_bombs: [&[u8]; 4] = [
        &[0xff, 0xff, 0xff, 0xff],
        &[0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
        &[5, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
        &[1, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
    ];
    let mut group = c.benchmark_group("decoder_rejection");

    group.bench_function("transaction_trailing_byte", |b| {
        b.iter(|| black_box(decode_transaction(black_box(&trailing_transaction)).unwrap_err()))
    });
    group.bench_function("oversized_transaction_precheck", |b| {
        b.iter(|| black_box(decode_transaction(black_box(&oversized_transaction)).unwrap_err()))
    });
    group.bench_function("oversized_block_precheck", |b| {
        b.iter(|| black_box(decode_block(black_box(&oversized_block)).unwrap_err()))
    });
    group.bench_function("four_length_bombs_across_tx_and_block", |b| {
        b.iter(|| {
            for bytes in length_bombs {
                black_box(decode_transaction(black_box(bytes)).unwrap_err());
                black_box(decode_block(black_box(bytes)).unwrap_err());
            }
        })
    });
    group.finish();
}

fn transaction_identity(c: &mut Criterion) {
    let signed = signed_transfer(0);
    let mut group = c.benchmark_group("transaction_identity");
    group.bench_function("payload_bytes", |b| {
        b.iter(|| black_box(transaction_bytes(black_box(&signed.transaction))))
    });
    group.bench_function("witness_bytes", |b| {
        b.iter(|| black_box(signed_transaction_bytes(black_box(&signed))))
    });
    group.bench_function("txid", |b| b.iter(|| black_box(black_box(&signed).txid())));
    group.bench_function("wtxid", |b| {
        b.iter(|| black_box(black_box(&signed).wtxid()))
    });
    group.finish();
}

fn block_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_validation");
    for transaction_count in [1, 8, 32] {
        let block = benchmark_block(transaction_count);
        group.throughput(Throughput::Elements(transaction_count as u64));
        group.bench_with_input(
            BenchmarkId::new("signed_transfers", transaction_count),
            &block,
            |b, block| {
                b.iter(|| {
                    let _: () = black_box(block).validate().unwrap();
                    black_box(())
                })
            },
        );
    }
    group.finish();
}

fn block_commitments(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_commitments");
    for transaction_count in [1, 32, 100] {
        let block = benchmark_block(transaction_count);
        group.throughput(Throughput::Elements(transaction_count as u64));
        group.bench_with_input(
            BenchmarkId::new("payload_merkle_root", transaction_count),
            &block,
            |b, block| b.iter(|| black_box(black_box(block).calculate_merkle_root())),
        );
        group.bench_with_input(
            BenchmarkId::new("witness_merkle_root", transaction_count),
            &block,
            |b, block| b.iter(|| black_box(black_box(block).calculate_witness_merkle_root())),
        );
        group.bench_with_input(
            BenchmarkId::new("refresh_both_commitments", transaction_count),
            &block,
            |b, block| {
                b.iter_batched(
                    || block.clone(),
                    |mut block| {
                        let _: () = block.refresh_commitments();
                        black_box(())
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
    group.finish();
}

fn state_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_root");
    for account_count in [1_u32, 100, 1_000] {
        let mut accounts = BTreeMap::new();
        for index in 0..account_count {
            let mut address = [0_u8; 20];
            address[..4].copy_from_slice(&index.to_le_bytes());
            let address = Address(address);
            accounts.insert(address, Account::new(address, Amount(index as u64 + 1)));
        }
        let mut ledger = Ledger::new();
        ledger.replace_accounts(accounts);
        group.throughput(Throughput::Elements(account_count as u64));
        group.bench_with_input(
            BenchmarkId::new("cached_read", account_count),
            &ledger,
            |b, ledger| b.iter(|| black_box(black_box(ledger).state_root())),
        );
        group.bench_with_input(
            BenchmarkId::new("full_rebuild", account_count),
            ledger.accounts(),
            |b, accounts| b.iter(|| black_box(calculate_state_root(black_box(accounts)))),
        );

        if account_count == 1_000 {
            let tree = SparseStateTree::from_accounts(ledger.accounts());
            let mut updated = ledger.accounts()[&Address([0; 20])].clone();
            updated.nonce.0 += 1;
            group.bench_function("incremental_update/1000", |b| {
                b.iter_batched(
                    || tree.clone(),
                    |mut tree| tree.update_account(black_box(&updated)),
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

fn state_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_proof");
    for account_count in [100_u32, 1_000] {
        let mut accounts = BTreeMap::new();
        for index in 0..account_count {
            let mut address = [0_u8; 20];
            address[..4].copy_from_slice(&index.to_le_bytes());
            let address = Address(address);
            accounts.insert(address, Account::new(address, Amount(index as u64 + 1)));
        }
        let target = *accounts.keys().nth(account_count as usize / 2).unwrap();
        let tree = SparseStateTree::from_accounts(&accounts);
        let account = accounts.get(&target).unwrap();
        let proof = tree.create_account_proof(account);
        let root = tree.root();

        group.bench_with_input(
            BenchmarkId::new("create_from_accounts", account_count),
            &account_count,
            |b, _| {
                b.iter(|| {
                    black_box(create_account_state_proof(
                        black_box(&accounts),
                        black_box(&target),
                    ))
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("create_from_cached_tree", account_count),
            &account_count,
            |b, _| b.iter(|| black_box(black_box(&tree).create_account_proof(black_box(account)))),
        );
        group.bench_with_input(
            BenchmarkId::new("verify", account_count),
            &account_count,
            |b, _| b.iter(|| black_box(verify_account_state_proof(root, black_box(&proof)))),
        );
    }
    group.finish();
}

fn large_state(c: &mut Criterion) {
    const ACCOUNT_COUNT: u32 = 10_000;
    let mut accounts = BTreeMap::new();
    for index in 0..ACCOUNT_COUNT {
        let mut address = [0_u8; 20];
        address[..4].copy_from_slice(&index.to_le_bytes());
        let address = Address(address);
        accounts.insert(address, Account::new(address, Amount(index as u64 + 1)));
    }
    let target = *accounts.keys().nth(ACCOUNT_COUNT as usize / 2).unwrap();
    let account = accounts.get(&target).unwrap();
    let tree = SparseStateTree::from_accounts(&accounts);
    let proof = tree.create_account_proof(account);
    let root = tree.root();
    let mut updated = account.clone();
    updated.nonce.0 += 1;
    let mut group = c.benchmark_group("large_state_10000_accounts");

    group.throughput(Throughput::Elements(ACCOUNT_COUNT as u64));
    group.bench_function("full_root_rebuild", |b| {
        b.iter(|| black_box(calculate_state_root(black_box(&accounts))))
    });
    group.throughput(Throughput::Elements(1));
    group.bench_function("cached_proof_creation", |b| {
        b.iter(|| black_box(black_box(&tree).create_account_proof(black_box(account))))
    });
    group.bench_function("proof_verification", |b| {
        b.iter(|| black_box(verify_account_state_proof(root, black_box(&proof))))
    });
    group.bench_function("incremental_account_update", |b| {
        b.iter_batched(
            || tree.clone(),
            |mut tree| tree.update_account(black_box(&updated)),
            BatchSize::LargeInput,
        )
    });
    group.finish();
}

fn ledger_transition(c: &mut Criterion) {
    let (baseline, block) = applicable_transfer_block();
    let mut applied = baseline.clone();
    applied.apply_block(block.clone()).unwrap();
    let block_hash = block.hash();
    let mut group = c.benchmark_group("ledger_transition");

    group.bench_function("apply_transfer_block", |b| {
        b.iter_batched(
            || baseline.clone(),
            |mut ledger| {
                let _: () = ledger.apply_block(black_box(block.clone())).unwrap();
                black_box(())
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function("rollback_transfer_block", |b| {
        b.iter_batched(
            || applied.clone(),
            |mut ledger| {
                let _: () = ledger.rollback_block(black_box(block_hash)).unwrap();
                black_box(())
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn multi_transaction_ledger_transition(c: &mut Criterion) {
    let mut group = c.benchmark_group("multi_transaction_ledger_transition");
    for transaction_count in [8, 32, 100] {
        let (baseline, block) = applicable_multi_transfer_block(transaction_count);
        group.throughput(Throughput::Elements(transaction_count as u64));
        group.bench_with_input(
            BenchmarkId::new("apply_transfers", transaction_count),
            &(baseline, block),
            |b, (baseline, block)| {
                b.iter_batched(
                    || (baseline.clone(), block.clone()),
                    |(mut ledger, block)| {
                        let _: () = ledger.apply_block(black_box(block)).unwrap();
                        black_box(())
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
    group.finish();
}

fn mixed_family_ledger_transition(c: &mut Criterion) {
    let (baseline, block) = applicable_mixed_family_block();
    let mut applied = baseline.clone();
    applied.apply_block(block.clone()).unwrap();
    let block_hash = block.hash();
    let encoded = block_bytes(&block);
    let mut group = c.benchmark_group("mixed_family_ledger_transition");
    group.throughput(Throughput::Elements(block.transaction_count() as u64));

    group.bench_function("encode_seven_families", |b| {
        b.iter(|| black_box(block_bytes(black_box(&block))))
    });
    group.bench_function("decode_and_validate_seven_families", |b| {
        b.iter(|| black_box(decode_block(black_box(&encoded)).unwrap()))
    });
    group.bench_function("validate_seven_families", |b| {
        b.iter(|| {
            let _: () = black_box(&block).validate().unwrap();
            black_box(())
        })
    });
    group.bench_function("apply_seven_families", |b| {
        b.iter_batched(
            || (baseline.clone(), block.clone()),
            |(mut ledger, block)| {
                let _: () = ledger.apply_block(black_box(block)).unwrap();
                black_box(())
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function("rollback_seven_families", |b| {
        b.iter_batched(
            || applied.clone(),
            |mut ledger| {
                let _: () = ledger.rollback_block(black_box(block_hash)).unwrap();
                black_box(())
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn failure_paths(c: &mut Criterion) {
    const TRANSACTION_COUNT: usize = 32;

    let mut invalid_signature = benchmark_block(TRANSACTION_COUNT);
    let last_signature = &mut invalid_signature
        .transactions
        .last_mut()
        .unwrap()
        .witness
        .signature
        .0;
    last_signature[0] ^= 1;
    invalid_signature.refresh_commitments();

    let (nonce_baseline, invalid_nonce) = late_invalid_nonce_block(TRANSACTION_COUNT);
    let (state_root_baseline, mut invalid_state_root) =
        applicable_multi_transfer_block(TRANSACTION_COUNT);
    invalid_state_root.set_state_root(Hash([0xAA; HASH_SIZE]));

    let mut group = c.benchmark_group("failure_paths");
    group.throughput(Throughput::Elements(TRANSACTION_COUNT as u64));
    group.bench_function("invalid_last_signature", |b| {
        b.iter(|| black_box(black_box(&invalid_signature).validate().unwrap_err()))
    });
    group.bench_function("invalid_last_nonce", |b| {
        b.iter_batched(
            || (nonce_baseline.clone(), invalid_nonce.clone()),
            |(mut ledger, block)| black_box(ledger.apply_block(black_box(block)).unwrap_err()),
            BatchSize::SmallInput,
        )
    });
    group.bench_function("invalid_state_root_after_execution", |b| {
        b.iter_batched(
            || (state_root_baseline.clone(), invalid_state_root.clone()),
            |(mut ledger, block)| black_box(ledger.apply_block(black_box(block)).unwrap_err()),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn reorg(c: &mut Criterion) {
    let (_baseline, active, fork_choice, competing_block) = competing_transfer_blocks();
    let competing_hash = competing_block.hash();
    let active_hash = active.tip_hash().unwrap();
    let plan = plan_reorg(&active, &fork_choice, competing_hash).unwrap();
    let (active_two, fork_choice_two, competing_tip_two, rollback_hashes_two) =
        two_block_competing_branches();
    let plan_two = plan_reorg(&active_two, &fork_choice_two, competing_tip_two).unwrap();
    let mut group = c.benchmark_group("reorg");

    group.bench_function("plan_one_block_competing_branch", |b| {
        b.iter(|| {
            black_box(plan_reorg(
                black_box(&active),
                black_box(&fork_choice),
                competing_hash,
            ))
        })
    });
    group.bench_function("execute_one_block_competing_branch", |b| {
        b.iter_batched(
            || (active.clone(), plan.clone()),
            |(mut ledger, plan)| {
                ledger.rollback_block(black_box(active_hash)).unwrap();
                for block in plan.apply {
                    ledger.apply_block(black_box(block)).unwrap();
                }
                black_box(ledger)
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function("plan_two_block_competing_branch", |b| {
        b.iter(|| {
            black_box(plan_reorg(
                black_box(&active_two),
                black_box(&fork_choice_two),
                competing_tip_two,
            ))
        })
    });
    group.bench_function("execute_two_block_competing_branch", |b| {
        b.iter_batched(
            || (active_two.clone(), plan_two.clone()),
            |(mut ledger, plan)| {
                for hash in &rollback_hashes_two {
                    ledger.rollback_block(black_box(*hash)).unwrap();
                }
                for block in plan.apply {
                    ledger.apply_block(black_box(block)).unwrap();
                }
                black_box(ledger)
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn fork_choice_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("fork_choice_operations");
    for block_count in [100_u64, 1_000] {
        let miner = Address([9; 20]);
        let genesis = Block::genesis(miner, TIMESTAMP, vec![]);
        let mut blocks = Vec::with_capacity(block_count as usize);
        let mut previous = genesis.hash();
        blocks.push(genesis);
        for height in 1..block_count {
            let block = Block::new(
                Height(height),
                previous,
                miner,
                TIMESTAMP + height,
                Nonce(height),
                vec![],
            );
            previous = block.hash();
            blocks.push(block);
        }

        let mut populated = ForkChoice::new();
        for block in blocks.iter().cloned() {
            populated.insert_block(block).unwrap();
        }
        let tip = populated.best_tip().unwrap().hash;

        group.throughput(Throughput::Elements(block_count));
        group.bench_with_input(
            BenchmarkId::new("insert_linear_chain", block_count),
            &blocks,
            |b, blocks| {
                b.iter_batched(
                    || blocks.clone(),
                    |blocks| {
                        let mut fork_choice = ForkChoice::new();
                        for block in blocks {
                            fork_choice.insert_block(block).unwrap();
                        }
                        black_box(fork_choice)
                    },
                    BatchSize::LargeInput,
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("walk_tip_ancestors", block_count),
            &populated,
            |b, fork_choice| b.iter(|| black_box(black_box(fork_choice).ancestor_hashes(tip))),
        );
    }
    group.finish();
}

fn standard_config() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .measurement_time(Duration::from_secs(5))
        .warm_up_time(Duration::from_secs(1))
}

criterion_group! {
    name = standard_benches;
    config = standard_config();
    targets = canonical_codec, decoder_rejection, transaction_identity, crypto_operations,
        qcash_file_operations, protocol_event_operations, protocol_envelope_operations,
        block_validation, block_commitments,
        state_root, state_proof
}

fn expensive_config() -> Criterion {
    Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(10))
        .warm_up_time(Duration::from_secs(2))
}

criterion_group! {
    name = expensive_benches;
    config = expensive_config();
    targets = large_state, ledger_transition, multi_transaction_ledger_transition,
        mixed_family_ledger_transition, failure_paths, reorg,
        fork_choice_operations
}
criterion_main!(standard_benches, expensive_benches);
