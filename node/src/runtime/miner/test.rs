use super::{MiningConfig, mine_candidate_block};
use crate::runtime::mempool::Mempool;
use crate::runtime::params::BASE_FEE;
use crate::test_support::BlockTestExt;
use xparq::block::{Block, Height, Nonce};
use xparq::consensus::supply::Amount;
use xparq::consensus::{Consensus, ConsensusConfig, MIN_DIFFICULTY, block_reward};
use xparq::crypto::{
    Address, HASH_SIZE, Hash, dual_address_from_public_keys, generate_keypair, sign,
};
use xparq::ledger::Ledger;
use xparq::transaction::{SignedTransaction, Transaction};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

fn address(byte: u8) -> Address {
    Address([byte; 20])
}

fn mine_test_block(mut block: Block, consensus: &Consensus) -> Block {
    while consensus.validate_proof_of_work(&block).is_err() {
        block.header.nonce = Nonce(block.header.nonce.0.saturating_add(1));
    }
    block
}

fn funded_test_ledger(account: Address) -> (Ledger, Amount) {
    let amount = block_reward(Height(1));
    let mut accounts = BTreeMap::new();
    accounts.insert(account, xparq::state::Account::new(account, amount));
    let mut ledger = Ledger::from_accounts_and_chain(accounts, Default::default()).unwrap();
    let genesis = Block::genesis(address(9), 1_700_000_000, vec![]).unwrap();
    let mut funding = Block::new(
        Height(1),
        genesis.hash().unwrap(),
        account,
        1_700_000_001,
        Nonce(0),
        vec![],
    );
    funding.set_state_root(ledger.state_root());
    ledger.chain.insert_block(genesis).unwrap();
    ledger.chain.insert_block(funding).unwrap();
    (ledger, amount)
}

#[test]
fn mines_coinbase_only_candidate_without_user_transactions() {
    let consensus = Consensus::new(ConsensusConfig::new(xparq::consensus::MIN_DIFFICULTY)).unwrap();
    let mut ledger = Ledger::new();
    let miner = address(9);
    ledger.create_account(miner, Amount(0)).unwrap();
    let genesis = mine_test_block(
        Block::new(
            Height(0),
            Hash([0; HASH_SIZE]),
            miner,
            1_700_000_000,
            Nonce(0),
            vec![],
        ),
        &consensus,
    );
    let now = genesis.timestamp();
    ledger.apply_block_at(genesis, now).unwrap();
    let mempool = Mempool::new();

    let result = mine_candidate_block(
        &mempool,
        &ledger,
        &consensus,
        miner,
        1_700_000_001,
        MiningConfig {
            difficulty: MIN_DIFFICULTY,
            start_nonce: 42,
            max_attempts: 50_000,
            transaction_limit: 10,
            min_fee_rate: 0,
        },
    )
    .unwrap()
    .expect("coinbase-only block should be mineable");

    assert_eq!(result.block.transaction_count(), 0);
    assert!(result.block.header.nonce.0 >= 42);
    assert!(result.block.coinbase.is_some());
    assert_eq!(consensus.validate_proof_of_work(&result.block), Ok(()));
}

#[test]
fn mines_candidate_block_until_pow_is_valid() {
    let consensus = Consensus::new(ConsensusConfig::new(xparq::consensus::MIN_DIFFICULTY)).unwrap();
    let keypair = generate_keypair();
    let sender = dual_address_from_public_keys(&keypair.public_key, &keypair.public_key);
    let receiver = address(2);
    let miner = address(9);
    let (ledger, _) = funded_test_ledger(sender);

    let transaction = {
        let template = Transaction::new(
            sender,
            receiver,
            Amount(10),
            0,
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
            sender,
            receiver,
            Amount(10),
            0,
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
    };
    let mut mempool = Mempool::new();
    mempool
        .insert_validated(&ledger, transaction.into())
        .unwrap();

    let result = mine_candidate_block(
        &mempool,
        &ledger,
        &consensus,
        miner,
        1_700_000_002,
        MiningConfig {
            difficulty: MIN_DIFFICULTY,
            start_nonce: 0,
            max_attempts: 50_000,
            transaction_limit: 10,
            min_fee_rate: 0,
        },
    )
    .unwrap()
    .expect("minimum difficulty should produce a test block");

    assert!(result.attempts >= 1);
    assert_eq!(result.block.difficulty(), MIN_DIFFICULTY);
    assert_eq!(result.block.transaction_count(), 1);
    assert_eq!(consensus.validate_proof_of_work(&result.block), Ok(()));
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
