use super::{Storage, StorageError};
use crate::runtime::params::{DEFAULT_TRANSACTION_FEE, STORAGE_VERSION};
use crate::runtime::recovery::{RollbackIssue, RollbackProofContext, RollbackRecoveryStatus};
use crate::test_support::BlockTestExt;
use xparq::block::merkle::MerkleInclusionProof;
use xparq::block::{Block, Height, Nonce};
use xparq::consensus::supply::Amount;
use xparq::crypto::{
    Address, BlockHash, HASH_SIZE, Hash, dual_address_from_public_keys, generate_keypair, sign,
};
use xparq::event::{ProtocolEvent, ProtocolEventKind};
use xparq::ledger::Ledger;
use xparq::state::{Account, Vault, VaultMetadata, VaultPolicy};
use xparq::transaction::{SignedProtocolTransaction, SignedTransaction, Transaction};
use std::collections::BTreeMap;

fn address(byte: u8) -> Address {
    Address([byte; 20])
}

fn block(height: u64, previous_hash: Hash) -> Block {
    Block::new(
        Height(height),
        previous_hash,
        address(9),
        1_700_000_000 + height,
        Nonce(0),
        vec![],
    )
}

fn funded_ledger(accounts: BTreeMap<Address, Account>) -> Ledger {
    let expected = xparq::consensus::block_reward(Height(1));
    let total = accounts
        .values()
        .fold(0_u64, |sum, account| sum.saturating_add(account.balance.0));
    assert_eq!(total, expected.0);

    let mut ledger = Ledger::from_accounts_and_chain(accounts, Default::default()).unwrap();
    let genesis = block(0, Hash([0; HASH_SIZE]));
    let mut funding = block(1, genesis.hash().unwrap().into());
    funding.set_state_root(ledger.protocol_state_root().unwrap());
    ledger.chain.insert_block(genesis).unwrap();
    ledger.chain.insert_block(funding).unwrap();
    ledger
}

fn signed_transaction(to: Address, amount: u64, nonce: u64) -> SignedTransaction {
    let keypair = generate_keypair();
    let auth_keypair = generate_keypair();
    let from = dual_address_from_public_keys(&keypair.public_key, &auth_keypair.public_key);
    let payload = Transaction::new(
        from,
        to,
        Amount(amount),
        nonce,
    );
    let signature = sign(&keypair.secret_key, &payload.signing_bytes().unwrap());
    let auth_signature = sign(&auth_keypair.secret_key, &payload.signing_bytes().unwrap());
    SignedTransaction::new_authorized(
        payload,
        keypair.public_key,
        signature,
        auth_keypair.public_key,
        auth_signature,
    )
}

#[test]
fn stores_and_loads_blocks_by_height_and_hash() {
    let storage = Storage::temporary().unwrap();
    let block = block(0, Hash([0; HASH_SIZE]));
    let hash = block.hash().unwrap();

    storage.save_block(&block).unwrap();

    assert_eq!(
        storage.load_block_by_height(Height(0)).unwrap(),
        Some(block.clone())
    );
    assert_eq!(storage.load_block_by_hash(&hash).unwrap(), Some(block));
    assert_eq!(
        storage
            .test_blocks_by_height_value_len(Height(0))
            .unwrap(),
        Some(HASH_SIZE)
    );
}

#[test]
fn side_blocks_do_not_overwrite_canonical_height_index() {
    let storage = Storage::temporary().unwrap();
    let genesis = block(0, Hash([0; HASH_SIZE]));
    let canonical = block(1, genesis.hash().unwrap().into());
    let side = Block::with_difficulty(
        Height(1),
        genesis.hash(),
        address(8),
        1,
        1_700_000_101,
        Nonce(7),
        vec![],
    );
    let side_hash = side.hash().unwrap();

    storage.save_block(&genesis).unwrap();
    storage.save_block(&canonical).unwrap();
    storage.save_side_block(&side).unwrap();

    assert_eq!(
        storage.load_block_by_height(Height(1)).unwrap(),
        Some(canonical)
    );
    assert_eq!(storage.load_block_by_hash(&side_hash).unwrap(), Some(side));
}

#[test]
fn persists_rollback_issue_with_original_signed_transaction() {
    let storage = Storage::temporary().unwrap();
    let transaction = SignedProtocolTransaction::from(signed_transaction(address(2), 10, 0));
    let header = block(9, Hash([6; HASH_SIZE])).header;
    let block_hash = header.hash().unwrap();
    let empty_proof = MerkleInclusionProof {
        leaf_index: 0,
        leaf_count: 1,
        siblings: Vec::new(),
    };
    let context =
        RollbackProofContext::new(vec![header.clone()], vec![header], block_hash).unwrap();
    storage.save_rollback_proof_context(&context).unwrap();
    let issue = RollbackIssue::new(
        Height(9),
        block_hash,
        0,
        transaction.clone(),
        context.id,
        empty_proof.clone(),
        empty_proof,
        1_700_000_009,
    )
    .unwrap();

    storage.save_rollback_issue(&issue).unwrap();
    let loaded = storage.load_rollback_issue(&issue.id).unwrap().unwrap();

    assert_eq!(loaded, issue);
    assert_eq!(loaded.transaction, transaction);
    assert_eq!(loaded.status, RollbackRecoveryStatus::Detected);
    assert_eq!(storage.load_rollback_issues().unwrap(), vec![loaded]);
    assert_eq!(
        storage.load_rollback_proof_context(&context.id).unwrap(),
        Some(context)
    );
}

#[test]
fn indexes_transactions_by_hash_and_address() {
    let storage = Storage::temporary().unwrap();
    let transaction = signed_transaction(address(2), 10, 0);
    let tx_hash = transaction.hash().unwrap();
    let wtxid = transaction.wtxid().unwrap();
    let sender = transaction.transaction.from;
    let receiver = transaction.transaction.to.address().unwrap();
    let block = Block::with_difficulty(
        Height(1),
        Hash([0; HASH_SIZE]),
        address(9),
        1,
        1_700_000_001,
        Nonce(0),
        vec![transaction.clone()],
    );
    let block_hash = block.hash().unwrap();

    storage.save_block(&block).unwrap();

    let (location, loaded) = storage.load_transaction(&tx_hash).unwrap().unwrap();
    assert_eq!(location.block_height, Height(1));
    assert_eq!(location.block_hash, block_hash);
    assert_eq!(location.tx_index, 0);
    assert_eq!(loaded, transaction);
    let (witness_location, witness_transaction) = storage
        .load_protocol_transaction_by_wtxid(&wtxid)
        .unwrap()
        .unwrap();
    assert_eq!(witness_location, location);
    assert_eq!(witness_transaction.wtxid().unwrap(), wtxid);

    let sent = storage.load_address_transaction_locations(&sender).unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].tx_hash, tx_hash);
    assert!(sent[0].sent);

    let received = storage
        .load_address_transaction_locations(&receiver)
        .unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].tx_hash, tx_hash);
    assert!(!received[0].sent);
}

#[test]
fn persists_and_indexes_protocol_events() {
    let storage = Storage::temporary().unwrap();
    let transaction = signed_transaction(address(2), 10, 0);
    let sender = transaction.transaction.from;
    let receiver = transaction.transaction.to.address().unwrap();
    let transaction_hash = transaction.hash().unwrap();
    let funding = xparq::consensus::block_reward(Height(1));
    let mut accounts = BTreeMap::new();
    accounts.insert(sender, Account::new(sender, funding));
    let mut ledger = funded_ledger(accounts);
    let block_hash = ledger.tip_hash().unwrap();
    let event = ProtocolEvent::new(
        Height(1),
        block_hash,
        Some(transaction_hash),
        0,
        ProtocolEventKind::Transfer {
            from: sender,
            to: receiver,
            amount: Amount(10),
        },
    );
    let event_id = event.id().unwrap();
    ledger
        .events_by_block
        .insert(block_hash, vec![event.clone()]);

    storage.save_ledger(&ledger).unwrap();

    assert_eq!(
        storage.load_protocol_event(&event_id).unwrap(),
        Some(event.clone())
    );
    assert_eq!(
        storage.load_block_events(&block_hash).unwrap(),
        vec![event.clone()]
    );
    assert_eq!(
        storage.load_transaction_events(&transaction_hash).unwrap(),
        vec![event.clone()]
    );
    assert_eq!(
        storage.load_address_events(&sender).unwrap(),
        vec![event.clone()]
    );
    assert_eq!(
        storage.load_address_events(&receiver).unwrap(),
        vec![event.clone()]
    );
    assert_eq!(
        storage.load_ledger().unwrap().events_for_block(&block_hash),
        &[event]
    );
}

#[test]
fn indexes_canonical_blocks_by_miner_address() {
    let storage = Storage::temporary().unwrap();
    let miner = address(7);
    let side_miner = address(8);
    let genesis = block(0, Hash([0; HASH_SIZE]));
    let canonical = Block::with_coinbase(
        Height(1),
        genesis.hash(),
        miner,
        1,
        1_700_000_001,
        Nonce(0),
        Some(xparq::block::CoinbaseTransaction::new(miner, Amount(0))),
        vec![],
    );
    let side = Block::with_coinbase(
        Height(1),
        genesis.hash(),
        side_miner,
        1,
        1_700_000_002,
        Nonce(1),
        Some(xparq::block::CoinbaseTransaction::new(
            side_miner,
            Amount(0),
        )),
        vec![],
    );

    storage.save_block(&genesis).unwrap();
    storage.save_block(&canonical).unwrap();
    storage.save_side_block(&side).unwrap();

    let mined = storage.load_miner_block_locations(&miner).unwrap();
    assert_eq!(mined.len(), 1);
    assert_eq!(mined[0].block_height, Height(1));
    assert_eq!(mined[0].block_hash, canonical.hash().unwrap());
    assert!(
        storage
            .load_miner_block_locations(&side_miner)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn save_ledger_rebuilds_canonical_transaction_indexes() {
    let storage = Storage::temporary().unwrap();
    let genesis = block(0, Hash([0; HASH_SIZE]));
    let old_transaction = signed_transaction(address(2), 10, 0);
    let old_hash = old_transaction.hash().unwrap();
    let old_block = Block::with_difficulty(
        Height(1),
        genesis.hash(),
        address(9),
        1,
        1_700_000_001,
        Nonce(1),
        vec![old_transaction],
    );
    let new_transaction = signed_transaction(address(3), 11, 0);
    let new_hash = new_transaction.hash().unwrap();
    let new_block = Block::with_difficulty(
        Height(1),
        genesis.hash(),
        address(8),
        1,
        1_700_000_002,
        Nonce(2),
        vec![new_transaction.clone()],
    );

    let mut old_ledger = Ledger::new();
    old_ledger.chain.insert_block(genesis.clone()).unwrap();
    old_ledger.chain.insert_block(old_block).unwrap();
    storage.save_ledger(&old_ledger).unwrap();
    assert!(storage.load_transaction(&old_hash).unwrap().is_some());

    let mut new_ledger = Ledger::new();
    new_ledger.chain.insert_block(genesis).unwrap();
    new_ledger.chain.insert_block(new_block.clone()).unwrap();
    storage.save_ledger(&new_ledger).unwrap();

    assert!(storage.load_transaction(&old_hash).unwrap().is_none());
    let (location, loaded) = storage.load_transaction(&new_hash).unwrap().unwrap();
    assert_eq!(location.block_height, Height(1));
    assert_eq!(location.block_hash, new_block.hash().unwrap());
    assert_eq!(loaded, new_transaction);
    assert_eq!(
        storage.load_block_by_height(Height(1)).unwrap(),
        Some(new_block)
    );
}

#[test]
fn save_ledger_rebuilds_miner_block_index() {
    let storage = Storage::temporary().unwrap();
    let genesis = block(0, Hash([0; HASH_SIZE]));
    let old_miner = address(4);
    let new_miner = address(5);
    let old_block = Block::with_coinbase(
        Height(1),
        genesis.hash(),
        old_miner,
        1,
        1_700_000_001,
        Nonce(1),
        Some(xparq::block::CoinbaseTransaction::new(old_miner, Amount(0))),
        vec![],
    );
    let new_block = Block::with_coinbase(
        Height(1),
        genesis.hash(),
        new_miner,
        1,
        1_700_000_002,
        Nonce(2),
        Some(xparq::block::CoinbaseTransaction::new(new_miner, Amount(0))),
        vec![],
    );

    let mut old_ledger = Ledger::new();
    old_ledger.chain.insert_block(genesis.clone()).unwrap();
    old_ledger.chain.insert_block(old_block).unwrap();
    storage.save_ledger(&old_ledger).unwrap();
    assert_eq!(
        storage
            .load_miner_block_locations(&old_miner)
            .unwrap()
            .len(),
        1
    );

    let mut new_ledger = Ledger::new();
    new_ledger.chain.insert_block(genesis).unwrap();
    new_ledger.chain.insert_block(new_block.clone()).unwrap();
    storage.save_ledger(&new_ledger).unwrap();

    assert!(
        storage
            .load_miner_block_locations(&old_miner)
            .unwrap()
            .is_empty()
    );
    let mined = storage.load_miner_block_locations(&new_miner).unwrap();
    assert_eq!(mined.len(), 1);
    assert_eq!(mined[0].block_hash, new_block.hash().unwrap());
}

#[test]
fn initializes_storage_version_for_empty_database() {
    let storage = Storage::temporary().unwrap();

    assert_eq!(
        storage.load_storage_version().unwrap(),
        Some(STORAGE_VERSION)
    );
}

#[test]
fn rejects_unsupported_storage_version() {
    let storage = Storage::temporary().unwrap();
    storage
        .test_put_meta(b"storage_version", &STORAGE_VERSION.saturating_add(1))
        .unwrap();

    assert!(matches!(
        storage.load_ledger(),
        Err(StorageError::UnsupportedStorageVersion {
            expected: STORAGE_VERSION,
            found
        }) if found == STORAGE_VERSION.saturating_add(1)
    ));
}

#[test]
fn rejects_existing_database_without_storage_version() {
    let storage = Storage::temporary().unwrap();
    storage.test_remove_meta(b"storage_version").unwrap();
    storage.save_block(&block(0, Hash([0; HASH_SIZE]))).unwrap();

    assert!(matches!(
        storage.load_ledger(),
        Err(StorageError::MissingStorageVersion)
    ));
}

#[test]
fn rejects_block_loaded_from_wrong_height_key() {
    let storage = Storage::temporary().unwrap();
    let block = block(1, Hash([0; HASH_SIZE]));
    let hash = block.hash().unwrap();

    storage.save_side_block(&block).unwrap();
    storage
        .test_put_blocks_by_height(&Height(0).0.to_be_bytes(), &hash)
        .unwrap();

    assert!(matches!(
        storage.load_block_by_height(Height(0)),
        Err(StorageError::Integrity(
            "stored block height does not match height key"
        ))
    ));
}

#[test]
fn rejects_block_loaded_from_wrong_hash_key() {
    let storage = Storage::temporary().unwrap();
    let block = block(0, Hash([0; HASH_SIZE]));
    let wrong_hash = BlockHash([7; HASH_SIZE]);

    storage
        .test_put_blocks_by_hash(wrong_hash.0.as_slice(), &block)
        .unwrap();

    assert!(matches!(
        storage.load_block_by_hash(&wrong_hash),
        Err(StorageError::Integrity(
            "stored block hash does not match hash key"
        ))
    ));
}

#[test]
fn rejects_stored_block_with_tampered_witness() {
    let storage = Storage::temporary().unwrap();
    let mut block = Block::with_difficulty(
        Height(1),
        Hash([0; HASH_SIZE]),
        address(9),
        1,
        1_700_000_001,
        Nonce(0),
        vec![signed_transaction(address(2), 10, 0)],
    );
    block.transactions[0].witness_mut().signature.0[0] ^= 0xff;
    let hash = block.hash().unwrap();

    storage
        .test_put_blocks_by_hash(&hash.0, &block)
        .unwrap();
    storage
        .test_put_blocks_by_height(&Height(1).0.to_be_bytes(), &hash)
        .unwrap();

    assert!(matches!(
        storage.load_block_by_height(Height(1)),
        Err(StorageError::Integrity("stored block failed validation"))
    ));
}

#[test]
fn stores_and_loads_accounts() {
    let storage = Storage::temporary().unwrap();
    let account = Account::trusted_with_nonce(address(1), Amount(25), Nonce(7));

    storage.save_account(&account).unwrap();

    assert_eq!(storage.load_account(&address(1)).unwrap(), Some(account));
    assert_eq!(storage.load_account(&address(2)).unwrap(), None);
}

#[test]
fn stores_and_loads_chain_tip() {
    let storage = Storage::temporary().unwrap();
    let hash = BlockHash([7; HASH_SIZE]);

    assert_eq!(storage.load_tip().unwrap(), None);

    storage.save_tip(Height(3), &hash).unwrap();

    assert_eq!(storage.load_tip().unwrap(), Some((Height(3), hash)));
}

#[test]
fn aborted_write_does_not_corrupt_committed_tip() {
    let storage = Storage::temporary().unwrap();
    let committed = BlockHash([7; HASH_SIZE]);
    storage.save_tip(Height(3), &committed).unwrap();

    storage
        .test_abort_tip_write(Height(99), BlockHash([9; HASH_SIZE]))
        .unwrap();

    assert_eq!(storage.load_tip().unwrap(), Some((Height(3), committed)));
}

#[test]
fn validates_stored_chain_integrity() {
    let storage = Storage::temporary().unwrap();
    let genesis = block(0, Hash([0; HASH_SIZE]));
    let next = block(1, genesis.hash().unwrap().into());

    storage.save_block(&genesis).unwrap();
    storage.save_block(&next).unwrap();
    storage
        .save_tip(next.height(), &next.hash().unwrap())
        .unwrap();

    assert!(storage.validate_chain_integrity().is_ok());
}

#[test]
fn rejects_chain_integrity_when_tip_block_is_missing() {
    let storage = Storage::temporary().unwrap();

    storage
        .save_tip(Height(3), &BlockHash([7; HASH_SIZE]))
        .unwrap();

    assert!(matches!(
        storage.validate_chain_integrity(),
        Err(StorageError::Integrity(
            "stored tip height block is missing"
        ))
    ));
}

#[test]
fn rejects_chain_integrity_when_previous_link_is_broken() {
    let storage = Storage::temporary().unwrap();
    let genesis = block(0, Hash([0; HASH_SIZE]));
    let next = block(1, Hash([9; HASH_SIZE]));

    storage.save_block(&genesis).unwrap();
    storage.save_block(&next).unwrap();
    storage
        .save_tip(next.height(), &next.hash().unwrap())
        .unwrap();

    assert!(matches!(
        storage.validate_chain_integrity(),
        Err(StorageError::Integrity(
            "stored chain block previous hash is broken"
        ))
    ));
}

#[test]
fn stores_complete_archive_ledger() {
    let storage = Storage::temporary().unwrap();
    let mut ledger = Ledger::new();
    let mut genesis = block(0, Hash([0; HASH_SIZE]));

    ledger.create_account(address(1), Amount(100)).unwrap();
    genesis.set_state_root(ledger.state_root());
    let hash = genesis.hash().unwrap();
    ledger.chain.insert_block(genesis.clone()).unwrap();

    storage.save_ledger(&ledger).unwrap();

    assert_eq!(
        storage.load_account(&address(1)).unwrap().unwrap().balance,
        Amount(100)
    );
    assert_eq!(
        storage.load_block_by_height(Height(0)).unwrap(),
        Some(genesis)
    );
    assert_eq!(storage.load_tip().unwrap(), Some((Height(0), hash)));
}

#[test]
fn loads_complete_archive_ledger() {
    let storage = Storage::temporary().unwrap();
    let funding = xparq::consensus::block_reward(Height(1));
    let mut accounts = BTreeMap::new();
    accounts.insert(address(1), Account::new(address(1), funding));
    let ledger = funded_ledger(accounts);
    let hash = ledger.tip_hash().unwrap();
    storage.save_ledger(&ledger).unwrap();

    let restored = storage.load_ledger().unwrap();

    assert_eq!(restored.balance(&address(1)), Some(funding));
    assert_eq!(restored.tip_height(), Some(Height(1)));
    assert_eq!(restored.tip_hash(), Some(hash));
}

#[test]
fn stores_and_restores_vault_consensus_state() {
    let storage = Storage::temporary().unwrap();
    let mut ledger = Ledger::new();
    let creator = address(1);
    ledger.create_account(creator, Amount(100)).unwrap();
    let funding = Amount(40);
    let vault = Vault::new(
        creator,
        0,
        VaultMetadata {
            name: "stored vault".to_string(),
            description: String::new(),
        },
        VaultPolicy::new(vec![creator], None).unwrap(),
        funding,
    )
    .unwrap();
    let vault_id = ledger.create_vault_from_account(vault, Height(0)).unwrap();

    storage.save_ledger(&ledger).unwrap();
    let restored = storage.load_ledger().unwrap();

    assert_eq!(restored.vaults, ledger.vaults);
    assert_eq!(restored.vaults.vault(&vault_id).unwrap().remaining, funding);
    assert_eq!(
        restored.economic_supply().unwrap(),
        ledger.economic_supply().unwrap()
    );
}

#[test]
fn load_ledger_rejects_tampered_supply() {
    let storage = Storage::temporary().unwrap();
    let funding = xparq::consensus::block_reward(Height(1));
    let mut accounts = BTreeMap::new();
    accounts.insert(address(1), Account::new(address(1), funding));
    let ledger = funded_ledger(accounts);
    storage.save_ledger(&ledger).unwrap();

    storage
        .test_put_account(&Account::new(address(1), Amount(0)))
        .unwrap();

    assert!(matches!(
        storage.load_ledger(),
        Err(StorageError::Integrity("stored ledger supply is invalid"))
    ));
}

#[test]
fn load_ledger_rejects_tampered_state_with_preserved_supply() {
    let storage = Storage::temporary().unwrap();
    let funding = xparq::consensus::block_reward(Height(1));
    let first = funding.0 / 2;
    let second = funding.0.saturating_sub(first);
    let mut accounts = BTreeMap::new();
    accounts.insert(address(1), Account::new(address(1), Amount(first)));
    accounts.insert(address(2), Account::new(address(2), Amount(second)));
    let ledger = funded_ledger(accounts);
    storage.save_ledger(&ledger).unwrap();

    storage
        .test_put_account(&Account::new(address(1), Amount(first.saturating_add(1))))
        .unwrap();
    storage
        .test_put_account(&Account::new(address(2), Amount(second.saturating_sub(1))))
        .unwrap();

    assert!(matches!(
        storage.load_ledger(),
        Err(StorageError::Integrity(
            "stored ledger state root does not match canonical tip"
        ))
    ));
}

#[test]
fn stores_and_loads_genesis_accounts() {
    let storage = Storage::temporary().unwrap();
    let mut accounts = std::collections::BTreeMap::new();
    accounts.insert(address(1), Account::new(address(1), Amount(100)));

    storage.save_genesis_accounts(&accounts).unwrap();

    assert_eq!(storage.load_genesis_accounts().unwrap(), Some(accounts));
}

#[test]
fn difficulty_window_uses_previous_block_for_single_block_interval() {
    let storage = Storage::temporary().unwrap();
    let genesis = block(0, Hash([0; HASH_SIZE]));
    let next = block(1, genesis.hash().unwrap().into());

    storage.save_block(&genesis).unwrap();
    storage.save_block(&next).unwrap();

    assert_eq!(storage.difficulty_window(Height(0), 1).unwrap(), None);
    assert_eq!(
        storage.difficulty_window(Height(1), 1).unwrap(),
        Some((genesis.timestamp(), next.timestamp(), 1, next.difficulty()))
    );
}

#[test]
fn difficulty_window_uses_configured_block_interval() {
    let storage = Storage::temporary().unwrap();
    let mut previous_hash = Hash([0; HASH_SIZE]);

    for height in 0..=10 {
        let block = block(height, previous_hash);
        previous_hash = block.hash().unwrap().into();
        storage.save_block(&block).unwrap();
    }

    assert_eq!(storage.difficulty_window(Height(9), 10).unwrap(), None);
    assert_eq!(
        storage.difficulty_window(Height(10), 10).unwrap(),
        Some((
            block(0, Hash([0; HASH_SIZE])).timestamp(),
            block(10, Hash([0; HASH_SIZE])).timestamp(),
            10,
            block(10, Hash([0; HASH_SIZE])).difficulty()
        ))
    );
}
