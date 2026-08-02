
use super::*;
use crate::block::{Block, Height, Nonce};
use crate::consensus::supply::XPQ;
use crate::consensus::{Consensus, DIFFICULTY_START};
use crate::crypto::{Hash, dual_address_from_public_keys, generate_keypair, sign};
use crate::genesis::genesis_block;
use crate::qcash::{
    QCashDenomination, QCashWithdrawalMetadata, qcash_redeem_key_commitment_from_secret,
};
use crate::transaction::{QCashTransaction, SignedQCashTransaction, Transaction, TransferOutput};

fn single_output_transaction(from: Address, to: Address, amount: Amount) -> Transaction {
    Transaction::new(
        from,
        vec![TransferOutput {
            to: to.into(),
            amount,
        }],
    )
}

fn authorized_transfer(
    spend: &crate::crypto::KeyPair,
    auth: &crate::crypto::KeyPair,
    to: Address,
    last_state: crate::crypto::Hash,
) -> SignedTransaction {
    let from = dual_address_from_public_keys(&spend.public_key, &auth.public_key);
    let transaction =
        single_output_transaction(from, to, Amount(25)).with_last_state(last_state);
    let payload = transaction.signing_bytes().unwrap();
    SignedTransaction::new_authorized(
        transaction,
        spend.public_key,
        sign(&spend.secret_key, &payload),
        auth.public_key,
        sign(&auth.secret_key, &payload),
    )
}

fn authorized_transfer_amount(
    spend: &crate::crypto::KeyPair,
    auth: &crate::crypto::KeyPair,
    to: Address,
    amount: Amount,
    last_state: crate::crypto::Hash,
) -> SignedTransaction {
    let from = dual_address_from_public_keys(&spend.public_key, &auth.public_key);
    let transaction = single_output_transaction(from, to, amount).with_last_state(last_state);
    let payload = transaction.signing_bytes().unwrap();
    SignedTransaction::new_authorized(
        transaction,
        spend.public_key,
        sign(&spend.secret_key, &payload),
        auth.public_key,
        sign(&auth.secret_key, &payload),
    )
}

fn mine_for_test(mut block: Block) -> Block {
    for nonce in 0..100_000_u64 {
        block.proof.nonce = Nonce(nonce);
        if Consensus::validate_proof_of_work_at_difficulty(&block, block.difficulty()).is_ok() {
            return block;
        }
    }
    panic!("test block nonce not found");
}

#[test]
fn spam_transfers_between_two_accounts_and_shared_recipient() {
    let addr1_owner = generate_keypair();
    let addr1_auth = generate_keypair();
    let addr2_owner = generate_keypair();
    let addr2_auth = generate_keypair();
    let addr1 = dual_address_from_public_keys(&addr1_owner.public_key, &addr1_auth.public_key);
    let addr2 = dual_address_from_public_keys(&addr2_owner.public_key, &addr2_auth.public_key);
    let addr3 = Address([3; 20]);
    let mut ledger = Ledger::new();
    ledger
        .create_account_with_authorization(addr1, addr1_auth.public_key, Amount(100))
        .unwrap();
    ledger
        .create_account_with_authorization(addr2, addr2_auth.public_key, Amount(100))
        .unwrap();

    let addr1_to_addr2 = authorized_transfer_amount(
        &addr1_owner,
        &addr1_auth,
        addr2,
        Amount(10),
        ledger.account(&addr1).unwrap().statement,
    );
    ledger
        .apply_signed_transaction_at(&addr1_to_addr2, Height(1))
        .unwrap();

    let addr2_to_addr1 = authorized_transfer_amount(
        &addr2_owner,
        &addr2_auth,
        addr1,
        Amount(20),
        ledger.account(&addr2).unwrap().statement,
    );
    ledger
        .apply_signed_transaction_at(&addr2_to_addr1, Height(2))
        .unwrap();

    let addr1_to_addr3 = authorized_transfer_amount(
        &addr1_owner,
        &addr1_auth,
        addr3,
        Amount(30),
        ledger.account(&addr1).unwrap().statement,
    );
    ledger
        .apply_signed_transaction_at(&addr1_to_addr3, Height(3))
        .unwrap();

    let addr2_to_addr3 = authorized_transfer_amount(
        &addr2_owner,
        &addr2_auth,
        addr3,
        Amount(40),
        ledger.account(&addr2).unwrap().statement,
    );
    ledger
        .apply_signed_transaction_at(&addr2_to_addr3, Height(4))
        .unwrap();

    let account1 = ledger.account(&addr1).unwrap();
    let account2 = ledger.account(&addr2).unwrap();
    let account3 = ledger.account(&addr3).unwrap();
    assert_eq!(account1.balance, Amount(80));
    assert_eq!(account2.balance, Amount(50));
    assert_eq!(account3.balance, Amount(70));
    assert_eq!(account1.available_balance_at(Height(4)), Amount(80));
    assert_eq!(account2.available_balance_at(Height(4)), Amount(50));
    assert_eq!(account3.available_balance_at(Height(4)), Amount(0));
    assert_eq!(account3.available_balance_at(Height(6)), Amount(70));
}

#[test]
fn qcash_withdraw_moves_value_out_of_account_into_bearer_utxo() {
    let spend = generate_keypair();
    let auth = generate_keypair();
    let signer = dual_address_from_public_keys(&spend.public_key, &auth.public_key);
    let initial_balance = Amount(2 * XPQ);
    let amount = QCashDenomination::One.amount();
        let redeem_secret = [0x44; 32];
    let metadata = QCashWithdrawalMetadata::with_denominations(
        amount,
        &[QCashDenomination::One],
        &[qcash_redeem_key_commitment_from_secret(&redeem_secret)],
    )
    .unwrap();
    let mut ledger = Ledger::new();
    ledger
        .create_account_with_authorization(signer, auth.public_key, initial_balance)
        .unwrap();
    let transaction = QCashTransaction::withdraw(signer, amount, metadata)
        .with_last_state(ledger.account(&signer).unwrap().statement);
    let payload = transaction.signing_bytes().unwrap();
    let signed = SignedQCashTransaction::new_authorized(
        transaction,
        spend.public_key,
        sign(&spend.secret_key, &payload),
        auth.public_key,
        sign(&auth.secret_key, &payload),
    );
    ledger
        .apply_signed_qcash_transaction(&signed, Height(1))
        .unwrap();

    let account = ledger.account(&signer).unwrap();
    assert_eq!(
        account.balance,
        Amount(initial_balance.0 - amount.0)
    );
    assert_eq!(ledger.qcash_utxos.total_value().unwrap(), amount);
    assert_eq!(
        ledger.economic_supply().unwrap(),
        initial_balance
    );
}

#[test]
fn account_rollbacks_include_before_and_after_snapshots() {
    let alice = Address([1; 20]);
    let bob = Address([2; 20]);
    let mut before = BTreeMap::new();
    before.insert(
        alice,
        Account::trusted(alice, Amount(500)),
    );
    before.insert(bob, Account::trusted(bob, Amount(100)));

    let mut after = BTreeMap::new();
    after.insert(
        alice,
        Account::trusted(alice, Amount(800)),
    );
    after.insert(bob, Account::trusted(bob, Amount(100)));

    let rollbacks = account_rollbacks(&before, &after);

    assert_eq!(rollbacks.len(), 1);
    assert_eq!(rollbacks[0].address, alice);
    assert_eq!(
        rollbacks[0].before,
        Some(AccountSnapshot {
            balance: Amount(500),
            statement: before.get(&alice).unwrap().statement,
        })
    );
    assert_eq!(
        rollbacks[0].after,
        Some(AccountSnapshot {
            balance: Amount(800),
            statement: after.get(&alice).unwrap().statement,
        })
    );
}

#[test]
fn signed_transfer_requires_account_authorization_signature() {
    let spend = generate_keypair();
    let auth = generate_keypair();
    let recipient = Address([7; 20]);
    let sender = dual_address_from_public_keys(&spend.public_key, &auth.public_key);
    let mut ledger = Ledger::new();
    ledger
        .insert_account(Account::new_with_authorization(
            sender,
            auth.public_key,
            Amount(100),
        ))
        .unwrap();

    ledger
        .apply_signed_transaction(&authorized_transfer(
            &spend,
            &auth,
            recipient,
            ledger.account(&sender).unwrap().statement,
        ))
        .unwrap();

    assert_eq!(ledger.balance(&sender), Some(Amount(75)));
    assert_eq!(ledger.balance(&recipient), Some(Amount(25)));
}

#[test]
fn first_spend_uses_stateless_dual_authorization() {
    let spend = generate_keypair();
    let auth = generate_keypair();
    let recipient = Address([6; 20]);
    let sender = dual_address_from_public_keys(&spend.public_key, &auth.public_key);
    let mut ledger = Ledger::new();
    ledger.create_account(sender, Amount(100)).unwrap();

    let first = single_output_transaction(sender, recipient, Amount(25))
        .with_last_state(ledger.account(&sender).unwrap().statement);
    let first_payload = first.signing_bytes().unwrap();
    let signed_first = SignedTransaction::new_authorized(
        first,
        spend.public_key,
        sign(&spend.secret_key, &first_payload),
        auth.public_key,
        sign(&auth.secret_key, &first_payload),
    );
    ledger.apply_signed_transaction(&signed_first).unwrap();

    let second = single_output_transaction(sender, Address([7; 20]), Amount(1))
        .with_last_state(ledger.account(&sender).unwrap().statement);
    let second_payload = second.signing_bytes().unwrap();
    let unsigned_auth_second = SignedTransaction::new(
        second.clone(),
        spend.public_key,
        sign(&spend.secret_key, &second_payload),
    );
    assert!(
        ledger
            .apply_signed_transaction(&unsigned_auth_second)
            .is_err()
    );

    let signed_second = SignedTransaction::new_authorized(
        second,
        spend.public_key,
        sign(&spend.secret_key, &second_payload),
        auth.public_key,
        sign(&auth.secret_key, &second_payload),
    );
    ledger
        .apply_signed_transaction_at(&signed_second, Height(2))
        .unwrap();
}

#[test]
fn stale_account_statement_is_rejected() {
    let spend = generate_keypair();
    let auth = generate_keypair();
    let recipient = Address([0x11; 20]);
    let sender = dual_address_from_public_keys(&spend.public_key, &auth.public_key);
    let mut ledger = Ledger::new();
    ledger.create_account(sender, Amount(100)).unwrap();
    let original_statement = ledger.account(&sender).unwrap().statement;

    let first = single_output_transaction(sender, recipient, Amount(10))
        .with_last_state(original_statement);
    let first_payload = first.signing_bytes().unwrap();
    let signed_first = SignedTransaction::new_authorized(
        first,
        spend.public_key,
        sign(&spend.secret_key, &first_payload),
        auth.public_key,
        sign(&auth.secret_key, &first_payload),
    );
    ledger.apply_signed_transaction(&signed_first).unwrap();

    let stale = single_output_transaction(sender, Address([0x12; 20]), Amount(1))
        .with_last_state(original_statement);
    let stale_payload = stale.signing_bytes().unwrap();
    let signed_stale = SignedTransaction::new_authorized(
        stale,
        spend.public_key,
        sign(&spend.secret_key, &stale_payload),
        auth.public_key,
        sign(&auth.secret_key, &stale_payload),
    );

    assert_eq!(
        ledger.apply_signed_transaction(&signed_stale),
        Err(LedgerError::InvalidState(
            StateError::InvalidAccountStatement
        ))
    );
}

#[test]
fn new_account_statement_activates_in_next_block() {
    let spend = generate_keypair();
    let auth = generate_keypair();
    let sender = dual_address_from_public_keys(&spend.public_key, &auth.public_key);
    let mut ledger = Ledger::new();
    ledger.create_account(sender, Amount(100)).unwrap();

    let first = authorized_transfer(
        &spend,
        &auth,
        Address([0x21; 20]),
        ledger.account(&sender).unwrap().statement,
    );
    ledger
        .apply_signed_transaction_at(&first, Height(1))
        .unwrap();

    let second = authorized_transfer(
        &spend,
        &auth,
        Address([0x22; 20]),
        ledger.account(&sender).unwrap().statement,
    );
    assert_eq!(
        ledger.clone().apply_signed_transaction_at(&second, Height(1)),
        Err(LedgerError::InvalidState(
            StateError::InvalidAccountStatement
        ))
    );
    ledger
        .apply_signed_transaction_at(&second, Height(2))
        .unwrap();
}

#[test]
fn incoming_transfer_does_not_advance_recipient_statement() {
    let alice_spend = generate_keypair();
    let alice_auth = generate_keypair();
    let bob_spend = generate_keypair();
    let bob_auth = generate_keypair();
    let john = Address([0x13; 20]);
    let alice = dual_address_from_public_keys(&alice_spend.public_key, &alice_auth.public_key);
    let bob = dual_address_from_public_keys(&bob_spend.public_key, &bob_auth.public_key);
    let mut ledger = Ledger::new();
    ledger.create_account(alice, Amount(100)).unwrap();
    ledger.create_account(bob, Amount(100)).unwrap();

    let bob_original_statement = ledger.account(&bob).unwrap().statement;
    let bob_to_john = authorized_transfer(&bob_spend, &bob_auth, john, bob_original_statement);
    let alice_to_bob = authorized_transfer(&alice_spend, &alice_auth, bob, ledger.account(&alice).unwrap().statement);

    ledger.apply_signed_transaction(&alice_to_bob).unwrap();
    assert_eq!(ledger.balance(&bob), Some(Amount(125)));
    assert_eq!(ledger.account(&bob).unwrap().statement, bob_original_statement);

    ledger.apply_signed_transaction(&bob_to_john).unwrap();
    assert_eq!(ledger.balance(&bob), Some(Amount(100)));
    assert_ne!(ledger.account(&bob).unwrap().statement, bob_original_statement);
}

#[test]
fn next_outgoing_statement_embeds_latest_balance_after_incoming() {
    let alice_spend = generate_keypair();
    let alice_auth = generate_keypair();
    let bob_spend = generate_keypair();
    let bob_auth = generate_keypair();
    let john = Address([0x14; 20]);
    let alice = dual_address_from_public_keys(&alice_spend.public_key, &alice_auth.public_key);
    let bob = dual_address_from_public_keys(&bob_spend.public_key, &bob_auth.public_key);
    let mut ledger = Ledger::new();
    ledger.create_account(alice, Amount(100)).unwrap();
    ledger.create_account(bob, Amount(100)).unwrap();

    let bob_original_statement = ledger.account(&bob).unwrap().statement;
    let alice_to_bob =
        authorized_transfer(&alice_spend, &alice_auth, bob, ledger.account(&alice).unwrap().statement);
    ledger.apply_signed_transaction(&alice_to_bob).unwrap();
    assert_eq!(ledger.account(&bob).unwrap().statement, bob_original_statement);

    let bob_to_john = authorized_transfer(&bob_spend, &bob_auth, john, bob_original_statement);
    let authorized_tx_hash = bob_to_john.transaction.hash().unwrap().as_hash();
    let authorization_proof_hash = bob_to_john
        .authorization_proof
        .hash_with_transaction(authorized_tx_hash)
        .unwrap();
    let mut expected_bob = ledger.account(&bob).unwrap().clone();
    expected_bob
        .register_authorization(bob_spend.public_key, bob_auth.public_key)
        .unwrap();
    expected_bob.debit_at(Amount(25), Height(0)).unwrap();
    let expected_statement = expected_bob
        .calculate_statement(
            bob_original_statement,
            authorized_tx_hash,
            authorization_proof_hash,
        )
        .unwrap();

    ledger.apply_signed_transaction(&bob_to_john).unwrap();
    assert_eq!(ledger.account(&bob).unwrap().balance, Amount(100));
    assert_eq!(ledger.account(&bob).unwrap().statement, expected_statement);
}

#[test]
fn registered_account_accepts_signature_only_authorization_proof_and_saves_both_keys() {
    let owner = generate_keypair();
    let auth = generate_keypair();
    let sender = dual_address_from_public_keys(&owner.public_key, &auth.public_key);
    let recipient = Address([0x44; 20]);
    let mut ledger = Ledger::new();
    ledger.create_account(sender, Amount(100)).unwrap();

    let first = single_output_transaction(sender, recipient, Amount(1))
        .with_last_state(ledger.account(&sender).unwrap().statement);
    let first_payload = first.signing_bytes().unwrap();
    let registration = SignedTransaction::new_authorized(
        first,
        owner.public_key,
        sign(&owner.secret_key, &first_payload),
        auth.public_key,
        sign(&auth.secret_key, &first_payload),
    );
    ledger.apply_signed_transaction(&registration).unwrap();
    assert!(ledger.account(&sender).unwrap().authorization.is_some());

    let second = single_output_transaction(sender, recipient, Amount(1))
        .with_last_state(ledger.account(&sender).unwrap().statement);
    let second_payload = second.signing_bytes().unwrap();
    let compact = SignedTransaction::new_stored_authorized(
        second.clone(),
        sign(&owner.secret_key, &second_payload),
        sign(&auth.secret_key, &second_payload),
    );
    let repeated = SignedTransaction::new_authorized(
        second,
        owner.public_key,
        sign(&owner.secret_key, &second_payload),
        auth.public_key,
        sign(&auth.secret_key, &second_payload),
    );
    assert_eq!(
        repeated.to_bytes().unwrap().len() - compact.to_bytes().unwrap().len(),
        2 * crate::crypto::PUBLIC_KEY_SIZE
    );
    ledger
        .apply_signed_transaction_at(&compact, Height(2))
        .unwrap();
    assert_ne!(ledger.account(&sender).unwrap().statement, Hash::ZERO);
}

#[test]
fn signed_transfer_rejects_signature_from_wrong_authorization_key() {
    let spend = generate_keypair();
    let account_auth = generate_keypair();
    let wrong_auth = generate_keypair();
    let sender = dual_address_from_public_keys(&spend.public_key, &account_auth.public_key);
    let mut ledger = Ledger::new();
    ledger
        .insert_account(Account::new_with_authorization(
            sender,
            account_auth.public_key,
            Amount(100),
        ))
        .unwrap();

    let transaction = single_output_transaction(sender, Address([8; 20]), Amount(25))
        .with_last_state(ledger.account(&sender).unwrap().statement);
    let payload = transaction.signing_bytes().unwrap();
    let signed = SignedTransaction::new_authorized(
        transaction,
        spend.public_key,
        sign(&spend.secret_key, &payload),
        wrong_auth.public_key,
        sign(&wrong_auth.secret_key, &payload),
    );
    let error = ledger.apply_signed_transaction(&signed).unwrap_err();

    assert_eq!(error, LedgerError::InvalidSignature);
}

#[test]
fn dual_authorized_transfer_block_state_root_validates() {
    let spend = generate_keypair();
    let auth = generate_keypair();
    let recipient = Address([9; 20]);
    let sender = dual_address_from_public_keys(&spend.public_key, &auth.public_key);
    let miner = Address([3; 20]);
    let mut ledger = Ledger::new();
    let genesis = genesis_block().unwrap();
    let (staged, _) = ledger.execute_block(&genesis).unwrap();
    ledger = staged;

    // Fund the sender exclusively through consensus coinbase issuance.
    // Executing the first 50 blocks without enforcing PoW keeps this unit
    // test fast while still exercising coinbase amount, maturity, state
    // commitment, and global supply validation for every transition.
    for height in 1..=crate::ledger::BLOCK_REWARD_MATURITY as u64 {
        let height = Height(height);
        let block = Block::from_protocol_transactions(
            height,
            ledger.tip_hash().unwrap(),
            sender,
            DIFFICULTY_START,
            Nonce(0),
            Vec::new(),
            Some(crate::block::CoinbaseTransaction::new(
                sender,
                ledger.mintable_subsidy(height),
            )),
            Vec::new(),
        )
        .unwrap();
        let (staged, _) = ledger.execute_block(&block).unwrap();
        ledger = staged;
    }

    let tx = authorized_transfer(
        &spend,
        &auth,
        recipient,
        ledger.account(&sender).unwrap().statement,
    );
    let transfer_height = Height(crate::ledger::BLOCK_REWARD_MATURITY as u64 + 1);
    let coinbase = crate::block::CoinbaseTransaction::new(
        miner,
        ledger.mintable_subsidy(transfer_height),
    );
    let mut block = Block::from_protocol_transactions(
        transfer_height,
        ledger.tip_hash().unwrap(),
        miner,
        DIFFICULTY_START,
        Nonce(0),
        Vec::new(),
        Some(coinbase),
        vec![tx.into()],
    )
    .unwrap();
    let state_root = ledger
        .staged_after_validated_block(&block, false)
        .map(|(_, state_root)| state_root)
        .unwrap();
    block.set_state_root(state_root);
    let block = mine_for_test(block);

    assert_eq!(ledger.validate_block(&block), Ok(state_root));
    let block_hash = block.hash().unwrap();
    ledger.apply_block(block).unwrap();
    assert!(ledger.account(&sender).unwrap().authorization.is_some());
    ledger.rollback_block(block_hash).unwrap();
    assert!(ledger.account(&sender).unwrap().authorization.is_none());
}

#[test]
fn expected_next_difficulty_uses_wbda_weight_window() {
    let miner = Address([3; 20]);
    let mut ledger = Ledger::new();
    let genesis = genesis_block().unwrap();
    let (staged, _) = ledger.execute_block(&genesis).unwrap();
    ledger = staged;

    for height in 1..crate::consensus::WBDA_WINDOW as u64 {
        let height = Height(height);
        let block = Block::from_protocol_transactions(
            height,
            ledger.tip_hash().unwrap(),
            miner,
            ledger.expected_difficulty_after_tip().unwrap(),
            Nonce(height.0),
            Vec::new(),
            Some(crate::block::CoinbaseTransaction::new(
                miner,
                ledger.mintable_subsidy(height),
            )),
            Vec::new(),
        )
        .unwrap();
        let (staged, _) = ledger.execute_block(&block).unwrap();
        ledger = staged;
    }

    assert_eq!(
        ledger.chain.tip_height(),
        Some(Height(crate::consensus::WBDA_WINDOW as u64 - 1))
    );
    assert_eq!(ledger.expected_difficulty_after_tip().unwrap(), 2);
}

#[test]
fn block_state_commitment_matches_protocol_root_components() {
    let ledger = Ledger::new();
    let block_hash = BlockHash([7; crate::crypto::HASH_SIZE]);
    let commitment = ledger.state_commitment_for_block_hash(block_hash).unwrap();

    assert_eq!(commitment.block_hash, block_hash);
    assert_eq!(commitment.account_state_root, ledger.state_root());
    assert_eq!(
        commitment.protocol_state_root,
        ledger.protocol_state_root().unwrap()
    );
    assert!(commitment.matches_protocol_root().unwrap());
}

#[test]
fn initialized_chain_rejects_inflated_economic_supply() {
    let mut ledger = Ledger::new();
    let genesis = genesis_block().unwrap();
    ledger.apply_block(genesis.clone()).unwrap();
    ledger.accounts.insert(
        Address([0x44; crate::crypto::ADDRESS_SIZE]),
        Account::new(Address([0x44; crate::crypto::ADDRESS_SIZE]), Amount(1)),
    );
    assert_eq!(ledger.validate_supply(), Err(LedgerError::SupplyMismatch));
}

#[test]
fn initialized_chain_rejects_non_coinbase_account_issuance_atomically() {
    let mut ledger = Ledger::new();
    let genesis = genesis_block().unwrap();
    ledger.apply_block(genesis.clone()).unwrap();
    let supply_before = ledger.economic_supply().unwrap();
    let address = Address([0x45; crate::crypto::ADDRESS_SIZE]);

    assert_eq!(
        ledger.create_account(address, Amount(1)),
        Err(LedgerError::UnauthorizedSupplyCreation)
    );
    assert!(ledger.account(&address).is_none());
    assert_eq!(ledger.economic_supply().unwrap(), supply_before);

    // Zero-balance account creation is not issuance.
    ledger.create_account(address, Amount(0)).unwrap();
    assert_eq!(ledger.economic_supply().unwrap(), supply_before);
}

#[test]
fn expected_supply_switches_to_tail_emission_at_the_boundary() {
    let genesis = Amount(123);
    let boundary = crate::consensus::supply::TAIL_EMISSION_START_HEIGHT;
    let before = expected_issued_supply(Height(boundary - 1), [genesis].into_iter()).unwrap();
    let at_boundary = expected_issued_supply(Height(boundary), [genesis].into_iter()).unwrap();
    let after = expected_issued_supply(Height(boundary + 1), [genesis].into_iter()).unwrap();

    assert_eq!(
        at_boundary.0 - before.0,
        crate::consensus::supply::TAIL_EMISSION
    );
    assert_eq!(
        after.0 - at_boundary.0,
        crate::consensus::supply::TAIL_EMISSION
    );
    assert_eq!(
        crate::consensus::block_reward(Height(boundary - 1)),
        Amount(crate::consensus::supply::BLOCK_REWARD)
    );
    assert_eq!(
        crate::consensus::block_reward(Height(boundary)),
        Amount(crate::consensus::supply::TAIL_EMISSION)
    );
}
