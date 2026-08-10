use super::*;
use crate::block::Height;
use crate::consensus::supply::Amount;
use crate::crypto::{Address, dual_address_from_public_keys, generate_keypair, sign};
use crate::state::{XpqCoinId, XpqCoinSource};
use crate::transaction::{
    QCashTransaction, SignedQCashTransaction, SignedTransfer, Transfer, TransferOutput,
};

fn funded_ledger(amount: u64) -> (Ledger, crate::crypto::KeyPair, crate::crypto::KeyPair, Address) {
    let owner = generate_keypair();
    let authorization = generate_keypair();
    let sender = dual_address_from_public_keys(&owner.public_key, &authorization.public_key);
    let mut ledger = Ledger::new();
    ledger
        .create_account_with_authorization(
            sender,
            owner.public_key,
            authorization.public_key,
            Amount(amount),
        )
        .unwrap();
    (ledger, owner, authorization, sender)
}

fn sign_transfer(
    transaction: Transfer,
    owner: &crate::crypto::KeyPair,
    authorization: &crate::crypto::KeyPair,
) -> SignedTransfer {
    let payload = transaction.signing_bytes().unwrap();
    SignedTransfer::new_authorized(
        transaction,
        owner.public_key,
        sign(&owner.secret_key, &payload),
        authorization.public_key,
        sign(&authorization.secret_key, &payload),
    )
}

#[test]
fn transfer_consumes_old_coin_and_creates_recipient_and_change_coins() {
    let (mut ledger, owner, authorization, sender) = funded_ledger(100);
    let recipient = Address([7; crate::crypto::ADDRESS_SIZE]);
    let input = ledger.xpq_utxos.coins_for_owner(sender).next().unwrap().id;
    let transaction = Transfer::from_outputs(
        sender,
        vec![input],
        vec![
            TransferOutput::new(recipient, Amount(30)),
            TransferOutput::new(sender, Amount(70)),
        ],
    );
    let txid = transaction.hash().unwrap();
    ledger
        .apply_signed_transaction_at(&sign_transfer(transaction, &owner, &authorization), Height(0))
        .unwrap();

    assert!(ledger.xpq_utxos.coin(input).is_none());
    assert_eq!(ledger.balance(&recipient), Some(Amount(30)));
    assert_eq!(ledger.balance(&sender), Some(Amount(70)));
    assert!(ledger.xpq_utxos.coin(XpqCoinId::derive(txid, 0).unwrap()).is_some());
    assert!(ledger.xpq_utxos.coin(XpqCoinId::derive(txid, 1).unwrap()).is_some());
}

#[test]
fn stored_key_transfer_uses_registered_account_authorization() {
    let (mut ledger, owner, authorization, sender) = funded_ledger(100);
    let recipient = Address([0x6c; crate::crypto::ADDRESS_SIZE]);
    let input = ledger.xpq_utxos.coins_for_owner(sender).next().unwrap().id;
    let transaction = Transfer::new(sender, vec![input], recipient, Amount(100));
    let payload = transaction.signing_bytes().unwrap();
    let signed = SignedTransfer::new_stored_authorized(
        transaction,
        sign(&owner.secret_key, &payload),
        sign(&authorization.secret_key, &payload),
    );

    ledger
        .apply_signed_transaction_at(&signed, Height(0))
        .unwrap();

    assert!(signed.authorization_proof.uses_stored_keys());
    assert_eq!(ledger.balance(&recipient), Some(Amount(100)));
}

#[test]
fn spent_coin_cannot_be_replayed() {
    let (mut ledger, owner, authorization, sender) = funded_ledger(100);
    let input = ledger.xpq_utxos.coins_for_owner(sender).next().unwrap().id;
    let transaction = Transfer::new(sender, vec![input], Address([8; 20]), Amount(100));
    let signed = sign_transfer(transaction, &owner, &authorization);
    ledger
        .apply_signed_transaction_at(&signed, Height(0))
        .unwrap();
    assert!(ledger.apply_signed_transaction_at(&signed, Height(0)).is_err());
}

#[test]
fn coin_id_is_domain_separated_and_output_indexed() {
    let txid = crate::crypto::TransactionHash([3; crate::crypto::HASH_SIZE]);
    assert_ne!(
        XpqCoinId::derive(txid, 0).unwrap(),
        XpqCoinId::derive(txid, 1).unwrap()
    );
}

#[test]
fn balance_is_derived_only_from_unspent_outputs() {
    let (ledger, _, _, sender) = funded_ledger(42);
    let coin = ledger.xpq_utxos.coins_for_owner(sender).next().unwrap();
    assert_eq!(coin.amount, Amount(42));
    assert_eq!(coin.source, XpqCoinSource::TrustedGenesis);
    assert_eq!(ledger.total_supply().unwrap(), Amount(42));
}

#[test]
fn finalized_rollback_pruning_keeps_explorer_history_and_unfinalized_state() {
    let (mut ledger, _, _, _) = funded_ledger(42);
    let finalized = crate::crypto::BlockHash([0x21; crate::crypto::HASH_SIZE]);
    let unfinalized = crate::crypto::BlockHash([0x22; crate::crypto::HASH_SIZE]);
    for (block_hash, block_height) in [(finalized, Height(5)), (unfinalized, Height(6))] {
        ledger.rollback_states.insert(
            block_hash,
            AccountRollbackState {
                block_height,
                accounts: ledger.accounts.clone(),
                account_state_tree: ledger.account_state_tree.clone(),
                xpq_utxos: ledger.xpq_utxos.clone(),
            },
        );
        ledger.qcash_account_journals.insert(
            block_hash,
            QCashAccountJournal {
                block_hash,
                block_height,
                previous_accounts: Default::default(),
            },
        );
    }
    ledger.events_by_block.insert(finalized, Vec::new());

    ledger.prune_finalized_rollback_state(Height(5));

    assert!(!ledger.rollback_states.contains_key(&finalized));
    assert!(ledger.rollback_states.contains_key(&unfinalized));
    assert!(!ledger.qcash_account_journals.contains_key(&finalized));
    assert!(ledger.qcash_account_journals.contains_key(&unfinalized));
    assert!(ledger.events_by_block.contains_key(&finalized));
}

#[test]
fn qcash_redeem_creates_recipient_and_block_miner_outputs() {
    let (mut ledger, owner, authorization, sender) =
        funded_ledger(crate::consensus::supply::XPQ);
    let redeem_secret = [0x31; 32];
    let commitment = crate::qcash::qcash_redeem_key_commitment_from_secret(&redeem_secret);
    let metadata = crate::qcash::QCashWithdrawalMetadata::with_selected_denominations(
        &[crate::qcash::QCashDenomination::One],
        &[commitment],
    )
    .unwrap();
    let input = ledger.xpq_utxos.coins_for_owner(sender).next().unwrap().id;
    let withdraw = QCashTransaction::withdraw(
        sender,
        vec![input],
        Vec::new(),
        Amount(crate::consensus::supply::XPQ),
        metadata.clone(),
    );
    let withdraw_hash = withdraw.hash().unwrap();
    let withdraw_payload = withdraw.signing_bytes().unwrap();
    let signed_withdraw = SignedQCashTransaction::new_authorized(
        withdraw,
        owner.public_key,
        sign(&owner.secret_key, &withdraw_payload),
        authorization.public_key,
        sign(&authorization.secret_key, &withdraw_payload),
    );
    ledger
        .apply_signed_qcash_transaction(&signed_withdraw, Height(0))
        .unwrap();
    assert_eq!(ledger.total_supply().unwrap(), Amount(0));
    assert_eq!(
        ledger.qcash_utxos.total_value().unwrap(),
        Amount(crate::consensus::supply::XPQ)
    );
    let before_redeem = ledger.clone();

    let file = crate::qcash::QCashCoinFile::new(
        withdraw_hash,
        &metadata.outputs[0],
        redeem_secret,
    )
    .unwrap();
    let miner = Address([0x71; crate::crypto::ADDRESS_SIZE]);
    let miner_bounty = Amount(10_000);
    let recipient_amount = Amount(crate::consensus::supply::XPQ - miner_bounty.0);
    let redeem = QCashTransaction::redeem_from_files(
        sender,
        vec![
            TransferOutput::new(sender, recipient_amount),
            TransferOutput::new(crate::transaction::OutputTarget::BlockMiner, miner_bounty),
        ],
        &[file],
    )
    .unwrap();
    let redeem_hash = redeem.hash().unwrap();
    let redeem_payload = redeem.signing_bytes().unwrap();
    let signed_redeem = SignedQCashTransaction::new_stored_authorized(
        redeem,
        sign(&owner.secret_key, &redeem_payload),
        sign(&authorization.secret_key, &redeem_payload),
    );
    let redeem_block_hash = crate::crypto::BlockHash([0x72; crate::crypto::HASH_SIZE]);
    ledger
        .apply_signed_qcash_transaction_in_block(
            &signed_redeem,
            Height(1),
            redeem_block_hash,
            miner,
        )
        .unwrap();

    assert_eq!(ledger.qcash_utxos.total_value().unwrap(), Amount(0));
    assert_eq!(
        ledger.balance(&sender),
        Some(recipient_amount)
    );
    assert_eq!(ledger.balance(&miner), Some(miner_bounty));
    assert_eq!(ledger.xpq_utxos.coins_for_owner(sender).count(), 1);
    assert_eq!(ledger.xpq_utxos.coins_for_owner(miner).count(), 1);
    assert!(
        ledger
            .xpq_utxos
            .coin(XpqCoinId::derive_issuance(redeem_hash.as_hash(), 0).unwrap())
            .is_some()
    );
    assert!(
        ledger
            .xpq_utxos
            .coin(XpqCoinId::derive_issuance(redeem_hash.as_hash(), 1).unwrap())
            .is_some()
    );
    assert_eq!(ledger.economic_supply().unwrap(), Amount(crate::consensus::supply::XPQ));

    ledger.rollback_qcash_block(redeem_block_hash).unwrap();
    assert_eq!(ledger, before_redeem);
}

#[test]
fn qcash_block_rollback_restores_owned_xpq_and_authorization_state() {
    let (mut ledger, owner, authorization, sender) =
        funded_ledger(crate::consensus::supply::XPQ);
    let before = ledger.clone();
    let metadata = crate::qcash::QCashWithdrawalMetadata::with_selected_denominations(
        &[crate::qcash::QCashDenomination::One],
        &[crate::qcash::qcash_redeem_key_commitment_from_secret(
            &[0x51; 32],
        )],
    )
    .unwrap();
    let input = ledger.xpq_utxos.coins_for_owner(sender).next().unwrap().id;
    let transaction = QCashTransaction::withdraw(
        sender,
        vec![input],
        Vec::new(),
        Amount(crate::consensus::supply::XPQ),
        metadata,
    );
    let payload = transaction.signing_bytes().unwrap();
    let signed = SignedQCashTransaction::new_authorized(
        transaction,
        owner.public_key,
        sign(&owner.secret_key, &payload),
        authorization.public_key,
        sign(&authorization.secret_key, &payload),
    );
    let block_hash = crate::crypto::BlockHash([0x52; crate::crypto::HASH_SIZE]);

    ledger
        .apply_signed_qcash_transaction_in_block(
            &signed,
            Height(1),
            block_hash,
            Address([0x53; crate::crypto::ADDRESS_SIZE]),
        )
        .unwrap();
    assert_ne!(ledger.xpq_utxos, before.xpq_utxos);
    ledger.rollback_qcash_block(block_hash).unwrap();
    assert_eq!(ledger, before);
}

#[test]
fn rollback_receipts_report_balances_derived_from_utxos() {
    let (before, owner, authorization, sender) = funded_ledger(100);
    let recipient = Address([0x55; crate::crypto::ADDRESS_SIZE]);
    let input = before.xpq_utxos.coins_for_owner(sender).next().unwrap().id;
    let transaction = Transfer::from_outputs(
        sender,
        vec![input],
        vec![
            TransferOutput::new(recipient, Amount(30)),
            TransferOutput::new(sender, Amount(70)),
        ],
    );
    let mut after = before.clone();
    after
        .apply_signed_transaction_at(&sign_transfer(transaction, &owner, &authorization), Height(0))
        .unwrap();

    let changes = account_rollbacks(
        &before.accounts,
        &before.xpq_utxos,
        &after.accounts,
        &after.xpq_utxos,
    );
    let sender_change = changes.iter().find(|change| change.address == sender).unwrap();
    assert_eq!(sender_change.before.as_ref().unwrap().balance, Amount(100));
    assert_eq!(sender_change.after.as_ref().unwrap().balance, Amount(70));
    let recipient_change = changes
        .iter()
        .find(|change| change.address == recipient)
        .unwrap();
    assert_eq!(recipient_change.after.as_ref().unwrap().balance, Amount(30));
}

#[test]
fn candidate_preview_cannot_commit_a_pow_bypassing_ledger() {
    let ledger = crate::genesis::genesis_ledger().unwrap();
    let height = Height(1);
    let miner = Address([6; crate::crypto::ADDRESS_SIZE]);
    let reward = ledger.mintable_subsidy(height).unwrap();
    let mut candidate = crate::block::Block::from_protocol_transactions(
        height,
        ledger.tip_hash().unwrap(),
        ledger.expected_difficulty_after_tip().unwrap(),
        crate::block::Nonce(0),
        Some(crate::block::EmissionTransaction::new(miner, reward)),
        Vec::new(),
    )
    .unwrap();

    let preview = ledger.preview_candidate_block(&candidate).unwrap();
    assert_ne!(preview.state_root_after, crate::crypto::StateRoot::ZERO);
    assert_eq!(ledger.tip_height(), Some(Height(0)));

    while crate::consensus::Consensus::validate_pow_at_difficulty(
        &candidate,
        candidate.difficulty(),
    )
    .is_err()
    {
        candidate.header.nonce.0 = candidate.header.nonce.0.saturating_add(1);
    }
    assert_eq!(
        ledger.validate_and_execute_block(&candidate),
        Err(LedgerError::InvalidStateRoot)
    );

    candidate.set_state_root(preview.state_root_after);
    while crate::consensus::Consensus::validate_pow_at_difficulty(
        &candidate,
        candidate.difficulty(),
    )
    .is_err()
    {
        candidate.header.nonce.0 = candidate.header.nonce.0.saturating_add(1);
    }
    let candidate_hash = candidate.hash().unwrap();
    let (mut committed, _) = ledger.validate_and_execute_block(&candidate).unwrap();
    assert_eq!(committed.tip_height(), Some(height));
    committed.rollback_block(candidate_hash).unwrap();
    assert_eq!(committed.tip_height(), ledger.tip_height());
    assert_eq!(committed.tip_hash(), ledger.tip_hash());
    assert_eq!(committed.state_root(), ledger.state_root());
}
