#![allow(dead_code)]

use paqus::block::{Block, CoinbaseTransaction, Height, Nonce};
use paqus::consensus::DIFFICULTY_START;
use paqus::consensus::supply::{Amount, XPQ};
use paqus::crypto::{
    Address, Hash, KeyPair, dual_address_from_public_keys, generate_keypair, sign,
};
use paqus::ledger::Ledger;
use paqus::qcash::{
    QCashDenomination, QCashWithdrawalMetadata, qcash_redeem_key_commitment_from_secret,
};
use paqus::transaction::{
    QCashTransaction, SignedProtocolTransaction, SignedQCashTransaction, SignedTransaction,
    Transaction, TransferOutput,
};
use std::sync::OnceLock;

pub fn protocol_fixtures() -> &'static [SignedProtocolTransaction; 2] {
    static FIXTURES: OnceLock<[SignedProtocolTransaction; 2]> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let primary = generate_keypair();
        let authorization = generate_keypair();
        let signer = signer_address(&primary, &authorization);
        let mut ledger = Ledger::new();
        ledger
            .create_account_with_authorization(signer, authorization.public_key, Amount(10 * XPQ))
            .expect("fixture account");

        let signed_transfer = signed_transfer(
            &primary,
            &authorization,
            signer,
            Address([0x42; paqus::crypto::ADDRESS_SIZE]),
            Amount(XPQ),
            ledger.account(&signer).expect("fixture account").statement,
        );

        let redeem_secret = [0x31; 32];
        let qcash_amount = QCashDenomination::One.amount();
        let qcash_metadata = QCashWithdrawalMetadata::with_denominations(
            qcash_amount,
            &[QCashDenomination::One],
            &[qcash_redeem_key_commitment_from_secret(&redeem_secret)],
        )
        .expect("valid QCash fixture");
        let qcash = QCashTransaction::withdraw(signer, qcash_amount, qcash_metadata)
            .with_last_state(ledger.account(&signer).expect("fixture account").statement);
        let qcash_bytes = qcash.signing_bytes().expect("fixture serialization");
        let signed_qcash = SignedQCashTransaction::new_authorized(
            qcash,
            primary.public_key,
            sign(&primary.secret_key, &qcash_bytes),
            authorization.public_key,
            sign(&authorization.secret_key, &qcash_bytes),
        );

        [signed_transfer.into(), signed_qcash.into()]
    })
}

pub fn ledger_for(transaction: &SignedProtocolTransaction) -> Ledger {
    let mut ledger = Ledger::new();
    let auth_public_key = transaction.authorization_proof().auth_public_key;
    ledger
        .create_account_with_authorization(transaction.signer(), auth_public_key, Amount(10 * XPQ))
        .expect("fixture account");
    ledger
}

pub fn qcash_lifecycle_fixture() -> (Ledger, SignedQCashTransaction, SignedQCashTransaction) {
    static FIXTURE: OnceLock<(Ledger, SignedQCashTransaction, SignedQCashTransaction)> =
        OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let primary = generate_keypair();
            let authorization = generate_keypair();
            let signer = signer_address(&primary, &authorization);
            let recipient = Address([0x91; paqus::crypto::ADDRESS_SIZE]);
            let mut ledger = Ledger::new();
            ledger
                .create_account_with_authorization(
                    signer,
                    authorization.public_key,
                    Amount(10 * XPQ),
                )
                .expect("fixture account");

            let redeem_secret = [0x31; 32];
            let amount = QCashDenomination::One.amount();
            let metadata = QCashWithdrawalMetadata::with_denominations(
                amount,
                &[QCashDenomination::One],
                &[qcash_redeem_key_commitment_from_secret(&redeem_secret)],
            )
            .expect("withdraw metadata");
            let withdraw = QCashTransaction::withdraw(signer, amount, metadata)
                .with_last_state(ledger.account(&signer).expect("fixture account").statement);
            let bytes = withdraw.signing_bytes().expect("withdraw signing bytes");
            let withdraw = SignedQCashTransaction::new_authorized(
                withdraw,
                primary.public_key,
                sign(&primary.secret_key, &bytes),
                authorization.public_key,
                sign(&authorization.secret_key, &bytes),
            );

            let output = match &withdraw.transaction.kind {
                paqus::transaction::QCashTransactionKind::Withdraw { metadata, .. } => {
                    &metadata.outputs[0]
                }
                _ => unreachable!(),
            };
            let file = paqus::qcash::QCashCoinFile::new(
                withdraw.transaction.hash().expect("withdraw hash"),
                output,
                redeem_secret,
            )
            .expect("cash file");
            let redeem = QCashTransaction::redeem_from_files_at(signer, recipient, &[file])
                .map(|transaction| {
                    transaction.with_last_state(
                        ledger.account(&signer).expect("fixture account").statement,
                    )
                })
                .expect("redeem transaction");
            let bytes = redeem.signing_bytes().expect("redeem signing bytes");
            let redeem = SignedQCashTransaction::new_authorized(
                redeem,
                primary.public_key,
                sign(&primary.secret_key, &bytes),
                authorization.public_key,
                sign(&authorization.secret_key, &bytes),
            );
            (ledger, withdraw, redeem)
        })
        .clone()
}

pub fn mixed_family_block() -> Block {
    let transactions = protocol_fixtures().to_vec();
    let miner = Address([0x72; paqus::crypto::ADDRESS_SIZE]);
    Block::from_protocol_transactions(
        Height(1),
        Hash([0x73; paqus::crypto::HASH_SIZE]),
        miner,
        DIFFICULTY_START,
        Nonce(0),
        Vec::new(),
        Some(CoinbaseTransaction::new(miner, Amount(0))),
        transactions,
    )
    .expect("mixed-family fixture")
}

pub fn mutate_transaction(transaction: &mut SignedProtocolTransaction, data: &[u8]) {
    let proof = transaction.authorization_proof_mut();
    match data.first().copied().unwrap_or(0) % 4 {
        0 => {}
        1 => proof.signature.0[0] ^= 1,
        2 => proof.auth_signature.0[0] ^= 1,
        _ if proof.carries_registration_keys() => proof.auth_public_key.0[0] ^= 1,
        _ => proof.signature.0[1] ^= 1,
    }
}

fn signer_address(primary: &KeyPair, authorization: &KeyPair) -> Address {
    dual_address_from_public_keys(&primary.public_key, &authorization.public_key)
}

fn signed_transfer(
    primary: &KeyPair,
    authorization: &KeyPair,
    signer: Address,
    recipient: Address,
    amount: Amount,
    last_state: Hash,
) -> SignedTransaction {
    let transaction = Transaction::new(
        signer,
        vec![TransferOutput {
            to: recipient.into(),
            amount,
        }],
    )
    .with_last_state(last_state);
    let transfer_bytes = transaction.signing_bytes().expect("fixture serialization");
    SignedTransaction::new_authorized(
        transaction,
        primary.public_key,
        sign(&primary.secret_key, &transfer_bytes),
        authorization.public_key,
        sign(&authorization.secret_key, &transfer_bytes),
    )
}
