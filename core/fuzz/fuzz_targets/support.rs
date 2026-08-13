#![allow(dead_code)]

use xparq::block::{Block, EmissionTransaction, Height, Nonce};
use xparq::consensus::DIFFICULTY_START;
use xparq::consensus::supply::{Amount, XPQ};
use xparq::crypto::{Address, Hash, KeyPair, address_from_public_key, generate_keypair, sign};
use xparq::ledger::Ledger;
use xparq::qcash::{QCashWithdrawalMetadata, qcash_redeem_key_commitment_from_secret};
use xparq::transaction::{
    QCashTransaction, SignedProtocolTransaction, SignedQCashTransaction, SignedTransfer, Transfer,
    TransferOutput,
};
use std::sync::OnceLock;

pub fn protocol_fixtures() -> &'static [SignedProtocolTransaction; 2] {
    static FIXTURES: OnceLock<[SignedProtocolTransaction; 2]> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let primary = generate_keypair();
        let signer = signer_address(&primary);
        let mut ledger = Ledger::new();
        ledger
            .create_account_with_authorization(
                signer,
                primary.public_key,
                Amount(10 * XPQ),
            )
            .expect("fixture account");

        let input = ledger
            .xpq_utxos
            .coins_for_owner(signer)
            .next()
            .expect("funded fixture coin")
            .id;
        let signed_transfer = signed_transfer(
            &primary,
            signer,
            input,
            Address([0x42; xparq::crypto::ADDRESS_SIZE]),
            Amount(XPQ),
        );

        let redeem_secret = [0x31; 32];
        let qcash_amount = Amount(XPQ);
        let qcash_metadata = QCashWithdrawalMetadata::with_amounts(
            qcash_amount,
            &[qcash_amount],
            &[qcash_redeem_key_commitment_from_secret(&redeem_secret)],
        )
        .expect("valid QCash fixture");
        let qcash = QCashTransaction::withdraw(
            signer,
            vec![input],
            vec![TransferOutput::new(signer, Amount(9 * XPQ))],
            qcash_amount,
            qcash_metadata,
        );
        let qcash_bytes = qcash.signing_bytes().expect("fixture serialization");
        let signed_qcash = SignedQCashTransaction::new(
            qcash,
            primary.public_key,
            sign(&primary.secret_key, &qcash_bytes),
        );

        [signed_transfer.into(), signed_qcash.into()]
    })
}

pub fn ledger_for(transaction: &SignedProtocolTransaction) -> Ledger {
    let mut ledger = Ledger::new();
    let authorization_proof = transaction.authorization_proof();
    if authorization_proof.carries_registration_keys() {
        ledger
            .create_account_with_authorization(
                transaction.signer(),
                authorization_proof.public_key,
                Amount(10 * XPQ),
            )
            .expect("fixture account");
    } else {
        ledger
            .create_account(transaction.signer(), Amount(10 * XPQ))
            .expect("fixture account");
    }
    ledger
}

pub fn qcash_lifecycle_fixture() -> (Ledger, SignedQCashTransaction, SignedQCashTransaction) {
    static FIXTURE: OnceLock<(Ledger, SignedQCashTransaction, SignedQCashTransaction)> =
        OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let primary = generate_keypair();
            let signer = signer_address(&primary);
            let recipient = Address([0x91; xparq::crypto::ADDRESS_SIZE]);
            let mut ledger = Ledger::new();
            ledger
                .create_account_with_authorization(
                    signer,
                    primary.public_key,
                    Amount(10 * XPQ),
                )
                .expect("fixture account");

            let redeem_secret = [0x31; 32];
            let amount = Amount(XPQ);
            let metadata = QCashWithdrawalMetadata::with_amounts(
                amount,
                &[amount],
                &[qcash_redeem_key_commitment_from_secret(&redeem_secret)],
            )
            .expect("withdraw metadata");
            let input = ledger
                .xpq_utxos
                .coins_for_owner(signer)
                .next()
                .expect("funded fixture coin")
                .id;
            let withdraw = QCashTransaction::withdraw(
                signer,
                vec![input],
                vec![TransferOutput::new(signer, Amount(9 * XPQ))],
                amount,
                metadata,
            );
            let bytes = withdraw.signing_bytes().expect("withdraw signing bytes");
            let withdraw = SignedQCashTransaction::new(
                withdraw,
                primary.public_key,
                sign(&primary.secret_key, &bytes),
            );

            let output = match &withdraw.transaction.kind {
                xparq::transaction::QCashTransactionKind::Withdraw { metadata, .. } => {
                    &metadata.outputs[0]
                }
                _ => unreachable!(),
            };
            let file = xparq::qcash::QCashCoinFile::new(
                withdraw.transaction.hash().expect("withdraw hash"),
                output,
                redeem_secret,
            )
            .expect("cash file");
            let redeem = QCashTransaction::redeem_from_files(
                signer,
                vec![TransferOutput::new(recipient, amount)],
                &[file],
            )
            .expect("redeem transaction");
            let bytes = redeem.signing_bytes().expect("redeem signing bytes");
            let redeem = SignedQCashTransaction::new(
                redeem,
                primary.public_key,
                sign(&primary.secret_key, &bytes),
            );
            (ledger, withdraw, redeem)
        })
        .clone()
}

pub fn mixed_family_block() -> Block {
    let transactions = protocol_fixtures().to_vec();
    let miner = Address([0x72; xparq::crypto::ADDRESS_SIZE]);
    Block::from_protocol_transactions(
        Height(1),
        Hash([0x73; xparq::crypto::HASH_SIZE]),
        DIFFICULTY_START,
        Nonce(0),
        Some(EmissionTransaction::new(miner, Amount(0))),
        transactions,
    )
    .expect("mixed-family fixture")
}

pub fn mutate_transaction(transaction: &mut SignedProtocolTransaction, data: &[u8]) {
    let proof = transaction.authorization_proof_mut();
    match data.first().copied().unwrap_or(0) % 4 {
        0 => {}
        1 => proof.signature.0[0] ^= 1,
        2 if proof.carries_registration_keys() => proof.public_key.0[0] ^= 1,
        _ => proof.signature.0[1] ^= 1,
    }
}

fn signer_address(primary: &KeyPair) -> Address {
    address_from_public_key(&primary.public_key)
}

fn signed_transfer(
    primary: &KeyPair,
    signer: Address,
    input: xparq::state::XpqCoinId,
    recipient: Address,
    amount: Amount,
) -> SignedTransfer {
    let transaction = Transfer::new(signer, vec![input], recipient, amount);
    let transfer_bytes = transaction.signing_bytes().expect("fixture serialization");
    SignedTransfer::new(
        transaction,
        primary.public_key,
        sign(&primary.secret_key, &transfer_bytes),
    )
}
