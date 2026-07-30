#![allow(dead_code)]

use paqus::block::{Block, CoinbaseTransaction, Height, Nonce};
use paqus::consensus::DIFFICULTY_START;
use paqus::consensus::supply::{Amount, XPQ};
use paqus::crypto::{Address, Hash, dual_address_from_public_keys, generate_keypair, sign};
use paqus::governance::{GovernanceAction, SignedGovernanceAction};
use paqus::ledger::Ledger;
use paqus::qcash::{QCashDenomination, QCashWithdrawMetadata, qcash_coin_commitment};
use paqus::transaction::{
    QCashTransaction, SignedProtocolTransaction, SignedQCashTransaction, SignedTransaction,
    Transaction,
};
use std::sync::OnceLock;

pub fn protocol_fixtures() -> &'static [SignedProtocolTransaction; 3] {
    static FIXTURES: OnceLock<[SignedProtocolTransaction; 3]> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let primary = generate_keypair();
        let authorization = generate_keypair();
        let signer = dual_address_from_public_keys(&primary.public_key, &authorization.public_key);
        let recipient = Address([0x42; paqus::crypto::ADDRESS_SIZE]);

        let transfer = Transaction::new(signer, recipient, Amount(XPQ), Amount(1), Nonce(0));
        let transfer_bytes = transfer.signing_bytes().expect("fixture serialization");
        let signed_transfer = SignedTransaction::new_authorized(
            transfer,
            primary.public_key,
            sign(&primary.secret_key, &transfer_bytes),
            authorization.public_key,
            sign(&authorization.secret_key, &transfer_bytes),
        );

        let opening_secret = [0x31; 32];
        let qcash_amount = QCashDenomination::One.amount();
        let qcash_metadata = QCashWithdrawMetadata::with_denominations(
            qcash_amount,
            &[QCashDenomination::One],
            &[qcash_coin_commitment(&opening_secret)],
        )
        .expect("valid QCash fixture");
        let qcash =
            QCashTransaction::withdraw(signer, qcash_amount, Amount(1), Nonce(0), qcash_metadata);
        let qcash_bytes = qcash.signing_bytes().expect("fixture serialization");
        let signed_qcash = SignedQCashTransaction::new_authorized(
            qcash,
            primary.public_key,
            sign(&primary.secret_key, &qcash_bytes),
            authorization.public_key,
            sign(&authorization.secret_key, &qcash_bytes),
        );

        let governance = GovernanceAction::register_issuer(
            signer,
            Amount(1),
            Nonce(0),
            primary.public_key,
            Hash([0x51; paqus::crypto::HASH_SIZE]),
            Vec::new(),
            Hash([0x52; paqus::crypto::HASH_SIZE]),
            Vec::new(),
            Amount(XPQ),
            Height(3),
        );
        let governance_bytes = governance.signing_bytes().expect("fixture serialization");
        let signed_governance = SignedGovernanceAction::new_authorized(
            governance,
            primary.public_key,
            sign(&primary.secret_key, &governance_bytes),
            authorization.public_key,
            sign(&authorization.secret_key, &governance_bytes),
        );

        [
            signed_transfer.into(),
            signed_qcash.into(),
            signed_governance.into(),
        ]
    })
}

pub fn ledger_for(transaction: &SignedProtocolTransaction) -> Ledger {
    let mut ledger = Ledger::new();
    ledger
        .create_account_with_authorization(
            transaction.signer(),
            transaction.witness().auth_public_key,
            Amount(10 * XPQ),
        )
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
            let signer =
                dual_address_from_public_keys(&primary.public_key, &authorization.public_key);
            let recipient = Address([0x91; paqus::crypto::ADDRESS_SIZE]);
            let mut ledger = Ledger::new();
            ledger
                .create_account_with_authorization(
                    signer,
                    authorization.public_key,
                    Amount(10 * XPQ),
                )
                .expect("fixture account");

            let opening_secret = [0x31; 32];
            let amount = QCashDenomination::One.amount();
            let metadata = QCashWithdrawMetadata::with_denominations(
                amount,
                &[QCashDenomination::One],
                &[qcash_coin_commitment(&opening_secret)],
            )
            .expect("withdraw metadata");
            let withdraw =
                QCashTransaction::withdraw(signer, amount, Amount(1), Nonce(0), metadata);
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
                opening_secret,
            )
            .expect("cash file");
            let deposit = QCashTransaction::deposit_from_files(
                signer,
                recipient,
                Amount(1),
                Nonce(1),
                &[file],
            )
            .expect("deposit transaction");
            let bytes = deposit.signing_bytes().expect("deposit signing bytes");
            let deposit = SignedQCashTransaction::new_authorized(
                deposit,
                primary.public_key,
                sign(&primary.secret_key, &bytes),
                authorization.public_key,
                sign(&authorization.secret_key, &bytes),
            );
            (ledger, withdraw, deposit)
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
        1,
        Nonce(0),
        Vec::new(),
        Some(CoinbaseTransaction::new(miner, Amount(0), Amount(3))),
        transactions,
    )
    .expect("mixed-family fixture")
}

pub fn mutate_transaction(transaction: &mut SignedProtocolTransaction, data: &[u8]) {
    let mode = data.first().copied().unwrap_or(0) % 4;
    match mode {
        0 => {}
        1 => {
            let index = data.get(1).copied().unwrap_or(0) as usize
                % transaction.witness().signature.0.len();
            transaction.witness_mut().signature.0[index] ^= 1;
        }
        2 => {
            let index = data.get(1).copied().unwrap_or(0) as usize
                % transaction.witness().auth_signature.0.len();
            transaction.witness_mut().auth_signature.0[index] ^= 1;
        }
        _ => {
            transaction.witness_mut().auth_public_key.0[0] ^= 1;
        }
    }
}
