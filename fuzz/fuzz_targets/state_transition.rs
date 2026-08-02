#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;
use paqus::block::Height;
use paqus::ledger::validate_ledger_invariants;
use paqus::transaction::SignedProtocolTransaction;

fuzz_target!(|data: &[u8]| {
    let fixtures = support::protocol_fixtures();
    let family = data.first().copied().unwrap_or(0) as usize % fixtures.len();
    let mut transaction = fixtures[family].clone();
    support::mutate_transaction(&mut transaction, data.get(1..).unwrap_or_default());

    let mut ledger = support::ledger_for(&transaction);
    let before = ledger.clone();
    let before_supply = ledger.economic_supply().expect("fixture supply");

    let result = match &transaction {
        SignedProtocolTransaction::BatchTransfer(signed) => {
            ledger.apply_signed_transaction_at(signed, Height(1))
        }
        SignedProtocolTransaction::QCash(signed) => {
            ledger.apply_signed_qcash_transaction(signed, Height(1))
        }
    };

    if result.is_err() {
        assert_eq!(ledger, before, "failed state transition was not atomic");
        return;
    }

    validate_ledger_invariants(&ledger).expect("successful transition broke ledger invariants");
    let after_supply = ledger.economic_supply().expect("post-transition supply");
    assert_eq!(
        after_supply.0, before_supply.0,
        "transaction family failed to conserve value"
    );
});
