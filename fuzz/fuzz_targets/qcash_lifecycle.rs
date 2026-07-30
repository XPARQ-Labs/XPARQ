#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;
use paqus::block::Height;
use paqus::crypto::BlockHash;
use paqus::ledger::validate_ledger_invariants;

fuzz_target!(|data: &[u8]| {
    let (mut ledger, mut withdraw, mut deposit) = support::qcash_lifecycle_fixture();
    let initial = ledger.clone();
    let initial_supply = ledger.economic_supply().expect("initial supply");
    if data.first().copied().unwrap_or(0) & 1 != 0 {
        withdraw.witness.signature.0[0] ^= 1;
    }
    let withdraw_block = BlockHash([0x81; paqus::crypto::HASH_SIZE]);
    if ledger
        .apply_signed_qcash_transaction_in_block(&withdraw, Height(1), withdraw_block)
        .is_err()
    {
        assert_eq!(ledger, initial);
        return;
    }

    if data.first().copied().unwrap_or(0) & 2 != 0 {
        deposit.witness.auth_signature.0[0] ^= 1;
    }
    let before_deposit = ledger.clone();
    let deposit_block = BlockHash([0x82; paqus::crypto::HASH_SIZE]);
    let deposit_result =
        ledger.apply_signed_qcash_transaction_in_block(&deposit, Height(11), deposit_block);
    if deposit_result.is_err() {
        assert_eq!(ledger, before_deposit);
    } else {
        let final_supply = ledger.economic_supply().expect("final supply");
        assert_eq!(
            final_supply.0 + withdraw.transaction.fee.0 + deposit.transaction.fee.0,
            initial_supply.0,
            "QCash withdraw/deposit did not conserve value plus fees"
        );
        ledger
            .rollback_qcash_block(deposit_block)
            .expect("deposit rollback");
    }
    ledger
        .rollback_qcash_block(withdraw_block)
        .expect("withdraw rollback");
    assert_eq!(ledger, initial, "QCash withdrawal rollback was not exact");
    validate_ledger_invariants(&ledger).expect("rollback broke ledger invariants");
});
