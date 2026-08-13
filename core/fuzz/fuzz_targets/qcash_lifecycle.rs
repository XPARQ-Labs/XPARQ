#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;
use xparq::block::Height;
use xparq::crypto::BlockHash;
use xparq::ledger::validate_ledger_invariants;

fuzz_target!(|data: &[u8]| {
    let (mut ledger, mut withdraw, mut redeem) = support::qcash_lifecycle_fixture();
    let initial = ledger.clone();
    let initial_supply = ledger.economic_supply().expect("initial supply");
    if data.first().copied().unwrap_or(0) & 1 != 0 {
        withdraw.authorization_proof.signature.0[0] ^= 1;
    }
    let withdraw_block = BlockHash([0x81; xparq::crypto::HASH_SIZE]);
    let miner = xparq::crypto::Address([0x83; xparq::crypto::ADDRESS_SIZE]);
    if ledger
        .apply_signed_qcash_transaction_in_block(&withdraw, Height(1), withdraw_block, miner)
        .is_err()
    {
        assert_eq!(ledger, initial);
        return;
    }

    if data.first().copied().unwrap_or(0) & 2 != 0 {
        redeem.authorization_proof.signature.0[0] ^= 1;
    }
    let before_redeem = ledger.clone();
    let redeem_block = BlockHash([0x82; xparq::crypto::HASH_SIZE]);
    let redeem_result = ledger.apply_signed_qcash_transaction_in_block(
        &redeem,
        Height(2),
        redeem_block,
        miner,
    );
    if redeem_result.is_err() {
        assert_eq!(ledger, before_redeem);
    } else {
        let final_supply = ledger.economic_supply().expect("final supply");
        assert_eq!(
            final_supply.0, initial_supply.0,
            "QCash withdraw/redeem did not conserve value"
        );
        ledger
            .rollback_qcash_block(redeem_block)
            .expect("redeem rollback");
    }
    ledger
        .rollback_qcash_block(withdraw_block)
        .expect("withdraw rollback");
    assert_eq!(ledger, initial, "QCash withdrawal rollback was not exact");
    validate_ledger_invariants(&ledger).expect("rollback broke ledger invariants");
});
