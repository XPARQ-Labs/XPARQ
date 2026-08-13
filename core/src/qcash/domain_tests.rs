
use super::*;
use crate::consensus::supply::XPQ;

#[test]
fn selected_amounts_accept_fractional_xpq() {
    let commitments = [[1_u8; 32]];
    let amount = Amount(1_000 * XPQ + 500_000);
    let metadata = QCashWithdrawalMetadata::with_selected_amounts(&[amount], &commitments).unwrap();

    assert_eq!(metadata.outputs.len(), 1);
    assert_eq!(metadata.outputs[0].amount, amount);
    assert_eq!(metadata.amount(), Ok(amount));
}

#[test]
fn automatic_plan_uses_one_file_and_keeps_fractional_value() {
    let amount = Amount(1_000_000 * XPQ + 123_456);
    let plan = QCashWithdrawalMetadata::plan_automatic(amount).unwrap();
    assert_eq!(plan.amounts, vec![amount]);
    assert_eq!(plan.qcash_amount, amount);
    assert_eq!(plan.remainder, Amount(0));
}
