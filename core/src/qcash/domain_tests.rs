
use super::*;

#[test]
fn selected_denominations_can_use_large_cash_notes() {
    let commitments = [[1_u8; 32]];
    let metadata = QCashWithdrawalMetadata::with_selected_denominations(
        &[QCashDenomination::OneThousand],
        &commitments,
    )
    .unwrap();

    assert_eq!(metadata.outputs.len(), 1);
    assert_eq!(
        metadata.outputs[0].denomination,
        QCashDenomination::OneThousand
    );
    assert_eq!(metadata.amount(), Ok(Amount(1000 * XPQ)));
}

#[test]
fn automatic_selection_prefers_new_largest_denominations() {
    let coins = format_qcash_coins(Amount(1500 * XPQ)).unwrap();

    assert_eq!(
        coins,
        vec![
            QCashDenominationRun {
                denomination: QCashDenomination::OneThousand,
                count: 1,
            },
            QCashDenominationRun {
                denomination: QCashDenomination::FiveHundred,
                count: 1,
            },
        ]
    );
}

#[test]
fn one_million_denomination_roundtrips_and_uses_one_output() {
    let denomination = QCashDenomination::OneMillion;
    let bytes = crate::codec::canonical_bytes(&denomination);
    let decoded =
        crate::codec::canonical_deserialize::<QCashDenomination>(&bytes.unwrap()).unwrap();
    assert_eq!(decoded, denomination);

    let plan = QCashWithdrawalMetadata::plan_automatic(Amount(1_000_000 * XPQ)).unwrap();
    assert_eq!(plan.denominations, vec![QCashDenomination::OneMillion]);
    assert_eq!(plan.remainder, Amount(0));
}
