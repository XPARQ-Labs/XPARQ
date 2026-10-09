use super::*;

#[test]
fn utilization_thresholds_and_pow_limit_are_preserved() {
    assert_eq!(
        adjustment_for_utilization_ppm(799_999),
        WbdaAdjustment::Increase
    );
    assert_eq!(
        adjustment_for_utilization_ppm(800_000),
        WbdaAdjustment::Keep
    );
    assert_eq!(
        adjustment_for_utilization_ppm(1_200_000),
        WbdaAdjustment::Keep
    );
    assert_eq!(
        adjustment_for_utilization_ppm(1_200_001),
        WbdaAdjustment::Decrease
    );
    let limit = crate::consensus::TARGET_BITS_START;
    let busy = vec![2 * WBDA_TARGET_BLOCK_WEIGHT; WBDA_WINDOW];
    assert_eq!(next_difficulty_from_window(limit, &busy), Some(limit));
    assert_eq!(
        next_difficulty_from_window(limit, &busy[..WBDA_WINDOW - 1]),
        None
    );
}

#[test]
fn epoch_reads_exact_parent_window_and_propagates_history_failure() {
    for height in [1, 2, 2_500, 2_502] {
        let expected = if height == 1 {
            crate::consensus::TARGET_BITS_START
        } else {
            0x207f_ffff
        };
        let result = expected_difficulty_for_height::<()>(height, 0x207f_ffff, |_| {
            panic!("history must only be read at an epoch boundary")
        });
        assert_eq!(result, Ok(Some(expected)));
    }
    let mut visited = Vec::new();
    let target = crate::consensus::TARGET_BITS_START;
    assert_eq!(
        expected_difficulty_for_height(2_501, target, |height| {
            visited.push(height);
            Ok::<_, ()>(WBDA_TARGET_BLOCK_WEIGHT)
        }),
        Ok(Some(target))
    );
    assert_eq!(visited, (1..=2_500).collect::<Vec<_>>());
    assert_eq!(
        expected_difficulty_for_height(2_501, 0x207f_ffff, |_| Err("missing history")),
        Err("missing history")
    );
}
