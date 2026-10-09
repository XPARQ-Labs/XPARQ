use super::*;

#[test]
fn emission_vectors_cover_epoch_edges_peak_halvings_and_tail() {
    for (height, amount) in [
        (0, 156_250_000),
        (1, 156_250_000),
        (100_000, 156_250_000),
        (100_001, 312_500_000),
        (500_001, 5_000_000_000),
        (600_000, 5_000_000_000),
        (600_001, 2_500_000_000),
        (1_000_001, 156_250_000),
        (1_100_001, 78_125_000),
        (u64::MAX, 78_125_000),
    ] {
        assert_eq!(block_emission_for_height(Height(height)).as_zeno(), amount);
    }
    assert!(!is_emission_epoch_boundary(1));
    assert!(!is_emission_epoch_boundary(100_000));
    assert!(is_emission_epoch_boundary(100_001));
}
