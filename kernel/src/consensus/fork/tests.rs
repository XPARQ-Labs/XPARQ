use super::*;

#[test]
fn xparq_pow_limit_has_expected_chainwork() {
    let work = block_work(0x207f_ffff).expect("valid XPARQ target");

    assert_eq!(work, Work::from_be_limbs([0, 0, 0, 0, 0, 0, 0, 2,]));
}

#[test]
fn harder_target_produces_more_work() {
    let easier = block_work(0x207f_ffff).expect("valid easier target");

    let harder = block_work(0x203f_ffff).expect("valid harder target");

    assert!(harder > easier);

    assert_eq!(easier, Work::from_be_limbs([0, 0, 0, 0, 0, 0, 0, 2,]));

    assert_eq!(harder, Work::from_be_limbs([0, 0, 0, 0, 0, 0, 0, 4,]));
}

#[test]
fn bitcoin_genesis_target_matches_reference_chainwork() {
    let work = block_work(0x1d00_ffff).expect("valid Bitcoin genesis target");

    assert_eq!(
        work,
        Work::from_be_limbs([0, 0, 0, 0, 0, 0, 0, 0x0000_0001_0001_0001,])
    );
}

#[test]
fn invalid_compact_target_has_no_chainwork() {
    assert!(block_work(0).is_none());
    assert!(block_work(0x1d80_ffff).is_none());
}
