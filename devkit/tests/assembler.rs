use std::collections::BTreeMap;
use xparq_devkit::{assemble, validate};
#[test]
fn counter_matches_independently_encoded_v4() {
    let mut expected = b"XPVM\x04\x08\x00\x01\x00\x00\x00\x00\x00".to_vec();
    expected.extend([0x04, 0x01]);
    expected.extend(1u128.to_le_bytes());
    expected.extend([0x02, 0x16, 0x05, 0x03]);
    assert_eq!(
        assemble(include_str!("../examples/counter.xpa"), &BTreeMap::new()).unwrap(),
        expected
    );
}
#[test]
fn labels_resolve_to_body_instruction_boundaries() {
    let code = assemble(
        "u128.const 0\njump.zero end\nu128.const 7\nend:\nreturn",
        &BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(&code[31..35], &39u32.to_le_bytes());
    let mut bad = code;
    bad[31..35].copy_from_slice(&1u32.to_le_bytes());
    assert!(validate(&bad).is_err());
}
#[test]
fn rejects_invalid_sources_and_vm_limits() {
    for source in [
        "return extra",
        "unknown",
        "bytes.const z0\nreturn",
        "jump missing\nreturn",
        "a:\na:\nreturn",
        ".stack 0\nreturn",
        ".memory 17\nreturn",
        "nop",
        "u128.const -1\nreturn",
        "return\n.stack 8",
        "owner.const abc\nreturn",
        "u128.const $MISSING\nreturn",
    ] {
        assert!(assemble(source, &BTreeMap::new()).is_err(), "{source}");
    }
}
#[test]
fn examples_and_definitions_use_kernel_validation() {
    assemble(include_str!("../examples/vault.xpa"), &BTreeMap::new()).unwrap();
    let vars = BTreeMap::from([
        ("ASSET".into(), "11".repeat(32)),
        ("RECIPIENT".into(), "22".repeat(32)),
        ("AMOUNT".into(), "42".into()),
    ]);
    let code = assemble(include_str!("../examples/asset-transfer.xpa"), &vars).unwrap();
    validate(&code).unwrap();
    assert!(code.windows(33).any(|w| w[0] == 0 && w[1..] == [0x22; 32]));
}
