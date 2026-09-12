//! Frozen values captured from the working tree before crate consolidation.

#[test]
#[cfg(feature = "mainnet")]
fn mainnet_genesis_is_unchanged_and_effect_rules_have_a_new_identity() {
    use kernel::{codec, genesis};
    assert_eq!(
        genesis::genesis_hash().unwrap().into_bytes(),
        [
            101, 64, 118, 68, 54, 86, 64, 225, 100, 102, 49, 159, 182, 7, 174, 208, 84, 59, 30, 75,
            237, 239, 84, 225, 186, 104, 102, 129, 199, 140, 66, 159
        ]
    );
    // The current state-root and explicit coin burn separate this protocol from the old
    // chain spec, while preserving the frozen genesis block and native IDs.
    assert_eq!(genesis::CHAIN_SPEC_VERSION, 2);
    assert_eq!(
        genesis::chain_spec_hash().unwrap().into_bytes(),
        [
            83, 224, 12, 56, 185, 39, 161, 57, 138, 115, 139, 102, 17, 169, 220, 8, 78, 78, 226,
            64, 119, 97, 85, 80, 196, 14, 14, 80, 32, 111, 144, 234
        ]
    );
    assert_ne!(
        genesis::chain_spec_hash().unwrap().into_bytes(),
        [
            166, 191, 246, 35, 4, 125, 100, 134, 53, 253, 52, 62, 165, 243, 91, 247, 90, 255, 55,
            241, 236, 179, 25, 8, 168, 155, 66, 92, 154, 68, 94, 218
        ]
    );
    let expected = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 125, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ];
    let block = genesis::genesis_block().unwrap();
    assert_eq!(codec::block_bytes(&block).unwrap(), expected);
    assert_eq!(codec::decode_block(&expected).unwrap(), block);
    genesis::genesis_ledger().unwrap();
}

#[test]
fn native_asset_and_share_ids_are_frozen() {
    use kernel::{
        crypto::{ADDRESS_SIZE, Address},
        native::asset::{Contract, Metadata, Share, Unit},
    };
    let parent = Contract::derive(
        &Metadata::new(
            "Test Asset".into(),
            "TEST".into(),
            6,
            Unit::from_units(1_000_000),
            Address([7; ADDRESS_SIZE]),
            Address([7; ADDRESS_SIZE]),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        parent.to_string(),
        "40db0d5be4a57edb2d3c7ce96fc4d600ff37c65042dd9793191bdefce60dd659"
    );
    assert_eq!(
        Share::derive(parent, [9; 32], 3).to_string(),
        "baed600776659b95bf8c4ca0b8b225dd633b42a20cd9db1acce2e0b262a90aa4"
    );
}
