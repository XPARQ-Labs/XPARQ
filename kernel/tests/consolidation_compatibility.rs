//! Frozen values captured from the working tree before crate consolidation.

#[test]
#[cfg(feature = "mainnet")]
fn mainnet_genesis_is_unchanged_and_effect_rules_have_a_new_identity() {
    use kernel::{codec, genesis};
    assert_eq!(
        genesis::genesis_hash().unwrap().0,
        [
            101, 64, 118, 68, 54, 86, 64, 225, 100, 102, 49, 159, 182, 7, 174, 208, 84, 59, 30, 75,
            237, 239, 84, 225, 186, 104, 102, 129, 199, 140, 66, 159
        ]
    );
    // The current state-root and explicit coin burn separate this protocol from the old
    // chain spec, while preserving the frozen genesis block and native IDs.
    assert_eq!(genesis::CHAIN_SPEC_VERSION, 6);
    assert_eq!(
        genesis::chain_spec_hash().unwrap().0,
        [
            41, 171, 225, 111, 57, 18, 23, 181, 45, 167, 129, 115, 99, 107, 228, 148, 16, 76,
            207, 223, 138, 9, 65, 70, 149, 205, 226, 0, 92, 179, 41, 39
        ]
    );
    assert_ne!(
        genesis::chain_spec_hash().unwrap().0,
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
fn asset_and_share_ids_are_unchanged() {
    use kernel::{
        asset::{AssetHash, AssetShareHash},
        crypto::Address,
    };
    let parent = AssetHash::derive(Address([7; 20]), "TEST");
    assert_eq!(
        parent.to_string(),
        "asset:7dc45da03fd526fdc16bb2a31db1778de16c7ad7f17dcef000611f878508c5ff"
    );
    assert_eq!(
        AssetShareHash::derive(parent, [9; 32], 3).to_string(),
        "share:69c51154490a408dbcf67cf9836ca189f6f74cd16289be28376aeac892e3b0c8"
    );
}
