//! Frozen values captured from the working tree before crate consolidation.

#[test]
#[cfg(feature = "mainnet")]
fn mainnet_genesis_and_chain_spec_match_the_current_structure() {
    use kernel::{codec, genesis};
    assert_eq!(
        genesis::genesis_hash().unwrap().into_bytes(),
        [
            212, 9, 99, 195, 104, 129, 74, 178, 35, 16, 87, 234, 192, 76, 226, 169, 187, 120, 36,
            172, 185, 246, 186, 145, 237, 119, 232, 131, 179, 234, 188, 197
        ]
    );
    // The target-bits header and current consensus parameters define a new chain
    // identity while the native asset IDs below remain frozen independently.
    assert_eq!(genesis::CHAIN_SPEC_VERSION, 1);
    assert_eq!(
        genesis::chain_spec_hash().unwrap().into_bytes(),
        [
            73, 19, 98, 10, 177, 15, 27, 246, 3, 192, 27, 148, 189, 244, 136, 217, 158, 39, 117,
            79, 85, 171, 238, 57, 42, 100, 47, 147, 183, 91, 206, 40
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
        0, 0, 0, 0, 0, 0, 255, 255, 127, 32, 125, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
        0,
    )
    .unwrap();
    assert_eq!(
        parent.to_string(),
        "e91c4dea105744cb320d7881bc55ce8bf492da026f19daa99be649b11939e87c"
    );
    assert_eq!(
        Share::derive(parent, [9; 32], 3).to_string(),
        "283647b427cd9a41c83845d7045e80a254b3ecf8cc998495179e2e972640f8b1"
    );
}
