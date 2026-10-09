use kernel::{
    block::{Block, Emission, GENESIS_TARGET_BITS},
    blockchain::Chain,
    common::{Height, Nonce},
    crypto::ProgramId,
    genesis::genesis_block,
    monetary::coin::Zeno,
};

#[test]
fn eviction_keeps_all_headers_and_rehydration_rejects_a_different_branch() {
    let mut chain = Chain::new();
    chain.insert_block(genesis_block().unwrap()).unwrap();
    let mut saved = None;
    for height in 1..=160 {
        let block = Block::from_protocol_operations(
            Height(height),
            chain.tip_hash().unwrap(),
            GENESIS_TARGET_BITS,
            Nonce(0),
            Some(Emission::new(ProgramId([3; 32]), Zeno::ONE)),
            vec![],
        )
        .unwrap();
        if height == 1 {
            saved = Some(block.clone());
        }
        chain.insert_block(block).unwrap();
    }
    let headers = chain.chain_headers();
    let tip = chain.tip_hash();
    chain.retain_recent_bodies(2048, 8).unwrap();
    assert_eq!(chain.chain_headers(), headers);
    assert_eq!(chain.tip_hash(), tip);
    assert!(chain.block(&Height(1)).is_none());
    assert!(chain.block(&Height(0)).is_some());
    assert!(chain.block(&Height(160)).is_some());
    assert!(chain.blocks().count() <= 9); // At most eight recent entries plus genesis.
    let bytes: usize = chain.blocks().map(|block| block.weight().unwrap()).sum();
    assert!(bytes <= 2048 + chain.block(&Height(0)).unwrap().weight().unwrap());
    let saved = saved.unwrap();
    let mut wrong = saved.clone();
    wrong.header.nonce.0 += 1;
    assert!(chain.cache_known_block(wrong).is_err());
    assert!(chain.block(&Height(1)).is_none());
    chain.cache_known_block(saved.clone()).unwrap();
    assert_eq!(chain.block(&Height(1)), Some(&saved));
    assert_eq!(chain.chain_headers(), headers);
    assert_eq!(chain.tip_hash(), tip);
}
