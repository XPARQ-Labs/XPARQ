#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;
use paqus::transaction::TransactionFamily;

fuzz_target!(|data: &[u8]| {
    let mut block = support::mixed_family_block();
    if data.first().copied().unwrap_or(0) & 1 != 0 {
        block.body.transactions.reverse();
        block = paqus::block::Block::from_protocol_transactions(
            block.height(),
            block.previous_hash(),
            block.miner_address(),
            block.difficulty(),
            block.proof.nonce,
            Vec::new(),
            block.body.coinbase,
            block.body.transactions,
        )
        .expect("rebuild reordered block");
    }

    let mut families = [false; 2];
    for transaction in &block.body.transactions {
        families[match transaction.family() {
            TransactionFamily::Transfer => 0,
            TransactionFamily::QCash => 1,
        }] = true;
    }
    assert_eq!(families, [true; 2]);

    let encoded = paqus::codec::block_bytes(&block).expect("mixed block encoding");
    let decoded = paqus::codec::decode_block(&encoded).expect("mixed block decoding");
    assert_eq!(decoded, block);

    // Exercise hostile/near-boundary count prefixes without allocating the
    // advertised number of large protocol values.
    let payload_count_offset = paqus::codec::canonical_bytes(&block.header)
        .expect("header encoding")
        .len()
        + paqus::codec::canonical_bytes(&block.body.genesis_allocations)
            .expect("allocation encoding")
            .len()
        + paqus::codec::canonical_bytes(&block.body.coinbase)
            .expect("coinbase encoding")
            .len();
    let mut hostile = encoded;
    if hostile.len() >= payload_count_offset + 4 {
        let prefix = match data.get(1).copied().unwrap_or(0) % 3 {
            0 => u32::MAX,
            1 => paqus::block::MAX_BLOCK_DECODE_ITEMS as u32,
            _ => paqus::block::MAX_BLOCK_DECODE_ITEMS as u32 + 1,
        };
        hostile[payload_count_offset..payload_count_offset + 4]
            .copy_from_slice(&prefix.to_le_bytes());
        let _ = paqus::codec::decode_block(&hostile);
    }
});
