#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;
use xparq::transaction::TransactionFamily;

fuzz_target!(|data: &[u8]| {
    let mut block = support::mixed_family_block();
    if data.first().copied().unwrap_or(0) & 1 != 0 {
        block.body.transactions.reverse();
        block = xparq::block::Block::from_protocol_transactions(
            block.height(),
            block.previous_hash(),
            block.difficulty(),
            block.header.nonce,
            block.body.emission,
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

    let encoded = xparq::codec::block_bytes(&block).expect("mixed block encoding");
    let decoded = xparq::codec::decode_block(&encoded).expect("mixed block decoding");
    assert_eq!(decoded, block);

    // Exercise hostile/near-boundary count prefixes without allocating the
    // advertised number of large protocol values.
    let payload_count_offset = xparq::codec::canonical_bytes(&block.header)
        .expect("header encoding")
        .len()
        + xparq::codec::canonical_bytes(&block.height)
            .expect("height encoding")
            .len()
        + xparq::codec::canonical_bytes(&block.body.emission)
            .expect("emission encoding")
            .len();
    let mut hostile = encoded;
    if hostile.len() >= payload_count_offset + 4 {
        let prefix = match data.get(1).copied().unwrap_or(0) % 3 {
            0 => u32::MAX,
            1 => xparq::block::MAX_BLOCK_DECODE_ITEMS as u32,
            _ => xparq::block::MAX_BLOCK_DECODE_ITEMS as u32 + 1,
        };
        hostile[payload_count_offset..payload_count_offset + 4]
            .copy_from_slice(&prefix.to_le_bytes());
        let _ = xparq::codec::decode_block(&hostile);
    }
});
