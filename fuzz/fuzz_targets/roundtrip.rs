#![no_main]

use libfuzzer_sys::fuzz_target;
use paqus::block::Height;

fuzz_target!(|data: &[u8]| {
    if let Ok(block) = paqus::codec::decode_block(data)
        && let Ok(encoded) = paqus::codec::block_bytes(&block)
    {
        assert_eq!(
            paqus::codec::decode_block(&encoded).ok().as_ref(),
            Some(&block)
        );
    }

    if let Ok(transaction) =
        paqus::codec::decode_signed_protocol_transaction_at(data, Height(0), 0, ())
        && let Ok(encoded) = paqus::codec::signed_protocol_transaction_bytes(&transaction)
    {
        assert_eq!(
            paqus::codec::decode_signed_protocol_transaction_at(&encoded, Height(0), 0, ())
                .ok()
                .as_ref(),
            Some(&transaction)
        );
    }
});
