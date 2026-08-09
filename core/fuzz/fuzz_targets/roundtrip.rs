#![no_main]

use libfuzzer_sys::fuzz_target;
use xparq::block::Height;

fuzz_target!(|data: &[u8]| {
    if let Ok(block) = xparq::codec::decode_block(data)
        && let Ok(encoded) = xparq::codec::block_bytes(&block)
    {
        assert_eq!(
            xparq::codec::decode_block(&encoded).ok().as_ref(),
            Some(&block)
        );
    }

    if let Ok(transaction) =
        xparq::codec::decode_signed_protocol_transaction_at(data, Height(0), |_| None)
        && let Ok(encoded) = xparq::codec::signed_protocol_transaction_bytes(&transaction)
    {
        assert_eq!(
            xparq::codec::decode_signed_protocol_transaction_at(&encoded, Height(0), |_| None)
                .ok()
                .as_ref(),
            Some(&transaction)
        );
    }
});
