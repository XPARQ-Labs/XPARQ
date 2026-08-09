#![no_main]

use libfuzzer_sys::fuzz_target;
use xparq::block::Height;

fuzz_target!(|data: &[u8]| {
    let _ = xparq::codec::decode_protocol_event(data);
    let _ = xparq::codec::decode_signed_protocol_transaction_at(data, Height(0), |_| None);
});
