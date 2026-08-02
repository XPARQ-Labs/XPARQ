#![no_main]

use libfuzzer_sys::fuzz_target;
use paqus::block::Height;

fuzz_target!(|data: &[u8]| {
    let _ = paqus::codec::decode_protocol_event(data);
    let _ = paqus::codec::decode_signed_protocol_transaction_at(data, Height(0), 0);
});
