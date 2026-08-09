#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = xparq::codec::decode_transaction(data);
    let _ = xparq::codec::decode_signed_transaction(data);
    let _ = xparq::codec::decode_qcash_transaction(data);
    let _ = xparq::codec::decode_signed_qcash_transaction(data);
});
