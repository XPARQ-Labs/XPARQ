#![no_main]

use libfuzzer_sys::fuzz_target;
use xparq::qcash::{decode_qcash_coin_file, encode_qcash_coin_file};

fuzz_target!(|data: &[u8]| {
    if let Ok(file) = decode_qcash_coin_file(data) {
        let encoded = encode_qcash_coin_file(&file).expect("decoded QCash coin re-encodes");
        let decoded = decode_qcash_coin_file(&encoded).expect("canonical QCash coin decodes");
        assert_eq!(decoded, file);
    }
});
