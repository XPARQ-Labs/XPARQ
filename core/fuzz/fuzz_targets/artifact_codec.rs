#![no_main]

use libfuzzer_sys::fuzz_target;
use xparq::genesis::{decode_genesis_xparq, decode_xparq_artifact, encode_xparq_artifact};

fuzz_target!(|data: &[u8]| {
    if let Ok(artifact) = decode_xparq_artifact(data) {
        let encoded = encode_xparq_artifact(&artifact).expect("decoded artifact re-encodes");
        assert_eq!(decode_xparq_artifact(&encoded), Ok(artifact));
    }
    let _ = decode_genesis_xparq(data);
});
