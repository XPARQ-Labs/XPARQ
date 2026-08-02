#![no_main]

use libfuzzer_sys::fuzz_target;
use paqus::genesis::{decode_genesis_paqus, decode_paqus_artifact, encode_paqus_artifact};

fuzz_target!(|data: &[u8]| {
    if let Ok(artifact) = decode_paqus_artifact(data) {
        let encoded = encode_paqus_artifact(&artifact).expect("decoded artifact re-encodes");
        assert_eq!(decode_paqus_artifact(&encoded), Ok(artifact));
    }
    let _ = decode_genesis_paqus(data);
});
