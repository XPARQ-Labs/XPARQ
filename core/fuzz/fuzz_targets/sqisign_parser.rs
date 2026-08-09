#![no_main]

use libfuzzer_sys::fuzz_target;
use sqisign_rs::{Level1, Level3, Level5, PublicKey, Signature, SigningKey};

fn parse_level1(kind: u8, bytes: &[u8]) {
    match kind % 3 {
        0 => {
            let _ = PublicKey::<Level1>::from_bytes(bytes);
        }
        1 => {
            let _ = Signature::<Level1>::from_bytes(bytes);
        }
        _ => {
            let _ = SigningKey::<Level1>::from_bytes(bytes);
        }
    }
}

fn parse_level3(kind: u8, bytes: &[u8]) {
    match kind % 3 {
        0 => {
            let _ = PublicKey::<Level3>::from_bytes(bytes);
        }
        1 => {
            let _ = Signature::<Level3>::from_bytes(bytes);
        }
        _ => {
            let _ = SigningKey::<Level3>::from_bytes(bytes);
        }
    }
}

fn parse_level5(kind: u8, bytes: &[u8]) {
    match kind % 3 {
        0 => {
            let _ = PublicKey::<Level5>::from_bytes(bytes);
        }
        1 => {
            let _ = Signature::<Level5>::from_bytes(bytes);
        }
        _ => {
            let _ = SigningKey::<Level5>::from_bytes(bytes);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, bytes)) = data.split_first() else {
        return;
    };
    let level = selector / 3;
    let kind = selector % 3;
    match level % 3 {
        0 => parse_level1(kind, bytes),
        1 => parse_level3(kind, bytes),
        _ => parse_level5(kind, bytes),
    }
});
