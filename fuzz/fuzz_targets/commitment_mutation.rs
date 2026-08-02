#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let original = support::mixed_family_block();
    original
        .validate_structure()
        .expect("mixed-family fixture must be structurally valid");

    let mut mutated = original.clone();
    match data.first().copied().unwrap_or(0) % 3 {
        0 => mutated.header.merkle_root.0[0] ^= 1,
        1 => mutated.header.block_weight = mutated.header.block_weight.saturating_add(1),
        _ => {
            mutated.body.transactions[0]
                .authorization_proof_mut()
                .signature
                .0[0] ^= 1
        }
    }
    assert!(
        mutated.validate_structure().is_err(),
        "mutated transaction commitment was accepted"
    );
});
