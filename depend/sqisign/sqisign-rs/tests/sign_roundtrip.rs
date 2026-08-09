//! End-to-end round-trip test: keygen → sign → verify.

use sqisign_rs::keygen::keypair;
use sqisign_rs::params::Level1;
use sqisign_rs::sign::sign;
use sqisign_rs::Verifier;

type L1 = Level1;

#[test]
fn sign_verify_roundtrip() {
    let mut rng = rand::rng();

    let (pk, sk) = keypair::<L1>(&mut rng);

    let msg = b"SQIsign round-trip test message";
    let sig = sign::<L1>(&sk, &pk, msg, &mut rng).expect("signing must succeed");

    assert!(pk.verify(msg, &sig).is_ok(), "valid signature must verify");
}

#[test]
fn sign_verify_empty_message() {
    let mut rng = rand::rng();

    let (pk, sk) = keypair::<L1>(&mut rng);

    let sig = sign::<L1>(&sk, &pk, b"", &mut rng).expect("signing must succeed");

    assert!(
        pk.verify(b"", &sig).is_ok(),
        "empty message signature must verify"
    );
}

#[test]
fn sign_verify_wrong_message_fails() {
    let mut rng = rand::rng();

    let (pk, sk) = keypair::<L1>(&mut rng);
    let msg = b"correct message";
    let wrong_msg = b"wrong message";

    let sig = sign::<L1>(&sk, &pk, msg, &mut rng).expect("signing must succeed");

    assert!(
        pk.verify(wrong_msg, &sig).is_err(),
        "signature must not verify under wrong message"
    );
}

#[test]
fn sign_verify_wrong_key_fails() {
    let mut rng = rand::rng();

    let (pk1, _sk1) = keypair::<L1>(&mut rng);
    let (pk2, _sk2) = keypair::<L1>(&mut rng);

    let msg = b"test message";
    let sig = sign::<L1>(&_sk1, &pk1, msg, &mut rng).expect("signing must succeed");

    assert!(
        pk2.verify(msg, &sig).is_err(),
        "signature must not verify under wrong public key"
    );
}
