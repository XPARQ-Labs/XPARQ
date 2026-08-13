#![cfg(feature = "sqisign-candidate")]

use xparq::crypto::SignatureContext;
use xparq::crypto::sqisign_candidate::{generate_keypair, sign, verify};

/// Level 5 key generation and signing are intentionally expensive. This test
/// is opt-in so normal CI and development builds remain fast.
#[test]
#[ignore = "expensive SQIsign Level 5 end-to-end test"]
fn level5_single_authority_roundtrip_and_rejections() {
    let signer = generate_keypair().expect("Level 5 key generation");
    let message = b"canonical protocol transaction bytes";
    let signature = sign(
        SignatureContext::ProtocolTransaction,
        &signer.secret_key,
        message,
    )
    .expect("Level 5 signing");

    assert!(verify(
        SignatureContext::ProtocolTransaction,
        &signer.public_key,
        message,
        &signature,
    ));
    assert!(!verify(
        SignatureContext::ProtocolTransaction,
        &signer.public_key,
        b"modified transaction bytes",
        &signature,
    ));
    assert!(!verify(
        SignatureContext::QCashTransaction,
        &signer.public_key,
        message,
        &signature,
    ));
}
