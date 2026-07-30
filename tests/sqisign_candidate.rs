#![cfg(feature = "sqisign-candidate")]

use paqus::crypto::SignatureContext;
use paqus::crypto::sqisign_candidate::{generate_keypair, sign_dual, verify_dual};

/// Level 5 key generation and signing are intentionally expensive. This test
/// is opt-in so normal CI and development builds remain fast.
#[test]
#[ignore = "expensive SQIsign Level 5 end-to-end test"]
fn level5_dual_authorization_roundtrip_and_rejections() {
    let owner = generate_keypair().expect("owner Level 5 key generation");
    let authorization = generate_keypair().expect("authorization Level 5 key generation");
    let message = b"canonical protocol transaction bytes";
    let signatures = sign_dual(
        SignatureContext::ProtocolTransaction,
        &owner.secret_key,
        &authorization.secret_key,
        message,
    )
    .expect("dual Level 5 signing");

    assert!(verify_dual(
        SignatureContext::ProtocolTransaction,
        &owner.public_key,
        &authorization.public_key,
        message,
        &signatures,
    ));
    assert!(!verify_dual(
        SignatureContext::ProtocolTransaction,
        &owner.public_key,
        &authorization.public_key,
        b"modified transaction bytes",
        &signatures,
    ));
    assert!(!verify_dual(
        SignatureContext::QCashTransaction,
        &owner.public_key,
        &authorization.public_key,
        message,
        &signatures,
    ));
    assert!(!verify_dual(
        SignatureContext::ProtocolTransaction,
        &authorization.public_key,
        &owner.public_key,
        message,
        &signatures,
    ));
}
