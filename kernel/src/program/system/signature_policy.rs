//! Stateless system authorization program. An instance is configured by the
//! canonical scheme/public-key/salt hash. The key is revealed in its spending proof.
use crate::program::{AccountAuthorization, AuthorizationCommitment, ProgramId};
use crypto::{program_id_from_public_key_with_salt, verify};

pub fn authorize(
    instance: ProgramId,
    commitment: &AuthorizationCommitment,
    proof: &AccountAuthorization,
    height: u64,
) -> bool {
    if !proof.active_at_height(height) {
        return false;
    }
    let Ok(identity) = program_id_from_public_key_with_salt(&proof.public_key, &proof.salt) else {
        return false;
    };
    instance == identity && verify(&proof.public_key, commitment.as_bytes(), &proof.signature)
}
