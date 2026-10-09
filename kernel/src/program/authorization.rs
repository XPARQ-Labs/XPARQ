use borsh::{BorshDeserialize, BorshSerialize};

use crate::program::system::script::{call::ProgramCall, execute::decode_program};
use crypto::{
    AccountSignature, HASH_SIZE, HashDomain, ProgramId, PublicKey, canonical_bytes, domain,
};

use crate::common::ChainContext;
use crate::program::{CoinTransition, IntentError};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum AuthorizationRole {
    Principal = 1,
    Payment = 2,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct AuthorizationCommitment([u8; HASH_SIZE]);

impl AuthorizationCommitment {
    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; HASH_SIZE] {
        self.0
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct ProgramIntentId([u8; HASH_SIZE]);

impl ProgramIntentId {
    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; HASH_SIZE] {
        self.0
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct ProgramInvocationId([u8; HASH_SIZE]);

impl ProgramInvocationId {
    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; HASH_SIZE] {
        self.0
    }
}

const TRANSACTION_INTENT_ID_TAG: [u8; 27] = *b"xparq:transaction-intent:v1";

const INTENT_KIND_PROGRAM_CALL: u8 = 4;

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AccountAuthorization {
    pub salt: crypto::AccountSalt,
    pub public_key: PublicKey,
    pub signature: AccountSignature,
}

impl AccountAuthorization {
    pub fn has_matching_scheme(&self) -> bool {
        self.public_key.scheme() == self.signature.scheme()
    }

    pub fn active_at_height(&self, _height: u64) -> bool {
        self.has_matching_scheme() && self.public_key.scheme().supported()
    }

    pub fn verify_commitment(
        &self,
        sender: ProgramId,
        commitment: &AuthorizationCommitment,
        height: u64,
    ) -> bool {
        super::system::signature_policy::authorize(sender, commitment, self, height)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AuthorizedProgramInvocation {
    pub signer: ProgramId,
    pub call: ProgramCall,
    pub payment: CoinTransition,
    pub authorization: AccountAuthorization,
}

impl AuthorizedProgramInvocation {
    pub fn validate_structure(&self) -> Result<(), IntentError> {
        decode_program(&self.call).map_err(|_| IntentError::InvalidAssetCall)?;
        self.payment.validate()?;
        if self.signer != self.payment.signer {
            return Err(IntentError::InvalidAssetCall);
        }
        Ok(())
    }

    pub fn verify_authorizations(
        &self,
        chain: ChainContext,
        height: u64,
    ) -> Result<bool, IntentError> {
        if !self.authorization.active_at_height(height)
            || !self.authorization.public_key.is_valid_encoding()
            || !self.authorization.signature.is_valid_encoding()
        {
            return Ok(false);
        }
        let commitment =
            program_invocation_commitment(self.signer, &self.call, &self.payment, chain)?;
        Ok(self
            .authorization
            .verify_commitment(self.signer, &commitment, height))
    }
}

/// One signature binds the program call and its XPQ payment to this chain.
pub fn program_invocation_commitment(
    signer: ProgramId,
    call: &ProgramCall,
    payment: &CoinTransition,
    chain: ChainContext,
) -> Result<AuthorizationCommitment, IntentError> {
    decode_program(call).map_err(|_| IntentError::InvalidAssetCall)?;
    payment.validate()?;
    if signer != payment.signer {
        return Err(IntentError::InvalidAssetCall);
    }
    let bytes = canonical_bytes(&(
        chain.genesis_hash,
        AuthorizationRole::Principal,
        b"xparq:program-transaction:v1",
        signer,
        call,
        payment,
    ))
    .map_err(|_| IntentError::Encoding)?;
    Ok(AuthorizationCommitment::from_bytes(
        domain(HashDomain::AssetIntent, &bytes).into_bytes(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum AuthorizedProgramEnvelope {
    Program(Box<AuthorizedProgramInvocation>),
}

impl AuthorizedProgramEnvelope {
    pub fn program_invocation_id(&self) -> Result<ProgramInvocationId, IntentError> {
        let bytes = canonical_bytes(self).map_err(|_| IntentError::Encoding)?;

        Ok(ProgramInvocationId::from_bytes(
            domain(HashDomain::Transaction, &bytes).into_bytes(),
        ))
    }

    pub fn intent_id(&self) -> Result<ProgramIntentId, IntentError> {
        self.validate_structure()
            .map_err(|_| IntentError::Encoding)?;

        let bytes = match self {
            Self::Program(tx) => canonical_bytes(&(
                TRANSACTION_INTENT_ID_TAG,
                INTENT_KIND_PROGRAM_CALL,
                tx.signer,
                &tx.call,
                &tx.payment,
            )),
        }
        .map_err(|_| IntentError::Encoding)?;

        Ok(ProgramIntentId::from_bytes(
            domain(HashDomain::Transaction, &bytes).into_bytes(),
        ))
    }

    pub fn id(&self) -> Result<[u8; HASH_SIZE], IntentError> {
        Ok(self.program_invocation_id()?.into_bytes())
    }

    pub fn validate_structure(&self) -> Result<(), IntentError> {
        match self {
            Self::Program(tx) => tx.validate_structure(),
        }
    }

    pub fn verify_authorizations(
        &self,
        chain: ChainContext,
        height: u64,
    ) -> Result<bool, IntentError> {
        self.validate_structure()?;

        match self {
            Self::Program(tx) => tx.verify_authorizations(chain, height),
        }
    }
}

#[cfg(test)]
mod program_transaction_tests {
    use super::*;
    use crate::program::system::{
        asset_program::{asset::Unit, opcode::AssetOpcode, type_::Register},
        script::call::SystemProgramId,
    };
    use crate::{
        consensus::{
            CoinInputState, ProgramConsensusError, ProgramStateView, validate_program_call,
        },
        monetary::coin::{CoinOutput, CoinShare, Zeno},
    };
    use crypto::{AccountSignatureScheme, SigningSeed, program_id_from_public_key};

    struct EmptyState;
    impl ProgramStateView for EmptyState {
        fn coin(&self, _: CoinShare) -> Option<CoinInputState> {
            None
        }
    }

    #[test]
    fn malformed_in_memory_public_key_cannot_authorize_a_commitment() {
        let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([14; 32]));
        let public_key = seed.public_key();
        let sender = program_id_from_public_key(&public_key).unwrap();
        let commitment = AuthorizationCommitment::from_bytes([8; HASH_SIZE]);
        let mut authorization = AccountAuthorization {
            salt: [0; 32],
            public_key,
            signature: seed.sign(commitment.as_bytes()),
        };
        assert!(authorization.verify_commitment(sender, &commitment, 0));
        authorization.public_key.bytes.pop();
        assert!(!authorization.verify_commitment(sender, &commitment, 0));
    }

    #[test]
    fn program_envelope_binds_payment_and_requires_state_view() {
        let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([14; 32]));
        let signer = program_id_from_public_key(&seed.public_key()).unwrap();
        let chain = ChainContext::new([8; HASH_SIZE]);
        let call = ProgramCall {
            program: SystemProgramId::ASSET,
            opcode: AssetOpcode::Register as u8,
            payload: borsh::to_vec(&Register {
                name: "PROGRAM".into(),
                max_supply: Unit::from_units(100),
                initial_mint: Unit::from_units(10),
                mint_authority: crate::common::Owner::Program(signer),
                nonce: 1,
            })
            .unwrap(),
        };
        let payment = CoinTransition::coin(
            signer,
            vec![CoinShare::from_bytes([1; crypto::HASH_SIZE])],
            vec![CoinOutput::new(signer, Zeno::from_zeno(1))],
        )
        .unwrap();
        let commitment = program_invocation_commitment(signer, &call, &payment, chain).unwrap();
        let signed = AuthorizedProgramInvocation {
            signer,
            call,
            payment,
            authorization: AccountAuthorization {
                salt: [0; 32],
                public_key: seed.public_key(),
                signature: seed.sign(commitment.as_bytes()),
            },
        };
        assert!(signed.verify_authorizations(chain, 0).unwrap());
        assert!(
            !signed
                .verify_authorizations(ChainContext::new([9; HASH_SIZE]), 0)
                .unwrap()
        );
        let mut changed = signed.clone();
        changed.payment.charges.miner_fee = Zeno::from_zeno(1);
        assert!(!changed.verify_authorizations(chain, 0).unwrap());
        let mut changed_call = signed.clone();
        changed_call.call.payload[4] ^= 1;
        assert!(!changed_call.verify_authorizations(chain, 0).unwrap());
        let mut changed_signer = signed.clone();
        changed_signer.signer = ProgramId::ZERO;
        changed_signer.payment.signer = ProgramId::ZERO;
        assert!(!changed_signer.verify_authorizations(chain, 0).unwrap());
        let transaction = AuthorizedProgramEnvelope::Program(Box::new(signed.clone()));
        let encoded = borsh::to_vec(&transaction).unwrap();
        assert_eq!(
            AuthorizedProgramEnvelope::try_from_slice(&encoded).unwrap(),
            transaction
        );
        assert!(matches!(
            validate_program_call(signed, chain, 0, &EmptyState),
            Err(ProgramConsensusError::Intent(IntentError::InvalidAssetCall))
        ));
    }
}
