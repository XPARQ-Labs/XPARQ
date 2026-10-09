use borsh::{BorshDeserialize, BorshSerialize};
use crypto::{Hash, HashDomain, canonical_bytes, domain};

use crate::{
    common::ChainContext,
    error::CodecError,
    program::DeployProgram,
    program::{
        AccountAuthorization, AuthorizationCommitment, AuthorizedProgramEnvelope,
        AuthorizedProgramInvocation, CoinTransition, ProgramHash,
    },
};

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedDeployProgram {
    pub deploy: DeployProgram,
    pub payment: CoinTransition,
    pub authorization: AccountAuthorization,
}

impl AuthorizedDeployProgram {
    pub fn commitment(&self, chain: ChainContext) -> Result<AuthorizationCommitment, CodecError> {
        let code_hash =
            ProgramHash::derive(&self.deploy.code).map_err(|_| CodecError::EncodeFailed)?;
        let bytes = canonical_bytes(&(
            b"xparq:deploy-program:v1",
            chain.genesis_hash,
            self.deploy.owner,
            self.deploy.nonce,
            code_hash,
            &self.payment,
        ))
        .map_err(|_| CodecError::EncodeFailed)?;
        Ok(AuthorizationCommitment::from_bytes(
            domain(HashDomain::XPARQArtifact, &bytes).into_bytes(),
        ))
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum BlockOperation {
    DeployProgram(Box<AuthorizedDeployProgram>),
    ProgramCall(Box<AuthorizedProgramInvocation>),
}

/// Borrowed wire view: variant order and payload encoding match BlockOperation.
/// Used to measure canonical size without cloning transaction payloads.
#[derive(BorshSerialize)]
pub enum BlockOperationRef<'a> {
    DeployProgram(&'a AuthorizedDeployProgram),
    ProgramCall(&'a AuthorizedProgramInvocation),
}

impl<'a> From<&'a BlockOperation> for BlockOperationRef<'a> {
    fn from(operation: &'a BlockOperation) -> Self {
        match operation {
            BlockOperation::DeployProgram(deploy) => Self::DeployProgram(deploy),
            BlockOperation::ProgramCall(call) => Self::ProgramCall(call),
        }
    }
}

impl BlockOperation {
    pub fn id(&self) -> Result<Hash, CodecError> {
        let bytes = canonical_bytes(self).map_err(|_| CodecError::EncodeFailed)?;

        Ok(domain(HashDomain::Operation, &bytes))
    }

    pub fn validate_structure(&self) -> Result<(), OperationError> {
        match self {
            Self::DeployProgram(operation) => operation
                .deploy
                .validate_structure()
                .and_then(|_| {
                    operation
                        .payment
                        .validate()
                        .map_err(|_| crate::program::DeployError::InvalidPayment)
                })
                .map_err(|_| OperationError::InvalidDeploy),

            Self::ProgramCall(operation) => operation
                .validate_structure()
                .map_err(|_| OperationError::InvalidProgramCall),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationError {
    InvalidDeploy,
    InvalidProgramCall,
}

impl BlockOperation {
    pub fn as_program_call(&self) -> Option<&AuthorizedProgramInvocation> {
        match self {
            Self::ProgramCall(call) => Some(call),
            Self::DeployProgram(_) => None,
        }
    }

    pub fn into_program_call(self) -> Option<Box<AuthorizedProgramInvocation>> {
        match self {
            Self::ProgramCall(call) => Some(call),
            Self::DeployProgram(_) => None,
        }
    }
}

impl From<AuthorizedProgramEnvelope> for BlockOperation {
    fn from(transaction: AuthorizedProgramEnvelope) -> Self {
        match transaction {
            AuthorizedProgramEnvelope::Program(call) => Self::ProgramCall(call),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        monetary::coin::{CoinOutput, CoinShare, Zeno},
        program::CoinTransition,
    };
    use crypto::{AccountSignatureScheme, SigningSeed, program_id_from_public_key};

    fn deploy_operation(code: Vec<u8>) -> BlockOperation {
        let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([0x41; 32]));

        let public_key = seed.public_key();
        let owner = program_id_from_public_key(&public_key).unwrap();

        BlockOperation::DeployProgram(Box::new(AuthorizedDeployProgram {
            deploy: DeployProgram {
                owner,
                nonce: 1,
                code: code.into(),
            },
            payment: CoinTransition::coin(
                owner,
                vec![CoinShare::from_bytes([0x11; crypto::HASH_SIZE])],
                vec![CoinOutput::new(owner, Zeno::ONE)],
            )
            .unwrap(),
            authorization: AccountAuthorization {
                salt: [0; 32],
                public_key,
                signature: seed.sign(b"xparq-operation-test"),
            },
        }))
    }

    fn size_fixtures(bytes: usize, inputs: usize) -> [BlockOperation; 2] {
        let deploy = deploy_operation(vec![7; bytes]);
        let BlockOperation::DeployProgram(ref signed) = deploy else {
            unreachable!()
        };
        let input_ids = (0..inputs)
            .map(|index| {
                let mut id = [0; crypto::HASH_SIZE];
                id[..8].copy_from_slice(&(index as u64).to_le_bytes());
                CoinShare::from_bytes(id)
            })
            .collect();
        let call = BlockOperation::ProgramCall(Box::new(AuthorizedProgramInvocation {
            signer: signed.deploy.owner,
            call: crate::program::system::script::call::ProgramCall {
                program: crate::program::system::script::call::SystemProgramId::VM,
                opcode: 0,
                payload: vec![5; bytes],
            },
            payment: CoinTransition::coin(
                signed.deploy.owner,
                input_ids,
                vec![CoinOutput::new(signed.deploy.owner, Zeno::ONE)],
            )
            .unwrap(),
            authorization: signed.authorization.clone(),
        }));
        [deploy, call]
    }

    #[test]
    fn borrowed_operation_encoding_and_size_match_owned_wire_format() {
        for (bytes, inputs) in [(0, 1), (32, 79), (65536, 256), (2 * 1024 * 1024, 1)] {
            for (tag, operation) in size_fixtures(bytes, inputs).iter().enumerate() {
                let owned = canonical_bytes(operation).unwrap();
                let borrowed = BlockOperationRef::from(operation);
                assert_eq!(owned[0], tag as u8);
                assert_eq!(canonical_bytes(&borrowed).unwrap(), owned);
                assert_eq!(
                    crypto::canonical_length(&borrowed).unwrap(),
                    owned.len() as u64
                );
                assert_eq!(
                    crypto::canonical_length(operation).unwrap(),
                    owned.len() as u64
                );
                assert_eq!(
                    owned.len() > crate::blockchain::MAX_OPERATION_SIZE,
                    crypto::canonical_length(&borrowed).unwrap()
                        > crate::blockchain::MAX_OPERATION_SIZE as u64
                );
            }
        }
    }

    #[test]
    #[ignore = "manual transaction size benchmark; use release mode and --nocapture"]
    fn benchmark_borrowed_operation_size() {
        use std::{hint::black_box, time::Instant};
        for (name, operation) in ["deploy", "call"]
            .into_iter()
            .zip(size_fixtures(65536, 256))
        {
            let expected = canonical_bytes(&operation).unwrap().len() as u64;
            let rounds = 1000;
            let start = Instant::now();
            for _ in 0..rounds {
                let cloned = black_box(&operation).clone();
                assert_eq!(
                    black_box(canonical_bytes(&cloned).unwrap().len() as u64),
                    expected
                );
            }
            let old = start.elapsed();
            let start = Instant::now();
            for _ in 0..rounds {
                assert_eq!(
                    black_box(
                        crypto::canonical_length(&BlockOperationRef::from(black_box(&operation)))
                            .unwrap()
                    ),
                    expected
                );
            }
            let new = start.elapsed();
            println!(
                "kind={name} bytes={expected} rounds={rounds} clone_vec_ms={:.3} borrowed_count_ms={:.3}",
                old.as_secs_f64() * 1000.0,
                new.as_secs_f64() * 1000.0
            );
        }
    }

    #[test]
    fn operation_id_is_deterministic() {
        let operation = deploy_operation(vec![0x01, 0x02]);

        assert_eq!(operation.id().unwrap(), operation.clone().id().unwrap());
    }

    #[test]
    fn different_deploy_code_produces_different_operation_id() {
        let first = deploy_operation(vec![0x01]);
        let second = deploy_operation(vec![0x02]);

        assert_ne!(first.id().unwrap(), second.id().unwrap());
    }

    #[test]
    fn empty_deploy_operation_is_structurally_invalid() {
        let operation = deploy_operation(vec![]);

        assert!(matches!(
            operation.validate_structure(),
            Err(OperationError::InvalidDeploy)
        ));
    }

    #[test]
    fn valid_deploy_operation_is_structurally_valid() {
        let mut code = b"XPVM".to_vec();
        code.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0, 0]);
        code.push(1);
        code.extend_from_slice(&7u64.to_le_bytes());
        code.push(3);
        let operation = deploy_operation(code);

        assert!(operation.validate_structure().is_ok());
    }
}
