use crate::monetary::coin::Zeno;
#[cfg(test)]
use crate::operation::BlockOperation;
#[cfg(test)]
use crypto::canonical_bytes;
use crypto::canonical_length;

use crate::{
    common::{ChainContext, Height},
    consensus::{
        ProgramConsensusError, ProtocolBurn, StateTransitionWeight, created_coin_output_count,
        validate_exact_burn,
    },
    ledger::LedgerState,
    operation::{AuthorizedDeployProgram, BlockOperationRef},
    program::{AuthorizationCommitment, DeployError, ProgramId, prepare_deployment},
};

#[derive(Debug, Clone)]
pub struct PreparedDeploy {
    pub(crate) signed: AuthorizedDeployProgram,
    pub(crate) commitment: AuthorizationCommitment,
    pub(crate) program_id: ProgramId,
    pub(crate) height: Height,
    pub required_burn: crate::monetary::coin::Zeno,
}

#[derive(Debug)]
pub enum DeployConsensusError {
    Deploy(DeployError),
    Program(ProgramConsensusError),
}

pub fn validate_deploy(
    signed: AuthorizedDeployProgram,
    chain: ChainContext,
    height: Height,
    state: &LedgerState,
) -> Result<PreparedDeploy, DeployConsensusError> {
    signed
        .deploy
        .validate_structure()
        .map_err(DeployConsensusError::Deploy)?;
    signed
        .payment
        .validate()
        .map_err(|_| DeployConsensusError::Deploy(DeployError::InvalidPayment))?;
    if signed.deploy.owner != signed.payment.signer {
        return Err(DeployConsensusError::Deploy(DeployError::InvalidPayment));
    }
    let commitment = signed
        .commitment(chain)
        .map_err(|_| DeployConsensusError::Deploy(DeployError::Encoding))?;
    if !signed
        .authorization
        .verify_commitment(signed.deploy.owner, &commitment, height.0)
    {
        return Err(DeployConsensusError::Deploy(
            DeployError::InvalidAuthorization,
        ));
    }
    let (program_id, required_burn) = quote_deploy_burn(&signed, height, state)?;
    let (inputs, outputs) = signed
        .payment
        .coin_parts()
        .ok_or(DeployConsensusError::Deploy(DeployError::InvalidPayment))?;
    let fee = signed.payment.charges.miner_fee;
    let actual =
        super::program_call::validate_coin_inputs(inputs, outputs, fee, signed.deploy.owner, state)
            .map_err(DeployConsensusError::Program)?;
    validate_exact_burn(actual, required_burn)
        .map_err(ProgramConsensusError::Burn)
        .map_err(DeployConsensusError::Program)?;
    Ok(PreparedDeploy {
        signed,
        commitment,
        program_id,
        height,
        required_burn,
    })
}

/// Quote archival and registry growth burn before the owner signs the payment.
pub fn quote_deploy_burn(
    signed: &AuthorizedDeployProgram,
    height: Height,
    state: &LedgerState,
) -> Result<(ProgramId, Zeno), DeployConsensusError> {
    signed
        .deploy
        .validate_structure()
        .map_err(DeployConsensusError::Deploy)?;
    signed
        .payment
        .validate()
        .map_err(|_| DeployConsensusError::Deploy(DeployError::InvalidPayment))?;
    if signed.deploy.owner != signed.payment.signer {
        return Err(DeployConsensusError::Deploy(DeployError::InvalidPayment));
    }
    let size = canonical_length(&BlockOperationRef::DeployProgram(signed))
        .map_err(|_| DeployConsensusError::Deploy(DeployError::Encoding))?;
    if size > crate::blockchain::MAX_OPERATION_SIZE as u64 {
        return Err(DeployConsensusError::Deploy(DeployError::ProgramTooLarge));
    }
    let (program_id, record) =
        prepare_deployment(signed.deploy.clone(), height).map_err(DeployConsensusError::Deploy)?;
    state
        .programs
        .check_available(program_id, record.owner, record.nonce)
        .map_err(DeployError::Registry)
        .map_err(DeployConsensusError::Deploy)?;
    // Borsh maps use a fixed u32 count prefix, so insertion grows the encoding
    // by exactly one key/value pair, independently of registry cardinality.
    let growth = canonical_length(&(program_id, &record))
        .map_err(|_| DeployConsensusError::Deploy(DeployError::Encoding))?;
    let (inputs, outputs) = signed
        .payment
        .coin_parts()
        .ok_or(DeployConsensusError::Deploy(DeployError::InvalidPayment))?;
    let fee = signed.payment.charges.miner_fee;
    let transition = StateTransitionWeight {
        created_coin_utxos: created_coin_output_count(outputs)
            .map_err(ProgramConsensusError::Burn)
            .map_err(DeployConsensusError::Program)?
            + u64::from(!fee.is_zero()),
        consumed_coin_utxos: inputs.len() as u64,
        created_state_weight: growth,
    };
    let required_burn = ProtocolBurn::for_program_call(transition, size)
        .and_then(ProtocolBurn::total)
        .map_err(ProgramConsensusError::Burn)
        .map_err(DeployConsensusError::Program)?;
    Ok((program_id, required_burn))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monetary::coin::{CoinOutput, CoinShare};
    use crate::program::{AccountAuthorization, CoinTransition, DeployProgram, deploy_program};
    use crypto::{AccountSignatureScheme, SigningSeed, program_id_from_public_key};

    #[test]
    fn optimized_quote_matches_legacy_burn_and_does_not_mutate_state() {
        let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([0x41; 32]));
        let public_key = seed.public_key();
        let owner = program_id_from_public_key(&public_key).unwrap();
        let mut code = b"XPVM".to_vec();
        code.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0, 0]);
        code.push(1);
        code.extend_from_slice(&7_u64.to_le_bytes());
        code.push(3);
        let mut state = LedgerState::default();
        for nonce in 0..32 {
            let draft = AuthorizedDeployProgram {
                deploy: DeployProgram {
                    owner,
                    nonce,
                    code: code.clone().into(),
                },
                payment: CoinTransition::coin(
                    owner,
                    vec![CoinShare::from_bytes([0x11; crypto::HASH_SIZE])],
                    vec![CoinOutput::new(owner, Zeno::ONE)],
                )
                .unwrap(),
                authorization: AccountAuthorization {
                    salt: [0; 32],
                    public_key: public_key.clone(),
                    signature: seed.sign(b"quote-fixture"),
                },
            };
            let before = state.clone();
            assert_eq!(
                quote_deploy_burn(&draft, Height(1), &state).unwrap(),
                legacy_quote(&draft, Height(1), &state).unwrap()
            );
            assert_eq!(state, before);
            deploy_program(&mut state.programs, draft.deploy.clone(), Height(1)).unwrap();
            assert!(quote_deploy_burn(&draft, Height(1), &state).is_err());
            assert!(legacy_quote(&draft, Height(1), &state).is_err());
        }
    }
    fn legacy_quote(
        signed: &AuthorizedDeployProgram,
        height: Height,
        state: &LedgerState,
    ) -> Result<(ProgramId, Zeno), DeployConsensusError> {
        signed
            .deploy
            .validate_structure()
            .map_err(DeployConsensusError::Deploy)?;
        signed
            .payment
            .validate()
            .map_err(|_| DeployConsensusError::Deploy(DeployError::InvalidPayment))?;
        if signed.deploy.owner != signed.payment.signer {
            return Err(DeployConsensusError::Deploy(DeployError::InvalidPayment));
        }
        let size = canonical_bytes(&BlockOperation::DeployProgram(Box::new(signed.clone())))
            .map_err(|_| DeployConsensusError::Deploy(DeployError::Encoding))?
            .len();
        if size > crate::blockchain::MAX_OPERATION_SIZE {
            return Err(DeployConsensusError::Deploy(DeployError::ProgramTooLarge));
        }
        let mut registry = state.programs.clone();
        let before = canonical_bytes(&registry)
            .map_err(|_| DeployConsensusError::Deploy(DeployError::Encoding))?
            .len();
        let (program_id, _) = deploy_program(&mut registry, signed.deploy.clone(), height)
            .map_err(DeployConsensusError::Deploy)?;
        let after = canonical_bytes(&registry)
            .map_err(|_| DeployConsensusError::Deploy(DeployError::Encoding))?
            .len();
        let growth = u64::try_from(
            after
                .checked_sub(before)
                .ok_or(DeployConsensusError::Deploy(DeployError::Encoding))?,
        )
        .map_err(|_| DeployConsensusError::Deploy(DeployError::Encoding))?;
        let (inputs, outputs) = signed
            .payment
            .coin_parts()
            .ok_or(DeployConsensusError::Deploy(DeployError::InvalidPayment))?;
        let fee = signed.payment.charges.miner_fee;
        let transition = StateTransitionWeight {
            created_coin_utxos: created_coin_output_count(outputs)
                .map_err(ProgramConsensusError::Burn)
                .map_err(DeployConsensusError::Program)?
                + u64::from(!fee.is_zero()),
            consumed_coin_utxos: inputs.len() as u64,
            created_state_weight: growth,
        };
        let required_burn = ProtocolBurn::for_program_call(transition, size as u64)
            .and_then(ProtocolBurn::total)
            .map_err(ProgramConsensusError::Burn)
            .map_err(DeployConsensusError::Program)?;
        Ok((program_id, required_burn))
    }
}
