use super::*;
use crate::consensus::{ProtocolBurn, StateTransitionWeight};
use crate::{common::ChainContext, monetary::coin::CoinShare, operation::BlockOperation};
use crypto::{ProgramId, canonical_bytes};

use crypto::{AccountSignatureScheme, HASH_SIZE, SigningSeed, program_id_from_public_key};

use crate::{
    monetary::coin::{CoinOutput, Zeno},
    program::{
        AccountAuthorization, AuthorizedProgramInvocation, CoinTransition,
        program_invocation_commitment,
    },
};

const TEST_HEIGHT: u64 = 0;

fn seed(tag: u8) -> SigningSeed {
    SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([tag; 32]))
}

fn signer(seed: &SigningSeed) -> ProgramId {
    program_id_from_public_key(&seed.public_key()).unwrap()
}

fn chain(tag: u8) -> ChainContext {
    ChainContext::new([tag; HASH_SIZE])
}

fn coin_intent(seed: &SigningSeed, input_tag: u8, amount: u64) -> CoinTransition {
    let owner = signer(seed);

    CoinTransition::coin(
        owner,
        vec![CoinShare::from_bytes([input_tag; HASH_SIZE])],
        vec![CoinOutput::new(owner, Zeno::from_zeno(amount))],
    )
    .expect("valid coin fixture")
}

fn authorize_transfer(
    intent: CoinTransition,
    signer_seed: &SigningSeed,
    chain: ChainContext,
) -> AuthorizedProgramInvocation {
    let signer = crypto::program_id_from_public_key(&signer_seed.public_key()).unwrap();
    let call = crate::program::system::coin_program::transfer_call();
    let commitment = program_invocation_commitment(signer, &call, &intent, chain).unwrap();
    AuthorizedProgramInvocation {
        signer,
        call,
        payment: intent,
        authorization: AccountAuthorization {
            salt: [0; 32],
            public_key: signer_seed.public_key(),
            signature: signer_seed.sign(commitment.as_bytes()),
        },
    }
}

#[test]
fn deployed_vm_call_requires_registry_and_exact_fuel_burn() {
    use crate::program::system::script::call::{ProgramCall, SystemProgramId};
    use crate::{
        common::Height,
        program::{DeployProgram, ProgramRegistry, deploy_program},
    };
    let owner = seed(7);
    let signer = signer(&owner);
    let chain = chain(0x37);
    let mut registry = ProgramRegistry::default();
    let mut code = b"XPVM".to_vec();
    code.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0, 0]);
    code.push(1);
    code.extend_from_slice(&42i64.to_le_bytes());
    code.push(3);
    let (id, _) = deploy_program(
        &mut registry,
        DeployProgram {
            owner: signer,
            nonce: 1,
            code: code.into(),
        },
        Height(1),
    )
    .unwrap();
    let call = ProgramCall {
        program: SystemProgramId::VM,
        opcode: 0,
        payload: id.as_bytes().to_vec(),
    };
    let input = CoinShare::from_bytes([9; HASH_SIZE]);
    let input_amount = Zeno::from_zeno(1_000_000);
    struct VmState {
        registry: ProgramRegistry,
        signer: ProgramId,
        input: CoinShare,
        input_amount: Zeno,
    }
    impl ProgramStateView for VmState {
        fn registry(&self) -> Option<&ProgramRegistry> {
            Some(&self.registry)
        }
        fn coin(&self, id: CoinShare) -> Option<CoinInputState> {
            (id == self.input).then_some(CoinInputState {
                amount: self.input_amount,
                owner: crate::common::Owner::Program(self.signer),
            })
        }
    }
    let state = VmState {
        registry,
        signer,
        input,
        input_amount,
    };
    let sign = |burn: u64| {
        let payment = CoinTransition::coin_with_charges(
            signer,
            vec![input],
            vec![CoinOutput::new(
                signer,
                Zeno::from_zeno(input_amount.as_zeno() - burn - 1),
            )],
            crate::program::CoinCharges::new(Zeno::ONE),
        )
        .unwrap();
        let commitment = program_invocation_commitment(signer, &call, &payment, chain).unwrap();
        AuthorizedProgramInvocation {
            signer,
            call: call.clone(),
            payment,
            authorization: AccountAuthorization {
                salt: [0; 32],
                public_key: owner.public_key(),
                signature: owner.sign(commitment.as_bytes()),
            },
        }
    };
    let provisional = sign(0);
    let size = canonical_bytes(&BlockOperation::ProgramCall(Box::new(provisional)))
        .unwrap()
        .len() as u64;
    let transition = StateTransitionWeight {
        created_coin_utxos: 2,
        consumed_coin_utxos: 1,
        created_state_weight: 0,
    };
    let base = ProtocolBurn::for_program_call(transition, size)
        .unwrap()
        .total()
        .unwrap()
        .as_zeno();
    let fuel = 2;
    let accepted = sign(base + fuel);
    assert_eq!(
        validate_program_call(accepted.clone(), chain, 1, &state)
            .unwrap()
            .required_burn
            .as_zeno(),
        base + fuel
    );
    assert!(matches!(
        validate_program_call(sign(base), chain, 1, &state),
        Err(ProgramConsensusError::Burn(_))
    ));
    let empty = VmState {
        registry: ProgramRegistry::default(),
        ..state
    };
    assert!(matches!(
        validate_program_call(accepted, chain, 1, &empty),
        Err(ProgramConsensusError::Vm(
            crate::program::vm::ExecutionError::UnknownProgram
        ))
    ));
}

#[test]
fn valid_transfer_call_passes_consensus_authorization_gate() {
    let owner = seed(1);
    let chain = chain(0x11);
    let intent = coin_intent(&owner, 1, 10);

    let call = authorize_transfer(intent, &owner, chain);
    struct EmptyState;
    impl ProgramStateView for EmptyState {
        fn coin(&self, _: CoinShare) -> Option<CoinInputState> {
            None
        }
    }
    assert!(matches!(
        validate_program_call(call, chain, TEST_HEIGHT, &EmptyState),
        Err(ProgramConsensusError::UtxoNotFound)
    ));
}

#[test]
fn cross_chain_transaction_is_rejected_before_state_validation() {
    let owner = seed(2);
    let chain_a = chain(0x21);
    let chain_b = chain(0x22);
    let intent = coin_intent(&owner, 2, 10);

    let call = authorize_transfer(intent, &owner, chain_a);
    struct EmptyState;
    impl ProgramStateView for EmptyState {
        fn coin(&self, _: CoinShare) -> Option<CoinInputState> {
            None
        }
    }

    assert!(matches!(
        validate_program_call(call, chain_b, TEST_HEIGHT, &EmptyState),
        Err(ProgramConsensusError::InvalidAuthorization)
    ));
}
