//! Program-state execution and coin-payment rollback regression.

use crate::{
    ledger::{CoinUtxo, LedgerState},
    monetary::coin::{CoinShare, Zeno},
    program::CoinTransition,
};

use crate::program::system::script::call::{ProgramCall, SystemProgramId};
use crate::{
    common::{ChainContext, Height},
    consensus::{ProtocolBurn, StateTransitionWeight},
    monetary::coin::CoinOutput,
    operation::BlockOperation,
    program::{
        AccountAuthorization, AuthorizedProgramInvocation, CoinCharges, DeployProgram,
        program_invocation_commitment,
    },
};
use crypto::{AccountSignatureScheme, SigningSeed, canonical_bytes, program_id_from_public_key};

#[test]
fn vm_state_call_updates_root_and_rolls_back_with_coin_payment() {
    let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([0x53; 32]));
    let owner = program_id_from_public_key(&seed.public_key()).unwrap();
    let chain = ChainContext::new([0x91; crypto::HASH_SIZE]);
    let mut state = LedgerState::default();
    let input = CoinShare::from_bytes([0x23; crypto::HASH_SIZE]);
    let amount = Zeno::from_zeno(1_000_000);
    state
        .utxos
        .insert_coin(
            input,
            CoinUtxo {
                amount,
                owner: crate::common::Owner::Program(owner),
            },
        )
        .unwrap();
    state.coin.total_mined = amount;
    let mut code = b"XPVM".to_vec();
    code.extend_from_slice(&[1, 2, 0, 0, 0, 0, 0, 0, 0]);
    code.push(0x04);
    code.push(0x01);
    code.extend_from_slice(&1i64.to_le_bytes());
    code.extend_from_slice(&[0x02, 0x05, 0x04, 0x03]);
    let (id, _) = crate::program::deploy_program(
        &mut state.programs,
        DeployProgram {
            owner,
            nonce: 1,
            code: code.into(),
        },
        Height(1),
    )
    .unwrap();
    let before = state.clone();
    let before_root = state.application_state_root().unwrap();
    let call = ProgramCall {
        program: SystemProgramId::VM,
        opcode: 0,
        payload: id.as_bytes().to_vec(),
    };
    let sign = |burn: u64| {
        let payment = CoinTransition::coin_with_charges(
            owner,
            vec![input],
            vec![CoinOutput::new(
                owner,
                Zeno::from_zeno(amount.as_zeno() - burn - 1),
            )],
            CoinCharges::new(Zeno::ONE),
        )
        .unwrap();
        let commitment = program_invocation_commitment(owner, &call, &payment, chain).unwrap();
        AuthorizedProgramInvocation {
            signer: owner,
            call: call.clone(),
            payment,
            authorization: AccountAuthorization {
                salt: [0; 32],
                public_key: seed.public_key(),
                signature: seed.sign(commitment.as_bytes()),
            },
        }
    };
    let size = canonical_bytes(&BlockOperation::ProgramCall(Box::new(sign(0))))
        .unwrap()
        .len() as u64;
    let base = ProtocolBurn::for_program_call(
        StateTransitionWeight {
            created_coin_utxos: 2,
            consumed_coin_utxos: 1,
            created_state_weight: 0,
        },
        size,
    )
    .unwrap()
    .total()
    .unwrap()
    .as_zeno();
    let journal = state
        .apply_program_call(sign(base + 12), owner, chain, 2)
        .unwrap();
    assert_eq!(state.programs.program(&id).unwrap().state_value, 1);
    assert_ne!(state.application_state_root().unwrap(), before_root);
    state.rollback_state(journal).unwrap();
    assert_eq!(state, before);
    assert_eq!(state.application_state_root().unwrap(), before_root);
}
