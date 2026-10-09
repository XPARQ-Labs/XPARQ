//! Active payment, authorization, execution and rollback regression tests.

use super::*;
use crate::program::{AccountAuthorization, system::script::call::ProgramCall};
use crypto::ProgramId;

mod payment_tests {
    use super::*;
    use crate::program::system::{
        asset_program::{asset::Unit, opcode::AssetOpcode, type_::Register},
        script::call::SystemProgramId,
    };
    use crate::{
        consensus::{ProtocolBurn, StateTransitionWeight},
        ledger::{CoinUtxo, LedgerState},
        monetary::coin::{CoinOutput, CoinShare, Zeno},
        program::{AuthorizedProgramEnvelope, AuthorizedProgramInvocation, CoinTransition},
    };
    use crypto::{AccountSignatureScheme, SigningSeed, program_id_from_public_key};

    #[test]
    fn payment_requires_exact_burn_and_binds_call_without_mutating_state() {
        let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([19; 32]));
        let signer = program_id_from_public_key(&seed.public_key()).unwrap();
        let chain = ChainContext::new([7; 32]);
        let input = CoinShare::from_bytes([2; crypto::HASH_SIZE]);
        let call = ProgramCall {
            program: SystemProgramId::ASSET,
            opcode: AssetOpcode::Register as u8,
            payload: borsh::to_vec(&Register {
                name: "STAGED".into(),
                max_supply: Unit::from_units(100),
                initial_mint: Unit::from_units(10),
                mint_authority: crate::common::Owner::Program(signer),
                nonce: 1,
            })
            .unwrap(),
        };
        let mut state = LedgerState::default();
        state
            .utxos
            .insert_coin(
                input,
                CoinUtxo {
                    owner: crate::common::Owner::Program(signer),
                    amount: Zeno::from_zeno(1_000_000),
                },
            )
            .unwrap();
        let original = state.clone();
        let payment = CoinTransition::coin(
            signer,
            vec![input],
            vec![CoinOutput::new(signer, Zeno::from_zeno(1))],
        )
        .unwrap();
        let sign = |payment: CoinTransition| {
            let commitment =
                crate::program::program_invocation_commitment(signer, &call, &payment, chain)
                    .unwrap();
            AuthorizedProgramInvocation {
                signer,
                call: call.clone(),
                payment,
                authorization: AccountAuthorization {
                    salt: [0; 32],
                    public_key: seed.public_key(),
                    signature: seed.sign(commitment.as_bytes()),
                },
            }
        };
        let tx = sign(payment);
        assert!(crate::consensus::validate_program_call(tx.clone(), chain, 0, &state).is_err());
        let mut preview = state.extensions.clone();
        let DecodedProgramCall::Asset(decoded) = decode_program(&call).unwrap() else {
            panic!("expected Asset call")
        };
        preview
            .assets
            .apply(
                &decoded,
                ExecutionContext {
                    actor: crate::common::Owner::Program(signer),
                    commitment: [1; 32],
                },
            )
            .unwrap();
        let growth = (canonical_bytes(&preview).unwrap().len()
            - canonical_bytes(&state.extensions).unwrap().len()) as u64;
        let size = canonical_bytes(&AuthorizedProgramEnvelope::Program(Box::new(tx.clone())))
            .unwrap()
            .len() as u64;
        let burn = ProtocolBurn::for_program_call(
            StateTransitionWeight {
                created_coin_utxos: 1,
                consumed_coin_utxos: 1,
                created_state_weight: growth,
            },
            size,
        )
        .unwrap()
        .total()
        .unwrap();
        let output = Zeno::from_zeno(1_000_000).checked_sub(burn).unwrap();
        let tx = sign(
            CoinTransition::coin(signer, vec![input], vec![CoinOutput::new(signer, output)])
                .unwrap(),
        );
        let prepared =
            crate::consensus::validate_program_call(tx.clone(), chain, 0, &state).unwrap();
        assert_eq!(prepared.required_burn, burn);
        assert_eq!(prepared.created_state_weight, growth);
        assert_eq!(state, original);
        let fee = Zeno::from_zeno(7);
        let fee_burn = ProtocolBurn::for_program_call(
            StateTransitionWeight {
                created_coin_utxos: 2,
                consumed_coin_utxos: 1,
                created_state_weight: growth,
            },
            size,
        )
        .unwrap()
        .total()
        .unwrap();
        let change = Zeno::from_zeno(1_000_000)
            .checked_sub(fee_burn)
            .unwrap()
            .checked_sub(fee)
            .unwrap();
        let payment = CoinTransition::coin_with_charges(
            signer,
            vec![input],
            vec![CoinOutput::new(signer, change)],
            crate::program::CoinCharges::new(fee),
        )
        .unwrap();
        assert_eq!(
            crate::consensus::validate_program_call(sign(payment), chain, 0, &state)
                .unwrap()
                .required_burn,
            fee_burn
        );
        let underpaid = CoinTransition::coin(
            signer,
            vec![input],
            vec![CoinOutput::new(
                signer,
                output.checked_add(Zeno::from_zeno(1)).unwrap(),
            )],
        )
        .unwrap();
        assert!(
            crate::consensus::validate_program_call(sign(underpaid), chain, 0, &state).is_err()
        );
        assert_eq!(state, original);
        assert!(matches!(
            crate::consensus::validate_program_call(tx, ChainContext::new([8; 32]), 0, &state),
            Err(crate::consensus::ProgramConsensusError::InvalidAuthorization)
        ));
    }
}

mod xpq_transfer_tests {
    use super::*;
    use crate::{
        consensus::{
            ProtocolBurn, StateTransitionWeight, validate_program_call as validate_consensus_call,
        },
        ledger::{CoinUtxo, LedgerState},
        monetary::coin::{CoinOutput, CoinShare, Zeno},
        program::{
            AccountAuthorization, AuthorizedProgramEnvelope, AuthorizedProgramInvocation,
            CoinCharges, CoinTransition, program_invocation_commitment,
        },
    };
    use crypto::{Signature, SigningSeed, program_id_from_public_key};

    fn fixture() -> (LedgerState, AuthorizedProgramInvocation, ChainContext) {
        fixture_for_scheme(Signature::MlDsa44, ProgramId([94; crypto::PROGRAM_ID_SIZE]))
    }

    fn fixture_for_scheme(
        scheme: Signature,
        recipient: ProgramId,
    ) -> (LedgerState, AuthorizedProgramInvocation, ChainContext) {
        let keys = SigningSeed::new(scheme, Box::new([91; 32]));
        let public_key = keys.public_key();
        let owner = program_id_from_public_key(&public_key).unwrap();
        let input = CoinShare::from_bytes([92; crypto::HASH_SIZE]);
        let amount = 1_000_000;
        let mut state = LedgerState::default();
        state.coin.total_mined = Zeno::from_zeno(amount);
        state
            .utxos
            .insert_coin(
                input,
                CoinUtxo {
                    owner: crate::common::Owner::Program(owner),
                    amount: Zeno::from_zeno(amount),
                },
            )
            .unwrap();
        let chain = ChainContext::new([93; crypto::HASH_SIZE]);
        let call = crate::program::system::coin_program::transfer_call();
        let mut size = 0;
        for _ in 0..8 {
            let fee = (size * 8).max(1);
            let burn = ProtocolBurn::for_program_call(
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
            let payment = CoinTransition::coin_with_charges(
                owner,
                vec![input],
                vec![CoinOutput::new(
                    recipient,
                    Zeno::from_zeno(amount - burn - fee),
                )],
                CoinCharges::new(Zeno::from_zeno(fee)),
            )
            .unwrap();
            let mut tx = AuthorizedProgramInvocation {
                signer: owner,
                call: call.clone(),
                payment,
                authorization: AccountAuthorization {
                    salt: [0; 32],
                    public_key: public_key.clone(),
                    signature: crypto::AccountSignature {
                        account: scheme,
                        bytes: vec![0; scheme.signature_size()],
                    },
                },
            };
            let actual = canonical_bytes(&AuthorizedProgramEnvelope::Program(Box::new(tx.clone())))
                .unwrap()
                .len() as u64;
            if actual == size {
                let commitment =
                    program_invocation_commitment(owner, &tx.call, &tx.payment, chain).unwrap();
                tx.authorization.signature = keys.sign(commitment.as_bytes());
                return (state, tx, chain);
            }
            size = actual;
        }
        panic!("native transaction size did not converge");
    }

    #[test]
    fn xpq_transfer_applies_atomically_and_rolls_back_without_asset_mutation() {
        let (mut state, tx, chain) = fixture();
        let before = state.clone();
        let prepared = validate_consensus_call(tx, chain, 1, &state).unwrap();
        assert_eq!(prepared.created_state_weight, 0);
        let journal = state
            .apply_program_call(
                prepared.invocation.clone(),
                ProgramId([95; crypto::PROGRAM_ID_SIZE]),
                chain,
                prepared.height,
            )
            .unwrap();
        assert_eq!(state.extensions, before.extensions);
        assert!(journal.extension.is_none());
        assert_ne!(state.utxos, before.utxos);
        state.rollback_state(journal).unwrap();
        assert_eq!(state, before);
    }

    #[test]
    fn slh_authorized_transfer_spends_and_rolls_back_end_to_end() {
        for scheme in crypto::AccountSignatureScheme::ALL
            .into_iter()
            .filter(|s| s.is_slh_dsa())
        {
            let (mut state, tx, chain) =
                fixture_for_scheme(scheme, ProgramId([94; crypto::PROGRAM_ID_SIZE]));
            let before = state.clone();
            let input = tx.payment.inputs[0];
            let prepared = validate_consensus_call(tx, chain, 1, &state).unwrap();
            let journal = state
                .apply_program_call(
                    prepared.invocation,
                    ProgramId([95; crypto::PROGRAM_ID_SIZE]),
                    chain,
                    1,
                )
                .unwrap();
            assert_ne!(state.utxos, before.utxos);
            assert!(state.utxos.coin(&input).is_none());
            assert_eq!(state.extensions, before.extensions);
            state.rollback_state(journal).unwrap();
            assert_eq!(state, before);
        }
    }

    #[test]
    fn xpq_transfer_binds_method_payment_and_chain_and_rejects_replay() {
        let (mut state, tx, chain) = fixture();
        let mut changed = tx.clone();
        changed.payment.charges.miner_fee = Zeno::from_zeno(1);
        assert!(!changed.verify_authorizations(chain, 1).unwrap());
        assert!(
            !tx.verify_authorizations(ChainContext::new([96; crypto::HASH_SIZE]), 1)
                .unwrap()
        );
        changed = tx.clone();
        changed.call.opcode = 2;
        assert!(changed.validate_structure().is_err());
        changed = tx.clone();
        changed.call.payload.push(0);
        assert!(changed.validate_structure().is_err());
        state
            .apply_program_call(
                tx.clone(),
                ProgramId([95; crypto::PROGRAM_ID_SIZE]),
                chain,
                1,
            )
            .unwrap();
        let after = state.clone();
        assert!(
            state
                .apply_program_call(tx, ProgramId([95; crypto::PROGRAM_ID_SIZE]), chain, 1)
                .is_err()
        );
        assert_eq!(state, after);
    }

    #[test]
    fn xpq_transfer_rejects_foreign_keys_with_same_or_different_scheme() {
        for owner_scheme in crypto::AccountSignatureScheme::ALL {
            let (mut state, tx, chain) =
                fixture_for_scheme(owner_scheme, ProgramId([94; crypto::PROGRAM_ID_SIZE]));
            validate_consensus_call(tx.clone(), chain, 1, &state).unwrap();
            let before = state.clone();
            // Preserve the ML-DSA cross-scheme matrix. Each SLH owner also
            // rejects a valid signature from a foreign key of its own scheme
            // and a foreign ML-DSA key; each ML owner rejects an SLH proof.
            let attacker_schemes = if owner_scheme.is_slh_dsa() {
                vec![owner_scheme, Signature::MlDsa44]
            } else {
                vec![
                    Signature::MlDsa44,
                    Signature::MlDsa65,
                    Signature::MlDsa87,
                    Signature::SlhDsaShake128s,
                ]
            };
            for attacker_scheme in attacker_schemes {
                let keys = SigningSeed::new(attacker_scheme, Box::new([90; 32]));
                let attacker = program_id_from_public_key(&keys.public_key()).unwrap();
                assert_ne!(attacker, tx.signer);
                let mut forged = tx.clone();
                let commitment = program_invocation_commitment(
                    forged.signer,
                    &forged.call,
                    &forged.payment,
                    chain,
                )
                .unwrap();
                forged.authorization = AccountAuthorization {
                    salt: [0; 32],
                    public_key: keys.public_key(),
                    signature: keys.sign(commitment.as_bytes()),
                };
                // The signature is valid; the ownership commitment is wrong.
                assert!(crypto::verify(
                    &forged.authorization.public_key,
                    commitment.as_bytes(),
                    &forged.authorization.signature,
                ));
                assert!(matches!(
                    validate_consensus_call(forged.clone(), chain, 1, &state),
                    Err(crate::consensus::ProgramConsensusError::InvalidAuthorization)
                ));
                assert!(
                    state
                        .apply_program_call(
                            forged,
                            ProgramId([95; crypto::PROGRAM_ID_SIZE]),
                            chain,
                            1,
                        )
                        .is_err()
                );
                assert_eq!(state, before);

                // Changing the signer cannot change the owner stored in the ledger.
                let mut rewritten = tx.clone();
                rewritten.signer = attacker;
                rewritten.payment.signer = attacker;
                let commitment = program_invocation_commitment(
                    attacker,
                    &rewritten.call,
                    &rewritten.payment,
                    chain,
                )
                .unwrap();
                rewritten.authorization = AccountAuthorization {
                    salt: [0; 32],
                    public_key: keys.public_key(),
                    signature: keys.sign(commitment.as_bytes()),
                };
                assert!(rewritten.verify_authorizations(chain, 1).unwrap());
                assert!(matches!(
                    validate_consensus_call(rewritten.clone(), chain, 1, &state),
                    Err(crate::consensus::ProgramConsensusError::RecipientMismatch)
                ));
                assert!(
                    state
                        .apply_program_call(
                            rewritten,
                            ProgramId([95; crypto::PROGRAM_ID_SIZE]),
                            chain,
                            1,
                        )
                        .is_err()
                );
                assert_eq!(state, before);
            }
        }
    }

    #[test]
    fn xpq_transfer_can_create_an_owner_with_a_different_scheme() {
        let recipient_keys = SigningSeed::new(Signature::MlDsa65, Box::new([99; 32]));
        let recipient = program_id_from_public_key(&recipient_keys.public_key()).unwrap();
        let (mut state, tx, chain) = fixture_for_scheme(Signature::MlDsa44, recipient);
        let input = tx.payment.coin_parts().unwrap().0[0];
        let amount = tx.payment.coin_parts().unwrap().1[0].amount;
        validate_consensus_call(tx.clone(), chain, 1, &state).unwrap();
        state
            .apply_program_call(tx, ProgramId([95; crypto::PROGRAM_ID_SIZE]), chain, 1)
            .unwrap();
        assert!(state.utxos.coin(&input).is_none());
        let transferred: Vec<_> = state
            .utxos
            .coins()
            .filter(|(_, coin)| coin.owner == crate::common::Owner::Program(recipient))
            .collect();
        assert_eq!(transferred.len(), 1);
        assert_eq!(transferred[0].1.amount, amount);
        let commitment =
            crate::program::AuthorizationCommitment::from_bytes([98; crypto::HASH_SIZE]);
        let authorization = AccountAuthorization {
            salt: [0; 32],
            public_key: recipient_keys.public_key(),
            signature: recipient_keys.sign(commitment.as_bytes()),
        };
        assert!(authorization.verify_commitment(recipient, &commitment, 1));
        let old_keys = SigningSeed::new(Signature::MlDsa44, Box::new([91; 32]));
        let old_authorization = AccountAuthorization {
            salt: [0; 32],
            public_key: old_keys.public_key(),
            signature: old_keys.sign(commitment.as_bytes()),
        };
        assert!(!old_authorization.verify_commitment(recipient, &commitment, 1));
    }

    #[test]
    fn xpq_transfer_uses_ledger_owner_for_input_authorization() {
        let (mut state, tx, chain) = fixture();
        let input = tx.payment.coin_parts().unwrap().0[0];
        state.utxos.consume_coin(&input).unwrap();
        state
            .utxos
            .insert_coin(
                input,
                CoinUtxo {
                    owner: crate::common::Owner::Program(ProgramId([97; crypto::PROGRAM_ID_SIZE])),
                    amount: Zeno::from_zeno(1_000_000),
                },
            )
            .unwrap();
        let before = state.clone();
        assert!(matches!(
            validate_consensus_call(tx, chain, 1, &state),
            Err(crate::consensus::ProgramConsensusError::RecipientMismatch)
        ));
        assert_eq!(state, before);
    }
}
