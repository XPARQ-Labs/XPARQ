use super::*;
use crate::asset::{AssetError, AssetHash};
use crate::transaction::{AssetInstruction, AssetIntent, SpendOutput};

fn funded() -> (LedgerState, ExtensionHash) {
    let program = ExtensionHash::derive("regression.coin.vault");
    let mut state = LedgerState::default();
    state
        .assets
        .utxos
        .insert(CoinUtxo {
            coin: Coin::new(CoinHash::from_bytes([7; 32]), Zeno::from_zeno(100)),
            owner: Authority::Extension(program),
        })
        .unwrap();
    (state, program)
}
fn transfer(amount: u64) -> ExtensionEffect {
    ExtensionEffect::TransferCoin {
        recipient: [2; 20],
        amount,
    }
}

#[test]
fn chained_coin_effects_roll_back_to_original_state() {
    let (mut state, program) = funded();
    let before = state.clone();
    let (_, journal) = state
        .apply_extension_effects(
            program,
            SpendCommitment::from_bytes([5; 32]),
            vec![transfer(10), transfer(20)],
            [9; 32],
        )
        .unwrap();
    assert_eq!(journal.consumed_coins.len(), 1);
    assert_eq!(journal.created_coin_ids.len(), 3);
    state.rollback(journal).unwrap();
    assert_eq!(state, before);
}

#[test]
fn failed_later_effect_restores_chained_transfers() {
    let (mut state, program) = funded();
    let before = state.clone();
    let result = state.apply_extension_effects(
        program,
        SpendCommitment::from_bytes([5; 32]),
        vec![transfer(10), transfer(20), transfer(1000)],
        [9; 32],
    );
    assert_eq!(result, Err(SpendStateError::InsufficientExtensionCoin));
    assert_eq!(state, before);
}

#[test]
fn fee_output_consumed_by_effect_is_not_restored_on_rollback() {
    let (mut state, program) = funded();
    // Use only a fee-created deposit as the program's funding.
    state
        .assets
        .utxos
        .consume(&CoinHash::from_bytes([7; 32]))
        .unwrap();
    let payer = Address([4; 20]);
    let input = CoinHash::from_bytes([8; 32]);
    state
        .assets
        .utxos
        .insert(CoinUtxo {
            coin: Coin::new(input, Zeno::from_zeno(100)),
            owner: Authority::Address(payer),
        })
        .unwrap();
    let before = state.clone();
    let fee = CoinIntent::new(
        payer,
        vec![input],
        vec![SpendOutput::extension(program, Zeno::from_zeno(100))],
    )
    .unwrap();
    let commitment = fee
        .commitment(crate::transaction::ChainContext::new([9; 32]))
        .unwrap();
    let mut fee_journal = state
        .apply_onchain_spend_with_commitment(&fee, commitment, payer)
        .unwrap();
    let (_, effects) = state
        .apply_extension_effects(
            program,
            commitment,
            vec![transfer(10), transfer(20)],
            [9; 32],
        )
        .unwrap();
    for coin in effects.consumed_coins {
        fee_journal.record_consumed(coin);
    }
    fee_journal
        .created_coin_ids
        .extend(effects.created_coin_ids);
    state.rollback(fee_journal).unwrap();
    assert_eq!(state, before);
}

#[test]
fn repeated_mints_preserve_supply_and_reject_reused_origin() {
    let program = ExtensionHash::derive("regression.mint");
    let creator = Address([1; 20]);
    let recipient = Address([2; 20]);
    let mut state = LedgerState::default();
    let call = AssetIntent::new(
        AssetInstruction::Register {
            name: "Regression".into(),
            symbol: "REG".into(),
            decimals: 0,
            max_supply: Unit::from_units(100),
            initial_mint: Unit::from_units(1),
            mint_authority: Some(Authority::Extension(program)),
        },
        creator,
        0,
    );
    state.assets.apply(&call, [9; 32]).unwrap();
    let asset = AssetHash::derive(creator, "REG");
    let initial = state.clone();
    let mut journals = Vec::new();
    for tx in [3, 4] {
        let (assets, _) = state
            .apply_extension_effects(
                program,
                SpendCommitment::from_bytes([tx; 32]),
                vec![ExtensionEffect::MintAsset {
                    asset_id: *asset.as_bytes(),
                    recipient: recipient.0,
                    amount: 10,
                }],
                [9; 32],
            )
            .unwrap();
        journals.extend(assets);
    }
    assert_eq!(state.assets.supply(asset), Unit::from_units(21));
    assert_eq!(
        state.assets.account_balance(asset, recipient),
        Unit::from_units(20)
    );
    let before_retry = state.clone();
    let retry = state.apply_extension_effects(
        program,
        SpendCommitment::from_bytes([4; 32]),
        vec![ExtensionEffect::MintAsset {
            asset_id: *asset.as_bytes(),
            recipient: recipient.0,
            amount: 10,
        }],
        [9; 32],
    );
    assert_eq!(
        retry,
        Err(SpendStateError::Asset(AssetError::ShareAlreadyExists))
    );
    assert_eq!(state, before_retry);
    for journal in journals.into_iter().rev() {
        state.assets.rollback(journal);
    }
    assert_eq!(state, initial);
}

#[test]
fn coin_output_domains_are_distinct() {
    let commitment = SpendCommitment::from_bytes([5; 32]);
    let payment = account_output_id(commitment, 0).unwrap();
    let output = extension_output_id(commitment, 0).unwrap();
    let change = extension_change_id(commitment, 0).unwrap();
    assert_ne!(payment, output);
    assert_ne!(payment, change);
    assert_ne!(output, change);
    assert_ne!(output, extension_output_id(commitment, 1).unwrap());
}

#[test]
fn validated_extension_applies_and_rolls_back_with_fee_output_at_index_zero() {
    use crate::common::{
        Extension, ExtensionCall, ExtensionContext, ExtensionFailure, ExtensionStateRead,
        ExtensionStateWrite, Height, canonical_bytes,
    };
    use crate::consensus::{
        StateTransitionWeight, TransactionStateView, account_key_state_weight, validate_transaction,
    };
    use crate::crypto::{Signature, SigningSeed, address_from_public_key};
    use crate::transaction::{
        AccountAuthorization, AuthorizedAccountIntent, AuthorizedExtensionTransaction,
        AuthorizedTransaction,
    };
    struct Pay(ExtensionHash);
    impl Extension for Pay {
        fn id(&self) -> ExtensionHash {
            self.0
        }
        fn activation_height(&self) -> Height {
            Height(0)
        }
        fn validate(
            &self,
            _: ExtensionContext,
            _: &ExtensionCall,
            _: &dyn ExtensionStateRead,
        ) -> Result<(), ExtensionFailure> {
            Ok(())
        }
        fn apply(
            &self,
            _: ExtensionContext,
            _: &ExtensionCall,
            state: &mut dyn ExtensionStateWrite,
        ) -> Result<(), ExtensionFailure> {
            state.emit(transfer(10))?;
            state.emit(transfer(20))
        }
    }
    let (mut state, program) = funded();
    let mut registry = extension::ExtensionRegistry::new();
    registry.register(Pay(program)).unwrap();
    extension::initialize_production_registry(registry).unwrap();
    let seed = SigningSeed::new(Signature::MlDsa44, [6; 32]);
    let public = seed.public_key();
    let sender = address_from_public_key(&public);
    let input = CoinHash::from_bytes([4; 32]);
    state
        .assets
        .utxos
        .insert(CoinUtxo {
            coin: Coin::new(input, Zeno::from_zeno(100_000)),
            owner: Authority::Address(sender),
        })
        .unwrap();
    let call = ExtensionCall::new(program, vec![]).unwrap();
    let chain = crate::genesis::chain_context().unwrap();
    let weight = state.extension_created_state_weight(&call, 1).unwrap();
    let state_burn = StateTransitionWeight {
        created_coin_utxos: 2,
        consumed_coin_utxos: 1,
        created_account_key_weight: account_key_state_weight(&public).unwrap(),
        extension_created_weight: weight,
    }
    .state_growth_burn()
    .unwrap()
    .as_zeno();
    let mut size = 1;
    let transaction = loop {
        let burn = state_burn + size;
        let intent = CoinIntent::new(
            sender,
            vec![input],
            vec![
                SpendOutput::new(sender, Zeno::from_zeno(100_000 - burn - size)),
                SpendOutput::burn(Zeno::from_zeno(burn)),
                SpendOutput::block_miner(Zeno::from_zeno(size)),
            ],
        )
        .unwrap();
        let signature = seed.sign(intent.commitment(chain).unwrap().as_bytes());
        let transaction =
            AuthorizedTransaction::Extension(Box::new(AuthorizedExtensionTransaction {
                call: call.clone(),
                fee: AuthorizedAccountIntent {
                    intent,
                    authorization: AccountAuthorization::AccountReveal {
                        public_key: public.clone(),
                        signature,
                    },
                },
            }));
        let actual = canonical_bytes(&transaction).unwrap().len() as u64;
        if actual == size {
            break transaction;
        }
        size = actual;
    };
    let valid = validate_transaction(transaction.clone(), chain, 1, &state).unwrap();
    let before = state.clone();
    let journal = state
        .apply_validated_transaction(&valid, Height(1), sender, chain)
        .unwrap();
    state.rollback_state(journal).unwrap();
    assert_eq!(state, before);

    // Exercise the canonical block journal and disconnect path as well.
    let mut ledger = crate::genesis::genesis_ledger().unwrap();
    ledger.state = state;
    let original = ledger.clone();
    let mut block = crate::blockchain::Block::from_protocol_transactions(
        Height(1),
        ledger.tip_hash().unwrap(),
        crate::consensus::DIFFICULTY_START,
        crate::blockchain::Nonce(0),
        Some(crate::blockchain::Emission::new(
            sender,
            crate::consensus::initial_block_emission(),
        )),
        vec![transaction],
    )
    .unwrap();
    let (root, weight) = ledger.preview_block_commitments(&block).unwrap();
    block.set_state_root(crate::crypto::StateRoot(*root.as_bytes()));
    block.set_block_weight(weight);
    let mut memory = crate::consensus::new_pow_memory();
    while crate::consensus::verify_pow_with_memory(&block.header, block.difficulty(), &mut memory)
        .is_err()
    {
        block.header.nonce.0 += 1;
        assert!(
            block.header.nonce.0 < 10_000,
            "test mining exhausted its bound"
        );
    }
    crate::consensus::apply_block(&mut ledger, block.clone()).unwrap();
    assert_eq!(ledger.rollback_tip().unwrap(), block);
    assert_eq!(ledger, original);
}
