// Consensus-valid synthetic fixtures shared by CPU benchmarks.
use kernel::crypto::{
    AccountSignature, AccountSignatureScheme, ChainContext, ProgramId, SigningSeed,
    canonical_length, program_id_from_public_key,
};
use kernel::{
    blockchain::{Block, Emission},
    common::{Height, Nonce, Owner},
    consensus::{
        PoWTarget, ProtocolBurn, StateTransitionWeight, apply_block_with_pow_memory,
        calculate_work_with_memory, expected_emission_for_height, expected_next_difficulty,
        new_pow_memory,
    },
    genesis::genesis_ledger,
    ledger::Ledger,
    monetary::coin::{CoinOutput, CoinShare, Zeno},
    operation::{BlockOperation, BlockOperationRef},
    program::{
        AccountAuthorization, AuthorizedProgramInvocation, CoinCharges, CoinTransition,
        program_invocation_commitment, system::coin_program::transfer_call,
    },
};

pub fn transfer(
    key: &SigningSeed,
    input: CoinShare,
    amount: u64,
    recipients: &[ProgramId],
    chain: ChainContext,
    split_evenly: bool,
) -> BlockOperation {
    let public_key = key.public_key();
    let signer = program_id_from_public_key(&public_key).unwrap();
    let fee = Zeno::from_zeno(1000);
    let mut tx = AuthorizedProgramInvocation {
        signer,
        call: transfer_call(),
        payment: CoinTransition::coin_with_charges(
            signer,
            vec![input],
            recipients
                .iter()
                .map(|&id| CoinOutput::new(id, Zeno::ONE))
                .collect(),
            CoinCharges::new(fee),
        )
        .unwrap(),
        authorization: AccountAuthorization {
            salt: [0; 32],
            public_key,
            signature: AccountSignature {
                account: key.scheme(),
                bytes: vec![0; key.scheme().signature_size()],
            },
        },
    };
    // Fixed-size amounts/signatures: burn calculation requires no trial signing.
    let size = canonical_length(&BlockOperationRef::ProgramCall(&tx)).unwrap() as u64;
    let burn = ProtocolBurn::for_program_call(
        StateTransitionWeight {
            created_coin_utxos: recipients.len() as u64 + 1, // fee UTXO
            consumed_coin_utxos: 1,
            created_state_weight: 0,
        },
        size,
    )
    .unwrap()
    .total()
    .unwrap()
    .as_zeno();
    let available = amount.checked_sub(burn + fee.as_zeno()).unwrap();
    let each = if split_evenly {
        available / recipients.len() as u64
    } else {
        1
    };
    assert!(each > 0);
    let mut outputs: Vec<_> = recipients
        .iter()
        .map(|&id| CoinOutput::new(id, Zeno::from_zeno(each)))
        .collect();
    outputs[0] = CoinOutput::new(
        recipients[0],
        Zeno::from_zeno(available - each * (recipients.len() as u64 - 1)),
    );
    tx.payment =
        CoinTransition::coin_with_charges(signer, vec![input], outputs, CoinCharges::new(fee))
            .unwrap();
    assert_eq!(
        canonical_length(&BlockOperationRef::ProgramCall(&tx)).unwrap() as u64,
        size
    );
    let commitment = program_invocation_commitment(signer, &tx.call, &tx.payment, chain).unwrap();
    tx.authorization.signature = key.sign(commitment.as_bytes());
    BlockOperation::ProgramCall(Box::new(tx))
}

pub fn candidate(ledger: &Ledger, miner: ProgramId, operations: Vec<BlockOperation>) -> Block {
    let height = Height(ledger.tip_height().unwrap().0 + 1);
    let mut block = Block::from_protocol_operations(
        height,
        ledger.tip_hash().unwrap(),
        expected_next_difficulty(&ledger.chain).unwrap(),
        Nonce(0),
        Some(Emission::new(miner, expected_emission_for_height(height))),
        operations,
    )
    .unwrap();
    let (root, weight) = ledger.preview_block_commitments(&block).unwrap();
    block.set_state_root(root);
    block.set_block_weight(weight);
    block.validate_structure().unwrap();
    let mut memory = new_pow_memory();
    let target = PoWTarget::from_compact(block.target_bits()).unwrap();
    while !target.meets(&calculate_work_with_memory(&block.header, &mut memory).unwrap()) {
        block.header.nonce.0 = block.header.nonce.0.checked_add(1).unwrap();
    }
    block
}

pub fn fixtures(shares_per_key: usize) -> (Ledger, Vec<SigningSeed>, ChainContext, ProgramId) {
    let mut ledger = genesis_ledger()
        .unwrap()
        .with_applications(extension::SystemApplications);
    let chain = ChainContext::new(ledger.tip_hash().unwrap().into_bytes());
    // Two independent keys per active scheme. All fixture balances come from a
    // mined emission and a consensus-valid funding transfer; no injected state.
    let keys: Vec<_> = AccountSignatureScheme::ALL
        .into_iter()
        .cycle()
        .take(12)
        .enumerate()
        .map(|(i, scheme)| SigningSeed::new(scheme, Box::new([i as u8 + 41; 32])))
        .collect();
    let owners: Vec<_> = keys
        .iter()
        .map(|key| program_id_from_public_key(&key.public_key()).unwrap())
        .collect();
    let miner = ProgramId([240; 32]);
    let mut memory = new_pow_memory();
    let emission = candidate(&ledger, owners[0], vec![]);
    apply_block_with_pow_memory(&mut ledger, emission, &mut memory).unwrap();
    let (input, coin) = ledger
        .state
        .utxos
        .coins_by_owner(Owner::Program(owners[0]))
        .next()
        .unwrap();
    let recipients: Vec<_> = owners
        .iter()
        .flat_map(|owner| std::iter::repeat_n(*owner, shares_per_key))
        .collect();
    let funding = transfer(
        &keys[0],
        input,
        coin.amount.as_zeno(),
        &recipients,
        chain,
        true,
    );
    let block = candidate(&ledger, miner, vec![funding]);
    apply_block_with_pow_memory(&mut ledger, block, &mut memory).unwrap();
    ledger.state.audit_coin_supply().unwrap();
    (ledger, keys, chain, miner)
}
