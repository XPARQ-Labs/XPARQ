//! Shared allocation must preserve canonical bytes and isolated mutations.
use borsh::{BorshDeserialize, BorshSerialize};
use kernel::{
    block::{Block, Emission, GENESIS_TARGET_BITS, Header, block_bytes, decode_block},
    common::{Height, Nonce},
    crypto::{
        AccountSignatureScheme, HashDomain, ProgramId, SigningSeed, canonical_bytes, domain,
        program_id_from_public_key,
    },
    monetary::coin::{CoinOutput, CoinShare, Zeno},
    operation::{AuthorizedDeployProgram, BlockOperation},
    program::{
        AccountAuthorization, CoinTransition, DeployProgram, ProgramHash, ProgramRecord,
        ProgramRegistry, deploy_program,
    },
};
use std::sync::Arc;

fn deployment() -> DeployProgram {
    let mut code = b"XPVM".to_vec();
    code.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0, 0]);
    code.push(1);
    code.extend_from_slice(&7_i64.to_le_bytes());
    code.push(3);
    DeployProgram {
        owner: ProgramId::ZERO,
        nonce: 1,
        code: code.into(),
    }
}

#[derive(BorshSerialize)]
struct OwnedDeploy {
    owner: ProgramId,
    nonce: u64,
    code: Vec<u8>,
}
#[derive(BorshSerialize)]
struct OwnedRecord {
    code_hash: ProgramHash,
    code: Vec<u8>,
    owner: ProgramId,
    nonce: u64,
    deployed_at: Height,
    state_value: i64,
}
#[derive(BorshSerialize)]
struct OwnedBlock {
    header: Header,
    height: Height,
    emission: Option<Emission>,
    operations: Vec<BlockOperation>,
}

#[test]
fn shared_code_preserves_owned_encoding_hash_and_registry_validation() {
    let deploy = deployment();
    let owned = OwnedDeploy {
        owner: deploy.owner,
        nonce: deploy.nonce,
        code: deploy.code.as_ref().clone(),
    };
    let bytes = canonical_bytes(&owned).unwrap();
    assert_eq!(canonical_bytes(&deploy).unwrap(), bytes);
    let restored = DeployProgram::try_from_slice(&bytes).unwrap();
    assert_eq!(restored, deploy);
    let legacy_hash = domain(
        HashDomain::XPARQArtifact,
        &canonical_bytes(&(b"xparq:program-code:v1", owned.code.clone())).unwrap(),
    );
    assert_eq!(
        ProgramHash::derive(&deploy.code).unwrap().as_bytes(),
        legacy_hash.as_bytes()
    );
    let mut registry = ProgramRegistry::default();
    let (id, _) = deploy_program(&mut registry, deploy.clone(), Height(1)).unwrap();
    let record = registry.program(&id).unwrap();
    assert!(Arc::ptr_eq(&deploy.code, &record.code));
    let owned_record = OwnedRecord {
        code_hash: record.code_hash,
        code: record.code.as_ref().clone(),
        owner: record.owner,
        nonce: record.nonce,
        deployed_at: record.deployed_at,
        state_value: record.state_value,
    };
    let record_bytes = canonical_bytes(&owned_record).unwrap();
    assert_eq!(canonical_bytes(record).unwrap(), record_bytes);
    assert_eq!(
        ProgramRecord::try_from_slice(&record_bytes).unwrap(),
        *record
    );
    let mut owned_registry = std::collections::BTreeMap::new();
    owned_registry.insert(id, owned_record);
    let registry_bytes = canonical_bytes(&owned_registry).unwrap();
    assert_eq!(canonical_bytes(&registry).unwrap(), registry_bytes);
    assert_eq!(
        ProgramRegistry::try_from_slice(&registry_bytes).unwrap(),
        registry
    );
    let mut fork = registry.clone();
    assert!(Arc::ptr_eq(&record.code, &fork.program(&id).unwrap().code));
    let mut added = deploy.clone();
    added.nonce = 2;
    deploy_program(&mut fork, added, Height(2)).unwrap();
    assert_eq!(registry.len(), 1);
    assert_eq!(fork.len(), 2);
    let mut private_record = record.clone();
    private_record.state_value = 23;
    assert_eq!(registry.program(&id).unwrap().state_value, 0);
    assert_eq!(private_record.state_value, 23);
    let mut changed = deploy.clone();
    Arc::make_mut(&mut changed.code)[14] ^= 1;
    assert_eq!(canonical_bytes(&deploy).unwrap(), bytes);
    assert_eq!(canonical_bytes(&registry).unwrap(), registry_bytes);
    assert_ne!(
        ProgramHash::derive(&changed.code).unwrap(),
        record.code_hash
    );
}

#[test]
fn cloned_blocks_share_payload_until_mutation_without_changing_wire_bytes() {
    let seed = SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([0x75; 32]));
    let owner = program_id_from_public_key(&seed.public_key()).unwrap();
    let mut deploy = deployment();
    deploy.owner = owner;
    let op = BlockOperation::DeployProgram(Box::new(AuthorizedDeployProgram {
        deploy,
        payment: CoinTransition::coin(
            owner,
            vec![CoinShare::from_bytes([1; 32])],
            vec![CoinOutput::new(owner, Zeno::ONE)],
        )
        .unwrap(),
        authorization: AccountAuthorization {
            salt: [0; 32],
            public_key: seed.public_key(),
            signature: seed.sign(&[0; 32]),
        },
    }));
    let block = Block::from_protocol_operations(
        Height(1),
        kernel::crypto::PreviousHash([9; 32]),
        GENESIS_TARGET_BITS,
        Nonce(0),
        Some(Emission::new(owner, Zeno::from_zeno(156_250_000))),
        vec![op],
    )
    .unwrap();
    let owned = OwnedBlock {
        header: block.header.clone(),
        height: block.height,
        emission: block.body.emission.clone(),
        operations: block.operations().to_vec(),
    };
    let bytes = canonical_bytes(&owned).unwrap();
    assert_eq!(block_bytes(&block).unwrap(), bytes);
    assert_eq!(decode_block(&bytes).unwrap(), block);
    let hash = block.hash().unwrap();
    let mut fork = block.clone();
    assert!(Arc::ptr_eq(&block.body, &fork.body));
    fork.body_mut().emission.as_mut().unwrap().to = ProgramId::ZERO;
    fork.refresh_commitments().unwrap();
    assert!(!Arc::ptr_eq(&block.body, &fork.body));
    assert_eq!(block.hash().unwrap(), hash);
    assert_eq!(block_bytes(&block).unwrap(), bytes);
    assert_ne!(fork.hash().unwrap(), hash);
    match (&block.operations()[0], &fork.operations()[0]) {
        (BlockOperation::DeployProgram(left), BlockOperation::DeployProgram(right)) => {
            assert!(Arc::ptr_eq(&left.deploy.code, &right.deploy.code));
        }
        _ => panic!("deployment disappeared after private body mutation"),
    }
}
