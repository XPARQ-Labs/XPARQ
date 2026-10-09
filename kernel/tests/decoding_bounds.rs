use std::io::{self, Cursor, Read};

use borsh::{BorshDeserialize, BorshSerialize};
use crypto::{HASH_SIZE, ProgramId};
use kernel::{
    common::Height,
    operation::BlockOperation,
    program::{
        DeployProgram, MAX_PROGRAM_CODE_SIZE, ProgramHash, ProgramRecord, ProgramRegistry,
        deploy_program,
        system::script::call::{ProgramCall, SystemProgramId},
    },
};

fn deployment() -> DeployProgram {
    let mut code = b"XPVM".to_vec();
    code.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0, 0]);
    code.push(1);
    code.extend_from_slice(&7_u64.to_le_bytes());
    code.push(3);
    DeployProgram {
        owner: ProgramId::ZERO,
        nonce: 1,
        code: code.into(),
    }
}

// Reading past the prefix is a test failure, rather than merely reaching EOF.
struct PrefixOnly(Cursor<Vec<u8>>);

impl Read for PrefixOnly {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        assert!(
            self.0.position() < self.0.get_ref().len() as u64,
            "decoder attempted to read payload after rejecting its length"
        );
        self.0.read(bytes)
    }
}

#[test]
fn oversized_code_prefixes_stop_before_payload_reads() {
    for length in [MAX_PROGRAM_CODE_SIZE as u32 + 1, u32::MAX] {
        let mut prefix = borsh::to_vec(&(ProgramId::ZERO, 1_u64)).unwrap();
        prefix.extend_from_slice(&length.to_le_bytes());
        assert_eq!(
            DeployProgram::deserialize_reader(&mut PrefixOnly(Cursor::new(prefix.clone())))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        prefix.insert(0, 0); // BlockOperation::DeployProgram discriminant.
        assert_eq!(
            BlockOperation::deserialize_reader(&mut PrefixOnly(Cursor::new(prefix)))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );

        let mut prefix = vec![0; HASH_SIZE];
        prefix.extend_from_slice(&length.to_le_bytes());
        assert_eq!(
            ProgramRecord::deserialize_reader(&mut PrefixOnly(Cursor::new(prefix.clone())))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        let mut registry_prefix = 1_u32.to_le_bytes().to_vec();
        registry_prefix.extend_from_slice(&[0; HASH_SIZE]);
        registry_prefix.extend_from_slice(&prefix);
        assert_eq!(
            ProgramRegistry::deserialize_reader(&mut PrefixOnly(Cursor::new(registry_prefix)))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[test]
fn bounded_code_decoding_preserves_historical_field_encoding() {
    for length in [0, 1, 8191, 8192, 8193, MAX_PROGRAM_CODE_SIZE] {
        let deploy = DeployProgram {
            code: vec![7; length].into(),
            ..deployment()
        };
        let bytes = borsh::to_vec(&deploy).unwrap();
        assert_eq!(
            bytes,
            borsh::to_vec(&(deploy.owner, deploy.nonce, &deploy.code)).unwrap()
        );
        assert_eq!(DeployProgram::try_from_slice(&bytes).unwrap(), deploy);
        let record = ProgramRecord {
            code_hash: ProgramHash::derive(&deploy.code).unwrap(),
            code: deploy.code,
            owner: deploy.owner,
            nonce: deploy.nonce,
            deployed_at: Height(1),
            state_value: -7,
            storage: Default::default(),
        };
        let bytes = borsh::to_vec(&record).unwrap();
        assert_eq!(
            bytes,
            borsh::to_vec(&(
                record.code_hash,
                &record.code,
                record.owner,
                record.nonce,
                record.deployed_at,
                record.state_value
            ))
            .unwrap()
        );
        assert_eq!(ProgramRecord::try_from_slice(&bytes).unwrap(), record);
    }
}

fn check_corpus<T: BorshDeserialize + BorshSerialize>(bytes: &[u8]) {
    for end in 0..bytes.len() {
        assert!(
            T::try_from_slice(&bytes[..end]).is_err(),
            "truncation at {end}"
        );
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(T::try_from_slice(&trailing).is_err());
    let mut random = 0x7b89_135f_u64;
    for _ in 0..512 {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        let mut mutated = bytes.to_vec();
        let position = random as usize % mutated.len();
        mutated[position] ^= (random >> 32) as u8 | 1;
        if let Ok(decoded) = T::try_from_slice(&mutated) {
            assert_eq!(borsh::to_vec(&decoded).unwrap(), mutated);
        }
    }
}

#[test]
fn deterministic_mutation_corpus_covers_truncation_and_canonical_decoding() {
    let deploy = deployment();
    check_corpus::<DeployProgram>(&borsh::to_vec(&deploy).unwrap());
    let record = ProgramRecord {
        code_hash: ProgramHash::derive(&deploy.code).unwrap(),
        code: deploy.code.clone(),
        owner: deploy.owner,
        nonce: deploy.nonce,
        deployed_at: Height(1),
        state_value: 7,
        storage: Default::default(),
    };
    check_corpus::<ProgramRecord>(&borsh::to_vec(&record).unwrap());
    let mut registry = ProgramRegistry::default();
    deploy_program(&mut registry, deploy, Height(1)).unwrap();
    check_corpus::<ProgramRegistry>(&borsh::to_vec(&registry).unwrap());
    let call = ProgramCall {
        program: SystemProgramId::VM,
        opcode: 0,
        payload: borsh::to_vec(&ProgramId::from_bytes([7; HASH_SIZE])).unwrap(),
    };
    check_corpus::<ProgramCall>(&borsh::to_vec(&call).unwrap());
}

#[test]
fn forged_maximum_registry_count_does_not_preallocate_entries() {
    // The decoder reads actual records sequentially and immediately encounters EOF.
    assert!(ProgramRegistry::try_from_slice(&u32::MAX.to_le_bytes()).is_err());
    let mut prefix = borsh::to_vec(&(ProgramId::ZERO, 1_u64)).unwrap();
    prefix.extend_from_slice(&(MAX_PROGRAM_CODE_SIZE as u32).to_le_bytes());
    assert!(DeployProgram::try_from_slice(&prefix).is_err());
}
