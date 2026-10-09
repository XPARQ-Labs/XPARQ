//! Bounded canonical program storage decoding and validation.

use super::{MAX_DATA_BYTES, MAX_KEY_BYTES, MAX_STORAGE_BYTES, MAX_STORAGE_ENTRIES};
use crate::program::vm::ExecutionError;
use borsh::BorshDeserialize;
use std::{
    collections::BTreeMap,
    io::{Error, ErrorKind, Read},
};

pub(super) type Storage = BTreeMap<Vec<u8>, Vec<u8>>;

pub(in crate::program) fn valid_storage(storage: &Storage) -> bool {
    storage.len() <= MAX_STORAGE_ENTRIES
        && storage.iter().all(|(k, v)| {
            !k.is_empty() && k.len() <= MAX_KEY_BYTES && !v.is_empty() && v.len() <= MAX_DATA_BYTES
        })
        && storage
            .iter()
            .map(|(k, v)| 8 + k.len() + v.len())
            .sum::<usize>()
            + 4
            <= MAX_STORAGE_BYTES
}
pub(crate) fn read_storage<R: Read>(reader: &mut R) -> std::io::Result<Storage> {
    fn bytes<R: Read>(r: &mut R, max: usize) -> std::io::Result<Vec<u8>> {
        let n = u32::deserialize_reader(r)? as usize;
        if n == 0 || n > max {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "invalid VM storage length",
            ));
        }
        let mut value = vec![0; n];
        r.read_exact(&mut value)?;
        Ok(value)
    }
    let count = u32::deserialize_reader(reader)? as usize;
    if count > MAX_STORAGE_ENTRIES {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "too many VM storage entries",
        ));
    }
    let mut map = Storage::new();
    let mut size = 4usize;
    for _ in 0..count {
        let key = bytes(reader, MAX_KEY_BYTES)?;
        if map.last_key_value().is_some_and(|(last, _)| last >= &key) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "noncanonical VM storage keys",
            ));
        }
        let value = bytes(reader, MAX_DATA_BYTES)?;
        size += 8 + key.len() + value.len();
        if size > MAX_STORAGE_BYTES {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "VM storage exceeds limit",
            ));
        }
        map.insert(key, value);
    }
    Ok(map)
}

pub(super) fn check_key(key: &[u8]) -> Result<(), ExecutionError> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        Err(ExecutionError::InvalidOperand)
    } else {
        Ok(())
    }
}
