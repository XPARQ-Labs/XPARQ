use crate::CodecError;
use borsh::{BorshDeserialize, BorshSerialize};

pub const CANONICAL_ENCODING_PROFILE: &str = "xparq-borsh-le";

pub fn canonical_bytes<T: BorshSerialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    borsh::to_vec(value).map_err(|_| CodecError::EncodeFailed)
}

pub fn canonical_deserialize<T: BorshDeserialize>(bytes: &[u8]) -> Result<T, CodecError> {
    T::try_from_slice(bytes).map_err(|_| CodecError::DecodeFailed)
}

pub fn canonical_decode<T: BorshDeserialize>(bytes: &[u8]) -> Result<T, CodecError> {
    canonical_deserialize(bytes)
}
