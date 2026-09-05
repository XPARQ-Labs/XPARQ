use borsh::{BorshDeserialize, BorshSerialize};

use crate::common::ExtensionHash;

/// An account or extension that can own a protocol object or receive a
/// delegated capability.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub enum Authority<A> {
    Address(A),
    Extension(ExtensionHash),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_have_stable_borsh_tags() {
        let address = Authority::Address([7_u8; 20]);
        let extension = Authority::<[u8; 20]>::Extension(ExtensionHash::from_bytes([9; 32]));

        assert_eq!(borsh::to_vec(&address).unwrap()[0], 0);
        assert_eq!(borsh::to_vec(&extension).unwrap()[0], 1);
    }
}
