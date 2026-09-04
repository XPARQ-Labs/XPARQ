use borsh::{BorshDeserialize, BorshSerialize};
use xparq_common::{ExtensionCall, canonical_bytes, domain_hash};
use xparq_crypto::{
    Address, ProfilePublicKey, ProfileSignature, address_from_profile_public_key, profile_verify,
};

use crate::{
    AssetIntent, ChainContext, CoinIntent, IntentError, SpendCommitment, TransactionEncodingError,
};

const TRANSACTION_ID_CONTEXT: &str = "XPARQ Transaction ID";

pub trait AccountIntent {
    fn sender(&self) -> Address;
    fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError>;
}

impl AccountIntent for CoinIntent {
    fn sender(&self) -> Address {
        self.sender
    }

    fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        self.commitment(chain)
    }
}

impl AccountIntent for AssetIntent {
    fn sender(&self) -> Address {
        self.signer
    }

    fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        self.commitment(chain.genesis_hash)
            .map(SpendCommitment::from_bytes)
            .map_err(|_| IntentError::InvalidAssetCall)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
// Boxing a variant would change the frozen canonical transaction encoding.
#[allow(clippy::large_enum_variant)]
pub enum AccountAuthorization {
    ProfileReveal {
        public_key: ProfilePublicKey,
        signature: ProfileSignature,
    },
    ProfileKnown {
        profile: xparq_crypto::SignatureProfile,
        signature: ProfileSignature,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AuthorizedAccountIntent<T> {
    pub intent: T,
    pub authorization: AccountAuthorization,
}

impl<T: AccountIntent> AuthorizedAccountIntent<T> {
    pub fn verify_revealed_signature(&self, chain: ChainContext) -> Result<bool, IntentError> {
        let commitment = self.intent.commitment(chain)?;
        match &self.authorization {
            AccountAuthorization::ProfileReveal {
                public_key,
                signature,
            } => Ok(
                address_from_profile_public_key(public_key) == self.intent.sender()
                    && profile_verify(public_key, commitment.as_bytes(), signature),
            ),
            AccountAuthorization::ProfileKnown { .. } => Ok(false),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AuthorizedExtensionTransaction {
    pub call: ExtensionCall,
    pub fee: AuthorizedAccountIntent<CoinIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AuthorizedAssetTransaction {
    pub call: AuthorizedAccountIntent<AssetIntent>,
    pub payment: AuthorizedAccountIntent<CoinIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum AuthorizedTransaction {
    Coin(Box<AuthorizedAccountIntent<CoinIntent>>),
    Asset(Box<AuthorizedAssetTransaction>),
    Extension(Box<AuthorizedExtensionTransaction>),
}

impl AuthorizedTransaction {
    pub fn id(&self) -> Result<[u8; 32], TransactionEncodingError> {
        let bytes = canonical_bytes(self).map_err(TransactionEncodingError::Encoding)?;
        Ok(domain_hash(TRANSACTION_ID_CONTEXT.as_bytes(), &[&bytes]))
    }

    pub fn validate_structure(&self) -> Result<(), IntentError> {
        match self {
            Self::Coin(tx) => tx.intent.validate(),
            Self::Asset(tx) => {
                tx.call
                    .intent
                    .validate_structure()
                    .map_err(|_| IntentError::InvalidAssetCall)?;
                tx.payment.intent.validate()
            }
            Self::Extension(tx) => tx.fee.intent.validate(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_authorization_tags_are_stable() {
        let reveal = AccountAuthorization::ProfileReveal {
            public_key: ProfilePublicKey {
                profile: xparq_crypto::SignatureProfile::MlDsa44,
                bytes: vec![1],
            },
            signature: ProfileSignature {
                profile: xparq_crypto::SignatureProfile::MlDsa44,
                bytes: vec![2],
            },
        };
        let known = AccountAuthorization::ProfileKnown {
            profile: xparq_crypto::SignatureProfile::MlDsa44,
            signature: ProfileSignature {
                profile: xparq_crypto::SignatureProfile::MlDsa44,
                bytes: vec![3],
            },
        };
        assert_eq!(borsh::to_vec(&reveal).unwrap()[0], 0);
        assert_eq!(borsh::to_vec(&known).unwrap()[0], 1);
    }

    #[test]
    fn native_asset_transaction_has_an_explicit_wire_tag() {
        let seed =
            xparq_crypto::ProfileSigningSeed::new(xparq_crypto::SignatureProfile::MlDsa44, [7; 32]);
        let public_key = seed.public_key();
        let signer = xparq_crypto::address_from_profile_public_key(&public_key);
        let call = crate::AssetIntent::new(
            crate::AssetInstruction::Register {
                name: "Test Asset".into(),
                symbol: "TST".into(),
                decimals: 8,
                max_supply: 1_000,
                initial_mint: 100,
                mint_authority: Some(xparq_common::Authority::Address(signer)),
            },
            signer,
            0,
        );
        let call_signature = seed.sign(&call.commitment([3; 32]).unwrap());
        let transaction = AuthorizedTransaction::Asset(Box::new(AuthorizedAssetTransaction {
            call: AuthorizedAccountIntent {
                intent: call,
                authorization: AccountAuthorization::ProfileReveal {
                    public_key,
                    signature: call_signature,
                },
            },
            payment: AuthorizedAccountIntent {
                intent: CoinIntent {
                    sender: Address::ZERO,
                    inputs: vec![xparq_coin::CoinHash::from_bytes([8; 32])],
                    outputs: vec![crate::SpendOutput::block_miner(
                        xparq_coin::Zeno::from_zeno(1),
                    )],
                },
                authorization: AccountAuthorization::ProfileKnown {
                    profile: xparq_crypto::SignatureProfile::MlDsa44,
                    signature: ProfileSignature {
                        profile: xparq_crypto::SignatureProfile::MlDsa44,
                        bytes: vec![],
                    },
                },
            },
        }));
        let encoded = borsh::to_vec(&transaction).unwrap();
        assert_eq!(encoded[0], 1);
        assert_eq!(
            AuthorizedTransaction::try_from_slice(&encoded).unwrap(),
            transaction
        );
        assert_eq!(transaction.validate_structure(), Ok(()));
    }

    #[test]
    fn extension_transaction_tag_and_payload_round_trip_are_stable_after_native_asset() {
        let call = ExtensionCall::new(
            xparq_common::ExtensionHash::derive("test-extension"),
            b"canonical payload".to_vec(),
        )
        .unwrap();
        let fee = AuthorizedAccountIntent {
            intent: CoinIntent {
                sender: Address::ZERO,
                inputs: vec![xparq_coin::CoinHash::from_bytes([9; 32])],
                outputs: vec![crate::SpendOutput::block_miner(
                    xparq_coin::Zeno::from_zeno(1),
                )],
            },
            authorization: AccountAuthorization::ProfileKnown {
                profile: xparq_crypto::SignatureProfile::MlDsa44,
                signature: ProfileSignature {
                    profile: xparq_crypto::SignatureProfile::MlDsa44,
                    bytes: vec![],
                },
            },
        };
        let transaction =
            AuthorizedTransaction::Extension(Box::new(AuthorizedExtensionTransaction {
                call,
                fee,
            }));
        let encoded = borsh::to_vec(&transaction).unwrap();
        // Tag 5 is reserved for the native Layer-1 Asset transaction.
        assert_eq!(encoded[0], 2);
        assert_eq!(
            AuthorizedTransaction::try_from_slice(&encoded).unwrap(),
            transaction
        );
        assert_eq!(transaction.validate_structure(), Ok(()));
    }
}
