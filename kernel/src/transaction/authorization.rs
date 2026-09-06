use crate::common::{canonical_bytes, domain_hash};
use borsh::{BorshDeserialize, BorshSerialize};
use crypto::{AccountSignature, Address, PublicKey, address_from_public_key, verify};

use crate::transaction::{
    AssetIntent, ChainContext, IntentError, Spend, SpendCommitment, SpendIntent,
    TransactionEncodingError,
};

const TRANSACTION_ID_CONTEXT: &str = "XPARQ Transaction ID";

pub trait AccountIntent {
    fn sender(&self) -> Address;
    fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError>;
}

impl AccountIntent for SpendIntent {
    fn sender(&self) -> Address {
        self.signer
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
    AccountReveal {
        public_key: PublicKey,
        signature: AccountSignature,
    },
    AccountKnown {
        account: crypto::Signature,
        signature: AccountSignature,
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
            AccountAuthorization::AccountReveal {
                public_key,
                signature,
            } => Ok(address_from_public_key(public_key) == self.intent.sender()
                && verify(public_key, commitment.as_bytes(), signature)),
            AccountAuthorization::AccountKnown { .. } => Ok(false),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AuthorizedAssetTransaction {
    pub call: AuthorizedAccountIntent<AssetIntent>,
    pub payment: AuthorizedAccountIntent<SpendIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AuthorizedSpendTransaction {
    pub spend: AuthorizedAccountIntent<SpendIntent>,
    /// Asset transfers pay their protocol/miner cost with a separate coin spend.
    /// Coin transfers carry their own miner outputs and explicit burn action and leave this empty.
    pub payment: Option<AuthorizedAccountIntent<SpendIntent>>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum AuthorizedTransaction {
    Spend(Box<AuthorizedSpendTransaction>),
    Asset(Box<AuthorizedAssetTransaction>),
}

impl AuthorizedTransaction {
    pub fn id(&self) -> Result<[u8; 32], TransactionEncodingError> {
        let bytes = canonical_bytes(self).map_err(TransactionEncodingError::Encoding)?;
        Ok(domain_hash(TRANSACTION_ID_CONTEXT.as_bytes(), &[&bytes]))
    }

    pub fn validate_structure(&self) -> Result<(), IntentError> {
        match self {
            Self::Spend(tx) => {
                tx.spend.intent.validate()?;
                match (&tx.spend.intent.spend, &tx.payment) {
                    (Spend::Coin { .. }, None) => Ok(()),
                    (Spend::Asset { .. }, Some(payment))
                        if matches!(payment.intent.spend, Spend::Coin { .. }) =>
                    {
                        payment.intent.validate()
                    }
                    _ => Err(IntentError::InvalidAssetCall),
                }
            }
            Self::Asset(tx) => {
                tx.call
                    .intent
                    .validate_structure()
                    .map_err(|_| IntentError::InvalidAssetCall)?;
                tx.payment.intent.validate()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_authorization_tags_are_stable() {
        let reveal = AccountAuthorization::AccountReveal {
            public_key: PublicKey {
                account: crypto::Signature::MlDsa44,
                bytes: vec![1],
            },
            signature: AccountSignature {
                account: crypto::Signature::MlDsa44,
                bytes: vec![2],
            },
        };
        let known = AccountAuthorization::AccountKnown {
            account: crypto::Signature::MlDsa44,
            signature: AccountSignature {
                account: crypto::Signature::MlDsa44,
                bytes: vec![3],
            },
        };
        assert_eq!(borsh::to_vec(&reveal).unwrap()[0], 0);
        assert_eq!(borsh::to_vec(&known).unwrap()[0], 1);
    }

    #[test]
    fn native_asset_transaction_has_an_explicit_wire_tag() {
        let seed = crypto::SigningSeed::new(crypto::Signature::MlDsa44, [7; 32]);
        let public_key = seed.public_key();
        let signer = crypto::address_from_public_key(&public_key);
        let call = crate::transaction::AssetIntent::new(
            crate::transaction::AssetInstruction::Register {
                name: "Test Asset".into(),
                symbol: "TST".into(),
                decimals: 8,
                max_supply: crate::asset::Unit::from_units(1_000),
                initial_mint: crate::asset::Unit::from_units(100),
                mint_authority: Some(signer),
            },
            signer,
            0,
        );
        let call_signature = seed.sign(&call.commitment([3; 32]).unwrap());
        let transaction = AuthorizedTransaction::Asset(Box::new(AuthorizedAssetTransaction {
            call: AuthorizedAccountIntent {
                intent: call,
                authorization: AccountAuthorization::AccountReveal {
                    public_key,
                    signature: call_signature,
                },
            },
            payment: AuthorizedAccountIntent {
                intent: SpendIntent::coin(
                    Address::ZERO,
                    vec![crate::coin::CoinHash::from_bytes([8; 32])],
                    vec![crate::transaction::CoinOutput::block_miner(
                        crate::coin::Zeno::from_zeno(1),
                    )],
                )
                .unwrap(),
                authorization: AccountAuthorization::AccountKnown {
                    account: crypto::Signature::MlDsa44,
                    signature: AccountSignature {
                        account: crypto::Signature::MlDsa44,
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

}
