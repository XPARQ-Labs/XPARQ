use borsh::{BorshDeserialize, BorshSerialize};
use xparq_common::{ExtensionCall, canonical_bytes};
use xparq_crypto::{
    Address, ProfilePublicKey, ProfileSignature, QCashSignature, address_from_profile_public_key,
    profile_verify,
};
use xparq_qcash::QCash;

use crate::{
    ChainContext, IntentError, MergeIntent, OnChainSpendIntent, QCashIntent, RedeemIntent,
    SpendCommitment, SplitIntent, TransactionEncodingError, WithdrawIntent,
};

const TRANSACTION_ID_CONTEXT: &str = "XPARQ Transaction ID";

pub trait AccountIntent {
    fn sender(&self) -> Address;
    fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError>;
}

impl AccountIntent for OnChainSpendIntent {
    fn sender(&self) -> Address {
        self.sender
    }

    fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        self.commitment(chain)
    }
}

impl AccountIntent for WithdrawIntent {
    fn sender(&self) -> Address {
        self.sender
    }

    fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        self.commitment(chain)
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
    /// Verifies an authorization that reveals its public key.
    ///
    /// `AccountAuthorization::Known` requires the registered account key from
    /// ledger state and must be verified by consensus validation instead.
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
pub struct QCashAuthorization {
    pub signature: QCashSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AuthorizedQCashIntent<T> {
    pub intent: T,
    pub authorizations: Vec<QCashAuthorization>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AuthorizedExtensionTransaction {
    pub call: ExtensionCall,
    pub fee: AuthorizedAccountIntent<OnChainSpendIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AuthorizedAssetTransaction {
    pub call: AuthorizedAccountIntent<xparq_asset::AssetCall>,
    pub payment: AuthorizedAccountIntent<OnChainSpendIntent>,
}

impl<T: QCashIntent> AuthorizedQCashIntent<T> {
    pub fn new(intent: T, authorizations: Vec<QCashAuthorization>) -> Result<Self, IntentError> {
        if intent.qcash_inputs().len() != authorizations.len() {
            return Err(IntentError::QCashAuthorizationCountMismatch);
        }
        Ok(Self {
            intent,
            authorizations,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum AuthorizedTransaction {
    OnChainSpend(Box<AuthorizedAccountIntent<OnChainSpendIntent>>),
    Withdraw(Box<AuthorizedAccountIntent<WithdrawIntent>>),
    Redeem(Box<AuthorizedQCashIntent<RedeemIntent>>),
    Merge(Box<AuthorizedQCashIntent<MergeIntent>>),
    Split(Box<AuthorizedQCashIntent<SplitIntent>>),
    Asset(Box<AuthorizedAssetTransaction>),
    Extension(Box<AuthorizedExtensionTransaction>),
}

impl AuthorizedTransaction {
    pub fn id(&self) -> Result<[u8; 32], TransactionEncodingError> {
        let bytes = canonical_bytes(self).map_err(TransactionEncodingError::Encoding)?;
        Ok(blake3::derive_key(TRANSACTION_ID_CONTEXT, &bytes))
    }

    pub fn validate_structure(&self) -> Result<(), IntentError> {
        match self {
            Self::OnChainSpend(tx) => tx.intent.validate(),
            Self::Withdraw(tx) => tx.intent.validate(),
            Self::Redeem(tx) => validate_bearer_shape(tx, &tx.intent.inputs),
            Self::Merge(tx) => validate_bearer_shape(tx, &tx.intent.inputs),
            Self::Split(tx) => validate_bearer_shape(tx, std::slice::from_ref(&tx.intent.input)),
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

fn validate_bearer_shape<T>(
    tx: &AuthorizedQCashIntent<T>,
    inputs: &[QCash],
) -> Result<(), IntentError>
where
    T: IntentValidation,
{
    tx.intent.validate_intent()?;
    if inputs.len() != tx.authorizations.len() {
        return Err(IntentError::QCashAuthorizationCountMismatch);
    }
    Ok(())
}

trait IntentValidation {
    fn validate_intent(&self) -> Result<(), IntentError>;
}

macro_rules! impl_intent_validation {
    ($($type:ty),+ $(,)?) => {$(
        impl IntentValidation for $type {
            fn validate_intent(&self) -> Result<(), IntentError> {
                self.validate()
            }
        }
    )+};
}

impl_intent_validation!(RedeemIntent, MergeIntent, SplitIntent);

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
        let call = xparq_asset::AssetCall::new(
            xparq_asset::AssetAction::Register {
                name: "Test Asset".into(),
                symbol: "TST".into(),
                decimals: 8,
                max_supply: 1_000,
                initial_mint: 100,
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
                intent: OnChainSpendIntent {
                    sender: Address::ZERO,
                    inputs: vec![xparq_coin::CoinId::from_bytes([8; 32])],
                    outputs: vec![crate::SpendOutput::block_miner(
                        xparq_coin::Amount::from_zeno(1),
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
        assert_eq!(encoded[0], 5);
        assert_eq!(
            AuthorizedTransaction::try_from_slice(&encoded).unwrap(),
            transaction
        );
        assert_eq!(transaction.validate_structure(), Ok(()));
    }

    #[test]
    fn extension_transaction_tag_and_payload_round_trip_are_stable_after_native_asset() {
        let call = ExtensionCall::new(
            xparq_common::ExtensionId::derive("test-extension"),
            b"canonical payload".to_vec(),
        )
        .unwrap();
        let fee = AuthorizedAccountIntent {
            intent: OnChainSpendIntent {
                sender: Address::ZERO,
                inputs: vec![xparq_coin::CoinId::from_bytes([9; 32])],
                outputs: vec![crate::SpendOutput::block_miner(
                    xparq_coin::Amount::from_zeno(1),
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
        assert_eq!(encoded[0], 6);
        assert_eq!(
            AuthorizedTransaction::try_from_slice(&encoded).unwrap(),
            transaction
        );
        assert_eq!(transaction.validate_structure(), Ok(()));
    }
}
