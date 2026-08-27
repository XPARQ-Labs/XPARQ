use borsh::{BorshDeserialize, BorshSerialize};
use xparq_common::canonical_bytes;
use xparq_crypto::{
    Address, ProfilePublicKey, ProfileSignature, QCashSignature, address_from_profile_public_key,
    profile_verify,
};
use xparq_qcash::QCash;

use crate::{
    ChainContext, IntentError, MergeIntent, OnChainSpendIntent, QCashIntent, RedeemIntent,
    SpendCommitment, SplitIntent, TransactionEncodingError, WithdrawIntent,
};

const TRANSACTION_ID_CONTEXT: &str = "XPARQ transaction id v1";

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
}
