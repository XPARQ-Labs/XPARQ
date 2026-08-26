use borsh::{BorshDeserialize, BorshSerialize};
use xparq_common::canonical_bytes;
use xparq_crypto::{
    Address, FalconPublicKey, FalconSignature, ProfilePublicKey, ProfileSignature, PublicKey,
    QCashSignature, Signature, address_from_falcon_public_key, address_from_profile_public_key,
    address_from_public_key, falcon_verify, profile_verify, verify,
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
    Reveal {
        public_key: PublicKey,
        signature: Signature,
    },
    Known {
        signature: Signature,
    },
    Falcon512Reveal {
        public_key: FalconPublicKey,
        signature: FalconSignature,
    },
    Falcon512Known {
        signature: FalconSignature,
    },
    ProfileReveal {
        public_key: ProfilePublicKey,
        signature: ProfileSignature,
    },
    ProfileKnown {
        profile: xparq_crypto::SignatureProfile,
        signature: ProfileSignature,
    },
}

impl AccountAuthorization {
    pub const fn ml_dsa_signature(&self) -> Option<&Signature> {
        match self {
            Self::Reveal { signature, .. } | Self::Known { signature } => Some(signature),
            Self::Falcon512Reveal { .. }
            | Self::Falcon512Known { .. }
            | Self::ProfileReveal { .. }
            | Self::ProfileKnown { .. } => None,
        }
    }

    pub const fn revealed_ml_dsa_public_key(&self) -> Option<&PublicKey> {
        match self {
            Self::Reveal { public_key, .. } => Some(public_key),
            Self::Known { .. }
            | Self::Falcon512Reveal { .. }
            | Self::Falcon512Known { .. }
            | Self::ProfileReveal { .. }
            | Self::ProfileKnown { .. } => None,
        }
    }

    pub const fn falcon_signature(&self) -> Option<&FalconSignature> {
        match self {
            Self::Falcon512Reveal { signature, .. } | Self::Falcon512Known { signature } => {
                Some(signature)
            }
            Self::Reveal { .. }
            | Self::Known { .. }
            | Self::ProfileReveal { .. }
            | Self::ProfileKnown { .. } => None,
        }
    }

    pub const fn revealed_falcon_public_key(&self) -> Option<&FalconPublicKey> {
        match self {
            Self::Falcon512Reveal { public_key, .. } => Some(public_key),
            Self::Reveal { .. }
            | Self::Known { .. }
            | Self::Falcon512Known { .. }
            | Self::ProfileReveal { .. }
            | Self::ProfileKnown { .. } => None,
        }
    }
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
            AccountAuthorization::Reveal {
                public_key,
                signature,
            } => Ok(address_from_public_key(public_key) == self.intent.sender()
                && verify(public_key, commitment.as_bytes(), signature)),
            AccountAuthorization::Falcon512Reveal {
                public_key,
                signature,
            } => Ok(public_key.level() == xparq_crypto::FalconLevel::Level1
                && signature.level() == xparq_crypto::FalconLevel::Level1
                && address_from_falcon_public_key(public_key) == self.intent.sender()
                && falcon_verify(public_key, commitment.as_bytes(), signature).unwrap_or(false)),
            AccountAuthorization::ProfileReveal {
                public_key,
                signature,
            } => Ok(
                address_from_profile_public_key(public_key) == self.intent.sender()
                    && profile_verify(public_key, commitment.as_bytes(), signature),
            ),
            AccountAuthorization::Known { .. } | AccountAuthorization::Falcon512Known { .. } => {
                Ok(false)
            }
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

    pub fn expiry_height(&self) -> u64 {
        match self {
            Self::OnChainSpend(tx) => tx.intent.expiry_height,
            Self::Withdraw(tx) => tx.intent.expiry_height,
            Self::Redeem(tx) => tx.intent.expiry_height,
            Self::Merge(tx) => tx.intent.expiry_height,
            Self::Split(tx) => tx.intent.expiry_height,
        }
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
    fn adding_falcon_variants_preserves_legacy_authorization_tags() {
        let reveal = AccountAuthorization::Reveal {
            public_key: PublicKey([1; xparq_crypto::PUBLIC_KEY_SIZE]),
            signature: Signature([2; xparq_crypto::SIGNATURE_SIZE]),
        };
        let known = AccountAuthorization::Known {
            signature: Signature([3; xparq_crypto::SIGNATURE_SIZE]),
        };
        assert_eq!(borsh::to_vec(&reveal).unwrap()[0], 0);
        assert_eq!(borsh::to_vec(&known).unwrap()[0], 1);
    }
}
