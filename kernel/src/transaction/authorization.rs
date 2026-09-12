use borsh::{BorshDeserialize, BorshSerialize};

use crypto::{
    AccountSignature, Address, HASH_SIZE, HashDomain, PublicKey, address_from_public_key,
    canonical_bytes, domain, verify,
};

use crate::transaction::{
    AssetIntent, ChainContext, IntentError, Spend, SpendCommitment, SpendIntent,
    TransactionEncodingError,
};

pub trait AccountIntent {
    fn sender(&self) -> Address;
    fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError>;
}

impl AccountIntent for SpendIntent {
    fn sender(&self) -> Address {
        self.signer
    }

    fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        SpendIntent::commitment(self, chain)
    }
}

impl AccountIntent for AssetIntent {
    fn sender(&self) -> Address {
        self.signer
    }

    fn commitment(&self, chain: ChainContext) -> Result<SpendCommitment, IntentError> {
        AssetIntent::commitment(self, chain.genesis_hash)
            .map(SpendCommitment::from_bytes)
            .map_err(|_| IntentError::InvalidAssetCall)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[allow(clippy::large_enum_variant)]
pub enum AccountAuthorization {
    /// First use of an account reveals the full public key.
    AccountReveal {
        public_key: PublicKey,
        signature: AccountSignature,
    },
    /// Later uses refer to the signature profile already registered for the account.
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
    pub payment: Option<AuthorizedAccountIntent<SpendIntent>>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum AuthorizedTransaction {
    Spend(Box<AuthorizedSpendTransaction>),
    Asset(Box<AuthorizedAssetTransaction>),
}

impl AuthorizedTransaction {
    pub fn id(&self) -> Result<[u8; HASH_SIZE], TransactionEncodingError> {
        let bytes = canonical_bytes(self).map_err(|_| TransactionEncodingError::Encoding)?;
        Ok(domain(HashDomain::Transaction, &bytes).into_bytes())
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

                if !matches!(tx.payment.intent.spend, Spend::Coin { .. }) {
                    return Err(IntentError::InvalidAssetCall);
                }

                tx.payment.intent.validate()
            }
        }
    }
}
