use borsh::{BorshDeserialize, BorshSerialize};

use crypto::{
    AccountSignature, Address, HASH_SIZE, HashDomain, PublicKey, address_from_public_key,
    canonical_bytes, domain, verify,
};

use crate::common::ChainContext;
use crate::transaction::{AssetIntent, IntentError, Spend, SpendIntent, TransactionEncodingError};

/// Stable authorization context written into every account-signature commitment.
///
/// The explicit role prevents a valid signature from being reused in another
/// authorization context. Discriminants are consensus-facing and must never be
/// renumbered after deployment.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum AuthorizationRole {
    DirectSpend = 1,
    AssetSpend = 2,
    AssetCall = 3,
    AssetSpendPayment = 4,
    AssetCallPayment = 5,
}

/// Canonical digest signed by an account authorization.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct AuthorizationCommitment([u8; HASH_SIZE]);

impl AuthorizationCommitment {
    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; HASH_SIZE] {
        self.0
    }
}

/// Hash of the unsigned transaction semantics.
///
/// This excludes public keys and signatures but includes every intent that
/// affects the resulting state transition, including a bound payment intent.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct IntentId([u8; HASH_SIZE]);

impl IntentId {
    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; HASH_SIZE] {
        self.0
    }
}

/// Hash of the complete authorized transaction, including public keys and
/// signatures. This is the canonical on-chain transaction identifier.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct TransactionId([u8; HASH_SIZE]);

impl TransactionId {
    pub const fn from_bytes(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; HASH_SIZE] {
        self.0
    }
}

const TRANSACTION_INTENT_ID_TAG: [u8; 27] = *b"xparq:transaction-intent:v1";
const INTENT_KIND_COIN_SPEND: u8 = 1;
const INTENT_KIND_ASSET_SPEND: u8 = 2;
const INTENT_KIND_ASSET_CALL: u8 = 3;

/// Intent that owns a principal account authorization.
///
/// The implementation chooses its own role. Callers cannot supply a role and
/// therefore cannot accidentally sign a coin transfer as an asset operation,
/// or vice versa.
pub trait AccountIntent {
    fn sender(&self) -> Address;
    fn authorization_role(&self) -> AuthorizationRole;

    fn authorization_commitment(
        &self,
        chain: ChainContext,
    ) -> Result<AuthorizationCommitment, IntentError>;
}

impl AccountIntent for SpendIntent {
    fn sender(&self) -> Address {
        self.signer
    }

    fn authorization_role(&self) -> AuthorizationRole {
        match &self.spend {
            Spend::Coin { .. } => AuthorizationRole::DirectSpend,
            Spend::Asset { .. } => AuthorizationRole::AssetSpend,
        }
    }

    fn authorization_commitment(
        &self,
        chain: ChainContext,
    ) -> Result<AuthorizationCommitment, IntentError> {
        self.validate()?;

        let role = self.authorization_role();
        let bytes = canonical_bytes(&(chain.genesis_hash, role, self))
            .map_err(|_| IntentError::Encoding)?;

        Ok(AuthorizationCommitment::from_bytes(
            domain(HashDomain::SpendIntent, &bytes).into_bytes(),
        ))
    }
}

impl AccountIntent for AssetIntent {
    fn sender(&self) -> Address {
        self.signer
    }

    fn authorization_role(&self) -> AuthorizationRole {
        AuthorizationRole::AssetCall
    }

    fn authorization_commitment(
        &self,
        chain: ChainContext,
    ) -> Result<AuthorizationCommitment, IntentError> {
        self.validate_structure()
            .map_err(|_| IntentError::InvalidAssetCall)?;

        let role = self.authorization_role();
        let bytes = canonical_bytes(&(chain.genesis_hash, role, self))
            .map_err(|_| IntentError::Encoding)?;

        Ok(AuthorizationCommitment::from_bytes(
            domain(HashDomain::AssetIntent, &bytes).into_bytes(),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AccountAuthorization {
    pub public_key: PublicKey,
    pub signature: AccountSignature,
}

impl AccountAuthorization {
    pub fn has_matching_scheme(&self) -> bool {
        self.public_key.scheme() == self.signature.scheme()
    }

    /// Compatibility helper. New code should use `has_matching_scheme()`.
    pub fn has_matching_account(&self) -> bool {
        self.has_matching_scheme()
    }

    pub fn active_at_height(&self, _height: u64) -> bool {
        self.has_matching_scheme() && self.public_key.scheme().supported()
    }

    /// Verify one already-constructed authorization commitment.
    ///
    /// Cheap checks run before the post-quantum signature verification.
    pub fn verify_commitment(
        &self,
        sender: Address,
        commitment: &AuthorizationCommitment,
        height: u64,
    ) -> bool {
        if !self.active_at_height(height) {
            return false;
        }

        if address_from_public_key(&self.public_key) != sender {
            return false;
        }

        verify(&self.public_key, commitment.as_bytes(), &self.signature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AuthorizedAccountIntent<T> {
    pub intent: T,
    pub authorization: AccountAuthorization,
}

impl<T: AccountIntent> AuthorizedAccountIntent<T> {
    /// Verify a principal authorization.
    ///
    /// Payment authorizations intentionally do not use this method because a
    /// payment must also commit to its parent intent.
    pub fn verify_principal_signature(
        &self,
        chain: ChainContext,
        height: u64,
    ) -> Result<bool, IntentError> {
        let commitment = self.intent.authorization_commitment(chain)?;

        Ok(self
            .authorization
            .verify_commitment(self.intent.sender(), &commitment, height))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AuthorizedAssetTransaction {
    pub call: AuthorizedAccountIntent<AssetIntent>,
    pub payment: AuthorizedAccountIntent<SpendIntent>,
}

impl AuthorizedAssetTransaction {
    pub fn verify_authorizations(
        &self,
        chain: ChainContext,
        height: u64,
    ) -> Result<bool, IntentError> {
        if !self.call.verify_principal_signature(chain, height)? {
            return Ok(false);
        }

        let payment_commitment =
            asset_call_payment_commitment(&self.call.intent, &self.payment.intent, chain)?;

        Ok(self.payment.authorization.verify_commitment(
            self.payment.intent.signer,
            &payment_commitment,
            height,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AuthorizedSpendTransaction {
    pub spend: AuthorizedAccountIntent<SpendIntent>,
    pub payment: Option<AuthorizedAccountIntent<SpendIntent>>,
}

impl AuthorizedSpendTransaction {
    pub fn verify_authorizations(
        &self,
        chain: ChainContext,
        height: u64,
    ) -> Result<bool, IntentError> {
        if !self.spend.verify_principal_signature(chain, height)? {
            return Ok(false);
        }

        match (&self.spend.intent.spend, &self.payment) {
            (Spend::Coin { .. }, None) => Ok(true),
            (Spend::Asset { .. }, Some(payment)) => {
                let payment_commitment =
                    asset_spend_payment_commitment(&self.spend.intent, &payment.intent, chain)?;

                Ok(payment.authorization.verify_commitment(
                    payment.intent.signer,
                    &payment_commitment,
                    height,
                ))
            }
            _ => Err(IntentError::InvalidAssetCall),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum AuthorizedTransaction {
    Spend(Box<AuthorizedSpendTransaction>),
    Asset(Box<AuthorizedAssetTransaction>),
}

impl AuthorizedTransaction {
    /// Canonical ID of the complete authorized transaction.
    ///
    /// This preserves the existing transaction-ID preimage: canonical bytes
    /// of the full `AuthorizedTransaction` under `HashDomain::Transaction`.
    pub fn transaction_id(&self) -> Result<TransactionId, TransactionEncodingError> {
        let bytes = canonical_bytes(self).map_err(|_| TransactionEncodingError::Encoding)?;
        Ok(TransactionId::from_bytes(
            domain(HashDomain::Transaction, &bytes).into_bytes(),
        ))
    }

    /// Stable semantic ID used to identify the state-transition intent without
    /// including authorization material.
    ///
    /// Payment intents are included because they spend coin state. Public keys
    /// and signatures are excluded so re-signing the same semantics does not
    /// create a different `IntentId`.
    pub fn intent_id(&self) -> Result<IntentId, TransactionEncodingError> {
        self.validate_structure()
            .map_err(|_| TransactionEncodingError::Encoding)?;

        let bytes = match self {
            Self::Spend(tx) => match (&tx.spend.intent.spend, &tx.payment) {
                (Spend::Coin { .. }, None) => canonical_bytes(&(
                    TRANSACTION_INTENT_ID_TAG,
                    INTENT_KIND_COIN_SPEND,
                    &tx.spend.intent,
                )),
                (Spend::Asset { .. }, Some(payment)) => canonical_bytes(&(
                    TRANSACTION_INTENT_ID_TAG,
                    INTENT_KIND_ASSET_SPEND,
                    &tx.spend.intent,
                    &payment.intent,
                )),
                _ => return Err(TransactionEncodingError::Encoding),
            },
            Self::Asset(tx) => canonical_bytes(&(
                TRANSACTION_INTENT_ID_TAG,
                INTENT_KIND_ASSET_CALL,
                &tx.call.intent,
                &tx.payment.intent,
            )),
        }
        .map_err(|_| TransactionEncodingError::Encoding)?;

        Ok(IntentId::from_bytes(
            domain(HashDomain::Transaction, &bytes).into_bytes(),
        ))
    }

    /// Compatibility accessor for callers that still expect raw transaction-ID
    /// bytes. New code should prefer `transaction_id()`.
    pub fn id(&self) -> Result<[u8; HASH_SIZE], TransactionEncodingError> {
        Ok(self.transaction_id()?.into_bytes())
    }

    pub fn validate_structure(&self) -> Result<(), IntentError> {
        match self {
            Self::Spend(tx) => {
                tx.spend.intent.validate()?;

                match (&tx.spend.intent.spend, &tx.payment) {
                    (Spend::Coin { .. }, None) => Ok(()),
                    (Spend::Asset { .. }, Some(payment))
                        if matches!(&payment.intent.spend, Spend::Coin { .. }) =>
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

                if !matches!(&tx.payment.intent.spend, Spend::Coin { .. }) {
                    return Err(IntentError::InvalidAssetCall);
                }

                tx.payment.intent.validate()
            }
        }
    }

    /// Authoritative transaction-level authorization verification.
    ///
    /// This method enforces role separation and parent-binding for payments.
    /// Consensus validation should prefer this over verifying individual
    /// signatures in isolation.
    pub fn verify_authorizations(
        &self,
        chain: ChainContext,
        height: u64,
    ) -> Result<bool, IntentError> {
        self.validate_structure()?;

        match self {
            Self::Spend(tx) => tx.verify_authorizations(chain, height),
            Self::Asset(tx) => tx.verify_authorizations(chain, height),
        }
    }
}

/// Commitment signed by the coin payer of an account-authorized asset transfer.
///
/// The parent asset-spend commitment is included, so the payment cannot be
/// detached and attached to another asset transfer.
pub fn asset_spend_payment_commitment(
    parent: &SpendIntent,
    payment: &SpendIntent,
    chain: ChainContext,
) -> Result<AuthorizationCommitment, IntentError> {
    if !matches!(&parent.spend, Spend::Asset { .. }) {
        return Err(IntentError::InvalidAssetCall);
    }

    let parent_commitment = parent.authorization_commitment(chain)?;

    payment_commitment(
        payment,
        parent_commitment,
        AuthorizationRole::AssetSpendPayment,
        chain,
    )
}

/// Commitment signed by the coin payer of a native asset call
/// (register/mint/burn).
///
/// The parent AssetIntent commitment is included, so the payment cannot be
/// detached and attached to another asset call.
pub fn asset_call_payment_commitment(
    parent: &AssetIntent,
    payment: &SpendIntent,
    chain: ChainContext,
) -> Result<AuthorizationCommitment, IntentError> {
    let parent_commitment = parent.authorization_commitment(chain)?;

    payment_commitment(
        payment,
        parent_commitment,
        AuthorizationRole::AssetCallPayment,
        chain,
    )
}

fn payment_commitment(
    payment: &SpendIntent,
    parent_commitment: AuthorizationCommitment,
    role: AuthorizationRole,
    chain: ChainContext,
) -> Result<AuthorizationCommitment, IntentError> {
    payment.validate()?;

    if !matches!(&payment.spend, Spend::Coin { .. }) {
        return Err(IntentError::InvalidAssetCall);
    }

    let bytes = canonical_bytes(&(chain.genesis_hash, role, parent_commitment, payment))
        .map_err(|_| IntentError::Encoding)?;

    Ok(AuthorizationCommitment::from_bytes(
        domain(HashDomain::SpendIntent, &bytes).into_bytes(),
    ))
}

#[cfg(test)]
mod adversarial_tests {
    use super::*;

    use borsh::BorshDeserialize;
    use crypto::{AccountSignatureScheme, SigningSeed, address_from_public_key};

    use crate::{
        common::ChainContext,
        native::{
            asset::{AssetOutput, Contract, Share, Unit},
            coin::{CoinOutput, XPQ, Zeno},
        },
        transaction::AssetInstruction,
    };

    const TEST_HEIGHT: u64 = 0;

    fn signing_seed(tag: u8) -> SigningSeed {
        SigningSeed::new(AccountSignatureScheme::MlDsa44, Box::new([tag; 32]))
    }

    fn signer_address(seed: &SigningSeed) -> Address {
        address_from_public_key(&seed.public_key())
    }

    fn chain(tag: u8) -> ChainContext {
        ChainContext::new([tag; HASH_SIZE])
    }

    fn coin_intent(seed: &SigningSeed, input_tag: u8, amount: u64) -> SpendIntent {
        let signer = signer_address(seed);

        SpendIntent::coin(
            signer,
            vec![XPQ::from_bytes([input_tag; HASH_SIZE])],
            vec![CoinOutput::new(signer, Zeno::from_zeno(amount))],
        )
        .expect("valid test coin intent")
    }

    fn asset_spend_intent(
        seed: &SigningSeed,
        contract_tag: u8,
        share_tag: u8,
        amount: u128,
    ) -> SpendIntent {
        let signer = signer_address(seed);

        SpendIntent::asset(
            signer,
            Contract::from_bytes([contract_tag; HASH_SIZE]),
            vec![Share::from_bytes([share_tag; HASH_SIZE])],
            vec![AssetOutput::new(signer, Unit::from_units(amount))],
        )
        .expect("valid test asset spend intent")
    }

    fn asset_call_intent(seed: &SigningSeed, nonce: u64) -> AssetIntent {
        let signer = signer_address(seed);

        AssetIntent::new(
            AssetInstruction::Register {
                name: "TEST".to_owned(),
                decimals: 8,
                max_supply: Unit::from_units(1_000_000),
                initial_mint: Unit::from_units(100),
                mint_authority: signer,
                nonce,
            },
            signer,
        )
    }

    fn authorize_principal<T: AccountIntent>(
        intent: T,
        seed: &SigningSeed,
        chain: ChainContext,
    ) -> AuthorizedAccountIntent<T> {
        let commitment = intent
            .authorization_commitment(chain)
            .expect("valid principal commitment");

        AuthorizedAccountIntent {
            intent,
            authorization: AccountAuthorization {
                public_key: seed.public_key(),
                signature: seed.sign(commitment.as_bytes()),
            },
        }
    }

    fn authorize_asset_call_payment(
        parent: &AssetIntent,
        payment: SpendIntent,
        payer: &SigningSeed,
        chain: ChainContext,
    ) -> AuthorizedAccountIntent<SpendIntent> {
        let commitment = asset_call_payment_commitment(parent, &payment, chain)
            .expect("valid asset-call payment commitment");

        AuthorizedAccountIntent {
            intent: payment,
            authorization: AccountAuthorization {
                public_key: payer.public_key(),
                signature: payer.sign(commitment.as_bytes()),
            },
        }
    }

    fn authorize_asset_spend_payment(
        parent: &SpendIntent,
        payment: SpendIntent,
        payer: &SigningSeed,
        chain: ChainContext,
    ) -> AuthorizedAccountIntent<SpendIntent> {
        let commitment = asset_spend_payment_commitment(parent, &payment, chain)
            .expect("valid asset-spend payment commitment");

        AuthorizedAccountIntent {
            intent: payment,
            authorization: AccountAuthorization {
                public_key: payer.public_key(),
                signature: payer.sign(commitment.as_bytes()),
            },
        }
    }

    #[test]
    fn direct_spend_signature_is_chain_bound() {
        let owner = signing_seed(1);
        let chain_a = chain(0xa1);
        let chain_b = chain(0xb1);
        let intent = coin_intent(&owner, 1, 10);
        let authorized = authorize_principal(intent, &owner, chain_a);

        assert!(
            authorized
                .verify_principal_signature(chain_a, TEST_HEIGHT)
                .unwrap()
        );
        assert!(
            !authorized
                .verify_principal_signature(chain_b, TEST_HEIGHT)
                .unwrap()
        );
    }

    #[test]
    fn principal_signature_is_bound_to_sender_address() {
        let attacker = signing_seed(2);
        let victim = signing_seed(3);
        let victim_address = signer_address(&victim);
        let chain = chain(0x11);

        let intent = SpendIntent::coin(
            victim_address,
            vec![XPQ::from_bytes([2; HASH_SIZE])],
            vec![CoinOutput::new(victim_address, Zeno::from_zeno(10))],
        )
        .unwrap();

        let commitment = intent.authorization_commitment(chain).unwrap();
        let authorized = AuthorizedAccountIntent {
            intent,
            authorization: AccountAuthorization {
                public_key: attacker.public_key(),
                signature: attacker.sign(commitment.as_bytes()),
            },
        };

        assert!(
            !authorized
                .verify_principal_signature(chain, TEST_HEIGHT)
                .unwrap()
        );
    }

    #[test]
    fn direct_spend_signature_cannot_authorize_asset_call_payment() {
        let caller = signing_seed(4);
        let payer = signing_seed(5);
        let chain = chain(0x22);

        let call = asset_call_intent(&caller, 7);
        let authorized_call = authorize_principal(call, &caller, chain);

        let payment = coin_intent(&payer, 3, 20);

        // Deliberately sign the payment as a normal DirectSpend instead of
        // AssetCallPayment. The bytes are a valid ML-DSA signature, but the
        // authorization role is wrong.
        let wrong_commitment = payment.authorization_commitment(chain).unwrap();
        let wrong_payment = AuthorizedAccountIntent {
            intent: payment,
            authorization: AccountAuthorization {
                public_key: payer.public_key(),
                signature: payer.sign(wrong_commitment.as_bytes()),
            },
        };

        let transaction = AuthorizedAssetTransaction {
            call: authorized_call,
            payment: wrong_payment,
        };

        assert!(
            !transaction
                .verify_authorizations(chain, TEST_HEIGHT)
                .unwrap()
        );
    }

    #[test]
    fn asset_call_payment_cannot_be_reused_for_another_parent() {
        let caller = signing_seed(6);
        let payer = signing_seed(7);
        let chain = chain(0x33);

        let call_a = asset_call_intent(&caller, 1);
        let call_b = asset_call_intent(&caller, 2);
        let payment = coin_intent(&payer, 4, 30);

        let payment_for_a = authorize_asset_call_payment(&call_a, payment, &payer, chain);

        let tx_a = AuthorizedAssetTransaction {
            call: authorize_principal(call_a, &caller, chain),
            payment: payment_for_a.clone(),
        };
        let tx_b = AuthorizedAssetTransaction {
            call: authorize_principal(call_b, &caller, chain),
            payment: payment_for_a,
        };

        assert!(tx_a.verify_authorizations(chain, TEST_HEIGHT).unwrap());
        assert!(!tx_b.verify_authorizations(chain, TEST_HEIGHT).unwrap());
    }

    #[test]
    fn asset_spend_payment_cannot_be_reused_for_another_parent() {
        let owner = signing_seed(8);
        let payer = signing_seed(9);
        let chain = chain(0x44);

        let spend_a = asset_spend_intent(&owner, 0x41, 0x51, 100);
        let spend_b = asset_spend_intent(&owner, 0x41, 0x51, 101);
        let payment = coin_intent(&payer, 5, 40);

        let payment_for_a = authorize_asset_spend_payment(&spend_a, payment, &payer, chain);

        let tx_a = AuthorizedSpendTransaction {
            spend: authorize_principal(spend_a, &owner, chain),
            payment: Some(payment_for_a.clone()),
        };
        let tx_b = AuthorizedSpendTransaction {
            spend: authorize_principal(spend_b, &owner, chain),
            payment: Some(payment_for_a),
        };

        assert!(tx_a.verify_authorizations(chain, TEST_HEIGHT).unwrap());
        assert!(!tx_b.verify_authorizations(chain, TEST_HEIGHT).unwrap());
    }

    #[test]
    fn intent_id_ignores_authorization_but_transaction_id_does_not() {
        let owner = signing_seed(10);
        let chain = chain(0x55);
        let intent = coin_intent(&owner, 6, 50);

        let transaction = AuthorizedTransaction::Spend(Box::new(AuthorizedSpendTransaction {
            spend: authorize_principal(intent, &owner, chain),
            payment: None,
        }));

        let mut changed_authorization = transaction.clone();
        let AuthorizedTransaction::Spend(tx) = &mut changed_authorization else {
            unreachable!();
        };
        tx.spend.authorization.signature.bytes[0] ^= 0x01;

        assert_eq!(
            transaction.intent_id().unwrap(),
            changed_authorization.intent_id().unwrap()
        );
        assert_ne!(
            transaction.transaction_id().unwrap(),
            changed_authorization.transaction_id().unwrap()
        );

        assert!(
            transaction
                .verify_authorizations(chain, TEST_HEIGHT)
                .unwrap()
        );
        assert!(
            !changed_authorization
                .verify_authorizations(chain, TEST_HEIGHT)
                .unwrap()
        );
    }

    #[test]
    fn intent_id_changes_when_payment_intent_changes() {
        let caller = signing_seed(11);
        let payer = signing_seed(12);
        let chain = chain(0x66);
        let call = asset_call_intent(&caller, 9);

        let payment_a = coin_intent(&payer, 7, 60);
        let payment_b = coin_intent(&payer, 8, 60);

        let tx_a = AuthorizedTransaction::Asset(Box::new(AuthorizedAssetTransaction {
            call: authorize_principal(call.clone(), &caller, chain),
            payment: authorize_asset_call_payment(&call, payment_a, &payer, chain),
        }));

        let tx_b = AuthorizedTransaction::Asset(Box::new(AuthorizedAssetTransaction {
            call: authorize_principal(call.clone(), &caller, chain),
            payment: authorize_asset_call_payment(&call, payment_b, &payer, chain),
        }));

        assert_ne!(tx_a.intent_id().unwrap(), tx_b.intent_id().unwrap());
        assert!(tx_a.verify_authorizations(chain, TEST_HEIGHT).unwrap());
        assert!(tx_b.verify_authorizations(chain, TEST_HEIGHT).unwrap());
    }

    #[test]
    fn borsh_round_trip_preserves_ids_and_authorization() {
        let caller = signing_seed(13);
        let payer = signing_seed(14);
        let chain = chain(0x77);
        let call = asset_call_intent(&caller, 10);
        let payment = coin_intent(&payer, 9, 70);

        let transaction = AuthorizedTransaction::Asset(Box::new(AuthorizedAssetTransaction {
            call: authorize_principal(call.clone(), &caller, chain),
            payment: authorize_asset_call_payment(&call, payment, &payer, chain),
        }));

        let bytes = borsh::to_vec(&transaction).unwrap();
        let decoded = AuthorizedTransaction::try_from_slice(&bytes).unwrap();

        assert_eq!(transaction, decoded);
        assert_eq!(
            transaction.intent_id().unwrap(),
            decoded.intent_id().unwrap()
        );
        assert_eq!(
            transaction.transaction_id().unwrap(),
            decoded.transaction_id().unwrap()
        );
        assert!(decoded.verify_authorizations(chain, TEST_HEIGHT).unwrap());
    }
}
