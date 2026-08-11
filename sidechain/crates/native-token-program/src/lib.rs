//! VM-free native token execution for the experimental XPARQ sidechain.
//!
//! Nodes execute this fixed instruction set directly. There is no deployable
//! bytecode, interpreter, dynamic dispatch, or general-purpose smart-contract
//! environment.

use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::BTreeMap;
use thiserror::Error;
use xparq_sidechain_primitives::{
    Address, AddressError, Hash256, HashDomain, PROTOCOL_VERSION, PublicKey, Signature,
    SignatureError, domain_hash, dual_address_from_public_keys, verify_dual,
};
use xparq_sidechain_tokens::{
    TokenAmount, TokenError, TokenId, TokenIssuanceEvent, TokenMetadata, TokenRegistry,
};
use xparq_sidechain_wxpq::{Amount as WxpqAmount, VerifiedL1Deposit, WxpqError, WxpqLedger};

pub const NATIVE_TOKEN_PROGRAM_VERSION: u8 = 1;

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum NativeTokenInstruction {
    CreateToken {
        metadata: TokenMetadata,
        wxpq_to_burn: WxpqAmount,
    },
    Transfer {
        token_id: TokenId,
        recipient: Address,
        amount: TokenAmount,
    },
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct NativeTokenTransaction {
    pub version: u8,
    pub chain_id: u32,
    pub nonce: u64,
    pub sender: Address,
    pub instruction: NativeTokenInstruction,
}

impl NativeTokenTransaction {
    pub fn signing_root(&self) -> Result<Hash256, NativeTokenProgramError> {
        if self.version != NATIVE_TOKEN_PROGRAM_VERSION || self.version != PROTOCOL_VERSION {
            return Err(NativeTokenProgramError::UnsupportedVersion);
        }
        if self.chain_id == 0 || self.sender == Address::ZERO {
            return Err(NativeTokenProgramError::InvalidTransactionIdentity);
        }
        canonical_hash(HashDomain::NativeTokenTransaction, self)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct SignedNativeTokenTransaction {
    pub transaction: NativeTokenTransaction,
    pub owner_public_key: PublicKey,
    pub authorization_public_key: PublicKey,
    pub owner_signature: Signature,
    pub authorization_signature: Signature,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub enum NativeTokenEvent {
    TokenCreated(TokenIssuanceEvent),
    TokenTransferred {
        token_id: TokenId,
        sender: Address,
        recipient: Address,
        amount: TokenAmount,
    },
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct NativeTokenReceipt {
    pub program_id: Hash256,
    pub transaction_id: Hash256,
    pub sender: Address,
    pub nonce: u64,
    pub event: NativeTokenEvent,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct NativeTokenProgram {
    chain_id: u32,
    account_nonces: BTreeMap<Address, u64>,
    wxpq: WxpqLedger,
    tokens: TokenRegistry,
}

impl NativeTokenProgram {
    pub fn new(chain_id: u32) -> Result<Self, NativeTokenProgramError> {
        if chain_id == 0 {
            return Err(NativeTokenProgramError::InvalidChainId);
        }
        Ok(Self {
            chain_id,
            account_nonces: BTreeMap::new(),
            wxpq: WxpqLedger::new(chain_id)?,
            tokens: TokenRegistry::new(chain_id)?,
        })
    }

    pub const fn chain_id(&self) -> u32 {
        self.chain_id
    }

    pub fn program_id(&self) -> Result<Hash256, NativeTokenProgramError> {
        native_token_program_id(self.chain_id)
    }

    pub fn account_nonce(&self, address: Address) -> u64 {
        self.account_nonces.get(&address).copied().unwrap_or(0)
    }

    pub const fn wxpq(&self) -> &WxpqLedger {
        &self.wxpq
    }

    pub const fn tokens(&self) -> &TokenRegistry {
        &self.tokens
    }

    /// Bridge-system entry point. The L1 proof must already have crossed the
    /// finalized-deposit verifier boundary.
    pub fn mint_wxpq_from_finalized_deposit(
        &mut self,
        deposit: VerifiedL1Deposit,
    ) -> Result<Hash256, NativeTokenProgramError> {
        Ok(self.wxpq.mint_from_finalized_deposit(deposit)?)
    }

    /// Verify dual SQIsign authorization and execute one fixed native
    /// instruction atomically.
    pub fn execute(
        &mut self,
        signed: &SignedNativeTokenTransaction,
    ) -> Result<NativeTokenReceipt, NativeTokenProgramError> {
        let transaction = &signed.transaction;
        if transaction.chain_id != self.chain_id {
            return Err(NativeTokenProgramError::ChainIdMismatch);
        }
        let transaction_id = transaction.signing_root()?;
        let derived_sender = dual_address_from_public_keys(
            self.chain_id,
            &signed.owner_public_key,
            &signed.authorization_public_key,
        )?;
        if derived_sender != transaction.sender {
            return Err(NativeTokenProgramError::SignerAddressMismatch);
        }
        verify_dual(
            &signed.owner_public_key,
            &signed.authorization_public_key,
            &transaction_id.0,
            &signed.owner_signature,
            &signed.authorization_signature,
        )?;

        let expected_nonce = self.account_nonce(transaction.sender);
        if transaction.nonce != expected_nonce {
            return Err(NativeTokenProgramError::InvalidNonce {
                expected: expected_nonce,
                received: transaction.nonce,
            });
        }
        let next_nonce = expected_nonce
            .checked_add(1)
            .ok_or(NativeTokenProgramError::NonceOverflow)?;

        let mut next = self.clone();
        let event = match transaction.instruction.clone() {
            NativeTokenInstruction::CreateToken {
                metadata,
                wxpq_to_burn,
            } => NativeTokenEvent::TokenCreated(next.tokens.create_token_after_authorization(
                &mut next.wxpq,
                transaction.sender,
                metadata,
                wxpq_to_burn,
            )?),
            NativeTokenInstruction::Transfer {
                token_id,
                recipient,
                amount,
            } => {
                next.tokens.transfer_after_authorization(
                    token_id,
                    transaction.sender,
                    recipient,
                    amount,
                )?;
                NativeTokenEvent::TokenTransferred {
                    token_id,
                    sender: transaction.sender,
                    recipient,
                    amount,
                }
            }
        };
        next.account_nonces.insert(transaction.sender, next_nonce);
        next.validate_invariants()?;
        *self = next;

        Ok(NativeTokenReceipt {
            program_id: self.program_id()?,
            transaction_id,
            sender: transaction.sender,
            nonce: transaction.nonce,
            event,
        })
    }

    pub fn state_root(&self) -> Result<Hash256, NativeTokenProgramError> {
        self.validate_invariants()?;
        canonical_hash(HashDomain::NativeTokenProgramState, self)
    }

    pub fn validate_invariants(&self) -> Result<(), NativeTokenProgramError> {
        if NATIVE_TOKEN_PROGRAM_VERSION != PROTOCOL_VERSION {
            return Err(NativeTokenProgramError::UnsupportedVersion);
        }
        if self.chain_id == 0
            || self.wxpq.chain_id() != self.chain_id
            || self.tokens.chain_id() != self.chain_id
        {
            return Err(NativeTokenProgramError::ChainIdMismatch);
        }
        self.wxpq.validate_invariants()?;
        self.tokens.validate_invariants()?;
        Ok(())
    }
}

pub fn native_token_program_id(chain_id: u32) -> Result<Hash256, NativeTokenProgramError> {
    if chain_id == 0 {
        return Err(NativeTokenProgramError::InvalidChainId);
    }
    canonical_hash(
        HashDomain::NativeTokenProgram,
        &(NATIVE_TOKEN_PROGRAM_VERSION, chain_id),
    )
}

fn canonical_hash<T: BorshSerialize>(
    domain: HashDomain,
    value: &T,
) -> Result<Hash256, NativeTokenProgramError> {
    let bytes = borsh::to_vec(value)
        .map_err(|error| NativeTokenProgramError::Encoding(error.to_string()))?;
    Ok(domain_hash(domain, &bytes))
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NativeTokenProgramError {
    #[error("unsupported native token program version")]
    UnsupportedVersion,
    #[error("sidechain chain ID must be nonzero")]
    InvalidChainId,
    #[error("transaction identity is invalid")]
    InvalidTransactionIdentity,
    #[error("transaction belongs to another sidechain")]
    ChainIdMismatch,
    #[error("transaction public keys do not derive its sender address")]
    SignerAddressMismatch,
    #[error("invalid account nonce: expected {expected}, received {received}")]
    InvalidNonce { expected: u64, received: u64 },
    #[error("account nonce overflow")]
    NonceOverflow,
    #[error("canonical encoding failed: {0}")]
    Encoding(String),
    #[error(transparent)]
    Address(#[from] AddressError),
    #[error(transparent)]
    Signature(#[from] SignatureError),
    #[error(transparent)]
    Token(#[from] TokenError),
    #[error(transparent)]
    Wxpq(#[from] WxpqError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqisign_rs::{Level5, SigningKey, generate};
    use xparq_sidechain_primitives::{PUBLIC_KEY_SIZE, SIGNATURE_SIZE};
    use xparq_sidechain_tokens::TOKEN_UNITS_PER_BURNED_WXPQ;
    use xparq_sidechain_wxpq::{
        FinalizedL1DepositVerifier, L1DepositClaim, PAQS_PER_WXPQ, WXPQ_VERSION,
        verify_finalized_l1_deposit,
    };

    const CHAIN_ID: u32 = 9_001;

    struct TestVerifier;

    impl FinalizedL1DepositVerifier<()> for TestVerifier {
        fn verify_finalized_deposit(&self, _claim: &L1DepositClaim, _proof: &()) -> bool {
            true
        }
    }

    struct TestAccount {
        address: Address,
        owner_public_key: PublicKey,
        authorization_public_key: PublicKey,
        owner_signing_key: SigningKey<Level5>,
        authorization_signing_key: SigningKey<Level5>,
    }

    fn account() -> TestAccount {
        let mut rng = rand_10::rng();
        let (owner_pk, owner_signing_key) = generate::<Level5>(&mut rng);
        let (authorization_pk, authorization_signing_key) = generate::<Level5>(&mut rng);
        let owner_public_key = PublicKey(
            owner_pk
                .to_bytes()
                .as_slice()
                .try_into()
                .expect("level 5 public key size"),
        );
        let authorization_public_key = PublicKey(
            authorization_pk
                .to_bytes()
                .as_slice()
                .try_into()
                .expect("level 5 public key size"),
        );
        assert_eq!(owner_public_key.0.len(), PUBLIC_KEY_SIZE);
        let address =
            dual_address_from_public_keys(CHAIN_ID, &owner_public_key, &authorization_public_key)
                .unwrap();
        TestAccount {
            address,
            owner_public_key,
            authorization_public_key,
            owner_signing_key,
            authorization_signing_key,
        }
    }

    fn sign(
        account: &TestAccount,
        transaction: NativeTokenTransaction,
    ) -> SignedNativeTokenTransaction {
        let root = transaction.signing_root().unwrap();
        let mut rng = rand_10::rng();
        let owner_signature = account.owner_signing_key.sign(&root.0, &mut rng).unwrap();
        let authorization_signature = account
            .authorization_signing_key
            .sign(&root.0, &mut rng)
            .unwrap();
        let owner_signature = Signature(
            owner_signature
                .to_bytes()
                .as_slice()
                .try_into()
                .expect("level 5 signature size"),
        );
        let authorization_signature = Signature(
            authorization_signature
                .to_bytes()
                .as_slice()
                .try_into()
                .expect("level 5 signature size"),
        );
        assert_eq!(owner_signature.0.len(), SIGNATURE_SIZE);
        SignedNativeTokenTransaction {
            transaction,
            owner_public_key: account.owner_public_key,
            authorization_public_key: account.authorization_public_key,
            owner_signature,
            authorization_signature,
        }
    }

    fn fund(program: &mut NativeTokenProgram, recipient: Address, amount: u64) {
        let claim = L1DepositClaim {
            version: WXPQ_VERSION,
            l1_chain_id: 747,
            sidechain_chain_id: CHAIN_ID,
            l1_block_hash: Hash256([7; 32]),
            l1_block_height: 100,
            deposit_index: 0,
            recipient,
            amount: WxpqAmount(amount),
        };
        let deposit = verify_finalized_l1_deposit(claim, &(), &TestVerifier).unwrap();
        program.mint_wxpq_from_finalized_deposit(deposit).unwrap();
    }

    #[test]
    fn fixed_native_program_id_is_chain_scoped() {
        assert_eq!(
            native_token_program_id(CHAIN_ID),
            native_token_program_id(CHAIN_ID)
        );
        assert_ne!(
            native_token_program_id(CHAIN_ID).unwrap(),
            native_token_program_id(CHAIN_ID + 1).unwrap()
        );
    }

    #[test]
    fn signed_create_instruction_burns_wxpq_and_issues_once() {
        let account = account();
        let mut program = NativeTokenProgram::new(CHAIN_ID).unwrap();
        fund(&mut program, account.address, PAQS_PER_WXPQ);
        let transaction = NativeTokenTransaction {
            version: NATIVE_TOKEN_PROGRAM_VERSION,
            chain_id: CHAIN_ID,
            nonce: 0,
            sender: account.address,
            instruction: NativeTokenInstruction::CreateToken {
                metadata: TokenMetadata::new("Example Token", "EXM").unwrap(),
                wxpq_to_burn: WxpqAmount(PAQS_PER_WXPQ),
            },
        };
        let signed = sign(&account, transaction);
        let before_root = program.state_root().unwrap();
        let receipt = program.execute(&signed).unwrap();
        let NativeTokenEvent::TokenCreated(issuance) = receipt.event else {
            panic!("expected token creation event")
        };

        assert_eq!(receipt.program_id, program.program_id().unwrap());
        assert_eq!(program.account_nonce(account.address), 1);
        assert_eq!(
            program
                .tokens()
                .token(issuance.token_id)
                .unwrap()
                .total_supply(),
            TokenAmount(TOKEN_UNITS_PER_BURNED_WXPQ)
        );
        assert_eq!(program.wxpq().total_supply(), WxpqAmount::ZERO);
        assert_ne!(before_root, program.state_root().unwrap());

        let recipient = Address([9; 20]);
        let transfer = sign(
            &account,
            NativeTokenTransaction {
                version: NATIVE_TOKEN_PROGRAM_VERSION,
                chain_id: CHAIN_ID,
                nonce: 1,
                sender: account.address,
                instruction: NativeTokenInstruction::Transfer {
                    token_id: issuance.token_id,
                    recipient,
                    amount: TokenAmount(25_000_000),
                },
            },
        );
        let transfer_receipt = program.execute(&transfer).unwrap();
        assert!(matches!(
            transfer_receipt.event,
            NativeTokenEvent::TokenTransferred { token_id, .. } if token_id == issuance.token_id
        ));
        assert_eq!(program.account_nonce(account.address), 2);
        assert_eq!(
            program
                .tokens()
                .token(issuance.token_id)
                .unwrap()
                .balance(recipient),
            TokenAmount(25_000_000)
        );
    }

    #[test]
    fn transaction_nonce_prevents_replay_without_state_changes() {
        let account = account();
        let mut program = NativeTokenProgram::new(CHAIN_ID).unwrap();
        fund(&mut program, account.address, PAQS_PER_WXPQ);
        let signed = sign(
            &account,
            NativeTokenTransaction {
                version: NATIVE_TOKEN_PROGRAM_VERSION,
                chain_id: CHAIN_ID,
                nonce: 0,
                sender: account.address,
                instruction: NativeTokenInstruction::CreateToken {
                    metadata: TokenMetadata::new("Example Token", "EXM").unwrap(),
                    wxpq_to_burn: WxpqAmount(PAQS_PER_WXPQ),
                },
            },
        );
        program.execute(&signed).unwrap();
        let before_replay = program.clone();

        assert_eq!(
            program.execute(&signed),
            Err(NativeTokenProgramError::InvalidNonce {
                expected: 1,
                received: 0,
            })
        );
        assert_eq!(program, before_replay);
    }
}
