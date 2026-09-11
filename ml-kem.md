crypto/
├── kem/
│   ├── mod.rs
│   └── mlkem.rs
│
└── vault/
    ├── owner.rs
    └── envelope.rs

kernel/
├── native/
│   └── vault.rs
│
└── transaction/
    └── vault.rs




use ml_kem::{
    MlKem768,
    kem::{Decapsulate, Encapsulate, Kem},
};

pub const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1088;
pub const ML_KEM_SHARED_SECRET_SIZE: usize = 32;

pub struct KemKeypair {
    pub decapsulation: <MlKem768 as Kem>::DecapsulationKey,
    pub encapsulation: <MlKem768 as Kem>::EncapsulationKey,
}

impl KemKeypair {
    pub fn generate() -> Self {
        let (decapsulation, encapsulation) = MlKem768::generate_keypair();

        Self {
            decapsulation,
            encapsulation,
        }
    }
}

pub fn encapsulate(
    public_key: &<MlKem768 as Kem>::EncapsulationKey,
) -> (
    <MlKem768 as Kem>::Ciphertext,
    ml_kem::SharedKey,
) {
    public_key.encapsulate()
}

pub fn decapsulate(
    secret_key: &<MlKem768 as Kem>::DecapsulationKey,
    ciphertext: &<MlKem768 as Kem>::Ciphertext,
) -> ml_kem::SharedKey {
    secret_key.decapsulate(ciphertext)
}

pub struct PaymentAddress {
    pub kem_public_key: KemPublicKey,
    pub spend_public_key: PublicKey,
}

QpBob
   │
   ├── ML-KEM-768 PK
   └── ML-DSA/Falcon spend PK



#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct Vault {
    pub value: VaultValue,
    pub owner: VaultOwner,
    pub envelope: Option<u16>,
}


#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum VaultValue {
    Coin(Zeno),

    Asset {
        asset: Asset,
        amount: Unit,
    },
}


#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct VaultOwner([u8; HASH_SIZE]);


owner: VaultOwner

pub struct KemEnvelope {
    pub ciphertext: Vec<u8>,
    pub payload: Vec<u8>,
}

if envelope.ciphertext.len() != 1088 {
    return Err(...);
}

Envelope #0 → Bob

Vault #0
10 XPQ
envelope = 0

Vault #1
500 GENESIS
envelope = 0

Bob kem_pk
    ↓
Encaps()
    ↓
CT + SS

VaultOwner =
H(
    "XPARQ/VAULT/OWNER/v1"
    || BobSpendPK
    || rho
)


pub fn vault_owner(
    spend_public_key: &PublicKey,
    rho: &[u8; 32],
) -> Result<VaultOwner, VaultError> {
    let bytes = canonical_bytes(&(
        b"XPARQ/VAULT/OWNER/v1",
        spend_public_key,
        rho,
    ))
    .map_err(|_| VaultError::Encoding)?;

    Ok(VaultOwner(
        domain(HashDomain::VaultOwner, &bytes).into_bytes(),
    ))
}

key =
H(
    "XPARQ/VAULT/ENVELOPE/v1"
    || SS
    || genesis_hash
    || transaction_context
)

payload = Encrypt(key, rho)

KemEnvelope {
    ciphertext: CT,
    payload: ENC(rho),
}

Vault {
    value: 10 XPQ,
    owner: H(BobSpendPK || rho),
    envelope: Some(0),
}

Vault → Vault

pub struct VaultInput {
    pub vault: VaultId,
    pub authorization: VaultAuthorization,
}

pub struct VaultOutput {
    pub value: VaultValue,
    pub owner: VaultOwner,
    pub envelope: Option<u16>,
}

pub struct VaultTransaction {
    pub inputs: Vec<VaultInput>,
    pub envelopes: Vec<KemEnvelope>,
    pub outputs: Vec<VaultOutput>,
}

for envelope in tx.envelopes.iter() {
    let ss = bob_kem_key.decapsulate(&envelope.ciphertext);

    let key = derive_envelope_key(
        &ss,
        chain_context,
        tx_context,
    );

    let Ok(rho) = decrypt(&key, &envelope.payload) else {
        continue;
    };

    for vault in vaults_using(envelope) {
        let expected = vault_owner(
            &bob_spend_public_key,
            &rho,
        )?;

        if expected == vault.owner {
            wallet.add_vault(vault);
        }
    }
}

rho_0 = KDF(rho, 0)
rho_1 = KDF(rho, 1)
rho_2 = KDF(rho, 2)

Envelope Bob
    │
    ├── slot 0 → Vault XPQ
    ├── slot 1 → Vault GENESIS
    └── slot 2 → Vault USDX

pub struct VaultOutput {
    pub value: VaultValue,
    pub owner: VaultOwner,
    pub envelope: Option<u16>,
    pub slot: u16,
}


pub struct VaultAuthorization {
    pub public_key: PublicKey,
    pub rho: [u8; 32],
    pub signature: AccountSignature,
}


vault_owner(&auth.public_key, &auth.rho)?
    == consumed_vault.owner

verify(
    &auth.public_key,
    transaction_signing_digest.as_bytes(),
    &auth.signature,
)


rho
+
Bob public key
        ↓
matches VaultOwner

Bob signature
        ↓
proves authorization


BOB
QpBob
├── ML-KEM PK
└── ML-DSA PK
       │
       ▼
ALICE WALLET

Encaps(KEM PK)
       │
       ├── CT
       └── SS
            │
      encrypt rho
            │
            ▼

TX
├── consume Vault A
├── Envelope Bob
│      CT
│      ENC(rho)
│
├── Vault B
│      10 XPQ
│      owner = H(BobPK || rho)
│
└── Vault C
       Alice change

CT
 ↓
Decaps
 ↓
SS
 ↓
decrypt rho
 ↓
calculate H(BobPK || rho)
 ↓
Vault B MATCH


vUTXO
+ ML-KEM-768 envelope
+ owner commitment
+ ML-DSA/Falcon spend
+ wallet scanning