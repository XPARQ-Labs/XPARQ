# Program identity and ownership

Coin-share owners, asset-share owners, creators, mint authorities, signer,
payment principal, deployer and miner payout all use ProgramId. There is no
separate wallet address type, encoding or endpoint. The shared primitive lives
in `crypto::ProgramId` and is re-exported by `kernel::program`.

## Signature-policy instances

ProgramId is SHA3-256 with the framed domain `XPARQ_HASH_PROGRAM_ACCOUNT`, over:
`xparq:signature-policy:v2 || scheme_id_u8 || canonical_public_key_bytes || salt_32_bytes`.
Public-key length is validated against the chosen scheme before hashing. Policy,
scheme, full key and salt are bound to the instance identity. Supported schemes remain
ML-DSA44/65/87 and Pure SLH-DSA SHAKE128s/192s/256s. Public keys appear in spending proofs, not in UTXO owners.

A witness reveals its 32-byte public salt, public key and signature. The system policy derives its
ProgramId, checks it against the transaction principal, and verifies the signature
against the chain-bound call/payment commitment. No account deployment or
persistent public-key record is needed. Deployed IDs bind the deploying ProgramId,
nonce and code hash under `xparq:program-id:v2` in the artifact hash domain.

## Resolution and execution

Registered IDs execute deployed code and cannot spend through a signature-policy
fallback. Unregistered IDs resolve to the stateless signature policy, which still
requires a witness deriving exactly that ID. Receiving funds does not prove that
anybody possesses the corresponding key. VM calls require deployed code.

Contract requests carry the actual executing ProgramId as monetary actor. Nested
calls carry the parent's ProgramId as caller. Kernel hosts consume only shares
owned by that authenticated actor; call data cannot replace it. Programs enforce
application permissions; kernel enforces conservation, authority, nonce, supply,
resource limits, exact protocol burn and atomic rollback.

The root envelope currently uses a signature-policy instance to pay fees. This
change does not add built-in multisig/timelock applications, arbitrary fee-payer
witnesses or a new authorization entry point. Custom application policies still
use deployed VM code and authenticated caller/state.

## CLI and RPC

Program IDs are exactly 64 hexadecimal characters, with lowercase canonical
output. `wallet program-id` replaces the old identity command. Transfers accept
Program IDs (optionally prefixed with `program:`); miners use `--miner PROGRAM_ID`.

- `/program/account/{program_id}`: paginated UTXOs, balances and program state.
- `/program/balance/{program_id}`: available/reserved coin balance.
- `/explorer/program/{program_id}`: paginated program activity.
- `/program/asset/{asset}/balance/{program_id}`: asset balance and shares.

## Compatibility

Owner remains tag 0 plus 32-byte ProgramId. Coin and asset share IDs now use
full 32-byte SHA3-256 hashes; canonical coin UTXO weight is 73 bytes. Chain-spec 1/database schema 1 separate this protocol from older chains.
Wallet files use version 2 and store the active `program_id`, active salt and the
list of account salts alongside one mnemonic/key. Even the default zero-salt ID
changes because the signature-policy domain is now v2. Old proofs and old wallet
files are not accepted; restore the mnemonic with its original scheme into a new
wallet file, supplying the account salt when recovering a nondefault account.
Signing keys are unchanged. No production restart, wallet rewrite or database
reset is performed automatically.

## Several accounts from one key

Default account salt is 32 zero bytes. Each distinct salt creates an independent
ProgramId from the same key, without deploying an account or registering it in
state. UTXOs and asset shares belong to their particular ProgramId; possession of
the same key does not let a transaction relabel that owner. The proof must derive
the exact principal, and its signature binds the chain, signer, call and payment.

```bash
wallet accounts --wallet wallet.json
wallet account-add --wallet wallet.json
wallet account-add --salt HEX64 --wallet wallet.json
wallet account-use --salt HEX64 --wallet wallet.json
wallet restore --mnemonic "..." --account mldsa44 --salt HEX64 --wallet restored.json
```

`account-add` records and selects its salt; without `--salt` it generates 32 random
public bytes. `account-use` selects a salt already recorded in the file. All balance,
history, transfer, asset and deploy commands then use the active account. The
interactive menu provides **13. Manage Accounts**: `add` generates and selects
a new account; `use` selects a recorded salt. Both update the same wallet JSON.
`account_salts` retains all accounts, while `account_salt` and `program_id` identify
the active one; other ProgramIds are derived when listing accounts. The file supports up to 256
unique salts and validates the selected salt/ProgramId on load and save. Account
updates write an owner-only temporary file, sync it and atomically replace the
existing wallet. A per-wallet update marker serializes CLI writers, and expected
file bytes reject stale edits. If an update process is terminated abruptly, its
`.WALLET_FILENAME.account.lock` marker may need removal after confirming no update
is running; the wallet JSON remains the recovery source.

Back up account salts along with the wallet: a mnemonic restores the key, but does
not reconstruct randomly chosen salts. Salt is public, and compromise of the shared
key affects every account using it.

Deployed/custom program identity remains `H(deployer_program_id, nonce, code_hash)`
under its existing artifact framing. The salt changes a signature account's
identity; it is not a new field on every program. Account A or B can deploy distinct
custom instances. Deploying still does not grant an automatic signature fallback
for spending a registered program's UTXOs; its VM policy remains authoritative.
