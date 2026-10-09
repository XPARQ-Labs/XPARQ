# XPARQ Wallet

`wallet/` contains the reusable `wallet` library and the `wallet`
executable. It never opens node storage and communicates through HTTP RPC.

```bash
cargo build --release --locked -p wallet
./target/release/wallet
./target/release/wallet --help
```

The interactive menu supports wallet creation and restoration, balances,
canonical history, UTXO tracking and consolidation, XPQ sends, Program assets,
block exploration, bytecode deployment, and salted account management.

## Security

The wallet file contains recovery and private signing material. It is checked
for internal consistency when loaded, created atomically, and given owner-only
permissions on Unix. Back up the mnemonic offline and never commit, upload, or
share the wallet file. A miner needs only the public payout Program ID. Keep plain
HTTP RPC on loopback or a trusted private network.

## XPQ transactions

Signed transactions are submitted automatically to `/transaction`. Use
`--offline` to print signed canonical transaction bytes without submitting them.
RPC is still needed when selecting inputs or calculating fees from node state.

```bash
./target/release/wallet sign-spend --to PROGRAM_ID --amount 1 --rpc 127.0.0.1:6666
./target/release/wallet consolidate --wallet wallet.json --rpc 127.0.0.1:6666
```

Without explicit inputs, the wallet selects available `/program/coins/{program_id}`
UTXOs and creates change. Consolidation merges the selected XPQ UTXOs into one
self-owned output. Consensus validates it as an ordinary transaction, so its
canonical bytes still incur archival burn and a miner fee.

The miner fee is node policy. The protocol burn separately covers canonical
transaction history and positive net state growth. Consumed Coin UTXOs offset
new Coin UTXOs for state growth but do not erase historical transaction bytes.
The current burn tariff is 1 zeno per byte; the wallet's automatic miner fee is
8 zeno per byte. These rates are calculated independently. Each net new Coin UTXO
adds 73 bytes of state burn. An empty block with emission has 165 archival bytes,
including three 32-byte header hashes, and one new 73-byte emission UTXO.

## Extension asset program

For integration details, see [ProgramCall documentation](../docs/PROGRAM_CALL.md).

The asset application runs in extension; canonical records and shares belong to
kernel `LedgerState.extensions.assets`. This is separate from the deployed-code
registry. Use `program-*` commands for assets. Amounts use
8 decimal places. XPQ fee inputs, change, miner fee and exact protocol burn are
selected automatically. Commands need a running node for balances and quotes.

The examples below assume the `wallet` executable is on PATH; otherwise use
`./target/release/wallet`. Set `--wallet` and `--rpc` as needed on every command.

```sh
wallet program-register --name Gold --max-supply 100 --initial-mint 40 --wallet wallet.json --rpc 127.0.0.1:6666
wallet program-mint --asset CONTRACT --to PROGRAM_ID --amount 20
wallet program-transfer --asset CONTRACT --to PROGRAM_ID --amount 15
wallet program-burn --asset CONTRACT --amount 5
wallet program-consolidate --asset CONTRACT
wallet program-info --asset CONTRACT
wallet program-balance --asset CONTRACT --program-id PROGRAM_ID
```

`--fixed-supply` disables further minting at registration. `--offline` prints
canonical signed transaction hex without submitting it; RPC is still needed to
select XPQ/share inputs and quote state growth. Transfer/burn consume at most
256 shares per call. Consolidation merges up to 256 shares per invocation and
requires at least two shares. Wait for pending asset operations to confirm
before submitting a dependent operation.

Interactive mode has a **Program Assets** menu. Normal balance and history show
extension holdings and operations; asset-only recipients also receive history
entries even when they receive no XPQ.

RPC reads: `/program/asset/{asset}` and
`/program/asset/{asset}/balance/{program_id}`. `/program/account` and `/program/balance` expose a
separate `program_assets` array; `/explorer/program` contains aggregate balances
without share lists. `/explorer/transaction` decodes Program asset instructions.
`POST /program/quote` reads a signed canonical Program transaction and returns
extension state growth in bytes without admitting or applying the transaction.
Its quote reflects canonical state; final submission revalidates against mempool
state and can reject a stale quote.

## Deployed programs

`program-register` creates an asset; `program-deploy` deploys validated XPVM
bytecode. Choose an unused nonce for the deploying owner.

```sh
./target/release/wallet program-deploy --code program.xpvm --nonce 1 --wallet wallet.json --rpc 127.0.0.1:6666
```

The wallet obtains a deploy quote, selects XPQ funding, signs and submits to
`/program/deploy`. `--offline` prints signed bytes instead of submitting; RPC is
still required for funding and the quote. See [XPVM](../docs/XPVM.md) for the
bytecode format. To execute a deployed program after deployment is confirmed:

```sh
./target/release/wallet program-call --program-id PROGRAM_ID --wallet wallet.json --rpc 127.0.0.1:6666
```

The ID must contain exactly 64 hexadecimal characters. The command signs a VM
call with opcode 0 and the program ID as payload, quotes state growth, selects
funding, and calculates burn and miner fees. `--offline` prints signed bytes
and still requires RPC. It returns a transaction hash on submission; wait for
confirmation before sending another call using the same wallet inputs.
See the [counter example](../examples/counter/README.md).

### Integration verification

```sh
cargo build -p node -p wallet --bins
cargo test -p wallet --test program_e2e -- --ignored --test-threads=1
```

These ignored tests require an explicit run. Both passed on 3 October 2026:
XPQ spend/consolidation and the asset lifecycle. They use real wallet/node binaries and temporary redb storage for register,
mint, transfer, burn, consolidation, balances, recipient history and restart.

## Contract balances and funding

`sign-spend`, `program-transfer`, and `program-mint` accept a deployed contract
recipient as `--to program:PROGRAM_ID`. All recipients use 64-character hex Program IDs.
`program-account --program-id PROGRAM_ID` displays the contract's coin balance
and live coin/asset shares. `program-call` executes its code and pays costs from
the calling wallet. See [the fixed payout contract](../examples/vault/README.md)
for an example that receives and sends both values.


XPVM v3 programs can also register and mint native assets with the deployed program
as mint authority. `program-call` quotes and pays the resulting state growth and
fuel from the caller's wallet. See the [asset issuer example](../examples/asset_issuer/README.md).


XPVM v4 supports authenticated caller checks, bounded key/value state, branches,
dynamic transfers and synchronous program calls. Use `program-call --program-id ID
--data HEX` for application input, and optionally `--deposit XPQ_AMOUNT` to fund
and execute a deposit atomically. Application code within the supported VM can be
deployed without rebuilding the node. See [the v4 instruction contract](../docs/XPVM.md#application-bytecode-v4).

## Program-owned accounts and unified monetary calls

Wallet balances belong to a stateless system signature-policy instance derived
from the signature policy, signature scheme, public key and 32-byte public salt. `wallet program-id` prints its 64-character
hex representation (32 decoded bytes). Public keys are included in spending
proofs, not ledger ownership. Coin and asset operations use monetary route 0.

`GET /program/coins/PROGRAM_ID` provides paginated coin UTXOs and reservation
flags without enumerating asset holdings. Wallet input selection, deployment
funding, and UTXO tracking use this endpoint, so a large asset inventory does
not enlarge their responses. It accepts `utxo_after` or `utxo_offset` and returns
at most 1,000 coin UTXOs per page. This wallet requires a node that supports
`/program/coins`; upgrade the node before the wallet.

`GET /program/account/PROGRAM_ID` returns both wallet and deployed-program
balances, paginated coin UTXOs, asset shares, and nullable scalar state. `GET
/program/balance/PROGRAM_ID` returns available/reserved coin balance. History is
`GET /explorer/program/PROGRAM_ID`. Asset balances accept a Program ID as their
last path parameter. The old identity routes and `wallet address` command do not
exist; Program IDs do not accept the old Base56 encoding.

Wallet files use version 2 and store the active `program_id`, `account_salt`,
`account_salts`, signature scheme, public key and recovery material. Chain-spec 1
and database schema 1 require compatible fresh storage; no old-chain migration
is included. Coin and asset share IDs are 32 bytes, displayed as 64 hexadecimal
characters. Old wallet files require explicit mnemonic restoration using the
original signature scheme and, for a nondefault account, its salt.

## Multiple accounts in one wallet

`wallet balance --wallet wallet.json --rpc 127.0.0.1:6666` displays balances
for every account recorded in `account_salts`, including zero balances, reserved
coins, UTXO counts and asset holdings. It labels the active account and shows
network totals once. A failed account query is reported without skipping later
accounts. This also applies to the interactive balance menu.

One key can control multiple signature-policy ProgramIds. Each distinct public
salt derives a different account. Account creation happens locally and requires
no deployment transaction or fee. Coin and asset balances belong to the selected
ProgramId; adding an account does not move existing funds.

```sh
wallet accounts --wallet wallet.json
wallet account-add --wallet wallet.json
wallet account-use --salt HEX64 --wallet wallet.json
```

In interactive mode, **13. Manage Accounts** lists the recorded accounts. Choose
`add` to generate a random salt, append it to `account_salts`, and update
`account_salt` and `program_id` to make the new account active. Choose `use` and
enter a recorded salt to select an existing account. **3. Show Program ID** prints
the active ID. All accounts share the same key; adding or selecting an account
updates the same wallet JSON atomically, without creating another wallet file.

Back up the updated wallet after each addition. The mnemonic recovers the key,
but cannot reconstruct random salts. Only the active ProgramId is stored in the
file; the others are derived from the recorded salts. Temporary update and lock
files are implementation details, not separate account backups. See
[ownership](../docs/OWNERSHIP.md#several-accounts-from-one-key) for persistence,
recovery and lock handling. **11. Deploy Program** instead submits custom XPVM
bytecode on-chain, pays fees and burn, and creates a separate deployed ProgramId.

Account schemes include `mldsa44`, `mldsa65`, `mldsa87`, `slhdsa-shake128s`,
`slhdsa-shake192s`, `slhdsa-shake256s`. Wallet creation defaults to 24 mnemonic
words for every scheme; `--words 12` remains explicit. See [signature parameters and consensus policy](../docs/SIGNATURE_SCHEMES.md).
