# XPARQ

**XPARQ** is a post-quantum Layer 1 blockchain written in Rust.

The project is organized around a small set of components:

- `crypto` — cryptographic primitives and post-quantum signature support
- `kernel` — consensus, ledger, transactions, native coin, and Program execution integration
- `extension` — unified monetary application for coin and asset operations
- `runtime` — node, P2P networking, synchronization, storage, mining, and RPC
- `wallet` — local wallet and CLI
- `devkit` — XPVM assembler and isolated local development workflows
- `docs` — protocol and RPC documentation
- `depend` — vendored or project-pinned dependencies

Build and dependency-check configuration is documented in
[Tooling](docs/TOOLING.md). `Cargo.lock` is committed, and `build.sh` uses
`--locked` to prevent dependency resolution changes during builds.

## Developer tooling

The [devkit](devkit/README.md) provides a kernel-validated XPVM v4 assembler,
isolated local devnet runner, counter/vault/asset-transfer examples and lifecycle
tests. Start with `python3 devkit/devnet/run.py build`, then
`python3 devkit/devnet/run.py demo`. Its devnet binaries and database are separate
from normal node/wallet builds and node storage.

## Program ownership

Coins and assets use a single ownership type: `Owner::Program(ProgramId)`.
A Program ID is 32 bytes, displayed as 64 hexadecimal characters. Wallets derive
their ID from the signature policy, signature scheme, public key and 32-byte public salt; public keys
appear in spending proofs. Wallet accounts require no deployment or stored
public-key record. Deployed contracts have their own Program IDs and can hold
and transfer coins and assets through the VM.

Programs enforce application permissions. The kernel checks the authenticated
owner, balances, asset authority, supply, fees and protocol burn, and rolls back
failed execution atomically. A registered contract must execute its code to
spend its funds. See [ownership](docs/OWNERSHIP.md).

Developers can deploy applications using the existing [XPVM](docs/XPVM.md)
instructions without rebuilding the node. Changes to VM instructions, compiled
system applications or consensus rules still require a node update.

## Requirements

XPARQ currently requires:

- Git
- Rust **1.99.0** (selected by `rust-toolchain.toml`; rustup installs it when needed)
- Cargo
- A supported 64-bit operating system

On Debian/Ubuntu, install common build tools:

```bash
sudo apt update
sudo apt install -y git curl build-essential pkg-config
```

Install Rust with `rustup` if it is not already installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Verify the installation:

```bash
rustc --version
cargo --version
```

## Clone the repository

```bash
git clone https://github.com/XPARQ-Labs/XPARQ.git
cd XPARQ
```

## Build

Build the node and wallet in release mode:

```bash
cargo build --release -p node -p wallet
```

The binaries will be available at:

```text
target/release/node
target/release/wallet
```

For development builds:

```bash
cargo build -p node -p wallet
```

## Run a node

### Mainnet

Mainnet is the default feature.

After building:

```bash
./target/release/node
```

This is equivalent to starting the automatic node runtime with the default mainnet configuration.

Default mainnet settings:

| Setting | Default |
| --- | --- |
| Data directory | `./data/mainnet` |
| P2P listen | `0.0.0.0:6677` |
| RPC listen | `127.0.0.1:6666` |
| Mining | Disabled |

A normal startup will print information similar to:

```text
database: ./data/mainnet
rpc: http://127.0.0.1:6666
outbound_peers: 0
mining: disabled
```

Stop the node with:

```text
Ctrl+C
```

### Desktop GUI (GPUI)

The optional [desktop console](gui/README.md) provides node/miner settings,
Start/Stop controls, live node logs, RPC status and a Wallet tab for wallet
creation, balances, history, UTXOs and reviewed XPQ transfers. It can also monitor an
existing node without opening its database. Desktop dependencies are built
separately from the node workspace.

```bash
cargo build --manifest-path gui/Cargo.toml
./gui/target/debug/xparq-gui
```

### Run with an explicit peer

To connect to another XPARQ node:

```bash
./target/release/node run \
  --peer <IP_OR_HOSTNAME:PORT>
```

Connect to the XPARQ mainnet DDNS bootstrap node (IPv6 connectivity required):

```bash
./target/release/node run \
  --peer xparqnode.duckdns.org:6677
```

The hostname follows the bootstrap node's changing IPv6 address. It is resolved
on each connection attempt. Bootstrap peers must be supplied explicitly; the
default startup does not automatically connect to this hostname.

See [IPv6 and DDNS networking](docs/IPV6_DDNS.md) for IPv6 listener settings,
public address advertisement, and hostname discovery.

Multiple peers can be provided:

```bash
./target/release/node run \
  --peer 203.0.113.10:6677 \
  --peer 203.0.113.11:6677
```

### Custom data directory

```bash
./target/release/node run \
  --data /path/to/xparq-data
```

Example:

```bash
./target/release/node run \
  --data "$HOME/.xparq/mainnet"
```

### Custom P2P and RPC addresses

```bash
./target/release/node run \
  --p2p '[::]:6677' \
  --rpc '[::]:6666'
```

`[::]:6666` listens on all IPv6 interfaces. Restrict RPC access with firewall
rules to the clients that need it. For local requests, use `http://[::1]:6666`;
remote clients use `http://[PUBLIC_IPV6]:6666` or
`http://xparqnode.duckdns.org:6666` when RPC is enabled and reachable there.

## Run a mining node

Mining requires a recipient Program ID.

First create a wallet:

```bash
./target/release/wallet new
```

Or open the interactive wallet:

```bash
./target/release/wallet
```

The wallet displays its 64-character hexadecimal Program ID after creation.
Use that ID as the mining recipient.

Start the node with mining enabled:

```bash
./target/release/node run \
  --miner <PROGRAM_ID>
```

Example:

```bash
./target/release/node run \
  --miner YOUR_PROGRAM_ID
```

You can combine mining with peers:

```bash
./target/release/node run \
  --peer xparqnode.duckdns.org:6677 \
  --miner <PROGRAM_ID>
```

When mining is active, the node prints:

```text
mining: enabled on the local canonical tip
```

Mining rewards belong to the program supplied through `--miner`.

Interactive terminals show a mining dashboard with the latest persisted block,
nonce, full block hash, session block count, gross session subsidy, and the five
most recent locally mined blocks. The display refreshes after each mined block.
Set `NO_COLOR=1` to disable colors. Terminals with `TERM=dumb` or no `TERM`, and
redirected output, use the single-line mined-block log with the full hash.
Weight is the consensus block weight; subsidy is gross emission in XPQ;
state burn is the block's total native protocol burn in zeno (archival plus state
growth); operations count all non-emission block operations. Compact target is
the header's decimal target bits, not a relative difficulty multiplier. Session
totals count locally mined blocks in the current process, not wallet balance.

## Public node

A node that accepts incoming P2P connections should expose its P2P port.

Default mainnet P2P port:

```text
6677/TCP
```

If using UFW:

```bash
sudo ufw allow 6677/tcp
```

Do **not** expose the RPC port to the public internet unless you understand the security implications.

To listen for RPC connections on IPv6, explicitly pass:

```text
--rpc '[::]:6666'
```

Without this option, the default RPC listener remains `127.0.0.1:6666`.

### Advertise a public address

If the machine has a directly reachable public IP:

```bash
./target/release/node run \
  --public-addr <PUBLIC_IP:6677>
```

Example:

```bash
./target/release/node run \
  --public-addr 203.0.113.20:6677
```

### Advertise a DDNS hostname

If your public IPv6 changes, advertise your own DDNS hostname instead of an IP
literal. For the operator of the XPARQ DDNS bootstrap node:

```bash
./target/release/node run \
  --p2p '[::]:6677' \
  --rpc '[::]:6666' \
  --public-addr xparqnode.duckdns.org:6677
```

Other node operators should substitute their own hostname. Configure an external
DDNS updater to keep its AAAA record current. The node preserves and shares the
hostname through peer storage and discovery, resolves it again on reconnect,
and refreshes its advertised public IP fallbacks every 60 seconds. See
[IPv6 and DDNS networking](docs/IPV6_DDNS.md).

### Automatic NAT traversal

XPARQ can attempt to map its P2P listener through a compatible NAT gateway:

```bash
./target/release/node run \
  --nat-traversal
```

`--public-addr` and `--nat-traversal` are mutually exclusive.

## RPC

The default mainnet RPC endpoint is:

```text
http://127.0.0.1:6666
```

Check node status:

```bash
curl -s http://127.0.0.1:6666/status
```

Pretty-print with `jq`:

```bash
curl -s http://127.0.0.1:6666/status | jq
```

Check the fee policy:

```bash
curl -s http://127.0.0.1:6666/fee-policy | jq
```

Get recent blocks:

```bash
curl -s http://127.0.0.1:6666/blocks/latest | jq
```

Query a block by height:

```bash
curl -s http://127.0.0.1:6666/block/0 | jq
```

Query a balance:

```bash
curl -s "http://127.0.0.1:6666/program/balance/<PROGRAM_ID>" | jq
```

Query account UTXOs and asset holdings:

```bash
curl -s "http://127.0.0.1:6666/program/account/<PROGRAM_ID>" | jq
```

The account response is paginated; use the returned pagination fields to fetch
additional UTXOs. Other program queries include:

| Endpoint | Data |
| --- | --- |
| `/explorer/program/{program_id}` | Paginated transaction activity |
| `/program/asset/{asset}/balance/{program_id}` | Asset balance and shares |
| `/program/state/{program_id}/{key}` | Deployed program storage; key encoded as hex |

The former `/account/`, `/balance/` and `/explorer/address/` routes have been
removed. Use the program routes above.

### RPC documentation

While the node is running, open:

```text
http://127.0.0.1:6666/docs
```

The raw OpenAPI document is available at:

```text
http://127.0.0.1:6666/openapi.json
```

## Wallet

Start the interactive wallet:

```bash
./target/release/wallet
```

The current interactive menu includes:

```text
XPARQ Wallet
1. Create Wallet
2. Import Wallet
3. Show Program ID
4. Show Balance
5. Transaction History
6. UTXO
7. Transfer
8. Consolidate UTXOs
9. Explorer
10. Program Assets
11. Deploy Program
12. Exit
13. Manage Accounts
```

### Create a wallet

Interactive:

```bash
./target/release/wallet
```

Or CLI:

```bash
./target/release/wallet new
```

The default wallet file is:

```text
wallet.json
```

A custom wallet path can be supplied:

```bash
./target/release/wallet new \
  --wallet my-wallet.json
```

By default, wallet creation uses the `mldsa44` signature account.

Available signature accounts currently include (see [signature parameters](docs/SIGNATURE_SCHEMES.md)):

```text
mldsa44
mldsa65
mldsa87
slhdsa-shake128s
slhdsa-shake192s
slhdsa-shake256s
```

Example:

```bash
./target/release/wallet new \
  --account mldsa44 \
  --wallet wallet.json
```

> [!IMPORTANT]
> Back up the mnemonic shown during wallet creation. Anyone with access to the mnemonic may be able to control the wallet.

### Show wallet Program ID

```bash
./target/release/wallet program-id \
  --wallet wallet.json
```

This command replaces `wallet address`. Transfer recipients use the same
64-character Program ID in `--to`; `program:<PROGRAM_ID>` is also accepted.

### Restore a wallet

Restore the mnemonic with the original signature scheme into a new wallet file:

```bash
./target/release/wallet restore \
  --mnemonic "YOUR MNEMONIC PHRASE" \
  --account mldsa44 \
  --wallet restored-wallet.json
```

Current wallet files use version 2 and store `program_id`, the selected account salt,
and a list of account salts. One key can control several separate account ProgramIds. Older files containing `address` are
not converted automatically. Restoring preserves the signing keys, but derives
a new Program ID under the current policy domain. It does not migrate funds
from an older chain.

### Show balance

With the mainnet RPC running locally:

```bash
./target/release/wallet balance \
  --wallet wallet.json \
  --rpc 127.0.0.1:6666
```

## Network modes

XPARQ currently defines separate Cargo features for:

- `mainnet`
- `testnet`
- `devnet`

Only one network mode should be selected for a build.

### Mainnet

Mainnet is enabled by default:

```bash
cargo build --release -p node -p wallet
```

Defaults:

```text
P2P: 0.0.0.0:6677
RPC: 127.0.0.1:6666
Data: ./data/mainnet
```

### Testnet

Build:

```bash
cargo build --release \
  -p node \
  -p wallet \
  --no-default-features \
  --features testnet
```

Defaults:

```text
P2P: 0.0.0.0:16677
RPC: 127.0.0.1:16666
Data: ./data/testnet
```

Run:

```bash
./target/release/node
```

### Devnet

Build:

```bash
cargo build --release \
  -p node \
  -p wallet \
  --no-default-features \
  --features devnet
```

Defaults:

```text
P2P: 0.0.0.0:26677
RPC: 127.0.0.1:26666
Data: ./data/devnet
```

Run:

```bash
./target/release/node
```

#### litep2p devnet transport

Install `protoc` (the Protocol Buffers compiler) before building `litep2p`.
This transport uses its own protocol and port; legacy TCP peers cannot connect to it.

```bash
cargo build -p node --no-default-features --features litep2p-devnet
./target/debug/node litep2p ./data/devnet-litep2p 127.0.0.1:27677
```

For the normal node with RPC and optional mining, use `node run --litep2p`
with `--data`, `--p2p`, `--rpc`, and `--peer ADDRESS@PEER_ID` as needed.

The node prints its persistent litep2p peer ID. To connect another devnet node,
pass `ADDRESS@PEER_ID`, for example:

```bash
./target/debug/node litep2p ./data/devnet-litep2p-2 127.0.0.1:27678 \
  127.0.0.1:27677@<first-node-peer-id>
```

The litep2p transport validates the genesis and chain-spec hashes during
notification handshake. It verifies a peer's header branch and cumulative
work, downloads matching blocks, and applies the same fork-choice and reorg
logic as the legacy transport. It also relays new blocks and mempool transactions.
Its devnet protocol names are `/xparq/devnet/blocks/2` and
`/xparq/devnet/announce/2`.

The litep2p transport stages block bodies in a resumable redb download cache,
with up to 100,000 verified headers and an 8 GiB logical body budget by default.
Use `node run --litep2p --sync-staging-mib 16384` to select a 16 GiB budget.
Canonical branch application and persistence consume bodies as a stream. Request
timeouts and connection limits remain enforced; ledger history still consumes RAM.
Per-peer inbound count/byte budgets guard request serving and announcement validation;
header/body continuation requests are paced to preserve healthy downloads.
Sync polls rotate among eligible peers; stalled sessions release their slot and a
replacement peer can reuse matching staged bodies.
Bootstrap endpoints accept `HOST:PORT@PEER_ID`; bounded discovery defaults to public
addresses and persists successfully dialed endpoints for reconnect after restart.
See [litep2p discovery and DNS policy](docs/LITEP2P_DISCOVERY.md).
See [litep2p hardening and verification](docs/LITEP2P_HARDENING.md).


## Node commands

Show available commands:

```bash
./target/release/node --help
```

Current node commands include:

```text
node run
node network
node rpc
node p2p-listen
node peer
node info
node check
node account
node mempool
node mine-block
node submit-transaction
node submit-deploy
node submit-block
node version
```

`DeployProgram` can be submitted as canonical Borsh `AuthorizedDeployProgram`
bytes with `node submit-deploy [data-dir] <hex>` or `POST /program/deploy`
(`application/octet-stream`). `POST /program/deploy/quote` accepts the same
structure before signing and returns the next-block program ID, exact protocol
burn, and authorization commitment. The owner signs the commitment and pays
the quoted burn plus a relay fee. The operation mempool persists deploys and
the miner includes them in blocks. The wallet can build and sign deploys:

```bash
wallet program-deploy --code program.xpvm --nonce 1 --wallet wallet.json --rpc 127.0.0.1:6666
```

The wallet selects available coin inputs, obtains the exact protocol burn,
calculates the miner fee, signs the final payment and submits it. Use
`--offline` to print the signed Borsh hex instead. The interactive wallet menu
also has **Deploy Program**. `program-register` creates an asset through a
ProgramCall; it is separate from bytecode deployment.

A lower-level Rust payload builder is in
[`runtime/examples/deploy_program.rs`](runtime/examples/deploy_program.rs). With
a funded ML-DSA-44 account and a running RPC node:

```bash
printf '5850564d01010000000000000001070000000000000003' | xxd -r -p > program.xpvm
cargo run -p node --example deploy_program -- \
  127.0.0.1:RPC_PORT owner-seed.hex COIN_SHARE INPUT_ZENO 1 program.xpvm deploy.borsh
curl -X POST http://127.0.0.1:RPC_PORT/program/deploy \
  -H 'Content-Type: application/octet-stream' --data-binary @deploy.borsh
```

The seed file contains 64 hex characters for the account's 32-byte signing
seed. `COIN_SHARE` and `INPUT_ZENO` identify one unreserved coin shown by
`node account`; `program.xpvm` is XPVM bytecode. The example requests the burn
quote, pays a 100,000 zeno miner fee, signs the final payment, and writes the
canonical Borsh payload. Keep the signing seed file private.

### Network information

```bash
./target/release/node info
```

This prints network-level identifiers such as:

- genesis hash
- chain specification hash
- P2P protocol version
- proof-of-work algorithm
- difficulty algorithm

### Check database

```bash
./target/release/node check
```

Or specify a data directory:

```bash
./target/release/node check /path/to/xparq-data
```

For an imported database or a full historical execution check, bypass snapshots:

```bash
./target/release/node check /path/to/xparq-data --full
```

### Local ledger snapshots

The node writes a ledger snapshot every 1,000 blocks, after a sync that applies
at least 1,000 blocks, and after startup replay. It retains the two newest
snapshots. Snapshot and validation checkpoint publication is atomic. The
checkpoint binds the exact encoded history prefix and snapshot to the genesis,
chain specification, validation version, height and tip hash.

For its own trusted local database, startup checks that fingerprint, snapshot
identity, state root, supply, registry and journals without repeating historical
PoW. Blocks after the snapshot still undergo full admission. Missing or
incompatible checkpoints require full genesis replay once; successful replay
publishes a new checkpoint. Recovery snapshot restore retains historical PoW
verification. This local trust policy does not authenticate a copied database;
use `check --full` for imported data. Restore logs report stage timings and the
number of PoW checks. See [restart validation](docs/RESTART_VALIDATION.md).

New snapshots use version 3. Legacy snapshots trigger full replay on production
startup; version 2 is not
accepted. A snapshot must match chain identity, checksum and canonical state.
The canonical block log remains required for startup and reorganization.

### Minimum remote chain work and weight

`node run` accepts local sync-admission floors:

```bash
./target/release/node run --data ./data/mainnet --minimum-chain-work HEX_WORK --minimum-chain-weight DECIMAL_WEIGHT
```

A candidate must have cumulative work **at least** the work floor and cumulative
weight **at least** the weight floor. Work accepts 1–128 big-endian hexadecimal
digits (up to 512 bits), with an optional `0x` prefix. Weight is an unsigned
64-bit decimal integer. Copy these formats from the `cumulative_work` and
`cumulative_weight` fields of a trusted node's `GET /status` response. Both default
to zero; configure the same options again after restarting.

TCP header sync, gossip/reverse sync and litep2p tip discovery skip below-floor
claims before requesting headers or bodies. Passing that cheap filter is not proof:
header PoW and advertised totals still have to match, and validated candidates are
checked before branch commit or recovery. Unannounced relay blocks are subject to
the same floors. Peers below the floor can still request our chain for bootstrap.
Once eligible, fork choice remains work first, then weight, then tip hash.

`GET /status` also returns `minimum_chain_work`, `minimum_chain_weight` and
`meets_chain_minimums`. A fresh local genesis or existing shorter ledger is still
allowed to start and serve RPC; the floors govern remote-chain admission, not
local validity or mining. Setting a floor above all available valid peers leaves
the node waiting for a chain that reaches it.

This is local policy and does not change chain identity or the wire protocol.
It does not skip PoW validation during local startup or speed up replay of an
existing database.

### Inspect mempool

```bash
./target/release/node mempool
```

### Inspect an account

```bash
./target/release/node program-account \
  ./data/mainnet \
  <PROGRAM_ID>
```

## Useful development commands

Validation and synchronization reuse the PoW working buffer across a batch and
append committed blocks without cloning the full chain history. Block execution
reuses one private state across its transactions; asset operations and quotes
use the touched entries instead of copying entire asset tables. See
[CPU measurements and remaining costs](docs/CPU_VALIDATION.md) for the benchmark
command and its limits.

Repeatable [signature and block-validation benchmarks](benches/README.md) run
with `cargo bench`; [measurement details](docs/BENCHMARKS.md) explain their scope.
The [2026-10-09 hardening report](docs/HARDENING_2026-10-09.md) records secret
buffer handling, wallet defaults, admission bounds, large-state replay and cache
measurements. An [independent-review handoff](docs/INDEPENDENT_SECURITY_REVIEW.md)
is prepared; external review has not been completed.

[Owner indexes](docs/OWNER_INDEX.md) narrow coin and asset lookups to a program's
own share IDs. They are rebuilt on restore and excluded from canonical storage
and state-root encoding.

Program storage is shared across staged ledger copies and VM previews. A write
copies only the changed program's storage; unchanged values and missing-key
deletions keep the shared copy. Canonical encoding remains unchanged.

Coin UTXOs, asset records, asset shares and their owner indexes use ordered trees
with shared branches. Cloning a state shares each root; writes copy only affected
paths, including within a large owner's index. Sorted encoding and monetary rules
are unchanged. See [state map implementation and limits](docs/STATE_MAP.md). Program
registries and deployment indexes also share tree roots. Repeated state-root
checks reuse a cached hash only when all canonical state components still match;
a changed state receives the same full hash calculation as before. See
[state-root cache and compatibility](docs/STATE_ROOT_CACHE.md).
Cold state-root hashing uses a 64 KiB streaming buffer instead of allocating the
full canonical ledger payload, with identical encoded bytes and hashes.
Program-call and deployment size checks count borrowed canonical encoding without
cloning the authorized transaction or building a full payload buffer. Operation
limits and protocol burn remain unchanged. Wallet fee calculations also count
canonical lengths without allocating full size-only buffers.
Mempool admission retains canonical bytes and operation IDs between requests,
uses an ID index for duplicates, and persists borrowed byte slices after full
validation. Each read compares the cache with committed database bytes; mining,
reorg and recovery changes therefore rebuild stale entries. See
[mempool cache and measurements](docs/MEMPOOL_SERIALIZATION.md).

Supply validation maintains per-asset share totals from sparse kernel journals
and checks affected assets against an audited baseline. Root guards force full
scans for stale summaries or untracked changes. Coin accounting is checked on every
call, and snapshot restore forces deep asset and coin audits. The derived summaries
are excluded from canonical bytes. See
[incremental supply validation and verification](docs/SUPPLY_AUDIT_CACHE.md).

### Coin spends and Program assets

The kernel owns native XPQ and asset types, checked monetary state, and UTXOs.
Coin and asset operations execute in `extension::monetary` through restricted
kernel hosts. Wallets use system dispatcher route `0`, which is separate from
the 32-byte Program ID identifying an owner.

| Operation | Opcode | Scope |
| --- | --- | --- |
| Transfer | `1` | Coin or asset |
| CreateAsset | `2` | Register an asset with its authority and policy |
| Mint | `3` | Asset minting subject to its authority and supply rules |
| Burn | `4` | Asset burn; voluntary coin burn is disabled |

Transfer and Burn encode the currency selector (`0` for coin, `1` for asset).
Native coin issuance remains governed by consensus. Mandatory protocol burn
is enforced separately from the Burn operation.

Assets live in kernel-owned Program state and use the wallet `program-*`
commands. Runtime installs `extension::SystemApplications` for validation and
execution. One Program signature binds the asset operation and its XPQ payment.
Legacy asset transactions, combined spends and `asset-*` commands have been
removed.

See [architecture](docs/ARCHITECTURE.md) for source ownership and the distinction
between extension applications and deployed [XPVM programs](docs/XPVM.md).
The [VM roadmap](ROADMAP.md) records implementation and open verification gates.

See [ProgramCall integration](docs/PROGRAM_CALL.md) for registration, mint,
transfer, burn and consolidation instructions.

All monetary Program calls carry `CoinTransition` with `CoinCharges { miner_fee }`.
The miner fee is credited to the block miner as a separate UTXO. Protocol burn
is the verified difference between XPQ inputs, program-owned outputs and the
miner fee. Coin outputs encode the recipient Program ID.

### Several accounts from one wallet key

The default signature account uses a zero salt. Adding a salt generates a new
ProgramId from the same public/private key and selects that account:

```bash
wallet accounts --wallet wallet.json
wallet account-add --wallet wallet.json
wallet account-use --salt HEX64 --wallet wallet.json
```

Use `account-add --salt HEX64` for a chosen 32-byte public salt. Transfer, balance,
history, asset and deploy commands use the selected account. To recover a
nondefault account, use `wallet restore ... --salt HEX64`. Preserve the salt list
with the wallet backup; mnemonic recovery alone cannot reconstruct random salts.
Custom program IDs continue to bind deployer ProgramId, deploy nonce and code hash.
See [salted ownership and CLI](docs/OWNERSHIP.md).

### Protocol and storage compatibility

The current protocol uses **chain-spec version 1** and **database schema 1**.
This fresh repository starts at release **1.0.0**. Earlier audit documents retain
the development version numbers used when those audits were recorded. The
version-1 chain identity requires fresh node storage; no old-chain migration is included.
Coin share and asset share identifiers use full domain-separated SHA3-256 hashes
(32 bytes, displayed as 64 hexadecimal characters). The former 16-byte share
encoding is rejected. A canonical coin UTXO occupies 73 bytes for state-growth
burn accounting.

Older databases are incompatible; no automatic migration of ledger state,
assets or transactions is provided. Use fresh storage for the current chain,
keeping older databases separate. See [Program ID compatibility](docs/OWNERSHIP.md#compatibility)
for wallet identity changes.

Check the complete workspace:

```bash
cargo check --workspace
```

Run workspace tests (the current chain-spec fixture and full-lifecycle gates
are tracked in [verification status](docs/PROGRAM_CALL.md#verification-status-and-remaining-gates)):

```bash
cargo test --workspace
```

Build optimized binaries:

```bash
cargo build --release -p node -p wallet
```

Check formatting:

```bash
cargo fmt --all -- --check
```

Run Clippy:

```bash
cargo clippy --workspace --all-targets
```

## Project structure

```text
XPARQ/
├── crypto/       Cryptographic primitives
├── kernel/       Consensus and ledger rules
├── extension/    XPQ and asset application implementations
├── runtime/      Node runtime
├── wallet/       Wallet and CLI
├── devkit/       XPVM assembler, devnet and examples
├── docs/         Protocol and RPC documentation
├── depend/       Vendored dependencies
├── Cargo.toml
├── Cargo.lock
├── LICENSE
└── SECURITY.md
```

## Security

XPARQ is under active development and has not reached a stable production release.

If you discover a security issue, avoid publishing exploit details before maintainers have had an opportunity to investigate it.

See [`SECURITY.md`](SECURITY.md) for the project's security policy.

## License

XPARQ is licensed under the [MIT License](LICENSE).

Copyright (c) 2026 XPARQ Network contributors.
