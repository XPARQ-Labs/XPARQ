# XPARQ Devkit

Build XPVM v4 programs, validate their bytecode with the kernel, and deploy and
execute them on an isolated local devnet. This tooling adds no VM instruction or
consensus rule. It is an assembler and development runner, not a general-purpose
language compiler or an alternative signature/ZK verifier.

Requirements: Rust/Cargo matching the workspace, Python 3, and a Unix system for
the devnet runner. Run commands from the repository root. Vendored/cached Cargo
dependencies allow the commands below to use `--offline`.

## Build and run the complete example

```bash
python3 devkit/devnet/run.py build
python3 devkit/devnet/run.py demo
```

Builds explicitly select **devnet** and put binaries in `devkit/target/debug`,
separate from normal node/wallet builds. The demo creates a local wallet, starts
its own loopback node and miner, waits for funding, assembles and deploys the
counter, calls it and checks state 1. It then deploys the coin vault, deposits
1 XPQ, withdraws 0.25 XPQ as the deployer and checks a remaining 0.75 XPQ. The
runner stops its node on completion, failure or Ctrl-C. Mining is active while
running and consumes CPU/memory. Each confirmation wait is bounded to 120 seconds.

The default development directory is `devkit/.local/` (ignored by Git):

- `wallet.json`: local signing/recovery material; creation output is suppressed.
- `chain/`: isolated devnet database, never the default node data directory.
- `node.log`: node output for diagnosing failed commands.
- `programs.json`: confirmed demo deployments.
- `*.xpvm`: assembled artifacts.

Keep this test wallet separate from wallets holding real funds. Nothing is deleted
or reset automatically. To use fresh storage, choose another directory:

```bash
python3 devkit/devnet/run.py --state /tmp/xparq-devkit-example demo
```

## Assemble and check

```bash
devkit/target/debug/xparq-devkit assemble devkit/examples/counter.xpa -o /tmp/counter.xpvm
devkit/target/debug/xparq-devkit check /tmp/counter.xpvm
```

`check` accepts all bytecode versions supported by kernel. Assembly targets v4.
Kernel validation checks structure, limits, instructions and branch destinations;
stack types, authorization, balances and executed branches remain runtime checks.
Passing structural validation does not guarantee a successful call.

Assembly uses one instruction per line, `#` comments and labels ending in `:`.
Header directives precede instructions: `.version 4`, `.stack N`, `.memory N`.
Defaults are stack 64 and one memory page; entry is always zero. Opcode names
and stack operands follow [XPVM v4](../docs/XPVM.md#application-bytecode-v4).

| Instruction with immediate | Syntax |
| --- | --- |
| Unsigned integer | `u128.const 42` or `u128.const 0x2a` |
| Hex bytes (empty allowed) | `bytes.const 0102ff` |
| UTF-8 convenience | `bytes.text storage-key` (remaining text, no quotes/escapes; `#` starts a comment) |
| Program owner | `owner.const HEX64` (kernel Owner tag 0) |
| Branch | `jump label` / `jump.zero label` |

All other supported instructions take their operands from the runtime stack and
have no inline argument. Labels resolve to body-relative instruction offsets.
Use `-D NAME=VALUE` with `$NAME` as the whole immediate operand:

```bash
devkit/target/debug/xparq-devkit assemble devkit/examples/asset-transfer.xpa \
  -D ASSET=HEX64 -D RECIPIENT=HEX64 -D AMOUNT=100000000 \
  -o /tmp/asset-transfer.xpvm
```

Replace HEX64 with actual IDs. This example transfers existing shares owned by
the deployed program; fund it first. It neither creates an asset nor mints shares.
Amounts are raw units, not decimal XPQ/asset strings. Compilation embeds the
parameters in immutable bytecode. See [examples](examples/README.md).

## Interactive local development

Terminal 1:

```bash
python3 devkit/devnet/run.py up
```

This starts loopback RPC `127.0.0.1:26666`, P2P `127.0.0.1:26001` and mining to the
active local wallet ProgramId. Ctrl-C stops the owned process. The launcher
refuses occupied ports and locks its development directory. Use `--rpc-port` and
`--p2p-port` after `up` to select different ports.

Terminal 2, after funding appears in the account:

```bash
python3 devkit/devnet/run.py deploy --code /tmp/counter.xpvm --nonce 1
python3 devkit/devnet/run.py call --program-id HEX_PROGRAM_ID
python3 devkit/devnet/run.py inspect --program-id HEX_PROGRAM_ID
```

Use a fresh nonce for each deployment by the active wallet account. Deploy waits
for the program to be confirmed; call waits for the transaction to be confirmed.
All actions use the existing wallet signing, fee/burn quote, payment selection
and submission paths. `call` also accepts `--data HEX` and `--deposit XPQ_AMOUNT`.
`inspect` returns public account state, balances and shares. Use the same global
`--state` directory and per-command `--rpc` when selecting nondefault locations.
For advanced workflows, invoke `devkit/target/debug/wallet` directly.

ProgramId is a 32-byte account/deployed-program identity. Monetary route 0 and VM
route 2 are dispatcher numbers, not owner IDs. Coin and asset Share IDs are also
32 bytes. Current compatibility is chain-spec 1, database schema 1, snapshot 3
and wallet file 2. Fresh compatible storage is required after a chain reset.

## Verification

```bash
cargo test -p xparq-devkit --locked --offline
python3 devkit/tests/smoke.py
```

Assembler tests check independently encoded output, label destinations, parameters,
malformed source and kernel limits. The smoke test requires the devkit build and
runs real local transactions with a temporary wallet/database, restarts the node
and verifies that malformed calldata and a different wallet cannot withdraw from
the vault. It does not join
an external network. Developer-created application logic still needs its own
permission, failure and accounting tests.
