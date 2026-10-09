# XPARQ Examples

Run these commands from the repository root:

```bash
./build.sh
./target/release/node
```

The node must be connected to the selected network, with a miner available to
include deployments in blocks. The default build uses mainnet. To experiment
on devnet:

```bash
./build.sh --no-default-features --features devnet
./target/release/node
```

Use a wallet funded with XPQ on the same network. Store the wallet outside the
repository; never commit private keys or mnemonics. In another terminal:

```bash
export WALLET_FILE="$HOME/.xparq/wallet.json"
export RPC_ADDR=127.0.0.1:26666 # devnet; mainnet: 127.0.0.1:6666
./examples/deploy/return7.sh 1
```

The script submits a real deployment and pays the protocol burn and miner fee.
Choose a nonce that the wallet owner has not used before. Wait for confirmation
in a block before relying on the deployed program.

## Deploy your own program

```bash
./examples/deploy/deploy.sh /path/to/program.xpvm 2
```

`return7.sh` creates temporary bytecode for `PUSH_I64 7; RETURN` and removes it
when finished. Deployment registers the program; execution requires a separate
VM call transaction.

To produce signed hex without submitting the deployment:

```bash
./examples/deploy/return7.sh 3 --offline
```

`--offline` mode still requires RPC for quotes and funding selection.
Set `WALLET_BIN` if the executable is in another location. Relative bytecode
and wallet paths are resolved from the directory where the script is invoked.

Bytecode format: [XPVM](../docs/XPVM.md).
Call a confirmed deployment with:

```bash
./target/release/wallet program-call --program-id PROGRAM_ID --wallet "$WALLET_FILE" --rpc "$RPC_ADDR"
```

## Persistent counter

The [counter example](counter/README.md) includes bytecode and scripts to deploy
and increment a value stored in program state. It works with XPVM v1.

## Staking

See the [staking status and design](staking/README.md). Staking is not
implemented yet.
