# XPARQ Bootstrap Database

This directory documents the optional XPARQ bootstrap database. Database
archives are distributed separately as GitHub Release assets and must not be
committed directly to the source repository.

## Pre-launch mining disclosure

The bootstrap chain is not a genesis premine. XPQ is not assigned directly by
the genesis state. Blocks before the public network launch are produced by the
normal XPARQ proof-of-work process and are subject to the same consensus rules,
difficulty schedule, emission schedule, state burn, and block validation as
later blocks.

The accurate description is **pre-launch bootstrap mining**. Although every
coin is backed by a valid proof-of-work block, mining access during this period
is not yet public. The resulting early supply and its recipient addresses must
therefore remain publicly auditable.

The planned bootstrap publication point is height `200000`. Before publishing
an archive, replace the placeholders below with values read from the stopped
and verified node:

```text
Bootstrap height:       200000
Tip hash:               <64-character block hash>
Total issued supply:    <gross XPQ emission through height 200000>
Total burned supply:    <XPQ burned through height 200000>
Bootstrap miner address:<address or documented address list>
Chain-spec hash:        <64-character chain-spec hash>
Node version:           <release version>
redb schema version:    1
Snapshot version:       1
Archive SHA-256:        <64-character archive checksum>
```

Do not publish an archive while any placeholder remains unresolved.

## Developer wallets

The following public developer wallet addresses participate in pre-launch
bootstrap mining, testing, and ecosystem distribution:

```text
Qxffb9effba63ceec2491c3b31ca00a5c3c6242fda18d213c9
Qxd6a98a1a699ae28b450fe9d118c9129906bdd70d5ca0fcf7
```

Balances, emissions, transfers, state burns, and later distributions involving
these addresses are publicly auditable from the canonical chain. Publishing an
address does not publish its private key; the corresponding wallet files and
recovery material must remain offline and must never be included in a database
archive or source commit.

## Purpose

The database archive lets a new node start from the published canonical chain
without downloading the complete pre-launch history from a single live peer.
It does not transfer ownership of XPQ. Coin ownership remains determined by the
canonical UTXO state, and the early mined XPQ remains under its recorded miner
addresses until moved by valid signed transactions.

The early supply is intended for transparent network bootstrapping and rapid
ecosystem distribution, such as community distribution, faucets, developer
grants, liquidity, and operating reserves. Allocation addresses, amounts, and
distribution transactions should be published separately and remain visible
through the block explorer.

## Creating a release archive

1. Stop every process writing to the database with a normal `Ctrl+C` shutdown.
2. Verify the stopped database:

   ```bash
   ./node check data/mainnet
   ```

3. Copy the database into a clean staging directory. Never archive an open
   redb file.
4. Exclude wallet files, private keys, mnemonics, `.QCash` bearer files,
   environment files, logs, and unrelated peer-local configuration.
5. Create a compressed archive and checksum, for example:

   ```bash
   tar --zstd -cf xparq-mainnet-bootstrap-height-200000.tar.zst data/mainnet
   sha256sum xparq-mainnet-bootstrap-height-200000.tar.zst > xparq-mainnet-bootstrap-height-200000.sha256
   ```

6. Upload the archive and checksum as assets of the matching GitHub Release.
   Do not add the archive to normal Git history or bypass `.gitignore` with
   `git add -f`.

The release notes must include the completed metadata above and identify the
exact source commit used to build the node.

## Restoring and verifying

Download both release assets, then verify the archive before extraction:

```bash
sha256sum -c xparq-mainnet-bootstrap-height-200000.sha256
tar --zstd -xf xparq-mainnet-bootstrap-height-200000.tar.zst
./node check data/mainnet
```

Run only a node version whose genesis, chain specification, database schema,
snapshot format, and consensus rules match the release metadata. A mismatch
must fail safely; never edit a stored schema or chain-spec version merely to
force an incompatible database to open.

The bootstrap archive is a transport optimization, not a substitute for
consensus verification. Nodes must continue validating the canonical block
history, state commitments, proof of work, transactions, and subsequent peer
data according to the XPARQ protocol.

## Sensitive data policy

The following files must never be included in a public database archive:

- `wallet.json` or any other keystore
- recovery mnemonics, private keys, or signing seeds
- `.QCash` bearer files
- `.env` files or RPC credentials
- private operational notes or machine credentials

Anyone restoring the public database still needs their own wallet. The
bootstrap database cannot recover wallet keys or grant access to the early
mined XPQ.
