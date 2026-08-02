# Backups and snapshots

## Check the database

```bash
cargo run --release --bin paqus-node -- \
  node db check data/mainnet
```

## Database backup

```bash
cargo run --release --bin paqus-node -- \
  node db backup data/mainnet backups/mainnet
```

Restore into the intended network path:

```bash
cargo run --release --bin paqus-node -- \
  node db restore backups/mainnet data/mainnet
```

Stop the node before manual filesystem-level copies. Prefer the node's
database commands because they understand the storage layout.

## Export a snapshot

```bash
cargo run --release --bin paqus-node -- \
  node snapshot export data/mainnet snapshot.PAQUS
```

Import into a new database:

```bash
cargo run --release --bin paqus-node -- \
  node snapshot import data/mainnet-restored snapshot.PAQUS
```

Snapshots are authenticated against chain parameters, headers, and state
commitments. They are not a license to skip greatest-work chain verification.

## What to back up

Back up:

* wallet JSON files;
* QCash `.XPQ` bearer files;
* their passwords through a separate secure process;
* node configuration when it contains non-secret operational settings.

The blockchain database can be reconstructed from peers. Secret-bearing files
usually cannot.
