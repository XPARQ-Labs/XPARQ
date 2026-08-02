# Paqus Documentation

Paqus is an experimental proof-of-work blockchain focused on deterministic
execution, post-quantum authorization, independently verifiable state, and
transferable QCash bearer value.

This documentation covers the Paqus `0.2.19` consensus crate, the full node,
and the command-line wallet.

## Start here

* [What is Paqus?](getting-started/overview.md)
* [Install and build](getting-started/installation.md)
* [Network identity](getting-started/networks.md)
* [Run a node](node/running-a-node.md)
* [Create a wallet](wallet/creating-a-wallet.md)

{% hint style="warning" %}
Paqus is under active development. Protocol compatibility may change before a
stable release. Do not use it to secure production value without independent
review.
{% endhint %}

## Current protocol snapshot

| Property | Value |
| --- | --- |
| Consensus crate | `paqus 0.2.19` |
| Protocol | Sharksphere, version 1 |
| Asset | XPQ |
| Smallest unit | paqus |
| Units per XPQ | 1,000,000 |
| Consensus | Proof of work, greatest cumulative chainwork |
| Proof of work | Argon2id, 64 MiB, 1 iteration, 4 lanes |
| Difficulty adjustment | WBDA, 2,048-block weight window |
| Confirmation depth | 2 blocks |
| Finality boundary | 5 blocks |
| Block reward maturity | 50 blocks |
| Genesis premine | None |

The implementation and frozen protocol vectors are authoritative if this
documentation differs from the source.
