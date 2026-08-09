# XPARQ Documentation Index

The active XPARQ workspace documentation is maintained at repository level and
beside each workspace package. This directory no longer contains a separate
GitBook documentation tree.

- [Project and protocol overview](../../README.md)
- [Mining and node tutorial](../../tutorial.md)
- [Core crate](../README.md)
- [Node binary](../../node/README.md)
- [Wallet library and CLI](../../wallet/README.md)
- [Fuzzing](../../FUZZING.md)
- [SQIsign integration status](../../depend/sqisign/INTEGRATION.md)
- [SQIsign validation plan](../../depend/sqisign/sqisign-improvement.md)

The workspace version is `0.1.0`. Source constants and frozen genesis data are
authoritative for consensus behavior; operational settings belong to the node
configuration and are not consensus parameters unless the core explicitly
commits to them.
