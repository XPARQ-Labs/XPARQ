# XPARQ VM Roadmap

This roadmap lists unfinished work only. Implemented behavior is documented in
[Architecture](docs/ARCHITECTURE.md), [XPVM](docs/XPVM.md), and
[ProgramCall integration](docs/PROGRAM_CALL.md).

XPVM v1–v4 now support bounded execution, kernel-checked monetary effects,
authenticated caller context, key/value storage, conditional control flow, and
synchronous calls between programs. CLI workflows include signed calldata,
deposits, quotes, offline output and submission. Public program state reads are
available over RPC.
Chain-spec version 8 fixtures are reconciled, including replay and rollback tests.
Compiled XPQ/asset applications remain in extension; new application logic is
deployed as bytecode rather than adding a native application to the node.

| Work | Status | Acceptance criteria |
| --- | --- | --- |
| Interactive deployed-program workflows | CLI and interactive deployment supported; interactive calldata/deposit calls pending | Expose application-call input and deposits in the interactive menu while retaining signing, quotes, offline output and submission behavior. |
| Execution receipts | Committed result contract not defined; quotes expose a preview return value | Specify committed results/costs, consensus versus derived RPC data, indexing after restart, and orphan removal. |

For security review and release requirements, see the
[Security Hardening Roadmap](docs/SECURITY_ROADMAP.md).

The initial [devkit](devkit/README.md) supplies a v4 assembler and isolated devnet
build/deploy/call/inspect workflows. A high-level language compiler and application
SDK are future work; they do not replace kernel bytecode validation.
