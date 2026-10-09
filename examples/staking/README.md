# Staking Example Design (Not Yet Deployable)

The repository does not currently provide stake/unstake commands or a staking
contract. XPVM v1 only supports NOP, PUSH_I64, ADD, RETURN, READ_STATE, and
WRITE_STATE. The VM cannot lock or transfer XPQ/assets, read block height, or
store staking positions per program. Deploying bytecode with a numeric state
value therefore does not implement staking or rewards.

## Required operations

| Operation | Required behavior |
| --- | --- |
| Stake | Authenticate the owner, move funds into escrow, and record the amount and block height |
| Claim | Calculate rewards deterministically and pay from a defined funding source |
| Unstake | Check the lock period, return funds, and close the position |
| Query | Display positions, lock periods, and claimable rewards |

This is a design, not an existing API. Implementation requires authorized
escrow/transfer host capabilities, state per owner, block height context,
reward rules and funding, and consensus validation. Another option is a new
system application with a route defined in kernel/extension.

Before providing a staking deployment script, verify balance conservation,
protection against double claims, rounding and overflow rules, rollback and
reorganization, and the stake → claim → unstake lifecycle through the node
and wallet.

For a working stateful example, use the [persistent counter](../counter/README.md).
For a constant-return deployment, use [return7](../README.md).
See the VM limits in [XPVM](../../docs/XPVM.md) and the system application
pattern in [ProgramCall](../../docs/PROGRAM_CALL.md).
