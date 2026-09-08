# consensus_fixed integration notes

This refactor targets the transaction/ledger model discussed in this chat.

## Removed / merged files

Old:
- apply.rs
- emission.rs
- error.rs
- fork.rs
- reorg.rs
- state_burn.rs
- validate.rs
- wbda.rs
- pow.rs
- mod.rs

New:
- block.rs       = apply + canonical block validation + Consensus
- transaction.rs = Commit/Reveal + authorization + value/ownership validation
- policy.rs      = WBDA + emission + protocol burn
- pow.rs         = Argon2id PoW only
- fork.rs        = fork choice + reorg planning
- header.rs      = header-only sync validation
- error.rs       = top-level ConsensusError
- mod.rs

## Required external changes

### 1. blockchain::Block transaction type

Blocks must carry the new outer transaction envelope:

    Vec<crate::transaction::Transaction>

not AuthorizedTransaction directly.

### 2. Ledger/validation view must support Commit/Reveal

`TransactionStateView` now requires:

    fn pending_commitment(&self, commitment: TransactionCommitment) -> bool;

A Commit must become canonical state (or be provided by an equivalent deterministic
canonical commit index) before Reveal validates.

When a Reveal is applied, consume/remove the matching pending commitment.

The pending commitment set must have rollback support.

### 3. Ownerless UTXO still needs ownership resolution

The canonical UTXO values remain ownerless:

    XPQ   -> Zeno
    Share -> AssetShare { parent, amount }

But consensus still needs to prove that an input was originally committed to the
current signer.

`TransactionStateView` therefore requires:

    fn coin_recipient(&self, id: XPQ) -> Option<Address>;
    fn share_recipient(&self, id: Share) -> Option<Address>;

These should be backed by a deterministic origin/reveal index reconstructed from
canonical transaction history, NOT by adding `owner` back into Utxo/UtxoSet.

Do not return a recipient based only on the current signer. It must be derived from
the output that originally created the XPQ/Share identifier.

### 4. Ledger apply types

Consensus now returns:

    ValidatedTransaction::Commit(...)
    ValidatedTransaction::Reveal(...)

and the Reveal contains:

    ValidatedAuthorizedTransaction::Spend(...)
    ValidatedAuthorizedTransaction::Asset(...)

`ledger/applied.rs` should apply only the inner ValidatedAuthorizedTransaction.
Commit inserts the commitment; Reveal removes the commitment then applies the
validated payload.

### 5. Burn

Spend no longer declares a `burn` field.

For a coin payment consensus derives:

    actual_burn = input_total - output_total

and requires:

    actual_burn == ProtocolBurn::for_transaction(...).total()

Ledger should record the same implicit delta.

`COIN_UTXO_STATE_WEIGHT` was corrected for the ownerless UTXO representation:
XPQ key + Zeno value; Address is no longer counted in coin UTXO state.

### 6. Commit fee caveat

The current `CommitTransaction` contains only a commitment hash, so it has no XPQ
payer of its own. That means the current protocol-burn rule can charge Reveal but
cannot directly charge Commit.

This is not hidden by this refactor. If Commit spam must itself pay an archival
burn, extend CommitTransaction with a coin payment or define another explicit
anti-spam rule.

### 7. Crypto domains

Expected HashDomain variants:
- PoWSeed
- PoWSalt
- XPQEmission
- SpendIntent
- AssetIntent
- Transaction
- TransactionCommit

`canonical_bytes` and `domain` are imported from the `crypto` crate.
