## BUG QCASH REDEEM — August 2, 2026
 The bug is in `redeem_from_files_at` (transaction/qcash.rs) — it's not a node validation issue, it's a commitment-ordering bug in the wallet's core transaction builder.

**Flow:**

1. `redeem_from_files_at` builds the transaction with `last_state = Hash::ZERO` (the default from `Self::redeem`)
2. It computes `redeem_transaction_commitment()` — which includes `last_state` in its payload — then signs each coin via `QCashRedeemMetadata::new_for_transaction(files, recipient, commitment)`, binding to a commitment that still has `last_state = ZERO`
3. Back in `commands.rs`, `.with_last_state(account_state.last_state)` is called *after* the coin signatures already exist — this only replaces the field, it does not re-sign anything
4. When the node (or local `validate()`) calls `redeem_transaction_commitment()` again to verify, `last_state` is now different (the real value, not ZERO) → the commitment differs → the signature produced in step 2 no longer matches → `InvalidMetadata`

**Fix — bind `last_state` before the commitment is computed, not after.**

`qcash.rs`:

```rust
pub fn redeem_from_files(
    signer: Address,
    recipient: Address,
    files: &[QCashCoinFile],
) -> Result<Self, QCashError> {
    Self::redeem_from_files_at(signer, recipient, files, Hash::ZERO)
}

pub fn redeem_from_files_at(
    signer: Address,
    recipient: Address,
    files: &[QCashCoinFile],
    last_state: Hash,
) -> Result<Self, QCashError> {
    let placeholder_inputs = files
        .iter()
        .map(|file| file.redeem_input_for_transaction(recipient, [0; 32]))
        .collect::<Result<Vec<_>, _>>()?;
    let mut transaction = Self::redeem(
        signer,
        recipient,
        QCashRedeemMetadata::from_inputs(placeholder_inputs)?,
    )
    .with_last_state(last_state);
    let commitment = transaction
        .redeem_transaction_commitment()
        .map_err(|_| QCashError::Serialization)?
        .ok_or(QCashError::InvalidCommitment)?;
    transaction.kind = QCashTransactionKind::Redeem {
        recipient,
        metadata: QCashRedeemMetadata::new_for_transaction(files, recipient, commitment)?,
    };
    Ok(transaction)
}
```

`commands.rs` (`wallet_cash_redeem`, around line 1583):

```rust
let transaction = QCashTransaction::redeem_from_files_at(
    wallet.address,
    recipient,
    &[file],
    account_state.last_state,
)
.map_err(|error| format!("failed to authorize cash coin: {error}"))?;
```

(remove the old `.map(|transaction| transaction.with_last_state(account_state.last_state))` — no longer needed.)

Also check other callers of `redeem_from_files` / `redeem_from_files_at` in `commands.rs` (around line 2618) and elsewhere in the codebase — all of them need to be updated to match the new signature.

## STATUS
RESOLVED