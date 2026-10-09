//! Runtime retention policy. This value has no effect on fork validity.
use super::state::canonical_block;
use super::*;

pub(super) const JOURNAL_BLOCKS: u64 = 256;

fn key(block: &Block) -> Result<String, String> {
    Ok(format!(
        "protocol-burns-v1/{}",
        hex::encode(block.hash().map_err(|e| e.to_string())?.0)
    ))
}

pub(super) fn protocol_burns(
    database: &Path,
    ledger: &Ledger,
    block: &Block,
) -> Result<Vec<Zeno>, String> {
    if ledger.chain.header(&block.height()) != Some(&block.header) {
        return Err("receipt body does not match canonical header".into());
    }
    if block.operations().is_empty() {
        return Ok(vec![]);
    }
    if let Some(burns) = ledger.program_call_protocol_burns_for_block(block) {
        return Ok(burns);
    }
    let bytes = crate::storage::auxiliary_get(database, &key(block)?)?
        .ok_or("historical execution receipts are missing")?;
    // Bound decoding before accepting this locally persisted, non-consensus cache.
    let expected_size = block
        .operations()
        .len()
        .checked_mul(8)
        .and_then(|size| size.checked_add(4))
        .ok_or("receipt size overflow")?;
    if bytes.len() != expected_size {
        return Err("historical receipt size is invalid".into());
    }
    let burns: Vec<Zeno> =
        canonical_decode(&bytes).map_err(|e| format!("decode historical receipts: {e}"))?;
    if burns.len() != block.operations().len() {
        return Err("historical receipt count is invalid".into());
    }
    Ok(burns)
}

pub(super) fn copy_receipt(
    source: &Path,
    target: &Path,
    ledger: &Ledger,
    block: &Block,
) -> Result<(), String> {
    if block.operations().is_empty() {
        return Ok(());
    }
    let burns = protocol_burns(source, ledger, block)?;
    crate::storage::auxiliary_put(
        target,
        &key(block)?,
        &canonical_bytes(&burns).map_err(|e| e.to_string())?,
    )
}

pub(super) fn prune_journals(database: &Path, ledger: &mut Ledger) -> Result<(), String> {
    prune_journals_with_window(database, ledger, JOURNAL_BLOCKS)
}

pub(super) fn prune_journals_with_window(
    database: &Path,
    ledger: &mut Ledger,
    retained_blocks: u64,
) -> Result<(), String> {
    let tip = ledger.tip_height().ok_or("cannot prune an empty ledger")?;
    let first = Height(tip.0.saturating_sub(retained_blocks.max(1) - 1));
    let expired = ledger
        .rollback_journal_heights()
        .take_while(|height| *height < first)
        .collect::<Vec<_>>();
    for height in expired {
        let archive = canonical_block(database, ledger, height)
            .and_then(|block| copy_receipt(database, database, ledger, &block));
        if let Err(error) = archive {
            eprintln!("journal: pruning deferred, preserving undo data: {error}");
            return Ok(());
        }
    }
    // Archive failures leave all undo data available. Bodies are never pruned.
    ledger.prune_rollback_journals_before(first);
    Ok(())
}
