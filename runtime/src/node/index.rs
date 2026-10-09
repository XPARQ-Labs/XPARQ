use super::mempool::block_program_transactions;
use super::*;

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TxLocation {
    pub(super) height: Height,
    pub(super) transaction_index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ActivityLocation {
    Emission {
        height: Height,
    },
    Transaction {
        height: Height,
        transaction_index: usize,
    },
}

pub(super) struct ProgramActivityPage {
    pub(super) locations: Vec<ActivityLocation>,
    pub(super) next_cursor: Option<[u8; crate::storage::PROGRAM_ACTIVITY_CURSOR_SIZE]>,
}

pub(super) fn canonical_block_height(
    path: &Path,
    ledger: &Ledger,
    hash: [u8; 32],
) -> Result<Option<Height>, String> {
    ensure_persistent_indexes(path, ledger)?;

    Ok(crate::storage::read_block_height_by_hash(path, hash)?.map(Height))
}

pub(super) fn coin_origin(
    path: &Path,
    ledger: &Ledger,
    share: kernel::monetary::coin::CoinShare,
) -> Result<Option<crate::storage::CoinOrigin>, String> {
    ensure_persistent_indexes(path, ledger)?;
    crate::storage::read_coin_origin(path, share)
}

fn transaction_program_ids(
    transaction: &Transaction,
    miner: ProgramId,
) -> Result<BTreeSet<ProgramId>, String> {
    let mut program_ids = BTreeSet::new();

    let (sender, outputs) = match transaction {
        AuthorizedProgramEnvelope::Program(transaction) => (
            transaction.payment.signer,
            explorer::coin_outputs_with_charges(&transaction.payment, miner),
        ),
    };

    let AuthorizedProgramEnvelope::Program(tx) = transaction;
    program_ids.extend(
        explorer::program_recipients(tx)
            .into_iter()
            .map(|owner| owner.program()),
    );
    program_ids.insert(sender);

    for output in outputs {
        if let Some(program_id) = explorer::output_recipient(&output) {
            program_ids.insert(program_id);
        }
    }

    Ok(program_ids)
}

pub(super) fn stored_program_activities(
    block: &Block,
) -> Result<Vec<crate::storage::StoredProgramActivity>, String> {
    let mut activities = Vec::new();

    if let Some(emission) = block.emission() {
        activities.push(crate::storage::StoredProgramActivity {
            program_id: emission.to.0,
            transaction_index: None,
        });
    }

    let miner = block.miner_program_id();

    for (transaction_index, transaction) in block_program_transactions(block).enumerate() {
        let transaction_index =
            u64::try_from(transaction_index).map_err(|_| "transaction index exceeds u64")?;

        for program_id in transaction_program_ids(&transaction, miner)? {
            activities.push(crate::storage::StoredProgramActivity {
                program_id: program_id.0,
                transaction_index: Some(transaction_index),
            });
        }
    }

    Ok(activities)
}

fn ensure_persistent_indexes(path: &Path, ledger: &Ledger) -> Result<(), String> {
    let tip_height = ledger
        .tip_height()
        .ok_or("canonical genesis is missing while checking persistent indexes")?;

    let tip_hash = ledger
        .tip_hash()
        .ok_or("canonical genesis is missing while checking persistent indexes")?
        .0;

    if crate::storage::canonical_index_tip(path)?
        .is_some_and(|(height, hash)| height == tip_height.0 && hash == tip_hash)
    {
        return Ok(());
    }

    let blocks = || {
        ledger.chain.headers().map(|(height, _)| {
            let block = super::state::canonical_block(path, ledger, *height)?;
            Ok(crate::storage::CanonicalIndexBlock {
                height: block.height().0,

                hash: block.hash().map_err(|error| error.to_string())?.0,

                bytes: kernel::blockchain::block_bytes(&block)
                    .map_err(|error| error.to_string())?,

                transactions: block_program_transactions(&block)
                    .map(|transaction| transaction.id().map_err(|error| error.to_string()))
                    .collect::<Result<Vec<_>, String>>()?,

                activities: stored_program_activities(&block)?,
            })
        })
    };

    crate::storage::rebuild_canonical_indexes_stream(path, blocks)
}

pub(super) fn transaction_location(
    path: &Path,
    ledger: &Ledger,
    hash: [u8; 32],
) -> Result<Option<TxLocation>, String> {
    ensure_persistent_indexes(path, ledger)?;

    let Some((height, transaction_index)) = crate::storage::read_transaction_location(path, hash)?
    else {
        return Ok(None);
    };

    let transaction_index =
        usize::try_from(transaction_index).map_err(|_| "stored transaction index exceeds usize")?;

    Ok(Some(TxLocation {
        height: Height(height),
        transaction_index,
    }))
}

#[cfg(test)]
pub(super) fn program_activity_locations(
    path: &Path,
    ledger: &Ledger,
    program_id: ProgramId,
) -> Result<Vec<ActivityLocation>, String> {
    ensure_persistent_indexes(path, ledger)?;

    crate::storage::read_program_activities(path, program_id.0)?
        .into_iter()
        .map(
            |(height, transaction_index)| -> Result<ActivityLocation, String> {
                let height = Height(height);

                match transaction_index {
                    None => Ok(ActivityLocation::Emission { height }),

                    Some(transaction_index) => {
                        let transaction_index =
                            usize::try_from(transaction_index).map_err(|_| {
                                "stored activity transaction index exceeds usize".to_string()
                            })?;

                        Ok(ActivityLocation::Transaction {
                            height,
                            transaction_index,
                        })
                    }
                }
            },
        )
        .collect()
}

pub(super) fn program_activity_page(
    path: &Path,
    ledger: &Ledger,
    program_id: ProgramId,
    before: Option<[u8; crate::storage::PROGRAM_ACTIVITY_CURSOR_SIZE]>,
    limit: usize,
) -> Result<ProgramActivityPage, String> {
    ensure_persistent_indexes(path, ledger)?;

    let page = crate::storage::read_program_activities_page(path, program_id.0, before, limit)?;

    let locations = page
        .entries
        .into_iter()
        .map(
            |(height, transaction_index)| -> Result<ActivityLocation, String> {
                let height = Height(height);

                match transaction_index {
                    None => Ok(ActivityLocation::Emission { height }),

                    Some(transaction_index) => {
                        let transaction_index =
                            usize::try_from(transaction_index).map_err(|_| {
                                "stored activity transaction index exceeds usize".to_string()
                            })?;

                        Ok(ActivityLocation::Transaction {
                            height,
                            transaction_index,
                        })
                    }
                }
            },
        )
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ProgramActivityPage {
        locations,
        next_cursor: page.next_cursor,
    })
}
