use super::*;

use super::{config::*, mempool::*, state::*, util::*};

use kernel::common::Owner;

use kernel::operation::BlockOperation;

pub(super) const DEFAULT_PROGRAM_ACTIVITY_LIMIT: usize = 50;

pub(super) const MAX_PROGRAM_ACTIVITY_LIMIT: usize = 250;

pub(super) fn print_account(path: Option<&str>, program_id: &str) -> Result<(), String> {
    let database = database_path(path);

    let ledger = load_or_initialize(&database)?;

    let program_id = parse_program_id(program_id)?;

    let response = account_response(
        &ledger,
        &read_pending_operations(&database)?,
        program_id,
        0,
        None,
    )?;

    println!(
        "{}",
        serde_json::to_string_pretty(&response).map_err(|error| error.to_string())?
    );

    Ok(())
}

pub(super) fn account_response(
    ledger: &Ledger,

    mempool: &[BlockOperation],

    program_id: ProgramId,

    utxo_offset: usize,

    utxo_after: Option<kernel::monetary::coin::CoinShare>,
) -> Result<serde_json::Value, String> {
    let next_height = ledger
        .tip_height()
        .map_or(0, |height| height.0.saturating_add(1));

    let reserved = reserved_coin_inputs(mempool);

    let mut total = Zeno::from_zeno(0);

    let account_utxos = ledger
        .state()
        .utxos
        .coins_by_owner(Owner::Program(program_id))
        .collect::<Vec<_>>();

    for (_, coin) in &account_utxos {
        total = total
            .checked_add(coin.amount)
            .ok_or("account balance overflow")?;
    }

    let page_start = utxo_after.map_or(utxo_offset, |cursor| {
        account_utxos.partition_point(|(id, _)| *id <= cursor)
    });

    let utxos = account_utxos
        .iter()
        .skip(page_start)
        .take(MAX_ACCOUNT_UTXOS_PER_PAGE)
        .map(|(id, coin)| {
            let is_reserved = reserved.contains(id);

            serde_json::json!({

                "id": id.to_string(),

                "amount": coin.amount.as_zeno(),

                "reserved": is_reserved,

            })
        })
        .collect::<Vec<_>>();

    let next_utxo_offset = page_start
        .checked_add(utxos.len())
        .filter(|offset| *offset < account_utxos.len());

    let next_utxo_cursor = next_utxo_offset
        .and_then(|_| account_utxos.get(page_start + utxos.len().saturating_sub(1)))
        .map(|(id, _)| id.to_string());

    let utxo_snapshot_entries = account_utxos
        .iter()
        .map(|(id, coin)| (*id, coin.amount, reserved.contains(id)))
        .collect::<Vec<_>>();

    let utxo_snapshot_bytes = kernel::crypto::canonical_bytes(&(program_id, utxo_snapshot_entries))
        .map_err(|error| format!("encode account UTXO snapshot: {error}"))?;

    let utxo_snapshot = kernel::crypto::domain_hash(
        kernel::crypto::HashDomain::AccountState,
        &utxo_snapshot_bytes,
    );

    let record = ledger.state().programs.program(&program_id);
    let mut owned_asset_shares: Vec<_> = ledger
        .state()
        .extensions
        .assets
        .shares_by_owner(Owner::Program(program_id))
        .collect();
    owned_asset_shares.sort_by_key(|(share, _)| *share);
    let asset_shares: Vec<_> = owned_asset_shares.into_iter()
        .map(|(share, value)| serde_json::json!({"id":share.to_string(),"asset":value.asset.to_string(),"amount":value.amount.to_string()}))
        .collect();
    Ok(serde_json::json!({

        "program_id": program_id.to_string(),
        "policy": if record.is_some() { "deployed" } else { "signature" },
        "state_value": record.map(|r| r.state_value),
        "coin_balance": total.as_zeno(),
        "coins": utxos,
        "asset_shares": asset_shares,

        "utxo_snapshot": hex::encode(utxo_snapshot.0),

        "tip_height": ledger.tip_height().map_or(0, |height| height.0),

        "next_height": next_height,

        "total": total.as_zeno(),

        "program_assets": program_account_assets(ledger, program_id)?,

        "utxos": utxos,

        "next_utxo_offset": next_utxo_offset,

        "next_utxo_cursor": next_utxo_cursor,

    }))
}

pub(super) fn balance_response(
    ledger: &Ledger,

    mempool: &[BlockOperation],

    program_id: ProgramId,
) -> Result<serde_json::Value, String> {
    let reserved_ids = reserved_coin_inputs(mempool);

    let mut total = Zeno::from_zeno(0);

    let mut reserved = Zeno::from_zeno(0);

    let mut utxo_count = 0_usize;

    for utxo in ledger
        .state()
        .utxos
        .coins_by_owner(Owner::Program(program_id))
    {
        total = total
            .checked_add(utxo.1.amount)
            .ok_or("account balance overflow")?;

        if reserved_ids.contains(&utxo.0) {
            reserved = reserved
                .checked_add(utxo.1.amount)
                .ok_or("reserved account balance overflow")?;
        }

        utxo_count = utxo_count
            .checked_add(1)
            .ok_or("account UTXO count overflow")?;
    }

    let available = total
        .checked_sub(reserved)
        .ok_or("reserved account balance exceeds total")?;

    Ok(serde_json::json!({

        "program_id": kernel::crypto::program_id_to_string(&program_id),

        "tip_height": ledger.tip_height().map_or(0, |height| height.0),

        "total": total.as_zeno(),

        "available": available.as_zeno(),

        "reserved": reserved.as_zeno(),

        "utxo_count": utxo_count,

        "program_assets": program_account_assets(ledger, program_id)?,

    }))
}

pub(super) fn explorer_program_response(
    database: &Path,

    ledger: &Ledger,

    mempool: &[BlockOperation],

    program_id: ProgramId,

    include_emissions: bool,

    limit: usize,

    before: Option<[u8; crate::storage::PROGRAM_ACTIVITY_CURSOR_SIZE]>,
) -> Result<serde_json::Value, String> {
    let reserved_ids = reserved_coin_inputs(mempool);

    let mut total = Zeno::from_zeno(0);

    let mut reserved = Zeno::from_zeno(0);

    for utxo in ledger
        .state()
        .utxos
        .coins_by_owner(Owner::Program(program_id))
    {
        total = total
            .checked_add(utxo.1.amount)
            .ok_or("explorer balance overflow")?;

        if reserved_ids.contains(&utxo.0) {
            reserved = reserved
                .checked_add(utxo.1.amount)
                .ok_or("explorer reserved balance overflow")?;
        }
    }

    let page = index::program_activity_page(database, ledger, program_id, before, limit)?;

    let mut activities = Vec::new();

    let mut emission_count = 0usize;

    for location in &page.locations {
        match *location {
            index::ActivityLocation::Emission { height } => {
                emission_count = emission_count.saturating_add(1);

                if !include_emissions {
                    continue;
                }

                let block = canonical_block(database, ledger, height)?;

                let emission = block
                    .emission()
                    .filter(|emission| emission.to == program_id)
                    .ok_or("indexed emission does not match the canonical chain")?;

                let protocol_burn = kernel::consensus::MINER_PROTOCOL_BURN;

                let miner_emission = emission
                    .subsidy
                    .checked_sub(protocol_burn)
                    .ok_or("block emission is below its protocol burn")?;

                activities.push(serde_json::json!({

                    "height": block.height().0,

                    "block_hash": hex::encode(

                        block.hash().map_err(|error| error.to_string())?.0

                    ),

                    "hash": serde_json::Value::Null,

                    "type": "emission",

                    "direction": "in",

                    "amount": miner_emission.as_zeno(),

                    "gross_subsidy": emission.subsidy.as_zeno(),

                    "protocol_burn": protocol_burn.as_zeno(),

                    "size_bytes": serde_json::Value::Null,

                }));
            }

            index::ActivityLocation::Transaction {
                height,

                transaction_index,
            } => {
                let block = canonical_block(database, ledger, height)?;

                let transaction = block_program_transactions(&block)
                    .nth(transaction_index)
                    .ok_or("indexed activity transaction is missing from its block")?;

                if let Some(activity) =
                    program_transaction_activity(&transaction, program_id, &block)?
                {
                    activities.push(activity);
                }
            }
        }
    }

    let next_cursor = page.next_cursor.map(hex::encode);

    Ok(serde_json::json!({

        "program_id": kernel::crypto::program_id_to_string(&program_id),

        "tip_height": ledger.tip_height().map_or(0, |height| height.0),

        "balance": {

            "total": total.as_zeno(),

            "reserved": reserved.as_zeno(),

        },

        "program_assets": program_asset_summaries(ledger, program_id)?,

        "activity_count": activities.len(),

        "emission_count": emission_count,

        "activities": activities,

        "next_cursor": next_cursor,

    }))
}

pub(super) fn program_transaction_activity(
    transaction: &Transaction,

    program_id: ProgramId,

    block: &Block,
) -> Result<Option<serde_json::Value>, String> {
    let authorized = transaction;

    let miner = block.miner_program_id();

    let (sender, outputs, extra_sent) = match authorized {
        AuthorizedProgramEnvelope::Program(tx) => (
            Some(tx.payment.signer),
            coin_outputs_with_charges(&tx.payment, miner),
            coin_burn(&tx.payment),
        ),
    };

    let received = checked_output_sum(
        outputs
            .iter()
            .filter(|output| output_recipient(output) == Some(program_id))
            .map(|output| output.amount),
    )?;

    let (direction, amount) = if sender == Some(program_id) {
        let external = checked_output_sum(
            outputs
                .iter()
                .filter(|output| output_recipient(output) != Some(program_id))
                .map(|output| output.amount),
        )?
        .checked_add(extra_sent)
        .ok_or("explorer transaction amount overflow")?;

        (
            if external.as_zeno() == 0 {
                "self"
            } else {
                "out"
            },
            external,
        )
    } else if received.as_zeno() > 0 {
        ("in", received)
    } else if matches!(transaction, AuthorizedProgramEnvelope::Program(tx) if program_recipients(tx).contains(&Owner::Program(program_id)))
    {
        ("in", Zeno::ZERO)
    } else {
        return Ok(None);
    };

    Ok(Some(serde_json::json!({

        "height": block.height().0,

        "block_hash": hex::encode(block.hash().map_err(|error| error.to_string())?.0),

        "hash": hex::encode(transaction.id().map_err(|error| error.to_string())?),

        "type": transaction_kind(transaction),

        "program": match transaction {AuthorizedProgramEnvelope::Program(tx) if !is_coin_transfer(&tx.call)=>Some(program_activity_response(tx,program_id)),_=>None},

        "direction": direction,

        "amount": amount.as_zeno(),

        "size_bytes": canonical_bytes(transaction).map_err(|error| error.to_string())?.len(),

    })))
}

pub(super) fn explorer_transaction_response(
    database: &Path,

    ledger: &Ledger,

    hash: [u8; 32],
) -> Result<serde_json::Value, String> {
    let tip_height = ledger.tip_height().map_or(0, |height| height.0);

    let location = index::transaction_location(database, ledger, hash)?
        .ok_or("transaction was not found in the canonical chain")?;

    let block = canonical_block(database, ledger, location.height)?;

    let transaction = block_program_transactions(&block)
        .nth(location.transaction_index)
        .ok_or("indexed transaction position is missing from its block")?;

    if transaction.id().map_err(|error| error.to_string())? != hash {
        return Err("transaction index does not match the canonical chain".into());
    }

    let burns = super::journal::protocol_burns(database, ledger, &block)?;

    let protocol_burn = burns
        .get(location.transaction_index)
        .copied()
        .ok_or("transaction execution receipt is missing")?;

    Ok(serde_json::json!({

        "hash": hex::encode(hash),

        "type": transaction_kind(&transaction),

        "status": "confirmed",

        "height": block.height().0,

        "block_hash": hex::encode(

            block.hash().map_err(|error| error.to_string())?.0

        ),

        "confirmations": tip_height

            .saturating_sub(block.height().0)

            .saturating_add(1),

        "size_bytes": canonical_bytes(&transaction)

            .map_err(|error| error.to_string())?

            .len(),

        "transaction": transaction_response(

            &transaction,

            protocol_burn,

        ),

    }))
}

pub(super) fn transaction_response(
    transaction: &Transaction,

    protocol_burn: Zeno,
) -> serde_json::Value {
    match transaction {
        AuthorizedProgramEnvelope::Program(program) => {
            program_transaction_response(program, protocol_burn)
        }
    }
}

pub(super) fn coin_outputs(intent: &kernel::program::CoinTransition) -> &[CoinOutput] {
    intent.coin_parts().map_or(&[], |(_, outputs)| outputs)
}

pub(super) fn coin_outputs_with_charges(
    intent: &kernel::program::CoinTransition,

    miner: ProgramId,
) -> Vec<CoinOutput> {
    let mut outputs = coin_outputs(intent).to_vec();

    if !intent.charges.miner_fee.is_zero() {
        outputs.push(CoinOutput::new(miner, intent.charges.miner_fee));
    }

    outputs
}

pub(super) fn coin_burn(_intent: &kernel::program::CoinTransition) -> Zeno {
    Zeno::ZERO
}

pub(super) fn asset_owner_response(owner: Owner) -> serde_json::Value {
    serde_json::json!({"type": "program", "value": hex::encode(owner.program().into_bytes())})
}

pub(super) fn output_recipient(output: &CoinOutput) -> Option<ProgramId> {
    Some(output.output.program())
}

pub(super) fn checked_output_sum(amounts: impl IntoIterator<Item = Zeno>) -> Result<Zeno, String> {
    amounts
        .into_iter()
        .try_fold(Zeno::from_zeno(0), |total, amount| {
            total
                .checked_add(amount)
                .ok_or_else(|| "explorer amount overflow".to_string())
        })
}

pub(super) fn transaction_kind(transaction: &Transaction) -> &'static str {
    match transaction {
        AuthorizedProgramEnvelope::Program(tx) if is_coin_transfer(&tx.call) => "transfer",

        AuthorizedProgramEnvelope::Program(_) => "program",
    }
}

pub(super) fn asset_authority_response(authority: Owner) -> serde_json::Value {
    asset_owner_response(authority)
}

pub(super) fn status_response(
    ledger: &Ledger,

    cumulative_work: Work,

    cumulative_weight: u64,
) -> Result<serde_json::Value, String> {
    let tip_height = ledger.tip_height().ok_or("canonical genesis is missing")?;

    let tip_hash = ledger.tip_hash().ok_or("canonical genesis is missing")?;

    let next_difficulty =
        expected_next_difficulty(&ledger.chain).map_err(|error| error.to_string())?;

    Ok(serde_json::json!({

        "tip_height": tip_height.0,

        "next_height": tip_height.0.saturating_add(1),

        "tip_hash": hex::encode(tip_hash.0),

        "next_difficulty": next_difficulty,

        "cumulative_work": format_work(cumulative_work.to_be_limbs()),

        "cumulative_weight": cumulative_weight.to_string(),

        "total_mined": ledger.state().coin.total_mined.as_zeno(),

        "total_burned": ledger.state().coin.total_burned.as_zeno(),

        "supply": ledger

              .state()

              .coin

              .supply()

              .map(|value| value.as_zeno())

              .unwrap_or(0),

    }))
}

pub(super) fn latest_blocks_response(
    database: &Path,

    ledger: &Ledger,
) -> Result<serde_json::Value, String> {
    let blocks = ledger
        .chain
        .headers()
        .rev()
        .take(20)
        .map(|(height, _)| {
            let block = canonical_block(database, ledger, *height)?;

            stored_block_response(database, ledger, &block)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(serde_json::json!({ "blocks": blocks }))
}

pub(super) fn stored_block_response(
    database: &Path,

    ledger: &Ledger,

    block: &Block,
) -> Result<serde_json::Value, String> {
    let burns = super::journal::protocol_burns(database, ledger, block)?;

    block_response_with_burns(block, burns)
}

#[cfg(test)]

pub(super) fn block_response(ledger: &Ledger, block: &Block) -> Result<serde_json::Value, String> {
    let burns = ledger
        .program_call_protocol_burns_for_block(block)
        .ok_or("transaction execution receipts are missing")?;

    block_response_with_burns(block, burns)
}

fn block_response_with_burns(block: &Block, burns: Vec<Zeno>) -> Result<serde_json::Value, String> {
    let gross_subsidy = block
        .emission()
        .map_or(Zeno::from_zeno(0), |emission| emission.subsidy);

    let state_burn = if block.emission().is_some() {
        kernel::consensus::MINER_PROTOCOL_BURN
    } else {
        Zeno::from_zeno(0)
    };

    let miner_emission = gross_subsidy
        .checked_sub(state_burn)
        .ok_or("block emission is below its created-state burn")?;

    let transaction_details = block
        .operations()
        .iter()
        .zip(burns)
        .filter_map(|(operation, protocol_burn)| {
            let call = operation.as_program_call()?;

            let transaction = AuthorizedProgramEnvelope::Program(Box::new(call.clone()));

            Some((transaction, protocol_burn))
        })
        .map(|(transaction, protocol_burn)| {
            Ok(serde_json::json!({

                "hash": hex::encode(

                    transaction.id().map_err(|error| error.to_string())?

                ),

                "type": transaction_kind(&transaction),

                "size_bytes": canonical_bytes(&transaction)

                    .map_err(|error| error.to_string())?

                    .len(),

                "transaction": transaction_response(

                    &transaction,

                    protocol_burn,

                ),

            }))
        })
        .collect::<Result<Vec<_>, String>>()?;

    let transaction_hashes = transaction_details
        .iter()
        .filter_map(|transaction| transaction.get("hash").cloned())
        .collect::<Vec<_>>();

    let operation_details = block
        .operations()
        .iter()
        .map(|operation| {
            let hash = operation.id().map_err(|error| error.to_string())?;

            Ok(match operation {
                kernel::operation::BlockOperation::ProgramCall(_) => serde_json::json!({

                    "operation_id": hex::encode(hash.into_bytes()), "type": "program_call"

                }),

                kernel::operation::BlockOperation::DeployProgram(deploy) => {
                    let code_hash = kernel::program::ProgramHash::derive(&deploy.deploy.code)
                        .map_err(|error| format!("derive deployed code hash: {error:?}"))?;

                    let program_id = kernel::program::ProgramId::derive(
                        deploy.deploy.owner,
                        deploy.deploy.nonce,
                        code_hash,
                    )
                    .map_err(|error| format!("derive deployed program ID: {error:?}"))?;

                    serde_json::json!({

                        "operation_id": hex::encode(hash.into_bytes()),

                        "type": "deploy_program",

                        "program_id": hex::encode(program_id.into_bytes()),

                        "owner": kernel::crypto::program_id_to_string(&deploy.deploy.owner),

                        "nonce": deploy.deploy.nonce,

                    })
                }
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let operation_hashes = operation_details
        .iter()
        .filter_map(|operation| operation.get("operation_id").cloned())
        .collect::<Vec<_>>();

    Ok(serde_json::json!({

        "height": block.height().0,

        "hash": hex::encode(block.hash().map_err(|error| error.to_string())?.0),

        "previous_hash": hex::encode(block.previous_hash().0),

        "difficulty": block.target_bits(),

        "block_weight": block.block_weight(),

        "nonce": block.header.nonce.0,

        "transactions": transaction_details.len(),

        "operations": operation_details.len(),

        "operation_hashes": operation_hashes,

        "operation_details": operation_details,

        "transaction_hashes": transaction_hashes,

        "transaction_details": transaction_details,

        "miner": kernel::crypto::program_id_to_string(&block.miner_program_id()),

        "subsidy": gross_subsidy.as_zeno(),

        "state_burn": state_burn.as_zeno(),

        "miner_emission": miner_emission.as_zeno(),

    }))
}

fn program_shares(
    ledger: &Ledger,

    asset: extension::asset_program::asset::AssetContract,

    program_id: ProgramId,
) -> Vec<serde_json::Value> {
    ledger.state().extensions.assets.shares_by_owner_asset(Owner::Program(program_id), asset)

        .map(|(id, s)| serde_json::json!({"share_id": id.to_string(), "amount": s.amount.to_string(), "owner": asset_owner_response(s.owner)})).collect()
}

pub(super) fn program_account_assets(
    ledger: &Ledger,

    program_id: ProgramId,
) -> Result<Vec<serde_json::Value>, String> {
    let state = &ledger.state().extensions.assets;

    let mut result = Vec::new();

    for (asset, record) in state.records() {
        let shares = program_shares(ledger, *asset, program_id);

        if shares.is_empty()
            && record.metadata.creator != Owner::Program(program_id)
            && record.metadata.mint_authority != Owner::Program(program_id)
        {
            continue;
        }

        result.push(serde_json::json!({"program_id":0,"asset":asset.to_string(),"name":record.metadata.name,"max_supply":record.metadata.max_supply.to_string(),"mint":record.supply.to_string(),"shares":shares}));
    }

    Ok(result)
}

pub(super) fn program_asset_response(
    ledger: &Ledger,

    route: &str,
) -> Result<serde_json::Value, String> {
    let parts = route
        .trim_start_matches("/program/asset/")
        .split('/')
        .collect::<Vec<_>>();

    let asset = parts[0]
        .parse::<extension::asset_program::asset::AssetContract>()
        .map_err(|_| "invalid program asset id")?;

    let record = ledger
        .state()
        .extensions
        .assets
        .records()
        .get(&asset)
        .ok_or("program asset was not found")?;

    if parts.len() == 1 {
        return Ok(
            serde_json::json!({"program_id":0,"asset":asset.to_string(),"name":record.metadata.name,"max_supply":record.metadata.max_supply.to_string(),"supply":record.supply.to_string(),"total_minted":record.total_minted.to_string(),"total_burned":record.total_burned.to_string(),"creator":asset_owner_response(record.metadata.creator),"mint_authority":asset_authority_response(record.metadata.mint_authority),"mint_nonce":record.mint_nonce}),
        );
    }

    if parts.len() == 3 && parts[1] == "balance" {
        let program_id = parse_program_id(parts[2])?;

        let shares = program_shares(ledger, asset, program_id);

        let total = ledger
            .state()
            .extensions
            .assets
            .shares_by_owner_asset(Owner::Program(program_id), asset)
            .try_fold(
                extension::asset_program::asset::Unit::ZERO,
                |sum, (_, s)| sum.checked_add(s.amount).ok_or("program balance overflow"),
            )?;

        return Ok(
            serde_json::json!({"monetary_program":0,"asset":asset.to_string(),"program_id":kernel::crypto::program_id_to_string(&program_id),"balance":total.to_string(),"shares":shares}),
        );
    }

    Err("invalid program asset route".into())
}

fn program_transaction_response(
    tx: &kernel::program::AuthorizedProgramInvocation,

    burn: Zeno,
) -> serde_json::Value {
    use extension::{
        asset_program::type_::AssetCall,
        script::execute::{DecodedProgramCall, decode_program},
    };

    if is_coin_transfer(&tx.call) {
        return serde_json::json!({

            "type":"transfer", "program_id":tx.call.program.0, "opcode":tx.call.opcode,

            "coin_contract":kernel::monetary::coin::CoinContract::derive().to_string(),

            "signer":kernel::crypto::program_id_to_string(&tx.signer),

            "inputs":tx.payment.coin_parts().map(|(inputs,_)|inputs.iter().map(ToString::to_string).collect::<Vec<_>>()),

            "outputs":coin_outputs(&tx.payment).iter().map(|o|serde_json::json!({"recipient":coin_owner_response(o.output),"amount":o.amount.as_zeno()})).collect::<Vec<_>>(),

            "miner_fee":tx.payment.charges.miner_fee.as_zeno(), "protocol_burn":burn.as_zeno(),

        });
    }

    let instruction = match decode_program(&tx.call) {
        Ok(DecodedProgramCall::Asset(call)) => match call {
            AssetCall::Register(v) => {
                serde_json::json!({"type":"register","name":v.name,"max_supply":v.max_supply.to_string(),"initial_mint":v.initial_mint.to_string(),"mint_authority":asset_authority_response(v.mint_authority),"nonce":v.nonce})
            }

            AssetCall::Mint(v) => {
                serde_json::json!({"type":"mint","asset":v.asset.to_string(),"nonce":v.nonce,"recipient":asset_owner_response(v.recipient),"amount":v.amount.to_string()})
            }

            AssetCall::Transfer(v) => {
                serde_json::json!({"type":"transfer","asset":v.asset.to_string(),"inputs":v.inputs.iter().map(ToString::to_string).collect::<Vec<_>>(),"outputs":v.outputs.iter().map(|o|serde_json::json!({"recipient":asset_owner_response(o.recipient),"amount":o.amount.to_string()})).collect::<Vec<_>>()})
            }

            AssetCall::Burn(v) => {
                serde_json::json!({"type":"burn","asset":v.asset.to_string(),"inputs":v.inputs.iter().map(ToString::to_string).collect::<Vec<_>>(),"amount":v.amount.to_string(),"output":v.output.to_string()})
            }
        },

        Ok(DecodedProgramCall::XpqTransfer) => serde_json::json!({"type":"xpq_transfer"}),

        Ok(DecodedProgramCall::Vm(id)) => {
            serde_json::json!({"type":"vm_call","deployed_program_id":hex::encode(id)})
        }

        Err(_) => serde_json::Value::Null,
    };

    serde_json::json!({"type":"program","program_id":tx.call.program.0,"opcode":tx.call.opcode,"payload":hex::encode(&tx.call.payload),"signer":kernel::crypto::program_id_to_string(&tx.signer),"asset_instruction":instruction,"coin_inputs":tx.payment.coin_parts().map(|(i,_)|i.iter().map(ToString::to_string).collect::<Vec<_>>()),"coin_outputs":coin_outputs(&tx.payment).iter().map(|o|serde_json::json!({"recipient":coin_owner_response(o.output),"amount":o.amount.as_zeno()})).collect::<Vec<_>>(),"miner_fee":tx.payment.charges.miner_fee.as_zeno(),"protocol_burn":burn.as_zeno()})
}

pub(super) fn program_recipients(tx: &kernel::program::AuthorizedProgramInvocation) -> Vec<Owner> {
    use extension::{
        asset_program::type_::AssetCall,
        script::execute::{DecodedProgramCall, decode_program},
    };

    match decode_program(&tx.call) {
        Ok(DecodedProgramCall::Asset(AssetCall::Mint(v))) => vec![v.recipient],

        Ok(DecodedProgramCall::Asset(AssetCall::Transfer(v))) => {
            v.outputs.iter().map(|o| o.recipient).collect()
        }

        _ => vec![],
    }
}

fn program_activity_response(
    tx: &kernel::program::AuthorizedProgramInvocation,

    program_id: ProgramId,
) -> serde_json::Value {
    use extension::{
        asset_program::{
            asset::{AssetContract, Metadata},
            type_::AssetCall,
        },
        script::execute::{DecodedProgramCall, decode_program},
    };

    let (operation, asset, amount) = match decode_program(&tx.call) {
        Ok(DecodedProgramCall::Asset(AssetCall::Register(v))) => {
            let asset = Metadata::new(
                v.name,
                v.max_supply,
                Owner::Program(tx.signer),
                v.mint_authority,
            )
            .and_then(|m| AssetContract::derive(&m, v.nonce))
            .map(|a| a.to_string())
            .unwrap_or_default();

            ("register", asset, v.initial_mint.as_units())
        }

        Ok(DecodedProgramCall::Asset(AssetCall::Mint(v))) => {
            ("mint", v.asset.to_string(), v.amount.as_units())
        }

        Ok(DecodedProgramCall::Asset(AssetCall::Transfer(v))) => {
            let amount = v
                .outputs
                .iter()
                .filter(|o| {
                    if program_id == tx.signer {
                        o.recipient != Owner::Program(program_id)
                    } else {
                        o.recipient == Owner::Program(program_id)
                    }
                })
                .fold(0_u128, |sum, o| sum.saturating_add(o.amount.as_units()));

            ("transfer", v.asset.to_string(), amount)
        }

        Ok(DecodedProgramCall::Asset(AssetCall::Burn(v))) => {
            ("burn", v.asset.to_string(), v.amount.as_units())
        }

        Ok(DecodedProgramCall::XpqTransfer) => ("xpq_transfer", String::new(), 0),

        Ok(DecodedProgramCall::Vm(id)) => ("vm_call", hex::encode(id), 0),

        Err(_) => ("invalid", String::new(), 0),
    };

    serde_json::json!({"program_id":tx.call.program.0,"opcode":tx.call.opcode,"operation":operation,"asset":asset,"amount":amount.to_string()})
}

fn program_asset_summaries(
    ledger: &Ledger,

    program_id: ProgramId,
) -> Result<Vec<serde_json::Value>, String> {
    program_account_assets(ledger, program_id)?
        .into_iter()
        .map(|mut entry| {
            let shares = entry.as_object_mut().unwrap().remove("shares").unwrap();

            let amount = shares
                .as_array()
                .unwrap()
                .iter()
                .try_fold(0_u128, |sum, s| {
                    let value = s["amount"]
                        .as_str()
                        .ok_or("invalid program balance")?
                        .parse::<u128>()
                        .map_err(|_| "invalid program balance")?;

                    sum.checked_add(value).ok_or("program balance overflow")
                })?;

            entry["balance"] = serde_json::Value::String(amount.to_string());

            Ok(entry)
        })
        .collect()
}

fn coin_owner_response(owner: Owner) -> serde_json::Value {
    asset_owner_response(owner)
}

/// Read a single public program storage entry; applications define their key layout.
pub(super) fn program_state_response(
    ledger: &Ledger,
    route: &str,
) -> Result<serde_json::Value, String> {
    let raw = route
        .strip_prefix("/program/state/")
        .ok_or("invalid program state route")?;
    let (program, key) = raw
        .split_once('/')
        .ok_or("program state route needs an ID and key")?;
    if program.len() != 64
        || key.is_empty()
        || key.len() > 2 * kernel::program::vm_app::MAX_KEY_BYTES
    {
        return Err("invalid program state ID or key length".into());
    }
    let id = kernel::program::ProgramId::from_bytes(
        hex::decode(program)
            .map_err(|_| "invalid program ID")?
            .try_into()
            .map_err(|_| "invalid program ID length")?,
    );
    let key = hex::decode(key).map_err(|_| "invalid storage key hex")?;
    let record = ledger
        .state()
        .programs
        .program(&id)
        .ok_or("deployed program was not found")?;
    Ok(
        serde_json::json!({"program_id":hex::encode(id.into_bytes()),"key":hex::encode(&key),"value":record.storage.get(&key).map(hex::encode),"height":ledger.tip_height().map(|h|h.0),"tip_hash":ledger.tip_hash().map(|h|hex::encode(h.0))}),
    )
}

fn is_coin_transfer(call: &kernel::program::system::script::call::ProgramCall) -> bool {
    matches!(
        kernel::program::system::script::execute::decode_program(call),
        Ok(kernel::program::system::script::execute::DecodedProgramCall::XpqTransfer)
    )
}
