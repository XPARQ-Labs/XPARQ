use super::transaction::{
    automatic_fee_transaction, reject_manual_fee, select_account_inputs_with_state_burn,
    submit_or_print_transaction,
};
use super::*;
use extension::{
    asset_program::{
        asset::{ASSET_DECIMALS, AssetContract, AssetOutput, Metadata, Share, Unit},
        opcode::AssetOpcode,
        type_::{Burn, Mint, Register, Transfer},
    },
    script::call::{ProgramCall, SystemProgramId},
};

use kernel::common::Owner;

fn amount(args: &[String], name: &str) -> Result<Unit, String> {
    parse_asset_display_amount(
        option(args, name).ok_or_else(|| format!("missing {name}"))?,
        ASSET_DECIMALS,
    )
    .map(Unit::from_units)
}
fn asset(args: &[String]) -> Result<AssetContract, String> {
    option(args, "--asset")
        .ok_or("missing --asset")?
        .parse()
        .map_err(|_| "invalid program asset id".into())
}
fn encode<T: borsh::BorshSerialize>(opcode: AssetOpcode, value: &T) -> Result<ProgramCall, String> {
    kernel::program::system::monetary::asset_call(opcode, value)
        .map_err(|e| format!("invalid monetary call: {e:?}"))
}
fn recipient(args: &[String]) -> Result<Owner, String> {
    super::util::parse_owner(option(args, "--to").ok_or("missing --to")?)
}
fn shares(
    rpc: &str,
    owner: ProgramId,
    asset: AssetContract,
    required: Option<Unit>,
) -> Result<(Vec<Share>, Unit), String> {
    let program_id = kernel::crypto::program_id_to_string(&owner);
    let response: serde_json::Value =
        http_get_json(rpc, &format!("/program/asset/{asset}/balance/{program_id}"))?;
    let mut inputs = Vec::new();
    let mut total = Unit::ZERO;
    for share in response["shares"]
        .as_array()
        .ok_or("invalid program shares response")?
    {
        if inputs.len() == 256 {
            break;
        }
        inputs.push(
            share["share_id"]
                .as_str()
                .ok_or("invalid program share id")?
                .parse()
                .map_err(|_| "invalid program share id")?,
        );
        let value = share["amount"]
            .as_str()
            .ok_or("invalid program share amount")?
            .parse::<u128>()
            .map_err(|_| "invalid program share amount")?;
        total = total
            .checked_add(Unit::from_units(value))
            .ok_or("program amount overflow")?;
        if required.is_some_and(|r| total >= r) {
            break;
        }
    }
    if inputs.is_empty() || required.is_some_and(|r| total < r) {
        return Err("insufficient program asset balance within 256 shares; consolidate or wait for pending transactions to confirm".into());
    }
    Ok((inputs, total))
}

fn submit(args: &[String], wallet: LoadedWallet, call: ProgramCall) -> Result<(), String> {
    reject_manual_fee(args)?;
    extension::script::execute::decode_program(&call)
        .map_err(|e| format!("invalid ProgramCall: {e:?}"))?;
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let deposit = option(args, "--deposit")
        .map(parse_amount)
        .transpose()?
        .map_or(0, Zeno::as_zeno);
    let deposit_owner = if deposit > 0 {
        let (id, _) = kernel::program::vm_app::call_input(&call)
            .map_err(|_| "--deposit requires a VM call")?;
        Some(Owner::Program(id))
    } else {
        None
    };
    // Quote state growth using a signed envelope; the quote performs no mutation.
    let (inputs, _, _, change) = select_account_inputs_with_state_burn(
        rpc,
        &wallet,
        deposit.checked_add(1).ok_or("deposit plus fee overflow")?,
        1 + u64::from(deposit_owner.is_some()),
        0,
        0,
    )?;
    let mut outputs = if change > 0 {
        vec![CoinOutput::new(
            wallet.program_id(),
            Zeno::from_zeno(change),
        )]
    } else {
        vec![]
    };
    if let Some(owner) = deposit_owner {
        outputs.push(CoinOutput::to_owner(owner, Zeno::from_zeno(deposit)));
    }
    let payment = CoinTransition::coin_with_charges(
        wallet.program_id(),
        inputs,
        outputs,
        CoinCharges::new(Zeno::ONE),
    )
    .map_err(|e| e.to_string())?;
    let dummy = AuthorizedProgramEnvelope::Program(Box::new(
        wallet.0.sign_program_call(call.clone(), payment)?,
    ));
    let quote: serde_json::Value = http_post_bytes(
        rpc,
        "/program/quote",
        &canonical_bytes(&dummy).map_err(|e| e.to_string())?,
    )?;
    let growth = quote["created_state_weight"]
        .as_u64()
        .ok_or("invalid program quote response")?;
    let vm_fuel = if call.program == SystemProgramId::VM {
        quote["vm_fuel"]
            .as_u64()
            .filter(|fuel| *fuel <= kernel::program::vm::MAX_CALL_FUEL)
            .ok_or("invalid or missing VM fuel quote; use a node supporting VM quotes")?
    } else {
        0
    };
    let vm_created = quote["vm_created_coin_utxos"].as_u64().unwrap_or(0);
    let vm_consumed = quote["vm_consumed_coin_utxos"].as_u64().unwrap_or(0);
    let transaction = automatic_fee_transaction(|fee, archival| {
        let (inputs, _, _, change) = super::transaction::select_account_inputs_with_vm_state_burn(
            rpc,
            &wallet,
            fee.checked_add(vm_fuel)
                .and_then(|v| v.checked_add(deposit))
                .ok_or("fee plus VM fuel and deposit overflow")?,
            (1_u64 + u64::from(deposit_owner.is_some()))
                .checked_add(vm_created)
                .ok_or("VM output count overflow")?,
            growth,
            archival,
            vm_consumed,
        )?;
        let mut outputs = if change > 0 {
            vec![CoinOutput::new(
                wallet.program_id(),
                Zeno::from_zeno(change),
            )]
        } else {
            vec![]
        };
        if let Some(owner) = deposit_owner {
            outputs.push(CoinOutput::to_owner(owner, Zeno::from_zeno(deposit)));
        }
        let payment = CoinTransition::coin_with_charges(
            wallet.program_id(),
            inputs,
            outputs,
            CoinCharges::new(Zeno::from_zeno(fee)),
        )
        .map_err(|e| e.to_string())?;
        Ok(AuthorizedProgramEnvelope::Program(Box::new(
            wallet.0.sign_program_call(call.clone(), payment)?,
        )))
    })?;
    drop(wallet);
    submit_or_print_transaction(args, &transaction)
}

pub(super) fn command(command: &str, args: &[String]) -> Result<(), String> {
    if command == "program-account" {
        let id = option(args, "--program-id").ok_or("missing --program-id")?;
        let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
        let value: serde_json::Value = http_get_json(rpc, &format!("/program/account/{id}"))?;
        super::cli::print_human_json(&value);
        return Ok(());
    }
    if command == "program-deploy" {
        return super::deploy::deploy_program(args);
    }
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    if command == "program-info" {
        let value: serde_json::Value =
            http_get_json(rpc, &format!("/program/asset/{}", asset(args)?))?;
        super::cli::print_human_json(&value);
        return Ok(());
    }
    if command == "program-balance" {
        let owner = match option(args, "--program-id") {
            Some(v) => program_id_from_string(v).map_err(|e| e.to_string())?,
            None => {
                load_wallet(option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH))?.program_id()
            }
        };
        let value: serde_json::Value = http_get_json(
            rpc,
            &format!(
                "/program/asset/{}/balance/{}",
                asset(args)?,
                kernel::crypto::program_id_to_string(&owner)
            ),
        )?;
        super::cli::print_human_json(&value);
        return Ok(());
    }
    if !matches!(
        command,
        "program-register"
            | "program-mint"
            | "program-transfer"
            | "program-burn"
            | "program-consolidate"
            | "program-call"
    ) {
        return Err(format!("unknown program command {command}"));
    }
    let wallet = load_wallet(option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH))?;
    let call = match command {
        "program-call" => vm_call(args)?,
        "program-register" => {
            let name = normalize_asset_name(option(args, "--name").ok_or("missing --name")?)?;
            let max_supply = amount(args, "--max-supply")?;
            let initial_mint = amount(args, "--initial-mint")?;
            let authority = if has_flag(args, "--fixed-supply") {
                ProgramId::ZERO
            } else {
                wallet.program_id()
            };
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_nanos() as u64;
            let metadata = Metadata::new(
                name.clone(),
                max_supply,
                Owner::Program(wallet.program_id()),
                Owner::Program(authority),
            )
            .map_err(|e| e.to_string())?;
            let id = AssetContract::derive(&metadata, nonce).map_err(|e| e.to_string())?;
            let call = encode(
                AssetOpcode::Register,
                &Register {
                    name,
                    max_supply,
                    initial_mint,
                    mint_authority: Owner::Program(authority),
                    nonce,
                },
            )?;
            submit(args, wallet, call)?;
            println!("program asset: {id}");
            return Ok(());
        }
        "program-mint" => {
            let id = asset(args)?;
            let info: serde_json::Value = http_get_json(rpc, &format!("/program/asset/{id}"))?;
            let nonce = info["mint_nonce"]
                .as_u64()
                .ok_or("invalid mint nonce")?
                .checked_add(1)
                .ok_or("mint nonce exhausted")?;
            encode(
                AssetOpcode::Mint,
                &Mint {
                    asset: id,
                    nonce,
                    recipient: recipient(args)?,
                    amount: amount(args, "--amount")?,
                },
            )?
        }
        "program-transfer" | "program-consolidate" => {
            let id = asset(args)?;
            let required = if command == "program-consolidate" {
                None
            } else {
                Some(amount(args, "--amount")?)
            };
            let (inputs, total) = shares(rpc, wallet.program_id(), id, required)?;
            if command == "program-consolidate" && inputs.len() < 2 {
                return Err("program consolidation requires at least two shares".into());
            }
            let sent = required.unwrap_or(total);
            let to = if command == "program-consolidate" {
                Owner::Program(wallet.program_id())
            } else {
                recipient(args)?
            };
            let mut outputs = vec![AssetOutput::new(to, sent)];
            let change = total
                .checked_sub(sent)
                .ok_or("insufficient program balance")?;
            if !change.is_zero() {
                outputs.push(AssetOutput::new(
                    Owner::Program(wallet.program_id()),
                    change,
                ));
            }
            encode(
                AssetOpcode::Transfer,
                &Transfer {
                    asset: id,
                    inputs,
                    outputs,
                },
            )?
        }
        "program-burn" => {
            let id = asset(args)?;
            let burn = amount(args, "--amount")?;
            let (inputs, total) = shares(rpc, wallet.program_id(), id, Some(burn))?;
            encode(
                AssetOpcode::Burn,
                &Burn {
                    asset: id,
                    inputs,
                    amount: burn,
                    output: total
                        .checked_sub(burn)
                        .ok_or("insufficient program balance")?,
                },
            )?
        }
        _ => unreachable!(),
    };
    submit(args, wallet, call)
}

fn vm_call(args: &[String]) -> Result<ProgramCall, String> {
    let value = option(args, "--program-id").ok_or("missing --program-id")?;
    if value.len() != 64 {
        return Err("program id must contain exactly 64 hexadecimal characters".into());
    }
    let mut payload = hex::decode(value).map_err(|_| "invalid hexadecimal program id")?;
    let data = option(args, "--data")
        .map(hex::decode)
        .transpose()
        .map_err(|_| "invalid hexadecimal call data")?;
    if data
        .as_ref()
        .is_some_and(|v| v.len() > kernel::program::vm_app::MAX_DATA_BYTES)
    {
        return Err("call data exceeds 4096 bytes".into());
    }
    let opcode = if let Some(data) = data {
        payload.extend(data);
        1
    } else {
        0
    };
    Ok(ProgramCall {
        program: SystemProgramId::VM,
        opcode,
        payload,
    })
}

#[cfg(test)]
mod vm_call_tests {
    use super::*;

    #[test]
    fn vm_call_uses_exact_program_id_and_rejects_invalid_ids() {
        let id = "a7".repeat(32);
        let call = vm_call(&["--program-id".into(), id.clone()]).unwrap();
        assert_eq!(call.program, SystemProgramId::VM);
        assert_eq!(call.opcode, 0);
        assert_eq!(call.payload, vec![0xa7; 32]);
        assert!(extension::script::execute::decode_program(&call).is_ok());
        for value in [
            "".to_string(),
            "ab".repeat(31),
            "ab".repeat(33),
            "zz".repeat(32),
            format!("0x{id}"),
        ] {
            assert!(vm_call(&["--program-id".into(), value]).is_err());
        }
        assert!(vm_call(&[]).is_err());
    }
}

pub(super) fn normalize_asset_name(name: &str) -> Result<String, String> {
    let normalized = name.trim().to_string();
    if normalized.is_empty()
        || normalized.len() > extension::asset_program::asset::ASSET_NAME_MAX_LEN
        || !normalized
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
    {
        return Err(format!(
            "invalid asset name; use 1-{} printable ASCII characters",
            extension::asset_program::asset::ASSET_NAME_MAX_LEN
        ));
    }
    Ok(normalized)
}

pub(super) fn parse_asset_display_amount(value: &str, decimals: u8) -> Result<u128, String> {
    if value.is_empty() || value.starts_with('+') || value.starts_with('-') {
        return Err("use a non-negative decimal amount".into());
    }
    let mut parts = value.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("use digits with at most one decimal point".into());
    }
    let fraction = fraction.unwrap_or_default();
    if fraction.len() > decimals as usize || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("at most {decimals} fractional digits are allowed"));
    }
    let scale = 10_u128
        .checked_pow(decimals as u32)
        .ok_or_else(|| "decimal scale overflow".to_string())?;
    let whole = whole
        .parse::<u128>()
        .map_err(|_| "amount exceeds the u128 range".to_string())?;
    let fractional_units = if fraction.is_empty() {
        0
    } else {
        let fraction_value = fraction
            .parse::<u128>()
            .map_err(|_| "invalid fractional amount".to_string())?;
        fraction_value
            .checked_mul(10_u128.pow(decimals as u32 - fraction.len() as u32))
            .ok_or_else(|| "amount exceeds the u128 range".to_string())?
    };
    whole
        .checked_mul(scale)
        .and_then(|units| units.checked_add(fractional_units))
        .ok_or_else(|| "amount exceeds the u128 range".to_string())
}
