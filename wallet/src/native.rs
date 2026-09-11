use std::{
    fs,
    io::{self, Read, Write},
    net::TcpStream,
    path::Path,
    str::FromStr,
};

use kernel::native::coin::Output as CoinOutput;
use kernel::native::asset::Asset;
use kernel::{
    codec::canonical_bytes,
    consensus::{DECIMALS, StateTransitionWeight, XPQ, Zeno, account_key_state_weight},
    crypto::{Address, Signature, address_from_string},
    transaction::{
        AssetInstruction, AuthorizedAssetTransaction,
        AuthorizedSpendTransaction, AuthorizedTransaction,
        SpendIntent,
    },
};
use serde::Deserialize;
use wallet::{
    AccountWallet, account_wallet_file_bytes, account_wallet_from_bip39_mnemonic,
    account_wallet_from_file_bytes, generate_bip39_mnemonic, wallet_address_from_file_bytes,
};
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_WALLET_PATH: &str = "wallet.json";
const AUTOMATIC_FEE_ZENO_PER_BYTE: u64 = 1;
const MAX_FEE_CONVERGENCE_ROUNDS: usize = 8;

struct LoadedWallet(AccountWallet);

impl LoadedWallet {
    fn address(&self) -> Address {
        self.0.address
    }

    fn new_account_key_weight(&self, public_key_known: bool) -> Result<u64, String> {
        if public_key_known {
            Ok(0)
        } else {
            account_key_state_weight(&self.0.public_key).map_err(|error| error.to_string())
        }
    }

    fn sign_onchain_spend(
        &self,
        intent: SpendIntent,
        public_key_known: bool,
    ) -> Result<kernel::transaction::AuthorizedAccountIntent<SpendIntent>, String> {
        self.0.sign_account_intent(intent, public_key_known)
    }
}
#[cfg(feature = "mainnet")]
const DEFAULT_RPC_ADDR: &str = "127.0.0.1:6666";
#[cfg(feature = "testnet")]
const DEFAULT_RPC_ADDR: &str = "127.0.0.1:16666";
#[cfg(feature = "devnet")]
const DEFAULT_RPC_ADDR: &str = "127.0.0.1:26666";

#[derive(Deserialize)]
struct AccountResponse {
    next_height: u64,
    public_key_registered: bool,
    #[serde(rename = "utxo_snapshot")]
    _utxo_snapshot: String,
    utxos: Vec<AccountUtxo>,
    next_utxo_offset: Option<usize>,
    next_utxo_cursor: Option<String>,
}

#[derive(Deserialize)]
struct BalanceResponse {
    total: u64,
    reserved: u64,
    utxo_count: usize,
    #[serde(default)]
    assets: Vec<AccountAssetBalance>,
}

#[derive(Deserialize)]
struct NodeBurnResponse {
    total_burned: u64,
}

#[derive(Deserialize)]
struct AccountAssetBalance {
    asset: String,
    name: String,
    symbol: String,
    decimals: u8,
    max_supply: String,
    mint: String,
    #[serde(default)]
    shares: Vec<AccountAssetShare>,
}

#[derive(Deserialize)]
struct AccountAssetShare {
    share: String,
    amount: String,
    owner: serde_json::Value,
}

#[derive(Deserialize)]
struct AssetMetadataResponse {
    decimals: u8,
    mint_capability: Option<String>,
}

#[derive(Deserialize)]
struct AccountUtxo {
    id: String,
    amount: u64,
    reserved: bool,
}

#[derive(Deserialize)]
struct AddressHistoryResponse {
    address: String,
    tip_height: u64,
    activity_count: usize,
    emission_count: usize,
    activities: Vec<AddressActivity>,
}

#[derive(Deserialize)]
struct AddressActivity {
    height: u64,
    block_hash: String,
    hash: Option<String>,
    #[serde(rename = "type")]
    activity_type: String,
    direction: String,
    amount: u64,
    size_bytes: Option<usize>,
}

#[derive(Deserialize)]
struct SubmitTransactionResponse {
    hash: String,
}

const MAX_CONSOLIDATION_INPUTS: usize = 10_000;

pub fn run(mut args: Vec<String>) -> Result<(), String> {
    let result = match args.first().map(String::as_str) {
        None | Some("menu") | Some("interactive") => interactive_menu(),
        Some("new") => create_wallet(&args[1..]),
        Some("restore") => restore_wallet(&args[1..]),
        Some("address") => print_address(&args[1..]),
        Some("balance") => print_balance(&args[1..]),
        Some("history") => print_history(&args[1..]),
        Some("utxos") | Some("utxo-tracker") => print_utxo_tracker(&args[1..]),
        Some("sign-spend") => sign_spend(&args[1..]),
        Some("consolidate") => consolidate_coin_utxos(&args[1..]),
        Some("asset-register") => asset_register(&args[1..]),
        Some("asset-mint") => asset_mint(&args[1..]),
        Some("asset-burn") => asset_burn(&args[1..]),
        Some("asset-transfer") => asset_transfer(&args[1..]),
        Some("asset-info") => asset_info(&args[1..]),
        Some("asset-balance") => asset_balance(&args[1..]),
        Some("version") | Some("--version") | Some("-V") => {
            println!("wallet {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("help") | Some("--help") | Some("-h") => {
            print_help();
            Ok(())
        }
        Some(command) => Err(format!("unknown command `{command}`")),
    };
    args.zeroize();
    result
}

fn asset_register(args: &[String]) -> Result<(), String> {
    let name = normalize_asset_name(option(args, "--name").ok_or("missing --name")?)?;
    let symbol = normalize_asset_symbol(option(args, "--symbol").ok_or("missing --symbol")?)?;
    let decimals = option(args, "--decimals")
        .ok_or("missing --decimals")?
        .parse::<u8>()
        .map_err(|_| "invalid --decimals")?;
    let max_supply = parse_asset_amount(args, "--max-supply", decimals)?;
    let initial_mint = parse_asset_amount(args, "--initial-mint", decimals)?;
    let authority = load_wallet(option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH))?.address();
    let mint_authority = if has_flag(args, "--fixed-supply") {
        Address::ZERO
    } else {
        authority
    };
    let asset = Asset::derive(
        &kernel::native::asset::AssetMetadata::new(
            name.clone(),
            symbol.clone(),
            decimals,
            max_supply,
            authority,
            mint_authority,
        )
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    submit_asset_instruction(
        args,
        AssetInstruction::Register {
            name,
            symbol,
            decimals,
            max_supply,
            initial_mint,
            mint_authority,
        },
    )?;
    println!("asset: {asset}");
    Ok(())
}

fn normalize_asset_name(name: &str) -> Result<String, String> {
    let normalized = name.trim().to_string();
    if normalized.is_empty()
        || normalized.len() > kernel::native::asset::ASSET_NAME_MAX_LEN
        || !normalized
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
    {
        return Err(format!(
            "invalid asset name; use 1-{} printable ASCII characters",
            kernel::native::asset::ASSET_NAME_MAX_LEN
        ));
    }
    Ok(normalized)
}

fn normalize_asset_symbol(symbol: &str) -> Result<String, String> {
    let normalized = symbol.to_ascii_uppercase();
    if normalized.is_empty()
        || normalized.len() > kernel::native::asset::ASSET_SYMBOL_MAX_LEN
        || !normalized
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(format!(
            "invalid asset symbol; use 1-{} ASCII letters A-Z or digits",
            kernel::native::asset::ASSET_SYMBOL_MAX_LEN
        ));
    }
    Ok(normalized)
}

fn asset_mint(args: &[String]) -> Result<(), String> {
    let asset = parse_asset(args)?;
    let metadata = asset_metadata(args, asset)?;
    let capability = metadata
        .mint_capability
        .ok_or("asset has no active mint capability")?
        .parse()
        .map_err(|_| "node returned an invalid mint capability id")?;
    submit_asset_instruction(
        args,
        AssetInstruction::Mint {
            asset,
            capability,
            recipient: asset_recipient(args)?,
            amount: parse_asset_amount(args, "--amount", metadata.decimals)?,
        },
    )
}

fn asset_burn(args: &[String]) -> Result<(), String> {
    let wallet = load_wallet(option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH))?;
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let asset = parse_asset(args)?;
    let amount = parse_asset_amount(args, "--amount", asset_decimals(args, asset)?)?;
    let (inputs, total) = select_asset_inputs(rpc, wallet.address(), asset, amount.as_units())?;
    if total != amount.as_units() {
        return Err("asset burn amount must exactly match selectable shares; transfer first to split a share".into());
    }
    submit_asset_instruction(args, AssetInstruction::Burn { asset, inputs })
}

fn asset_transfer(args: &[String]) -> Result<(), String> {
    submit_asset_spend(args, asset_recipient(args)?)
}

fn asset_recipient(args: &[String]) -> Result<Address, String> {
    address_from_string(option(args, "--to").ok_or("missing --to")?)
        .map_err(|error| error.to_string())
}

fn submit_asset_spend(args: &[String], recipient: Address) -> Result<(), String> {
    reject_manual_fee(args)?;
    let wallet = load_wallet(option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH))?;
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let asset = parse_asset(args)?;
    let amount = parse_asset_amount(args, "--amount", asset_decimals(args, asset)?)?;
    let (inputs, total) = select_asset_inputs(rpc, wallet.address(), asset, amount.as_units())?;
    let mut outputs = vec![kernel::native::asset::Output { recipient, amount }];
    if total > amount.as_units() {
        outputs.push(kernel::native::asset::Output {
            recipient: wallet.address(),
            amount: kernel::native::asset::Unit::from_units(total - amount.as_units()),
        });
    }
    let public_key_known = account_public_key_registered(rpc, &wallet);
    let spend = wallet.sign_onchain_spend(
        SpendIntent::asset(wallet.address(), asset, inputs, outputs.clone())
            .map_err(|e| e.to_string())?,
        public_key_known,
    )?;
    let asset_weight = outputs.iter().try_fold(0_u64, |weight, output| {
        kernel::native::asset::checked_asset_entry_weight(
            weight,
            32,
            &kernel::native::asset::AssetShare {
                parent: asset,
                amount: output.amount,
            },
        )
        .map_err(|e| format!("calculate asset state weight: {e:?}"))
    })?;
    let transaction = automatic_fee_transaction(|fee, archival_burn| {
        let (coin_inputs, _, _state_burn, change) = select_account_inputs_with_state_burn(
            rpc,
            &wallet,
            fee,
            1,
            asset_weight,
            archival_burn,
        )?;
        let mut fee_outputs = Vec::new();
        if change > 0 {
            fee_outputs.push(CoinOutput::new(wallet.address(), Zeno::from_zeno(change)));
        }
        fee_outputs.push(CoinOutput::block_miner(Zeno::from_zeno(fee)));
        let payment = wallet.sign_onchain_spend(
            SpendIntent::coin(wallet.address(), coin_inputs, fee_outputs)
                .map_err(|e| e.to_string())?,
            public_key_known,
        )?;
        Ok(AuthorizedTransaction::Spend(Box::new(
            AuthorizedSpendTransaction {
                spend: spend.clone(),
                payment: Some(payment),
            },
        )))
    })?;
    submit_or_print_transaction(args, &transaction)
}

fn select_asset_inputs(
    rpc: &str,
    owner: Address,
    asset: Asset,
    required: u128,
) -> Result<(Vec<kernel::native::asset::Share>, u128), String> {
    let address = kernel::crypto::address_to_string(&owner);
    let balance: BalanceResponse = http_get_json(rpc, &format!("/balance/{address}"))?;
    let entry = balance
        .assets
        .into_iter()
        .find(|entry| entry.asset == asset.to_string())
        .ok_or("wallet has no shares for this asset")?;
    let mut inputs = Vec::new();
    let mut total = 0_u128;
    for share in entry.shares {
        inputs.push(
            share
                .share
                .parse()
                .map_err(|_| "node returned an invalid asset share id")?,
        );
        total = total
            .checked_add(
                share
                    .amount
                    .parse::<u128>()
                    .map_err(|_| "node returned an invalid asset share amount")?,
            )
            .ok_or("asset share amount overflow")?;
        if total >= required {
            break;
        }
    }
    if total < required {
        return Err("insufficient asset balance".into());
    }
    Ok((inputs, total))
}

fn asset_info(args: &[String]) -> Result<(), String> {
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let response: serde_json::Value =
        http_get_json(rpc, &format!("/asset/{}", parse_asset(args)?))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&response).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn asset_balance(args: &[String]) -> Result<(), String> {
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let address = match option(args, "--address") {
        Some(address) => address_from_string(address).map_err(|error| error.to_string())?,
        None => load_wallet(option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH))?.address(),
    };
    let response: serde_json::Value = http_get_json(
        rpc,
        &format!(
            "/asset/{}/balance/{}",
            parse_asset(args)?,
            kernel::crypto::address_to_string(&address)
        ),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&response).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn submit_asset_instruction(args: &[String], instruction: AssetInstruction) -> Result<(), String> {
    reject_manual_fee(args)?;
    let wallet = load_wallet(option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH))?;
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let public_key_known = account_public_key_registered(rpc, &wallet);
    let call = wallet.0.sign_asset_intent(instruction, public_key_known)?;
    let created_state_weight = call
        .intent
        .created_state_weight()
        .map_err(|error| format!("calculate asset state weight: {error:?}"))?;
    let transaction = automatic_fee_transaction(|fee, archival_burn| {
        let (inputs, _total, _state_burn, change) = select_account_inputs_with_state_burn(
            rpc,
            &wallet,
            fee,
            1,
            created_state_weight,
            archival_burn,
        )?;
        let mut outputs = Vec::new();
        if change > 0 {
            outputs.push(CoinOutput::new(wallet.address(), Zeno::from_zeno(change)));
        }
        outputs.push(CoinOutput::block_miner(Zeno::from_zeno(fee)));
        let fee_intent = SpendIntent::coin(wallet.address(), inputs, outputs)
            .map_err(|error| error.to_string())?;
        let fee = wallet.sign_onchain_spend(fee_intent, public_key_known)?;
        Ok(AuthorizedTransaction::Asset(Box::new(
            AuthorizedAssetTransaction {
                call: call.clone(),
                payment: fee,
            },
        )))
    })?;
    submit_or_print_transaction(args, &transaction)
}

fn parse_asset(args: &[String]) -> Result<Asset, String> {
    option(args, "--asset")
        .ok_or_else(|| "missing --asset".to_string())?
        .parse::<Asset>()
        .map_err(|_| "invalid --asset id".to_string())
}

fn asset_decimals(args: &[String], asset: Asset) -> Result<u8, String> {
    Ok(asset_metadata(args, asset)?.decimals)
}

fn asset_metadata(args: &[String], asset: Asset) -> Result<AssetMetadataResponse, String> {
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    http_get_json(rpc, &format!("/asset/{asset}"))
}

fn parse_asset_amount(
    args: &[String],
    option_name: &str,
    decimals: u8,
) -> Result<kernel::native::asset::Unit, String> {
    let value = option(args, option_name).ok_or_else(|| format!("missing {option_name}"))?;
    parse_asset_display_amount(value, decimals)
        .map(kernel::native::asset::Unit::from_units)
        .map_err(|error| format!("invalid {option_name}: {error}"))
}

fn parse_asset_display_amount(value: &str, decimals: u8) -> Result<u128, String> {
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

fn format_asset_amount(value: &str, decimals: u8, symbol: &str) -> Result<String, String> {
    let units = value
        .parse::<u128>()
        .map_err(|_| "node returned an invalid asset amount".to_string())?;
    if decimals == 0 {
        return Ok(format!("{units} {symbol}"));
    }
    let scale = 10_u128.pow(decimals as u32);
    let whole = units / scale;
    let fraction = units % scale;
    let width = decimals as usize;
    Ok(format!("{whole}.{fraction:0width$} {symbol}"))
}

fn interactive_menu() -> Result<(), String> {
    loop {
        println!();
        println!("XPARQ Wallet");
        println!("1. Create Wallet");
        println!("2. Import Wallet");
        println!("3. Show Address");
        println!("4. Show Balance");
        println!("5. Transaction History");
        println!("6. UTXO");
        println!("7. Transfer");
        println!("8. Consolidate UTXOs");
        println!("9. Explorer");
        println!("10. Assets");
        println!("11. Exit");

        match prompt("Select")?.as_str() {
            "1" => {
                let path = prompt_default("Wallet file", DEFAULT_WALLET_PATH)?;
                let words = prompt_default("Mnemonic words (12 or 24)", "12")?;
                let account = prompt_signature_account()?;
                let mut args = vec!["--wallet".into(), path, "--words".into(), words];
                args.extend(["--account".into(), account]);
                create_wallet(&args)?;
            }
            "2" => {
                let path = prompt_default("Wallet file", DEFAULT_WALLET_PATH)?;
                let phrase = prompt("Mnemonic")?;
                let account = prompt_signature_account()?;
                let mut args = vec!["--wallet".into(), path, "--mnemonic".into(), phrase];
                args.extend(["--account".into(), account]);
                restore_wallet(&args)?;
            }
            "3" => {
                let path = prompt_default("Wallet file", DEFAULT_WALLET_PATH)?;
                print_address(&["--wallet".into(), path])?;
            }
            "4" => {
                let path = prompt_default("Wallet file", DEFAULT_WALLET_PATH)?;
                let rpc = prompt_default("RPC", DEFAULT_RPC_ADDR)?;
                print_balance(&["--wallet".into(), path, "--rpc".into(), rpc])?;
            }
            "5" => interactive_wallet_query(print_history)?,
            "6" => interactive_wallet_query(print_utxo_tracker)?,
            "7" => interactive_spend()?,
            "8" => interactive_wallet_query(consolidate_coin_utxos)?,
            "9" => interactive_block_explorer()?,
            "10" => interactive_assets()?,
            "11" | "exit" | "quit" => return Ok(()),
            choice => println!("Unknown selection `{choice}`"),
        }
    }
}

fn interactive_assets() -> Result<(), String> {
    println!();
    println!("XPARQ Assets");
    println!("1. Create");
    println!("2. Mint");
    println!("3. Transfer");
    println!("4. Burn");
    println!("5. Info");
    println!("6. Balance");
    println!("7. Back");

    match prompt("Select")?.as_str() {
        "1" => {
            let wallet_rpc_args = interactive_asset_wallet_rpc()?;
            let name = prompt("Asset Name")?;
            let symbol = prompt("Asset Symbol")?;
            let decimals = prompt_default("Decimals", "0")?;
            let max_supply = prompt("Maximum Supply")?;
            let mint_amount = prompt("Initial Mint")?;

            let mut register_args = wallet_rpc_args.clone();
            register_args.extend(["--name".into(), name]);
            register_args.extend(["--symbol".into(), symbol]);
            register_args.extend(["--decimals".into(), decimals]);
            register_args.extend(["--max-supply".into(), max_supply]);
            register_args.extend(["--initial-mint".into(), mint_amount]);
            asset_register(&register_args)
        }
        "2" => {
            let mut args = interactive_asset_wallet_rpc()?;
            args.extend(["--asset".into(), prompt("Asset Hash")?]);
            args.extend(interactive_asset_recipient()?);
            args.extend(["--amount".into(), prompt("Asset amount")?]);
            asset_mint(&args)
        }
        "3" => {
            let mut args = interactive_asset_wallet_rpc()?;
            args.extend(["--asset".into(), prompt("Asset Hash")?]);
            args.extend(interactive_asset_recipient()?);
            args.extend(["--amount".into(), prompt("Asset amount")?]);
            asset_transfer(&args)
        }
        "4" => {
            let mut args = interactive_asset_wallet_rpc()?;
            args.extend(["--asset".into(), prompt("Asset Hash")?]);
            args.extend(["--amount".into(), prompt("Asset amount")?]);
            asset_burn(&args)
        }
        "5" => {
            let args = vec![
                "--asset".into(),
                prompt("Asset Hash")?,
                "--rpc".into(),
                prompt_default("RPC", DEFAULT_RPC_ADDR)?,
            ];
            asset_info(&args)
        }
        "6" => {
            let args = vec![
                "--asset".into(),
                prompt("Asset ID")?,
                "--wallet".into(),
                prompt_default("Wallet file", DEFAULT_WALLET_PATH)?,
                "--rpc".into(),
                prompt_default("RPC", DEFAULT_RPC_ADDR)?,
            ];
            asset_balance(&args)
        }
        "7" | "back" => Ok(()),
        choice => Err(format!("unknown asset selection `{choice}`")),
    }
}

fn interactive_asset_recipient() -> Result<[String; 2], String> {
    let recipient = prompt("Recipient address")?;
    address_from_string(&recipient).map_err(|error| error.to_string())?;
    Ok(["--to".into(), recipient])
}

fn interactive_asset_wallet_rpc() -> Result<Vec<String>, String> {
    Ok(vec![
        "--wallet".into(),
        prompt_default("Wallet file", DEFAULT_WALLET_PATH)?,
        "--rpc".into(),
        prompt_default("RPC", DEFAULT_RPC_ADDR)?,
    ])
}

fn prompt_signature_account() -> Result<String, String> {
    loop {
        let value = prompt_default(
            "Signature account (mldsa44, mldsa65, mldsa87, falcon512, falcon1024)",
            "mldsa44",
        )?;
        if value.parse::<Signature>().is_ok() {
            return Ok(value);
        }
        println!("Unknown signature account `{value}`");
    }
}

fn interactive_wallet_query(query: fn(&[String]) -> Result<(), String>) -> Result<(), String> {
    let path = prompt_default("Wallet file", DEFAULT_WALLET_PATH)?;
    let rpc = prompt_default("RPC", DEFAULT_RPC_ADDR)?;
    query(&["--wallet".into(), path, "--rpc".into(), rpc])
}

fn interactive_spend() -> Result<(), String> {
    let rpc = prompt_default("RPC", DEFAULT_RPC_ADDR)?;
    let recipient = prompt("Recipient Address")?;
    address_from_string(&recipient).map_err(|error| error.to_string())?;
    let mut args = vec![
        "--to".into(),
        recipient,
        "--amount".into(),
        prompt("XPQ amount")?,
        "--rpc".into(),
        rpc,
    ];
    args.extend([
        "--wallet".into(),
        prompt_default("Wallet file", DEFAULT_WALLET_PATH)?,
    ]);
    sign_spend(&args)
}

fn interactive_block_explorer() -> Result<(), String> {
    let rpc = prompt_default("RPC", DEFAULT_RPC_ADDR)?;
    println!("1. Address activity");
    println!("2. Transaction by Hash");
    println!("3. Latest blocks");
    println!("4. Block by height");
    let response: serde_json::Value = match prompt("Select")?.as_str() {
        "1" => {
            let address = prompt("Address")?;
            address_from_string(&address).map_err(|_| "invalid address".to_string())?;
            http_get_json(&rpc, &format!("/explorer/address/{address}"))?
        }
        "2" => {
            let hash = prompt("Hash")?;
            if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err("Tx Hash must be 64 hexadecimal characters".into());
            }
            http_get_json(&rpc, &format!("/explorer/transaction/{hash}"))?
        }
        "3" => http_get_json(&rpc, "/blocks/latest")?,
        "4" => {
            let height = prompt("Block height")?;
            if height.parse::<u64>().is_err() {
                return Err("block height must be an unsigned integer".into());
            }
            http_get_json(&rpc, &format!("/block/{height}"))?
        }
        choice => return Err(format!("unknown explorer selection `{choice}`")),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&response).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn prompt(label: &str) -> Result<String, String> {
    print!("{label}: ");
    io::stdout().flush().map_err(|error| error.to_string())?;
    let mut value = String::new();
    io::stdin()
        .read_line(&mut value)
        .map_err(|error| format!("failed to read input: {error}"))?;
    Ok(value.trim().to_string())
}

fn prompt_default(label: &str, default: &str) -> Result<String, String> {
    let value = prompt(&format!("{label} [{default}]"))?;
    Ok(if value.is_empty() {
        default.to_string()
    } else {
        value
    })
}

fn create_wallet(args: &[String]) -> Result<(), String> {
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let words = option(args, "--words")
        .unwrap_or("12")
        .parse::<usize>()
        .map_err(|_| "--words must be 12 or 24".to_string())?;
    let mnemonic = generate_bip39_mnemonic(words)?;
    let account = signature_account_option(args)?.unwrap_or(Signature::MlDsa44);
    let mut wallet = account_wallet_from_bip39_mnemonic(&mnemonic, account)?;
    wallet.mnemonic = Some(mnemonic.to_string());
    let address = wallet.address;
    write_account_wallet(path, &wallet)?;
    println!("signature_account: {account}");
    println!("address: {}", kernel::crypto::address_to_string(&address));
    println!("mnemonic: {}", mnemonic.as_str());
    println!("wallet: {path}");
    Ok(())
}

fn restore_wallet(args: &[String]) -> Result<(), String> {
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let phrase = option(args, "--mnemonic").ok_or("missing --mnemonic")?;
    let account = signature_account_option(args)?.unwrap_or(Signature::MlDsa44);
    let mut wallet = account_wallet_from_bip39_mnemonic(phrase, account)?;
    wallet.mnemonic = Some(phrase.to_string());
    let address = wallet.address;
    write_account_wallet(path, &wallet)?;
    println!("signature_account: {account}");
    println!("address: {}", kernel::crypto::address_to_string(&address));
    println!("wallet: {path}");
    Ok(())
}

fn signature_account_option(args: &[String]) -> Result<Option<Signature>, String> {
    option(args, "--account")
        .map(|value| {
            value.parse::<Signature>().map_err(|_| {
                "invalid --account; use mldsa44, mldsa65, mldsa87, falcon512, or falcon1024"
                    .to_string()
            })
        })
        .transpose()
}

fn print_address(args: &[String]) -> Result<(), String> {
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let bytes =
        Zeroizing::new(fs::read(path).map_err(|error| format!("failed to read {path}: {error}"))?);
    let address = wallet_address_from_file_bytes(&bytes)?;
    println!("{}", kernel::crypto::address_to_string(&address));
    Ok(())
}

fn print_balance(args: &[String]) -> Result<(), String> {
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let bytes =
        Zeroizing::new(fs::read(path).map_err(|error| format!("failed to read {path}: {error}"))?);
    let address = kernel::crypto::address_to_string(&wallet_address_from_file_bytes(&bytes)?);
    let balance: BalanceResponse = http_get_json(rpc, &format!("/balance/{address}"))?;
    let burn: NodeBurnResponse = http_get_json(rpc, "/status")?;

    println!("Address: {address}");
    println!("Available: {}", format_amount(balance.total));
    println!("Reserved: {}", format_amount(balance.reserved));
    println!("UTXOs: {}", balance.utxo_count);
    println!("Total Burned: {}", format_amount(burn.total_burned));
    println!("Assets: {}", balance.assets.len());
    for asset in &balance.assets {
        let max_supply = format_asset_amount(&asset.max_supply, asset.decimals, &asset.symbol)?;
        let mint = format_asset_amount(&asset.mint, asset.decimals, &asset.symbol)?;
        println!(
            "- asset: {} name: {} symbol: {} decimals: {} max_supply: {} mint: {} shares: {}",
            asset.asset,
            asset.name,
            asset.symbol,
            asset.decimals,
            max_supply,
            mint,
            asset.shares.len(),
        );
        for share in &asset.shares {
            let amount = format_asset_amount(&share.amount, asset.decimals, &asset.symbol)?;
            println!(
                "  - share: {} amount: {} owner: {}",
                share.share, amount, share.owner
            );
        }
    }
    Ok(())
}

fn print_history(args: &[String]) -> Result<(), String> {
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let bytes =
        Zeroizing::new(fs::read(path).map_err(|error| format!("failed to read {path}: {error}"))?);
    let address = kernel::crypto::address_to_string(&wallet_address_from_file_bytes(&bytes)?);
    let mut history: AddressHistoryResponse = http_get_json(
        rpc,
        &format!("/explorer/address/{address}?include_emissions=false"),
    )?;

    println!("address: {}", history.address);
    println!("tip height: {}", history.tip_height);
    let emission_count = history.emission_count;
    history
        .activities
        .retain(|activity| activity.hash.is_some());
    println!("transactions: {}", history.activity_count);
    println!("emissions hidden: {emission_count}");
    if history.activities.is_empty() {
        println!("no canonical transaction history");
        return Ok(());
    }
    for activity in history.activities {
        let confirmations = history
            .tip_height
            .saturating_sub(activity.height)
            .saturating_add(1);
        println!(
            "- height={} confirmations={} direction={} type={} amount={} size={} bytes tx={} block={}",
            activity.height,
            confirmations,
            activity.direction,
            activity.activity_type,
            format_amount(activity.amount),
            activity.size_bytes.unwrap_or(0),
            activity.hash.as_deref().unwrap_or("emission"),
            activity.block_hash,
        );
    }
    Ok(())
}

fn print_utxo_tracker(args: &[String]) -> Result<(), String> {
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let bytes =
        Zeroizing::new(fs::read(path).map_err(|error| format!("failed to read {path}: {error}"))?);
    let address = kernel::crypto::address_to_string(&wallet_address_from_file_bytes(&bytes)?);
    let account = fetch_account(rpc, &address)?;

    println!("address: {address}");
    println!("next height: {}", account.next_height);
    println!("utxos: {}", account.utxos.len());
    let mut utxos = account.utxos.iter().collect::<Vec<_>>();
    utxos.sort_by(|left, right| left.id.cmp(&right.id));
    for utxo in utxos {
        println!(
            "- utxo: {}  {}",
            utxo.id,
            format_amount(utxo.amount),
        );
    }
    Ok(())
}

fn sign_spend(args: &[String]) -> Result<(), String> {
    reject_manual_fee(args)?;
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let recipient = option(args, "--to")
        .map(|value| address_from_string(value).map_err(|error| error.to_string()))
        .transpose()?;
    let recipient = recipient.ok_or("missing --to")?;
    let amount = parse_amount(option(args, "--amount").ok_or("missing --amount")?)?;
    let inputs = repeated_options(args, "--input")
        .into_iter()
        .map(kernel::native::coin::XPQ::from_str)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid --input coin id".to_string())?;
    let wallet = load_wallet(path)?;
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let known = account_public_key_registered(rpc, &wallet);
    let explicit_change = option(args, "--change").map(parse_amount).transpose()?;
    let change_target = option(args, "--change-to")
        .map(|address| address_from_string(address).map_err(|error| error.to_string()))
        .transpose()?;
    if inputs.is_empty() && (explicit_change.is_some() || change_target.is_some()) {
        return Err("automatic input selection also calculates change automatically".into());
    }
    let transaction = automatic_fee_transaction(|fee, archival_burn| {
        let required = amount
            .as_zeno()
            .checked_add(fee)
            .ok_or("transaction amount plus fee overflow")?;
        let (selected, change, _state_burn, change_address) = if inputs.is_empty() {
            let (selected, _total, state_burn, change) =
                select_account_inputs_with_state_burn(rpc, &wallet, required, 2, 0, archival_burn)?;
            (selected, change, state_burn, wallet.address())
        } else {
            let gross_change = explicit_change.map_or(0, Zeno::as_zeno);
            let created = 2_u64 + u64::from(gross_change > fee);
            let state_burn = StateTransitionWeight {
                created_coin_utxos: created,
                consumed_coin_utxos: u64::try_from(inputs.len())
                    .map_err(|_| "coin input count overflow")?,
                created_account_key_weight: wallet.new_account_key_weight(known)?,
                ..StateTransitionWeight::default()
            }
            .state_growth_burn()
            .map_err(|error| error.to_string())?
            .as_zeno()
            .checked_add(archival_burn)
            .ok_or("state burn plus transaction archival burn overflow")?;
            let change = gross_change
                .checked_sub(fee)
                .and_then(|change| change.checked_sub(state_burn))
                .ok_or("explicit change is smaller than the automatic fee and state burn")?;
            (
                inputs.clone(),
                change,
                state_burn,
                change_target.unwrap_or(wallet.address()),
            )
        };
        let mut outputs = vec![CoinOutput::new(recipient, amount)];
        if change > 0 {
            outputs.push(CoinOutput::new(change_address, Zeno::from_zeno(change)));
        }
        outputs.push(CoinOutput::block_miner(Zeno::from_zeno(fee)));
        let intent = SpendIntent::coin(wallet.address(), selected, outputs)
            .map_err(|error| error.to_string())?;
        let signed = wallet.sign_onchain_spend(intent, known)?;
        Ok(AuthorizedTransaction::Spend(Box::new(
            AuthorizedSpendTransaction {
                spend: signed,
                payment: None,
            },
        )))
    })?;
    submit_or_print_transaction(args, &transaction)
}

fn consolidate_coin_utxos(args: &[String]) -> Result<(), String> {
    reject_manual_fee(args)?;
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let wallet = load_wallet(path)?;
    let public_key_known = account_public_key_registered(rpc, &wallet);
    let mut candidates = account_input_candidates(rpc, &wallet)?;
    if candidates.len() < 2 {
        return Err("consolidation requires at least two available XPQ UTXOs".into());
    }
    candidates.sort_by(|left, right| {
        left.amount
            .cmp(&right.amount)
            .then_with(|| left.id.cmp(&right.id))
    });
    candidates.truncate(MAX_CONSOLIDATION_INPUTS);
    let inputs = candidates
        .iter()
        .map(|utxo| {
            kernel::native::coin::XPQ::from_str(&utxo.id)
                .map_err(|_| "node returned an invalid coin id".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let total = candidates.iter().try_fold(0_u64, |total, utxo| {
        total
            .checked_add(utxo.amount)
            .ok_or_else(|| "consolidation input amount overflow".to_string())
    })?;
    let consumed_coin_utxos =
        u64::try_from(inputs.len()).map_err(|_| "coin input count overflow")?;

    let transaction = automatic_fee_transaction(|fee, archival_burn| {
        let state_growth_burn = StateTransitionWeight {
            created_coin_utxos: 2,
            consumed_coin_utxos,
            created_account_key_weight: wallet.new_account_key_weight(public_key_known)?,
            ..StateTransitionWeight::default()
        }
        .state_growth_burn()
        .map_err(|error| error.to_string())?
        .as_zeno();
        let protocol_burn = archival_burn
            .checked_add(state_growth_burn)
            .ok_or("consolidation protocol burn overflow")?;
        let consolidated = total
            .checked_sub(fee)
            .and_then(|amount| amount.checked_sub(protocol_burn))
            .filter(|amount| *amount > 0)
            .ok_or("UTXO total is insufficient for consolidation fee and protocol burn")?;
        let outputs = vec![
            CoinOutput::new(wallet.address(), Zeno::from_zeno(consolidated)),
            CoinOutput::block_miner(Zeno::from_zeno(fee)),
        ];
        let intent = SpendIntent::coin(wallet.address(), inputs.clone(), outputs)
            .map_err(|error| error.to_string())?;
        let signed = wallet.sign_onchain_spend(intent, public_key_known)?;
        Ok(AuthorizedTransaction::Spend(Box::new(
            AuthorizedSpendTransaction {
                spend: signed,
                payment: None,
            },
        )))
    })?;
    submit_or_print_transaction(args, &transaction)
}

fn account_input_candidates(rpc: &str, wallet: &LoadedWallet) -> Result<Vec<AccountUtxo>, String> {
    let address = kernel::crypto::address_to_string(&wallet.address());
    let response = fetch_account(rpc, &address)?;
    let mut candidates = response
        .utxos
        .into_iter()
        .filter(|utxo| !utxo.reserved)
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        right
            .amount
            .cmp(&left.amount)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(candidates)
}

fn select_account_inputs_with_state_burn(
    rpc: &str,
    wallet: &LoadedWallet,
    base_required: u64,
    created_coin_without_change: u64,
    created_state_weight: u64,
    archival_burn: u64,
) -> Result<(Vec<kernel::native::coin::XPQ>, u64, u64, u64), String> {
    let created_account_key_weight =
        wallet.new_account_key_weight(account_public_key_registered(rpc, wallet))?;
    let candidates = account_input_candidates(rpc, wallet)?;
    let mut selected = Vec::new();
    let mut total = 0_u64;
    for utxo in candidates {
        selected.push(
            kernel::native::coin::XPQ::from_str(&utxo.id)
                .map_err(|_| "node returned an invalid coin id".to_string())?,
        );
        total = total
            .checked_add(utxo.amount)
            .ok_or_else(|| "selected input amount overflow".to_string())?;
        for has_change in [false, true] {
            let created = created_coin_without_change
                .checked_add(u64::from(has_change))
                .ok_or("state output count overflow")?;
            let ledger_burn = StateTransitionWeight {
                created_coin_utxos: created,
                consumed_coin_utxos: u64::try_from(selected.len())
                    .map_err(|_| "coin input count overflow")?,
                created_account_key_weight,
                created_state_weight,
                ..StateTransitionWeight::default()
            }
            .state_growth_burn()
            .map_err(|error| error.to_string())?
            .as_zeno();
            let burn = ledger_burn
                .checked_add(archival_burn)
                .ok_or("state burn plus transaction archival burn overflow")?;
            let required = base_required
                .checked_add(burn)
                .ok_or("required amount plus state burn overflow")?;
            let valid = if has_change {
                total > required
            } else {
                total == required
            };
            if valid {
                return Ok((selected, total, burn, total - required));
            }
        }
    }
    Err(format!(
        "insufficient available balance for amount, fee, and state burn: available {total} units"
    ))
}

fn account_public_key_registered(rpc: &str, wallet: &LoadedWallet) -> bool {
    let address = kernel::crypto::address_to_string(&wallet.address());
    http_get_json::<AccountResponse>(rpc, &format!("/account/{address}"))
        .map(|response| response.public_key_registered)
        .unwrap_or(false)
}

fn fetch_account(rpc: &str, address: &str) -> Result<AccountResponse, String> {
    let mut response: AccountResponse = http_get_json(rpc, &format!("/account/{address}"))?;
    while let Some(cursor) = response.next_utxo_cursor.clone() {
        let page: AccountResponse =
            http_get_json(rpc, &format!("/account/{address}?utxo_after={cursor}"))?;
        if page.utxos.is_empty() {
            return Err("node returned an invalid empty account page".into());
        }
        response.utxos.extend(page.utxos);
        response.next_utxo_offset = page.next_utxo_offset;
        response.next_utxo_cursor = page.next_utxo_cursor;
    }
    Ok(response)
}

fn http_get_json<T: for<'de> Deserialize<'de>>(rpc: &str, route: &str) -> Result<T, String> {
    let mut stream = TcpStream::connect(rpc).map_err(|error| format!("connect RPC: {error}"))?;
    write!(
        stream,
        "GET {route} HTTP/1.1\r\nHost: {rpc}\r\nConnection: close\r\n\r\n"
    )
    .map_err(|error| format!("write RPC request: {error}"))?;
    read_json_response(&mut stream)
}

fn read_json_response<T: for<'de> Deserialize<'de>>(stream: &mut TcpStream) -> Result<T, String> {
    let mut response = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(length) => {
                if response.len().saturating_add(length) > 1024 * 1024 {
                    return Err("RPC response exceeds maximum size".into());
                }
                response.extend_from_slice(&buffer[..length]);
            }
            Err(error)
                if error.kind() == io::ErrorKind::ConnectionReset && !response.is_empty() =>
            {
                break;
            }
            Err(error) => return Err(format!("read RPC response: {error}")),
        }
    }
    let separator = b"\r\n\r\n";
    let body_offset = response
        .windows(separator.len())
        .position(|window| window == separator)
        .map(|offset| offset + separator.len())
        .ok_or("invalid HTTP response")?;
    let status = std::str::from_utf8(&response[..body_offset])
        .map_err(|_| "invalid HTTP response headers")?;
    if !status.starts_with("HTTP/1.1 200 ") {
        let detail = serde_json::from_slice::<serde_json::Value>(&response[body_offset..])
            .ok()
            .and_then(|value| value.get("error")?.as_str().map(str::to_string))
            .or_else(|| {
                std::str::from_utf8(&response[body_offset..])
                    .ok()
                    .map(str::trim)
                    .filter(|body| !body.is_empty())
                    .map(str::to_string)
            });
        let status_line = status.lines().next().unwrap_or(status);
        return Err(format!(
            "node RPC rejected request: {status_line}{}",
            detail.map_or_else(String::new, |detail| format!(": {detail}"))
        ));
    }
    serde_json::from_slice(&response[body_offset..])
        .map_err(|error| format!("invalid node RPC response: {error}"))
}

fn reject_manual_fee(args: &[String]) -> Result<(), String> {
    if option(args, "--miner").is_some() {
        return Err(
            "--miner is no longer supported; wallet fee is automatic at 1 zeno/byte".into(),
        );
    }
    Ok(())
}

fn automatic_fee_transaction(
    mut build: impl FnMut(u64, u64) -> Result<AuthorizedTransaction, String>,
) -> Result<AuthorizedTransaction, String> {
    let mut fee = AUTOMATIC_FEE_ZENO_PER_BYTE;
    let mut archival_burn = 0_u64;
    for _ in 0..MAX_FEE_CONVERGENCE_ROUNDS {
        let transaction = build(fee, archival_burn)?;
        let size = canonical_bytes(&transaction)
            .map_err(|error| error.to_string())?
            .len();
        let required = u64::try_from(size)
            .ok()
            .and_then(|size| size.checked_mul(AUTOMATIC_FEE_ZENO_PER_BYTE))
            .ok_or("automatic transaction fee overflow")?;
        if required == fee && required == archival_burn {
            return Ok(transaction);
        }
        fee = required;
        archival_burn = required;
    }
    Err("automatic transaction fee did not converge".into())
}

fn submit_or_print_transaction(
    args: &[String],
    transaction: &AuthorizedTransaction,
) -> Result<(), String> {
    let transaction_bytes = canonical_bytes(transaction).map_err(|error| error.to_string())?;
    if has_flag(args, "--offline") {
        println!("transaction: {}", hex::encode(&transaction_bytes));
        eprintln!("byte: {}", transaction_bytes.len());
        return Ok(());
    }
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let response: SubmitTransactionResponse =
        http_post_bytes(rpc, "/transaction", &transaction_bytes)?;
    println!("hash: {}", response.hash);
    println!("byte: {}", transaction_bytes.len());
    Ok(())
}

fn http_post_bytes<T: for<'de> Deserialize<'de>>(
    rpc: &str,
    route: &str,
    body: &[u8],
) -> Result<T, String> {
    let mut stream = TcpStream::connect(rpc).map_err(|error| format!("connect RPC: {error}"))?;
    write!(
        stream,
        "POST {route} HTTP/1.1\r\nHost: {rpc}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .and_then(|_| stream.write_all(body))
    .map_err(|error| format!("write RPC request: {error}"))?;
    read_json_response(&mut stream)
}

fn load_wallet(path: &str) -> Result<LoadedWallet, String> {
    let bytes =
        Zeroizing::new(fs::read(path).map_err(|error| format!("failed to read {path}: {error}"))?);
    account_wallet_from_file_bytes(&bytes).map(LoadedWallet)
}

fn write_account_wallet(path: &str, wallet: &AccountWallet) -> Result<(), String> {
    let bytes = account_wallet_file_bytes(wallet)?;
    write_private_file_atomically(Path::new(path), &bytes)
}

fn write_private_file_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if path.exists() {
        return Err(format!("wallet already exists: {}", path.display()));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("wallet path has no UTF-8 filename: {}", path.display()))?;
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| format!("secure temporary wallet name failed: {error}"))?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", hex::encode(random)));

    write_new_file(&temporary, bytes)?;
    if let Err(error) = fs::hard_link(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(format!(
            "failed to atomically install wallet {}: {error}",
            path.display()
        ));
    }
    fs::remove_file(&temporary)
        .map_err(|error| format!("failed to remove {}: {error}", temporary.display()))?;
    sync_directory(parent)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("failed to create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("failed to write and sync {}: {error}", path.display()))
}

fn sync_directory(directory: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        fs::File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("failed to sync {}: {error}", directory.display()))?;
    }
    Ok(())
}

fn option<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].as_str())
}

fn repeated_options<'a>(args: &'a [String], name: &str) -> Vec<&'a str> {
    args.windows(2)
        .filter(|pair| pair[0] == name)
        .map(|pair| pair[1].as_str())
        .collect()
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|argument| argument == name)
}

fn parse_amount(value: &str) -> Result<Zeno, String> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > DECIMALS as usize || whole.is_empty() {
        return Err(format!("invalid XPQ amount `{value}`"));
    }
    let whole = whole
        .parse::<u64>()
        .map_err(|_| format!("invalid XPQ amount `{value}`"))?;
    let mut fraction_text = fraction.to_string();
    fraction_text.extend(std::iter::repeat_n('0', DECIMALS as usize - fraction.len()));
    let fraction = fraction_text
        .parse::<u64>()
        .map_err(|_| format!("invalid XPQ amount `{value}`"))?;
    let units = whole
        .checked_mul(XPQ::ZENO_PER_COIN)
        .and_then(|units| units.checked_add(fraction))
        .ok_or_else(|| "XPQ amount overflow".to_string())?;
    if units == 0 {
        return Err("XPQ amount must be positive".to_string());
    }
    Ok(Zeno::from_zeno(units))
}

fn format_amount(units: u64) -> String {
    let whole = units / XPQ::ZENO_PER_COIN;
    let fraction = units % XPQ::ZENO_PER_COIN;
    let width = DECIMALS as usize;
    format!("{whole}.{fraction:0width$} XPQ")
}

fn print_help() {
    println!(
        "wallet [menu]\nwallet new [--wallet PATH] [--words 12|24] [--account account]\nwallet restore --mnemonic PHRASE [--wallet PATH] [--account ACCOUNT]\nwallet address [--wallet PATH]\nwallet balance [--wallet PATH] [--rpc ADDRESS]\nwallet history [--wallet PATH] [--rpc ADDRESS]\nwallet utxos [--wallet PATH] [--rpc ADDRESS]\nwallet sign-spend [--input COIN_ID...] --to ADDRESS --amount XPQ [--change XPQ --change-to ADDRESS] [--rpc ADDRESS] [--wallet PATH] [--offline]\nwallet consolidate [--wallet PATH] [--rpc ADDRESS] [--offline]\nwallet version\n\nAll signature accounts are active from genesis. Signed transactions are submitted to node RPC automatically. Use --offline to print canonical transaction hex instead. The wallet automatically pays the node policy fee of 1 zeno per canonical transaction byte; manual --miner fee input is not supported. Consolidation merges selected XPQ UTXOs into one self-owned output and remains subject to archival burn and miner fee. History reports canonical address activity; UTXO tracker reads the wallet account endpoint and follows paginated UTXOs.\nRunning without a command opens the interactive menu.\nWithout --input, spend selects active XPQ inputs and calculates change through node RPC."
    );
    println!(
        "\nAsset commands:\nwallet asset-register --name NAME --symbol SYMBOL --decimals N --max-supply AMOUNT --initial-mint AMOUNT [--fixed-supply] [--wallet PATH] [--rpc ADDRESS]\nwallet asset-mint --asset Hash --to ADDRESS --amount AMOUNT [--wallet PATH] [--rpc ADDRESS]\nwallet asset-burn --asset Hash --amount AMOUNT [--wallet PATH] [--rpc ADDRESS]\nwallet asset-transfer --asset Hash --to ADDRESS --amount AMOUNT [--wallet PATH] [--rpc ADDRESS]\nwallet asset-info --asset Hash [--rpc ADDRESS]\nwallet asset-balance --asset Hash [--address ADDRESS | --wallet PATH] [--rpc ADDRESS]\n\nAsset amounts use the human decimal denomination declared by asset metadata. For decimals=8, 1.25 is encoded canonically as 125000000 Unit. Registration atomically credits the initial mint to the signing creator address."
    );
    println!(
        "\nPool commands:\nwallet pools [--rpc ADDRESS]\nwallet pool-info --pool HASH [--rpc ADDRESS]\nwallet pool-shares [--address ADDRESS | --wallet PATH] [--rpc ADDRESS]\nwallet pool-create --x PAIR --y PAIR --amount-x RAW --amount-y RAW --fee-units N [--wallet PATH] [--rpc ADDRESS] [--offline]\nwallet pool-add --pool HASH --amount-x RAW --amount-y RAW --minimum-liquidity RAW [--wallet PATH] [--rpc ADDRESS] [--offline]\nwallet pool-remove --share HASH --minimum-x RAW --minimum-y RAW [--wallet PATH] [--rpc ADDRESS] [--offline]\nwallet pool-swap --pool HASH --input PAIR --amount-in RAW --minimum-out RAW [--wallet PATH] [--rpc ADDRESS] [--offline]\n\nPAIR is `coin` or a 64-character asset ID. Pool quantities are raw base units. Pool funding consumes exact-value XPQ UTXOs or asset shares; fee and protocol burn are selected from separate XPQ inputs."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_symbol_is_normalized_and_rejects_non_ascii_punctuation() {
        assert_eq!(
            normalize_asset_name(" Test Asset "),
            Ok("Test Asset".into())
        );
        assert_eq!(normalize_asset_symbol("test"), Ok("TEST".into()));
        assert!(normalize_asset_symbol("test-asset").is_err());
        assert!(normalize_asset_symbol("").is_err());
        let args = vec!["--amount".into(), "1000000000000000.00000000".into()];
        assert_eq!(
            parse_asset_amount(&args, "--amount", 8),
            Ok(kernel::native::asset::Unit::from_units(
                100_000_000_000_000_000_000_000_u128
            ))
        );
        assert_eq!(parse_asset_display_amount("1.25", 8), Ok(125_000_000));
        assert_eq!(parse_asset_display_amount("1", 8), Ok(100_000_000));
        assert!(parse_asset_display_amount("1.000000001", 8).is_err());
        assert_eq!(
            format_asset_amount("125000000", 8, "TEST"),
            Ok("1.25000000 TEST".into())
        );
    }

    #[test]
    fn asset_recipient_accepts_address() {
        let address = Address::ZERO;
        let address_args = vec!["--to".into(), kernel::crypto::address_to_string(&address)];
        assert_eq!(asset_recipient(&address_args), Ok(address));

        assert!(asset_recipient(&[]).is_err());
    }

    #[test]
    fn transaction_submission_posts_canonical_bytes() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            while !request.ends_with(&[1, 2, 3, 4]) {
                let length = stream.read(&mut buffer).unwrap();
                assert!(length > 0 && request.len() + length <= 2048);
                request.extend_from_slice(&buffer[..length]);
            }
            assert!(request.starts_with(b"POST /transaction HTTP/1.1\r\n"));
            assert!(request.ends_with(&[1, 2, 3, 4]));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 85\r\nConnection: close\r\n\r\n{\"hash\":\"0000000000000000000000000000000000000000000000000000000000000000\"}",
                )
                .unwrap();
        });
        let response: SubmitTransactionResponse =
            http_post_bytes(&address.to_string(), "/transaction", &[1, 2, 3, 4]).unwrap();
        assert_eq!(response.hash, "0".repeat(64));
        server.join().unwrap();
    }

    #[test]
    fn wallet_file_is_atomically_created_as_owner_only() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "kernel-private-wallet-{}-{unique}",
            std::process::id()
        ));
        let path = directory.join("wallet.json");
        write_private_file_atomically(&path, b"secret mnemonic").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"secret mnemonic");
        assert!(write_private_file_atomically(&path, b"replace").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"secret mnemonic");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(fs::read_dir(&directory).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn utxo_status_and_amount_format_are_canonical() {
        let account = AccountResponse {
            next_height: 100,
            public_key_registered: false,
            _utxo_snapshot: "test-snapshot".into(),
            next_utxo_offset: None,
            next_utxo_cursor: None,
            utxos: vec![
                AccountUtxo {
                    id: "available-one".into(),
                    amount: 2 * XPQ::ZENO_PER_COIN,
                    reserved: false,
                },
                AccountUtxo {
                    id: "available-two".into(),
                    amount: 3 * XPQ::ZENO_PER_COIN,
                    reserved: false,
                },
                AccountUtxo {
                    id: "reserved".into(),
                    amount: XPQ::ZENO_PER_COIN,
                    reserved: true,
                },
            ],
        };

        assert_eq!(format_amount(2 * XPQ::ZENO_PER_COIN + 1), "2.000001 XPQ");
        assert_eq!(utxo_status(&account.utxos[0]), "available");
        assert_eq!(utxo_status(&account.utxos[1]), "available");
        assert_eq!(utxo_status(&account.utxos[2]), "reserved");
    }
}
