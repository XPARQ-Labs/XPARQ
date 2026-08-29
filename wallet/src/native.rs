use std::{
    collections::BTreeSet,
    fs,
    io::{self, Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    str::FromStr,
};

use serde::Deserialize;
use xparq::extension::asset::{AssetAction, AssetId};
use xparq::{
    codec::canonical_bytes,
    consensus::{Amount, COIN, DECIMALS, StateTransitionWeight},
    crypto::{Address, QCashPublicKey, SignatureProfile, address_from_string},
    ledger::{
        merge_qcash_output_id, redeem_qcash_change_output_id, split_qcash_output_id,
        withdraw_qcash_output_id,
    },
    qcash::{QCash, QCashFile, QCashSigningSeed, qcash_file_name, validate_qcash_file_name},
    transaction::{
        AuthorizedExtensionTransaction, AuthorizedQCashIntent, AuthorizedTransaction, MergeIntent,
        OnChainSpendIntent, QCashAuthorization, QCashIntent, QCashOutput, RedeemIntent,
        SpendOutput, SplitIntent, WithdrawIntent,
    },
};
use xparq_wallet::{
    ProfileWallet, generate_xparq_mnemonic, profile_wallet_file_bytes,
    profile_wallet_from_file_bytes, profile_wallet_from_xparq_mnemonic,
    wallet_address_from_file_bytes,
};
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_WALLET_PATH: &str = "wallet.json";
const AUTOMATIC_FEE_ZENO_PER_BYTE: u64 = 1;
const MAX_FEE_CONVERGENCE_ROUNDS: usize = 8;

struct LoadedWallet(ProfileWallet);

impl LoadedWallet {
    fn address(&self) -> Address {
        self.0.address
    }

    fn sign_onchain_spend(
        &self,
        intent: OnChainSpendIntent,
        public_key_known: bool,
    ) -> Result<xparq::transaction::AuthorizedAccountIntent<OnChainSpendIntent>, String> {
        self.0.sign_account_intent(intent, public_key_known)
    }

    fn sign_withdraw(
        &self,
        intent: WithdrawIntent,
        public_key_known: bool,
    ) -> Result<xparq::transaction::AuthorizedAccountIntent<WithdrawIntent>, String> {
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
    utxos: Vec<AccountUtxo>,
    next_utxo_offset: Option<usize>,
}

#[derive(Deserialize)]
struct BalanceResponse {
    total: u64,
    available: u64,
    reserved: u64,
    utxo_count: usize,
    #[serde(default)]
    assets: Vec<AccountAssetBalance>,
}

#[derive(Deserialize)]
struct AccountAssetBalance {
    asset_id: String,
    name: String,
    symbol: String,
    decimals: u8,
    balance: String,
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
    transaction_id: Option<String>,
    #[serde(rename = "type")]
    activity_type: String,
    direction: String,
    amount: u64,
    size_bytes: Option<usize>,
}

fn utxo_status(utxo: &AccountUtxo) -> &'static str {
    if utxo.reserved {
        "reserved"
    } else {
        "available"
    }
}

#[derive(Deserialize)]
struct SubmitTransactionResponse {
    transaction_id: String,
}

#[derive(Deserialize)]
struct AssetNonceResponse {
    nonce: u64,
}

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
        Some("sign-withdraw") => sign_withdraw(&args[1..]),
        Some("redeem") | Some("qcash-redeem") => redeem_qcash(&args[1..]),
        Some("split") | Some("qcash-split") => split_qcash(&args[1..]),
        Some("merge") | Some("qcash-merge") => merge_qcash(&args[1..]),
        Some("asset-register") => asset_register(&args[1..]),
        Some("asset-mint") => asset_mint(&args[1..]),
        Some("asset-burn") => asset_burn(&args[1..]),
        Some("asset-transfer") => asset_transfer(&args[1..]),
        Some("asset-info") => asset_info(&args[1..]),
        Some("asset-balance") => asset_balance(&args[1..]),
        Some("wasm-deploy") => wasm_deploy(&args[1..]),
        Some("wasm-info") => wasm_info(&args[1..]),
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
    let max_supply = parse_asset_amount(args, "--max-supply")?;
    let initial_mint = parse_asset_amount(args, "--initial-mint")?;
    let authority = load_wallet(option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH))?.address();
    let asset_id = AssetId::derive(authority, &symbol);
    submit_asset_action(
        args,
        AssetAction::Register {
            name,
            symbol,
            decimals,
            max_supply,
            initial_mint,
        },
    )?;
    println!("asset_id: {asset_id}");
    Ok(())
}

fn normalize_asset_name(name: &str) -> Result<String, String> {
    let normalized = name.trim().to_string();
    if normalized.is_empty()
        || normalized.len() > xparq::extension::asset::ASSET_NAME_MAX_LEN
        || !normalized
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
    {
        return Err(format!(
            "invalid token name; use 1-{} printable ASCII characters",
            xparq::extension::asset::ASSET_NAME_MAX_LEN
        ));
    }
    Ok(normalized)
}

fn normalize_asset_symbol(symbol: &str) -> Result<String, String> {
    let normalized = symbol.to_ascii_uppercase();
    if normalized.is_empty()
        || normalized.len() > xparq::extension::asset::ASSET_SYMBOL_MAX_LEN
        || !normalized
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(format!(
            "invalid token symbol; use 1-{} ASCII letters A-Z or digits",
            xparq::extension::asset::ASSET_SYMBOL_MAX_LEN
        ));
    }
    Ok(normalized)
}

fn asset_mint(args: &[String]) -> Result<(), String> {
    submit_asset_action(
        args,
        AssetAction::Mint {
            asset_id: parse_asset_id(args)?,
            recipient: address_option(args, "--to")?,
            amount: parse_asset_amount(args, "--amount")?,
        },
    )
}

fn asset_burn(args: &[String]) -> Result<(), String> {
    submit_asset_action(
        args,
        AssetAction::Burn {
            asset_id: parse_asset_id(args)?,
            amount: parse_asset_amount(args, "--amount")?,
        },
    )
}

fn asset_transfer(args: &[String]) -> Result<(), String> {
    submit_asset_action(
        args,
        AssetAction::Transfer {
            asset_id: parse_asset_id(args)?,
            recipient: address_option(args, "--to")?,
            amount: parse_asset_amount(args, "--amount")?,
        },
    )
}

fn asset_info(args: &[String]) -> Result<(), String> {
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let response: serde_json::Value =
        http_get_json(rpc, &format!("/asset/{}", parse_asset_id(args)?))?;
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
            parse_asset_id(args)?,
            xparq::crypto::address_to_string(&address)
        ),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&response).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn submit_asset_action(args: &[String], action: AssetAction) -> Result<(), String> {
    reject_manual_fee(args)?;
    let wallet = load_wallet(option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH))?;
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let address = xparq::crypto::address_to_string(&wallet.address());
    let nonce = http_get_json::<AssetNonceResponse>(rpc, &format!("/asset/nonce/{address}"))?.nonce;
    let call = wallet.0.sign_asset_call(action, nonce)?;
    let extension_created_weight = xparq::extension::asset::AssetCall::from_extension_call(&call)
        .and_then(|call| call.registration_metadata_weight())
        .map_err(|error| format!("calculate asset metadata state weight: {error:?}"))?;
    let public_key_known = account_public_key_registered(rpc, &wallet);
    let transaction = automatic_fee_transaction(|fee| {
        let (inputs, _total, state_burn, change) = select_account_inputs_with_state_burn(
            rpc,
            &wallet,
            fee,
            1,
            0,
            extension_created_weight,
        )?;
        let mut outputs = Vec::new();
        if change > 0 {
            outputs.push(SpendOutput::new(
                wallet.address(),
                Amount::from_zeno(change),
            ));
        }
        outputs.push(SpendOutput::block_miner(Amount::from_zeno(fee)));
        if state_burn > 0 {
            outputs.push(SpendOutput::burn(Amount::from_zeno(state_burn)));
        }
        let fee_intent = OnChainSpendIntent::new(wallet.address(), inputs, outputs)
            .map_err(|error| error.to_string())?;
        let fee = wallet.sign_onchain_spend(fee_intent, public_key_known)?;
        Ok(AuthorizedTransaction::Extension(Box::new(
            AuthorizedExtensionTransaction {
                call: call.clone(),
                fee,
            },
        )))
    })?;
    submit_or_print_transaction(args, &transaction)
}

fn wasm_deploy(args: &[String]) -> Result<(), String> {
    reject_manual_fee(args)?;
    let name = option(args, "--name").ok_or("missing --name")?.to_string();
    let module_path = option(args, "--wasm").ok_or("missing --wasm")?;
    let metadata = fs::metadata(module_path)
        .map_err(|error| format!("read WASM module metadata `{module_path}`: {error}"))?;
    if metadata.len() > xparq::extension::WASM_CODE_MAX_SIZE as u64 {
        return Err("WASM module exceeds the size limit".into());
    }
    let module = fs::read(module_path)
        .map_err(|error| format!("read WASM module `{module_path}`: {error}"))?;
    let wallet = load_wallet(option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH))?;
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let address = xparq::crypto::address_to_string(&wallet.address());
    let nonce = http_get_json::<AssetNonceResponse>(rpc, &format!("/wasm/nonce/{address}"))?.nonce;
    let call = wallet.0.sign_wasm_deploy_call(name, module, nonce)?;
    let extension_id = xparq::extension::WasmDeployCall::from_extension_call(&call)
        .map_err(|error| format!("decode signed WASM deploy call: {error:?}"))?
        .extension_id();
    let public_key_known = account_public_key_registered(rpc, &wallet);
    let transaction = automatic_fee_transaction(|fee| {
        let (inputs, _total, state_burn, change) =
            select_account_inputs_with_state_burn(rpc, &wallet, fee, 1, 0, 0)?;
        let mut outputs = Vec::new();
        if change > 0 {
            outputs.push(SpendOutput::new(
                wallet.address(),
                Amount::from_zeno(change),
            ));
        }
        outputs.push(SpendOutput::block_miner(Amount::from_zeno(fee)));
        if state_burn > 0 {
            outputs.push(SpendOutput::burn(Amount::from_zeno(state_burn)));
        }
        let fee_intent = OnChainSpendIntent::new(wallet.address(), inputs, outputs)
            .map_err(|error| error.to_string())?;
        let fee = wallet.sign_onchain_spend(fee_intent, public_key_known)?;
        Ok(AuthorizedTransaction::Extension(Box::new(
            AuthorizedExtensionTransaction {
                call: call.clone(),
                fee,
            },
        )))
    })?;
    submit_or_print_transaction(args, &transaction)?;
    println!("extension_id: {}", hex::encode(extension_id.as_bytes()));
    println!(
        "activation_delay_blocks: {}",
        xparq::extension::WASM_DEPLOY_ACTIVATION_DELAY
    );
    Ok(())
}

fn wasm_info(args: &[String]) -> Result<(), String> {
    let id = option(args, "--extension").ok_or("missing --extension")?;
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let response: serde_json::Value = http_get_json(rpc, &format!("/wasm/{id}"))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&response).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn parse_asset_id(args: &[String]) -> Result<AssetId, String> {
    option(args, "--asset")
        .ok_or_else(|| "missing --asset".to_string())?
        .parse::<AssetId>()
        .map_err(|_| "invalid --asset id".to_string())
}

fn parse_asset_amount(args: &[String], option_name: &str) -> Result<u128, String> {
    option(args, option_name)
        .ok_or_else(|| format!("missing {option_name}"))?
        .parse::<u128>()
        .map_err(|_| format!("invalid {option_name}; use integer base units"))
}

fn interactive_menu() -> Result<(), String> {
    loop {
        println!();
        println!("XPARQ Wallet");
        println!("1. Create wallet");
        println!("2. Restore wallet");
        println!("3. Show address");
        println!("4. Show balance");
        println!("5. Transaction history");
        println!("6. UTXO tracker");
        println!("7. Send XPQ");
        println!("8. Withdraw QCash");
        println!("9. Redeem QCash");
        println!("10. Split QCash");
        println!("11. Merge QCash");
        println!("12. Block explorer");
        println!("13. Assets");
        println!("14. Exit");

        match prompt("Select")?.as_str() {
            "1" => {
                let path = prompt_default("Wallet file", DEFAULT_WALLET_PATH)?;
                let words = prompt_default("Mnemonic words (12 or 24)", "12")?;
                let profile = prompt_signature_profile()?;
                let mut args = vec!["--wallet".into(), path, "--words".into(), words];
                args.extend(["--profile".into(), profile]);
                create_wallet(&args)?;
            }
            "2" => {
                let path = prompt_default("Wallet file", DEFAULT_WALLET_PATH)?;
                let phrase = prompt("Mnemonic")?;
                let profile = prompt_signature_profile()?;
                let mut args = vec!["--wallet".into(), path, "--mnemonic".into(), phrase];
                args.extend(["--profile".into(), profile]);
                restore_wallet(&args)?;
            }
            "3" => {
                let path = prompt_default("Wallet file", DEFAULT_WALLET_PATH)?;
                print_address(&["--wallet".into(), path])?;
            }
            "4" => {
                let path = prompt_default("Wallet file", DEFAULT_WALLET_PATH)?;
                let rpc = prompt_default("Node RPC address", DEFAULT_RPC_ADDR)?;
                print_balance(&["--wallet".into(), path, "--rpc".into(), rpc])?;
            }
            "5" => interactive_wallet_query(print_history)?,
            "6" => interactive_wallet_query(print_utxo_tracker)?,
            "7" => interactive_spend()?,
            "8" => interactive_withdraw()?,
            "9" => interactive_redeem()?,
            "10" => interactive_split()?,
            "11" => interactive_merge()?,
            "12" => interactive_block_explorer()?,
            "13" => interactive_assets()?,
            "14" | "exit" | "quit" => return Ok(()),
            choice => println!("Unknown selection `{choice}`"),
        }
    }
}

fn interactive_assets() -> Result<(), String> {
    println!();
    println!("XPARQ Assets");
    println!("1. Create asset");
    println!("2. Mint asset");
    println!("3. Transfer asset");
    println!("4. Burn asset");
    println!("5. Asset info");
    println!("6. Asset balance");
    println!("7. Back");

    match prompt("Select")?.as_str() {
        "1" => {
            let wallet_rpc_args = interactive_asset_wallet_rpc()?;
            let name = prompt("Token name")?;
            let symbol = prompt("Token symbol")?;
            let decimals = prompt_default("Decimals", "0")?;
            let max_supply = prompt("Maximum supply in base units")?;
            let mint_amount = prompt("Initial mint in base units")?;

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
            args.extend(["--asset".into(), prompt("Asset ID")?]);
            args.extend(["--to".into(), prompt("Recipient address")?]);
            args.extend(["--amount".into(), prompt("Amount in base units")?]);
            asset_mint(&args)
        }
        "3" => {
            let mut args = interactive_asset_wallet_rpc()?;
            args.extend(["--asset".into(), prompt("Asset ID")?]);
            args.extend(["--to".into(), prompt("Recipient address")?]);
            args.extend(["--amount".into(), prompt("Amount in base units")?]);
            asset_transfer(&args)
        }
        "4" => {
            let mut args = interactive_asset_wallet_rpc()?;
            args.extend(["--asset".into(), prompt("Asset ID")?]);
            args.extend(["--amount".into(), prompt("Amount in base units")?]);
            asset_burn(&args)
        }
        "5" => {
            let args = vec![
                "--asset".into(),
                prompt("Asset ID")?,
                "--rpc".into(),
                prompt_default("Node RPC address", DEFAULT_RPC_ADDR)?,
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
                prompt_default("Node RPC address", DEFAULT_RPC_ADDR)?,
            ];
            asset_balance(&args)
        }
        "7" | "back" => Ok(()),
        choice => Err(format!("unknown asset selection `{choice}`")),
    }
}

fn interactive_asset_wallet_rpc() -> Result<Vec<String>, String> {
    Ok(vec![
        "--wallet".into(),
        prompt_default("Wallet file", DEFAULT_WALLET_PATH)?,
        "--rpc".into(),
        prompt_default("Node RPC address", DEFAULT_RPC_ADDR)?,
    ])
}

fn prompt_signature_profile() -> Result<String, String> {
    loop {
        let value = prompt_default(
            "Signature profile (mldsa44, mldsa65, mldsa87, falcon512, falcon1024)",
            "mldsa44",
        )?;
        if value.parse::<SignatureProfile>().is_ok() {
            return Ok(value);
        }
        println!("Unknown signature profile `{value}`");
    }
}

fn interactive_wallet_query(query: fn(&[String]) -> Result<(), String>) -> Result<(), String> {
    let path = prompt_default("Wallet file", DEFAULT_WALLET_PATH)?;
    let rpc = prompt_default("Node RPC address", DEFAULT_RPC_ADDR)?;
    query(&["--wallet".into(), path, "--rpc".into(), rpc])
}

fn interactive_spend() -> Result<(), String> {
    let rpc = prompt_default("Node RPC address", DEFAULT_RPC_ADDR)?;
    let mut args = vec![
        "--to".into(),
        prompt("Recipient address")?,
        "--amount".into(),
        prompt("Amount XPQ")?,
        "--rpc".into(),
        rpc,
    ];
    args.extend([
        "--wallet".into(),
        prompt_default("Wallet file", DEFAULT_WALLET_PATH)?,
    ]);
    sign_spend(&args)
}

fn interactive_withdraw() -> Result<(), String> {
    let rpc = prompt_default("Node RPC address", DEFAULT_RPC_ADDR)?;
    let mut args = vec!["--qcash".into(), prompt("Amount to withdraw in XPQ")?];
    args.extend(["--rpc".into(), rpc]);
    append_optional_argument(
        &mut args,
        "--cash-dir",
        "QCash directory (blank for current)",
    )?;
    args.extend([
        "--wallet".into(),
        prompt_default("Wallet file", DEFAULT_WALLET_PATH)?,
    ]);
    sign_withdraw(&args)
}

fn interactive_split() -> Result<(), String> {
    let rpc = prompt_default("Node RPC address", DEFAULT_RPC_ADDR)?;
    let mut args = vec!["--file".into(), prompt("QCash file")?];
    for amount in prompt("Output XPQ amounts (remainder becomes QCash change)")?.split_whitespace()
    {
        args.extend(["--qcash".into(), amount.into()]);
    }
    args.extend(["--rpc".into(), rpc]);
    append_optional_argument(&mut args, "--cash-dir", "Output directory (blank for cash)")?;
    split_qcash(&args)
}

fn interactive_redeem() -> Result<(), String> {
    let rpc = prompt_default("Node RPC address", DEFAULT_RPC_ADDR)?;
    let mut args = vec![
        "--file".into(),
        prompt("QCash file")?,
        "--to".into(),
        prompt("Recipient address")?,
        "--rpc".into(),
        rpc,
    ];
    append_optional_argument(
        &mut args,
        "--amount",
        "Recipient XPQ (blank for all minus automatic fee)",
    )?;
    append_optional_argument(
        &mut args,
        "--cash-dir",
        "QCash change directory (blank for cash)",
    )?;
    redeem_qcash(&args)
}

fn interactive_merge() -> Result<(), String> {
    let rpc = prompt_default("Node RPC address", DEFAULT_RPC_ADDR)?;
    let mut args = Vec::new();
    for file in prompt("QCash files (space separated)")?.split_whitespace() {
        args.extend(["--file".into(), file.into()]);
    }
    args.extend(["--rpc".into(), rpc]);
    append_optional_argument(&mut args, "--cash-dir", "Output directory (blank for cash)")?;
    merge_qcash(&args)
}

fn interactive_block_explorer() -> Result<(), String> {
    let rpc = prompt_default("Node RPC address", DEFAULT_RPC_ADDR)?;
    println!("1. Address activity");
    println!("2. Transaction by ID");
    println!("3. Latest blocks");
    println!("4. Block by height");
    let response: serde_json::Value = match prompt("Select")?.as_str() {
        "1" => {
            let address = prompt("Address")?;
            address_from_string(&address).map_err(|_| "invalid address".to_string())?;
            http_get_json(&rpc, &format!("/explorer/address/{address}"))?
        }
        "2" => {
            let transaction_id = prompt("Transaction ID")?;
            if transaction_id.len() != 64
                || !transaction_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err("transaction ID must be 64 hexadecimal characters".into());
            }
            http_get_json(&rpc, &format!("/explorer/transaction/{transaction_id}"))?
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

fn append_optional_argument(
    args: &mut Vec<String>,
    option: &str,
    label: &str,
) -> Result<(), String> {
    let value = prompt(label)?;
    if !value.is_empty() {
        args.extend([option.into(), value]);
    }
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
    let mnemonic = generate_xparq_mnemonic(words)?;
    let profile = signature_profile_option(args)?.unwrap_or(SignatureProfile::MlDsa44);
    let mut wallet = profile_wallet_from_xparq_mnemonic(&mnemonic, profile)?;
    wallet.mnemonic = Some(mnemonic.to_string());
    let address = wallet.address;
    write_profile_wallet(path, &wallet)?;
    println!("signature_profile: {profile}");
    println!("address: {}", xparq::crypto::address_to_string(&address));
    println!("mnemonic: {}", mnemonic.as_str());
    println!("wallet: {path}");
    Ok(())
}

fn restore_wallet(args: &[String]) -> Result<(), String> {
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let phrase = option(args, "--mnemonic").ok_or("missing --mnemonic")?;
    let profile = signature_profile_option(args)?.unwrap_or(SignatureProfile::MlDsa44);
    let mut wallet = profile_wallet_from_xparq_mnemonic(phrase, profile)?;
    wallet.mnemonic = Some(phrase.to_string());
    let address = wallet.address;
    write_profile_wallet(path, &wallet)?;
    println!("signature_profile: {profile}");
    println!("address: {}", xparq::crypto::address_to_string(&address));
    println!("wallet: {path}");
    Ok(())
}

fn signature_profile_option(args: &[String]) -> Result<Option<SignatureProfile>, String> {
    option(args, "--profile")
        .map(|value| {
            value.parse::<SignatureProfile>().map_err(|_| {
                "invalid --profile; use mldsa44, mldsa65, mldsa87, falcon512, or falcon1024"
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
    println!("{}", xparq::crypto::address_to_string(&address));
    Ok(())
}

fn print_balance(args: &[String]) -> Result<(), String> {
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let bytes =
        Zeroizing::new(fs::read(path).map_err(|error| format!("failed to read {path}: {error}"))?);
    let address = xparq::crypto::address_to_string(&wallet_address_from_file_bytes(&bytes)?);
    let balance: BalanceResponse = http_get_json(rpc, &format!("/balance/{address}"))?;

    println!("address: {address}");
    println!("total: {}", format_amount(balance.total));
    println!("available: {}", format_amount(balance.available));
    println!("reserved: {}", format_amount(balance.reserved));
    println!("utxos: {}", balance.utxo_count);
    println!("assets: {}", balance.assets.len());
    for asset in &balance.assets {
        println!(
            "- asset_id={} name={} symbol={} decimals={} balance={}",
            asset.asset_id, asset.name, asset.symbol, asset.decimals, asset.balance
        );
    }
    Ok(())
}

fn print_history(args: &[String]) -> Result<(), String> {
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let bytes =
        Zeroizing::new(fs::read(path).map_err(|error| format!("failed to read {path}: {error}"))?);
    let address = xparq::crypto::address_to_string(&wallet_address_from_file_bytes(&bytes)?);
    let mut history: AddressHistoryResponse = http_get_json(
        rpc,
        &format!("/explorer/address/{address}?include_emissions=false"),
    )?;

    println!("address: {}", history.address);
    println!("tip height: {}", history.tip_height);
    let emission_count = history.emission_count;
    history
        .activities
        .retain(|activity| activity.transaction_id.is_some());
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
            activity.transaction_id.as_deref().unwrap_or("emission"),
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
    let address = xparq::crypto::address_to_string(&wallet_address_from_file_bytes(&bytes)?);
    let account = fetch_account(rpc, &address)?;

    println!("address: {address}");
    println!("next height: {}", account.next_height);
    println!("utxos: {}", account.utxos.len());
    let mut utxos = account.utxos.iter().collect::<Vec<_>>();
    utxos.sort_by(|left, right| left.id.cmp(&right.id));
    for utxo in utxos {
        println!(
            "- id={} amount={} status={}",
            utxo.id,
            format_amount(utxo.amount),
            utxo_status(utxo),
        );
    }
    Ok(())
}

fn sign_spend(args: &[String]) -> Result<(), String> {
    reject_manual_fee(args)?;
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let recipient = address_option(args, "--to")?;
    let amount = parse_amount(option(args, "--amount").ok_or("missing --amount")?)?;
    let inputs = repeated_options(args, "--input")
        .into_iter()
        .map(xparq::coin::CoinId::from_str)
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
    let transaction = automatic_fee_transaction(|fee| {
        let required = amount
            .as_zeno()
            .checked_add(fee)
            .ok_or("transaction amount plus fee overflow")?;
        let (selected, change, state_burn, change_address) = if inputs.is_empty() {
            let (selected, _total, state_burn, change) =
                select_account_inputs_with_state_burn(rpc, &wallet, required, 2, 0, 0)?;
            (selected, change, state_burn, wallet.address())
        } else {
            let gross_change = explicit_change.map_or(0, Amount::as_zeno);
            let created = 2_u64 + u64::from(gross_change > fee);
            let state_burn = StateTransitionWeight {
                consumed_coin_utxos: u64::try_from(inputs.len())
                    .map_err(|_| "too many explicit inputs")?,
                created_coin_utxos: created,
                ..StateTransitionWeight::default()
            }
            .required_burn()
            .map_err(|error| error.to_string())?
            .as_zeno();
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
        let mut outputs = vec![SpendOutput::new(recipient, amount)];
        if change > 0 {
            outputs.push(SpendOutput::new(change_address, Amount::from_zeno(change)));
        }
        outputs.push(SpendOutput::block_miner(Amount::from_zeno(fee)));
        if state_burn > 0 {
            outputs.push(SpendOutput::burn(Amount::from_zeno(state_burn)));
        }
        let intent = OnChainSpendIntent::new(wallet.address(), selected, outputs)
            .map_err(|error| error.to_string())?;
        let signed = wallet.sign_onchain_spend(intent, known)?;
        Ok(AuthorizedTransaction::OnChainSpend(Box::new(signed)))
    })?;
    submit_or_print_transaction(args, &transaction)
}

fn account_input_candidates(rpc: &str, wallet: &LoadedWallet) -> Result<Vec<AccountUtxo>, String> {
    let address = xparq::crypto::address_to_string(&wallet.address());
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
    created_qcash_utxos: u64,
    extension_created_weight: u64,
) -> Result<(Vec<xparq::coin::CoinId>, u64, u64, u64), String> {
    let candidates = account_input_candidates(rpc, wallet)?;
    let mut selected = Vec::new();
    let mut total = 0_u64;
    for utxo in candidates {
        selected.push(
            xparq::coin::CoinId::from_str(&utxo.id)
                .map_err(|_| "node returned an invalid coin id".to_string())?,
        );
        total = total
            .checked_add(utxo.amount)
            .ok_or_else(|| "selected input amount overflow".to_string())?;
        let consumed = u64::try_from(selected.len()).map_err(|_| "too many selected inputs")?;
        for has_change in [false, true] {
            let created = created_coin_without_change
                .checked_add(u64::from(has_change))
                .ok_or("state output count overflow")?;
            let burn = StateTransitionWeight {
                consumed_coin_utxos: consumed,
                created_coin_utxos: created,
                created_qcash_utxos,
                extension_created_weight,
                ..StateTransitionWeight::default()
            }
            .required_burn()
            .map_err(|error| error.to_string())?
            .as_zeno();
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
    let address = xparq::crypto::address_to_string(&wallet.address());
    http_get_json::<AccountResponse>(rpc, &format!("/account/{address}"))
        .map(|response| response.public_key_registered)
        .unwrap_or(false)
}

fn fetch_account(rpc: &str, address: &str) -> Result<AccountResponse, String> {
    let mut response: AccountResponse = http_get_json(rpc, &format!("/account/{address}"))?;
    while let Some(offset) = response.next_utxo_offset {
        let page: AccountResponse =
            http_get_json(rpc, &format!("/account/{address}?utxo_offset={offset}"))?;
        if page.next_height != response.next_height
            || page.public_key_registered != response.public_key_registered
        {
            return Err("account changed while reading paginated RPC response; retry".into());
        }
        if page.utxos.is_empty() {
            return Err("node returned an invalid empty account page".into());
        }
        response.utxos.extend(page.utxos);
        response.next_utxo_offset = page.next_utxo_offset;
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

fn sign_withdraw(args: &[String]) -> Result<(), String> {
    reject_manual_fee(args)?;
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let cash_dir = PathBuf::from(option(args, "--cash-dir").unwrap_or("cash"));
    let inputs = repeated_options(args, "--input")
        .into_iter()
        .map(xparq::coin::CoinId::from_str)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid --input coin id".to_string())?;
    let amounts = repeated_options(args, "--qcash")
        .into_iter()
        .map(parse_amount)
        .collect::<Result<Vec<_>, _>>()?;
    if amounts.is_empty() {
        return Err("at least one --qcash amount is required".to_string());
    }
    let secrets = amounts
        .iter()
        .map(|_| {
            QCashSigningSeed::random()
                .map_err(|error| format!("secure random generation failed: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let qcash_outputs: Vec<QCashOutput> = amounts
        .iter()
        .zip(&secrets)
        .map(|(amount, secret)| QCashOutput::new(*amount, secret.public_key()))
        .collect();
    let wallet = load_wallet(path)?;
    let chain = xparq::genesis::chain_context().map_err(|error| error.to_string())?;
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let known = account_public_key_registered(rpc, &wallet);
    let explicit_change = option(args, "--change").map(parse_amount).transpose()?;
    let change_target = option(args, "--change-to")
        .map(|address| address_from_string(address).map_err(|error| error.to_string()))
        .transpose()?;
    if inputs.is_empty() && (explicit_change.is_some() || change_target.is_some()) {
        return Err("automatic input selection also calculates change automatically".into());
    }
    let qcash_total = checked_amount_sum(amounts.iter().copied())?;
    let transaction = automatic_fee_transaction(|fee| {
        let required = qcash_total
            .checked_add(fee)
            .ok_or("withdraw amount plus fee overflow")?;
        let (selected, change, state_burn, change_address) = if inputs.is_empty() {
            let (selected, _total, state_burn, change) = select_account_inputs_with_state_burn(
                rpc,
                &wallet,
                required,
                1,
                u64::try_from(qcash_outputs.len()).map_err(|_| "too many QCash outputs")?,
                0,
            )?;
            (selected, change, state_burn, wallet.address())
        } else {
            let gross_change = explicit_change.map_or(0, Amount::as_zeno);
            let state_burn = StateTransitionWeight {
                consumed_coin_utxos: u64::try_from(inputs.len())
                    .map_err(|_| "too many explicit inputs")?,
                created_coin_utxos: 1 + u64::from(gross_change > fee),
                created_qcash_utxos: u64::try_from(qcash_outputs.len())
                    .map_err(|_| "too many QCash outputs")?,
                ..StateTransitionWeight::default()
            }
            .required_burn()
            .map_err(|error| error.to_string())?
            .as_zeno();
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
        let mut public_outputs = Vec::new();
        if change > 0 {
            public_outputs.push(SpendOutput::new(change_address, Amount::from_zeno(change)));
        }
        public_outputs.push(SpendOutput::block_miner(Amount::from_zeno(fee)));
        if state_burn > 0 {
            public_outputs.push(SpendOutput::burn(Amount::from_zeno(state_burn)));
        }
        let intent = WithdrawIntent::new(
            wallet.address(),
            selected,
            qcash_outputs.clone(),
            public_outputs,
        )
        .map_err(|error| error.to_string())?;
        let signed = wallet.sign_withdraw(intent, known)?;
        Ok(AuthorizedTransaction::Withdraw(Box::new(signed)))
    })?;
    let commitment = match &transaction {
        AuthorizedTransaction::Withdraw(transaction) => transaction
            .intent
            .commitment(chain)
            .map_err(|error| error.to_string())?,
        _ => unreachable!("withdraw fee builder returned another transaction kind"),
    };

    let mut files = Vec::with_capacity(amounts.len());
    for (index, (amount, secret)) in amounts.into_iter().zip(secrets).enumerate() {
        let id = withdraw_qcash_output_id(commitment, index).map_err(|error| error.to_string())?;
        files.push(QCashFile::new(QCash::new(id, amount), secret));
    }
    write_qcash_files(&cash_dir, &files)?;
    submit_or_print_transaction(args, &transaction)
}

fn redeem_qcash(args: &[String]) -> Result<(), String> {
    reject_manual_fee(args)?;
    let input_path = option(args, "--file").ok_or("missing --file")?;
    let input = load_qcash_file(Path::new(input_path))?;
    let recipient = address_option(args, "--to")?;
    let requested_amount = option(args, "--amount").map(parse_amount).transpose()?;
    let change_secret = requested_amount
        .map(|_| {
            QCashSigningSeed::random()
                .map_err(|error| format!("secure random generation failed: {error}"))
        })
        .transpose()?;
    let chain = xparq::genesis::chain_context().map_err(|error| error.to_string())?;
    let transaction = automatic_fee_transaction(|fee| {
        let input_amount = input.qcash.amount().as_zeno();
        let requested = requested_amount.map(Amount::as_zeno);
        let provisional_remainder = requested
            .and_then(|amount| input_amount.checked_sub(fee)?.checked_sub(amount))
            .unwrap_or(0);
        let created_qcash = u64::from(provisional_remainder > 0);
        let state_burn = StateTransitionWeight {
            consumed_qcash_utxos: 1,
            created_qcash_utxos: created_qcash,
            created_coin_utxos: 2,
            ..StateTransitionWeight::default()
        }
        .required_burn()
        .map_err(|error| error.to_string())?
        .as_zeno();
        let available = input_amount
            .checked_sub(fee)
            .and_then(|amount| amount.checked_sub(state_burn))
            .filter(|amount| *amount > 0)
            .ok_or("QCash amount is too small for the automatic fee and state burn")?;
        let recipient_amount = requested.unwrap_or(available);
        let change_amount = available
            .checked_sub(recipient_amount)
            .ok_or("redeem amount plus automatic fee and state burn exceeds the QCash amount")?;
        if u64::from(change_amount > 0) != created_qcash {
            return Err("QCash remainder is too small to fund its state burn".into());
        }
        let mut outputs = vec![SpendOutput::new(
            recipient,
            Amount::from_zeno(recipient_amount),
        )];
        outputs.push(SpendOutput::block_miner(Amount::from_zeno(fee)));
        if state_burn > 0 {
            outputs.push(SpendOutput::burn(Amount::from_zeno(state_burn)));
        }
        let qcash_outputs = change_secret
            .as_ref()
            .filter(|_| change_amount > 0)
            .map(|secret| QCashOutput::new(Amount::from_zeno(change_amount), secret.public_key()))
            .into_iter()
            .collect();
        let intent = RedeemIntent::new(vec![input.qcash], outputs, qcash_outputs)
            .map_err(|error| error.to_string())?;
        let authorized = authorize_qcash_intent(intent, std::slice::from_ref(&input), chain)?;
        Ok(AuthorizedTransaction::Redeem(Box::new(authorized)))
    })?;
    let (commitment, change_amount) = match &transaction {
        AuthorizedTransaction::Redeem(transaction) => (
            transaction
                .intent
                .commitment(chain)
                .map_err(|error| error.to_string())?,
            transaction
                .intent
                .qcash_outputs
                .first()
                .map_or(0, |output| output.amount.as_zeno()),
        ),
        _ => unreachable!("redeem fee builder returned another transaction kind"),
    };

    if let Some(secret) = change_secret.filter(|_| change_amount > 0) {
        let id = redeem_qcash_change_output_id(commitment, 0).map_err(|error| error.to_string())?;
        let change_file = QCashFile::new(QCash::new(id, Amount::from_zeno(change_amount)), secret);
        write_qcash_files(&cash_dir_option(args), &[change_file])?;
    }
    submit_or_print_transaction(args, &transaction)
}

fn split_qcash(args: &[String]) -> Result<(), String> {
    reject_manual_fee(args)?;
    let input_path = option(args, "--file").ok_or("missing --file")?;
    let input = load_qcash_file(Path::new(input_path))?;
    let amounts = repeated_options(args, "--qcash")
        .into_iter()
        .map(parse_amount)
        .collect::<Result<Vec<_>, _>>()?;
    if amounts.is_empty() {
        return Err("QCash split requires at least one --qcash amount".into());
    }
    let requested = checked_amount_sum(amounts.iter().copied())?;
    let maximum_outputs = amounts.len().saturating_add(1);
    let secrets = fresh_qcash_secrets(
        maximum_outputs,
        std::iter::once(input.signing_seed.public_key()),
    )?;
    let chain = xparq::genesis::chain_context().map_err(|error| error.to_string())?;
    let transaction = automatic_fee_transaction(|fee| {
        let mut state_burn = 0_u64;
        let mut resolved_amounts = None;
        for _ in 0..4 {
            let available = input
                .qcash
                .amount()
                .as_zeno()
                .checked_sub(fee)
                .and_then(|amount| amount.checked_sub(state_burn))
                .ok_or("split automatic fee and state burn exceed the QCash amount")?;
            let remainder = available
                .checked_sub(requested)
                .ok_or("split outputs plus automatic fee and state burn exceed the QCash amount")?;
            let mut final_amounts = amounts.clone();
            if remainder > 0 {
                final_amounts.push(Amount::from_zeno(remainder));
            }
            let required_burn = StateTransitionWeight {
                consumed_qcash_utxos: 1,
                created_qcash_utxos: u64::try_from(final_amounts.len())
                    .map_err(|_| "too many QCash outputs")?,
                created_coin_utxos: 1,
                ..StateTransitionWeight::default()
            }
            .required_burn()
            .map_err(|error| error.to_string())?
            .as_zeno();
            if required_burn == state_burn {
                resolved_amounts = Some(final_amounts);
                break;
            }
            state_burn = required_burn;
        }
        let final_amounts =
            resolved_amounts.ok_or("split state-burn calculation did not converge")?;
        if final_amounts.len() < 2 {
            return Err("QCash split must produce at least two outputs after fee".into());
        }
        let outputs = final_amounts
            .iter()
            .zip(&secrets)
            .map(|(amount, secret)| QCashOutput::new(*amount, secret.public_key()))
            .collect::<Vec<_>>();
        let mut public_outputs = vec![SpendOutput::block_miner(Amount::from_zeno(fee))];
        if state_burn > 0 {
            public_outputs.push(SpendOutput::burn(Amount::from_zeno(state_burn)));
        }
        let intent = SplitIntent::new(input.qcash, outputs, public_outputs)
            .map_err(|error| error.to_string())?;
        let authorized = authorize_qcash_intent(intent, std::slice::from_ref(&input), chain)?;
        Ok(AuthorizedTransaction::Split(Box::new(authorized)))
    })?;
    let (commitment, final_amounts) = match &transaction {
        AuthorizedTransaction::Split(transaction) => (
            transaction
                .intent
                .commitment(chain)
                .map_err(|error| error.to_string())?,
            transaction
                .intent
                .outputs
                .iter()
                .map(|output| output.amount)
                .collect::<Vec<_>>(),
        ),
        _ => unreachable!("split fee builder returned another transaction kind"),
    };
    let files = final_amounts
        .into_iter()
        .zip(secrets)
        .enumerate()
        .map(|(index, (amount, secret))| {
            split_qcash_output_id(commitment, index)
                .map(|id| QCashFile::new(QCash::new(id, amount), secret))
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    write_qcash_files(&cash_dir_option(args), &files)?;
    submit_or_print_transaction(args, &transaction)
}

fn merge_qcash(args: &[String]) -> Result<(), String> {
    reject_manual_fee(args)?;
    let paths = repeated_options(args, "--file");
    if paths.len() < 2 {
        return Err("QCash merge requires at least two --file inputs".into());
    }
    let inputs = paths
        .iter()
        .map(|path| load_qcash_file(Path::new(path)))
        .collect::<Result<Vec<_>, _>>()?;
    let total = checked_amount_sum(inputs.iter().map(|file| file.qcash.amount()))?;
    let forbidden = inputs.iter().map(|file| file.signing_seed.public_key());
    let secret = fresh_qcash_secrets(1, forbidden)?.remove(0);
    let chain = xparq::genesis::chain_context().map_err(|error| error.to_string())?;
    let transaction = automatic_fee_transaction(|fee| {
        let state_burn = StateTransitionWeight {
            consumed_qcash_utxos: u64::try_from(inputs.len())
                .map_err(|_| "too many QCash inputs")?,
            created_qcash_utxos: 1,
            created_coin_utxos: 1,
            ..StateTransitionWeight::default()
        }
        .required_burn()
        .map_err(|error| error.to_string())?
        .as_zeno();
        let output_amount = total
            .checked_sub(fee)
            .and_then(|amount| amount.checked_sub(state_burn))
            .filter(|amount| *amount > 0)
            .ok_or("merged QCash amount is too small for the automatic fee and state burn")?;
        let mut public_outputs = vec![SpendOutput::block_miner(Amount::from_zeno(fee))];
        if state_burn > 0 {
            public_outputs.push(SpendOutput::burn(Amount::from_zeno(state_burn)));
        }
        let intent = MergeIntent::new(
            inputs.iter().map(|file| file.qcash).collect(),
            QCashOutput::new(Amount::from_zeno(output_amount), secret.public_key()),
            public_outputs,
        )
        .map_err(|error| error.to_string())?;
        let authorized = authorize_qcash_intent(intent, &inputs, chain)?;
        Ok(AuthorizedTransaction::Merge(Box::new(authorized)))
    })?;
    let (commitment, output_amount) = match &transaction {
        AuthorizedTransaction::Merge(transaction) => (
            transaction
                .intent
                .commitment(chain)
                .map_err(|error| error.to_string())?,
            transaction.intent.output.amount.as_zeno(),
        ),
        _ => unreachable!("merge fee builder returned another transaction kind"),
    };
    let id = merge_qcash_output_id(commitment).map_err(|error| error.to_string())?;
    write_qcash_files(
        &cash_dir_option(args),
        &[QCashFile::new(
            QCash::new(id, Amount::from_zeno(output_amount)),
            secret,
        )],
    )?;
    submit_or_print_transaction(args, &transaction)
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
    mut build: impl FnMut(u64) -> Result<AuthorizedTransaction, String>,
) -> Result<AuthorizedTransaction, String> {
    let mut fee = AUTOMATIC_FEE_ZENO_PER_BYTE;
    for _ in 0..MAX_FEE_CONVERGENCE_ROUNDS {
        let transaction = build(fee)?;
        let size = canonical_bytes(&transaction)
            .map_err(|error| error.to_string())?
            .len();
        let required = u64::try_from(size)
            .ok()
            .and_then(|size| size.checked_mul(AUTOMATIC_FEE_ZENO_PER_BYTE))
            .ok_or("automatic transaction fee overflow")?;
        if required == fee {
            return Ok(transaction);
        }
        fee = required;
    }
    Err("automatic transaction fee did not converge".into())
}

fn cash_dir_option(args: &[String]) -> PathBuf {
    PathBuf::from(option(args, "--cash-dir").unwrap_or("cash"))
}

fn checked_amount_sum(mut amounts: impl Iterator<Item = Amount>) -> Result<u64, String> {
    amounts
        .try_fold(Amount::from_zeno(0), |sum, amount| {
            sum.checked_add(amount)
                .ok_or_else(|| "QCash amount overflow".to_string())
        })
        .map(Amount::as_zeno)
}

fn fresh_qcash_secrets(
    count: usize,
    forbidden: impl Iterator<Item = QCashPublicKey>,
) -> Result<Vec<QCashSigningSeed>, String> {
    let mut commitments = forbidden.collect::<BTreeSet<_>>();
    let mut secrets = Vec::with_capacity(count);
    while secrets.len() < count {
        let secret = QCashSigningSeed::random()
            .map_err(|error| format!("secure random generation failed: {error}"))?;
        if commitments.insert(secret.public_key()) {
            secrets.push(secret);
        }
    }
    Ok(secrets)
}

fn load_qcash_file(path: &Path) -> Result<QCashFile, String> {
    let bytes = Zeroizing::new(
        fs::read(path)
            .map_err(|error| format!("failed to read QCash file {}: {error}", path.display()))?,
    );
    let file = QCashFile::decode(&bytes)
        .map_err(|error| format!("invalid QCash file {}: {error}", path.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("QCash path has no UTF-8 filename: {}", path.display()))?;
    validate_qcash_file_name(file_name, file.qcash)
        .map_err(|error| format!("invalid QCash filename {}: {error}", path.display()))?;
    Ok(file)
}

fn write_qcash_files(directory: &Path, files: &[QCashFile]) -> Result<(), String> {
    fs::create_dir_all(directory)
        .map_err(|error| format!("failed to create {}: {error}", directory.display()))?;
    let mut reserved_paths = BTreeSet::new();
    let encoded = files
        .iter()
        .map(|file| {
            let mut sequence = 1_usize;
            let path = loop {
                let candidate = directory.join(qcash_file_name(file.qcash, sequence));
                if !candidate.exists() && reserved_paths.insert(candidate.clone()) {
                    break candidate;
                }
                sequence = sequence
                    .checked_add(1)
                    .ok_or("too many QCash files with the same amount")?;
            };
            let bytes = file.encode().map_err(|error| error.to_string())?;
            Ok((path, bytes))
        })
        .collect::<Result<Vec<_>, String>>()?;
    for (path, bytes) in encoded {
        write_new_file(&path, &bytes)?;
        eprintln!("QCash file: {}", path.display());
    }
    fs::File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("failed to sync {}: {error}", directory.display()))?;
    Ok(())
}

fn authorize_qcash_intent<T: QCashIntent>(
    intent: T,
    inputs: &[QCashFile],
    chain: xparq::transaction::ChainContext,
) -> Result<AuthorizedQCashIntent<T>, String> {
    let commitment = intent
        .commitment(chain)
        .map_err(|error| error.to_string())?;
    let authorizations = inputs
        .iter()
        .map(|file| QCashAuthorization {
            signature: file.signing_seed.sign(commitment.as_bytes()),
        })
        .collect();
    AuthorizedQCashIntent::new(intent, authorizations).map_err(|error| error.to_string())
}

fn submit_or_print_transaction(
    args: &[String],
    transaction: &AuthorizedTransaction,
) -> Result<(), String> {
    let bytes = canonical_bytes(transaction).map_err(|error| error.to_string())?;
    if has_flag(args, "--offline") {
        println!("{}", hex::encode(&bytes));
        eprintln!("transaction_size_bytes: {}", bytes.len());
        return Ok(());
    }
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let response: SubmitTransactionResponse = http_post_bytes(rpc, "/transaction", &bytes)?;
    println!("transaction_id: {}", response.transaction_id);
    println!("transaction_size_bytes: {}", bytes.len());
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
    profile_wallet_from_file_bytes(&bytes).map(LoadedWallet)
}

fn write_profile_wallet(path: &str, wallet: &ProfileWallet) -> Result<(), String> {
    let bytes = profile_wallet_file_bytes(wallet)?;
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

fn address_option(args: &[String], name: &str) -> Result<Address, String> {
    address_from_string(option(args, name).ok_or_else(|| format!("missing {name}"))?)
        .map_err(|error| format!("invalid {name}: {error}"))
}

fn parse_amount(value: &str) -> Result<Amount, String> {
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
        .checked_mul(COIN)
        .and_then(|units| units.checked_add(fraction))
        .ok_or_else(|| "XPQ amount overflow".to_string())?;
    if units == 0 {
        return Err("XPQ amount must be positive".to_string());
    }
    Ok(Amount::from_zeno(units))
}

fn format_amount(units: u64) -> String {
    let whole = units / COIN;
    let fraction = units % COIN;
    let width = DECIMALS as usize;
    format!("{whole}.{fraction:0width$} XPQ")
}

fn print_help() {
    println!(
        "wallet [menu]\nwallet new [--wallet PATH] [--words 12|24] [--profile PROFILE]\nwallet restore --mnemonic PHRASE [--wallet PATH] [--profile PROFILE]\nwallet address [--wallet PATH]\nwallet balance [--wallet PATH] [--rpc ADDRESS]\nwallet history [--wallet PATH] [--rpc ADDRESS]\nwallet utxos [--wallet PATH] [--rpc ADDRESS]\nwallet sign-spend [--input COIN_ID...] --to ADDRESS --amount XPQ [--change XPQ --change-to ADDRESS] [--rpc ADDRESS] [--wallet PATH] [--offline]\nwallet sign-withdraw --qcash XPQ... [--input COIN_ID...] [--change XPQ --change-to ADDRESS] [--rpc ADDRESS] [--cash-dir PATH] [--wallet PATH] [--offline]\nwallet qcash-redeem --file FILE --to ADDRESS [--amount XPQ] [--rpc ADDRESS] [--cash-dir PATH] [--offline]\nwallet qcash-split --file FILE --qcash XPQ [--qcash XPQ...] [--rpc ADDRESS] [--cash-dir PATH] [--offline]\nwallet qcash-merge --file FILE --file FILE... [--rpc ADDRESS] [--cash-dir PATH] [--offline]\nwallet version\n\nAll signature profiles are active from genesis. Signed transactions are submitted to node RPC automatically. Use --offline to print canonical transaction hex instead. The wallet automatically pays the node policy fee of 1 zeno per canonical transaction byte; manual --miner fee input is not supported. History reports canonical address activity; UTXO tracker reads the wallet account endpoint and follows paginated UTXOs. QCash operations use Falcon-512 bearer authorization. Keep input QCash files until the transaction is canonically confirmed.\nRunning without a command opens the interactive menu.\nWithout --input, spend and withdraw select active XPQ inputs and calculate change through node RPC."
    );
    println!(
        "\nAsset commands:\nwallet asset-register --name NAME --symbol SYMBOL --decimals N --max-supply UNITS --initial-mint UNITS [--wallet PATH] [--rpc ADDRESS]\nwallet asset-mint --asset ID --to ADDRESS --amount UNITS [--wallet PATH] [--rpc ADDRESS]\nwallet asset-burn --asset ID --amount UNITS [--wallet PATH] [--rpc ADDRESS]\nwallet asset-transfer --asset ID --to ADDRESS --amount UNITS [--wallet PATH] [--rpc ADDRESS]\nwallet asset-info --asset ID [--rpc ADDRESS]\nwallet asset-balance --asset ID [--address ADDRESS | --wallet PATH] [--rpc ADDRESS]\n\nAsset amounts are integer base units. Registration atomically credits the initial mint to the signing creator, makes that wallet the mint authority, and pays one XPQ miner fee. Distribution to other addresses uses asset-transfer."
    );
    println!(
        "\nWASM commands:\nwallet wasm-deploy --name NAME --wasm MODULE [--wallet PATH] [--rpc ADDRESS] [--offline]\nwallet wasm-info --extension ID [--rpc ADDRESS]\n\nWASM deploys are immutable and activate automatically after 100 blocks."
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use xparq::qcash::canonical_qcash_file_name;

    #[test]
    fn asset_symbol_is_normalized_and_rejects_non_ascii_punctuation() {
        assert_eq!(
            normalize_asset_name(" Test Token "),
            Ok("Test Token".into())
        );
        assert_eq!(normalize_asset_symbol("test"), Ok("TEST".into()));
        assert!(normalize_asset_symbol("test-token").is_err());
        assert!(normalize_asset_symbol("").is_err());
        let args = vec!["--amount".into(), "100000000000000000000000".into()];
        assert_eq!(
            parse_asset_amount(&args, "--amount"),
            Ok(100_000_000_000_000_000_000_000_u128)
        );
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
                    b"HTTP/1.1 200 OK\r\nContent-Length: 85\r\nConnection: close\r\n\r\n{\"transaction_id\":\"0000000000000000000000000000000000000000000000000000000000000000\"}",
                )
                .unwrap();
        });
        let response: SubmitTransactionResponse =
            http_post_bytes(&address.to_string(), "/transaction", &[1, 2, 3, 4]).unwrap();
        assert_eq!(response.transaction_id, "0".repeat(64));
        server.join().unwrap();
    }

    #[test]
    fn wallet_file_is_atomically_created_as_owner_only() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "xparq-private-wallet-{}-{unique}",
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
            next_utxo_offset: None,
            utxos: vec![
                AccountUtxo {
                    id: "available-one".into(),
                    amount: 2 * COIN,
                    reserved: false,
                },
                AccountUtxo {
                    id: "available-two".into(),
                    amount: 3 * COIN,
                    reserved: false,
                },
                AccountUtxo {
                    id: "reserved".into(),
                    amount: COIN,
                    reserved: true,
                },
            ],
        };

        assert_eq!(format_amount(2 * COIN + 1), "2.000001 XPQ");
        assert_eq!(utxo_status(&account.utxos[0]), "available");
        assert_eq!(utxo_status(&account.utxos[1]), "available");
        assert_eq!(utxo_status(&account.utxos[2]), "reserved");
    }

    #[test]
    fn core_qcash_file_name_contains_canonical_amount() {
        let id = xparq::coin::CoinId::from_bytes([0xab; xparq::coin::CoinId::SIZE]);

        assert_eq!(
            canonical_qcash_file_name(QCash::new(id, Amount::from_zeno(5 * COIN))),
            "5XPQ.QCash"
        );
        assert_eq!(
            canonical_qcash_file_name(QCash::new(id, Amount::from_zeno(29 * COIN + 900_000))),
            "29.9XPQ.QCash"
        );
        assert_eq!(
            canonical_qcash_file_name(QCash::new(id, Amount::from_zeno(1))),
            "0.000001XPQ.QCash"
        );
    }

    #[test]
    fn same_amount_qcash_files_receive_numbered_names() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "xparq-numbered-qcash-{}-{unique}",
            std::process::id()
        ));
        let files = (1_u8..=3)
            .map(|byte| {
                QCashFile::new(
                    QCash::new(
                        xparq::coin::CoinId::from_bytes([byte; xparq::coin::CoinId::SIZE]),
                        Amount::from_zeno(10 * COIN),
                    ),
                    QCashSigningSeed::from_bytes([byte; 32]),
                )
            })
            .collect::<Vec<_>>();

        write_qcash_files(&directory, &files).unwrap();

        let mut names = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(names, ["10XPQ(2).QCash", "10XPQ(3).QCash", "10XPQ.QCash"]);
        for name in names {
            assert!(load_qcash_file(&directory.join(name)).is_ok());
        }

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn automatic_fee_equals_canonical_transaction_size() {
        let input_seed = QCashSigningSeed::from_bytes([0x31; 32]);
        let output_seed = QCashSigningSeed::from_bytes([0x32; 32]);
        let input = QCash::new(
            xparq::coin::CoinId::from_bytes([0x33; xparq::coin::CoinId::SIZE]),
            Amount::from_zeno(COIN),
        );
        let chain = xparq::genesis::chain_context().unwrap();
        let transaction = automatic_fee_transaction(|fee| {
            let intent = SplitIntent::new(
                input,
                vec![
                    QCashOutput::new(Amount::from_zeno(1), output_seed.public_key()),
                    QCashOutput::new(
                        Amount::from_zeno(COIN - fee - 1),
                        QCashSigningSeed::from_bytes([0x34; 32]).public_key(),
                    ),
                ],
                vec![SpendOutput::block_miner(Amount::from_zeno(fee))],
            )
            .map_err(|error| error.to_string())?;
            let commitment = intent
                .commitment(chain)
                .map_err(|error| error.to_string())?;
            let authorized = AuthorizedQCashIntent::new(
                intent,
                vec![QCashAuthorization {
                    signature: input_seed.sign(commitment.as_bytes()),
                }],
            )
            .map_err(|error| error.to_string())?;
            Ok(AuthorizedTransaction::Split(Box::new(authorized)))
        })
        .unwrap();
        let size = canonical_bytes(&transaction).unwrap().len() as u64;
        let fee = match transaction {
            AuthorizedTransaction::Split(transaction) => transaction
                .intent
                .public_outputs
                .iter()
                .find(|output| output.target == xparq::transaction::OutputTarget::BlockMiner)
                .unwrap()
                .amount
                .as_zeno(),
            _ => unreachable!(),
        };
        assert_eq!(fee, size);
    }

    #[test]
    fn redeem_split_and_merge_create_canonical_validated_qcash_files() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "xparq-qcash-transform-{}-{unique}",
            std::process::id()
        ));
        let input_dir = root.join("input");
        let split_dir = root.join("split");
        let merge_dir = root.join("merge");
        let redeem_dir = root.join("redeem");
        let input = QCashFile::new(
            QCash::new(
                xparq::coin::CoinId::from_bytes([0x11; xparq::coin::CoinId::SIZE]),
                Amount::from_zeno(5 * COIN),
            ),
            QCashSigningSeed::from_bytes([0x22; 32]),
        );
        let input_name = canonical_qcash_file_name(input.qcash);
        write_qcash_files(&input_dir, &[input]).unwrap();
        let input_path = input_dir.join(input_name);

        split_qcash(&[
            "--file".into(),
            input_path.to_string_lossy().into_owned(),
            "--qcash".into(),
            "2".into(),
            "--cash-dir".into(),
            split_dir.to_string_lossy().into_owned(),
            "--offline".into(),
        ])
        .unwrap();

        let mut split_paths = fs::read_dir(&split_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        split_paths.sort();
        assert_eq!(split_paths.len(), 2);
        for path in &split_paths {
            assert!(load_qcash_file(path).is_ok());
        }

        let mut merge_args = vec![
            "--cash-dir".into(),
            merge_dir.to_string_lossy().into_owned(),
            "--offline".into(),
        ];
        for path in &split_paths {
            merge_args.extend(["--file".into(), path.to_string_lossy().into_owned()]);
        }
        merge_qcash(&merge_args).unwrap();

        let merged_paths = fs::read_dir(&merge_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(merged_paths.len(), 1);
        assert!(
            load_qcash_file(&merged_paths[0]).unwrap().qcash.amount() < Amount::from_zeno(5 * COIN)
        );

        let mnemonic = xparq_wallet::encode_xparq_mnemonic(&[7; 16]).unwrap();
        let recipient =
            xparq_wallet::profile_wallet_from_xparq_mnemonic(&mnemonic, SignatureProfile::MlDsa44)
                .unwrap();
        redeem_qcash(&[
            "--file".into(),
            merged_paths[0].to_string_lossy().into_owned(),
            "--to".into(),
            xparq::crypto::address_to_string(&recipient.address),
            "--amount".into(),
            "4".into(),
            "--cash-dir".into(),
            redeem_dir.to_string_lossy().into_owned(),
            "--offline".into(),
        ])
        .unwrap();
        let redeem_paths = fs::read_dir(&redeem_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(redeem_paths.len(), 1);
        assert!(
            load_qcash_file(&redeem_paths[0]).unwrap().qcash.amount() < Amount::from_zeno(COIN)
        );

        fs::remove_dir_all(root).unwrap();
    }
}
