use std::{
    fs,
    io::{self, Read, Write},
    net::TcpStream,
    path::Path,
    str::FromStr,
};

use serde::Deserialize;
use xparq::asset::AssetHash;
use xparq::common::Authority;
use xparq::transaction::AssetInstruction;
use xparq::{
    codec::canonical_bytes,
    consensus::{Amount, COIN, DECIMALS, StateTransitionWeight, profile_key_state_weight},
    crypto::{Address, SignatureProfile, address_from_string},
    transaction::{
        AuthorizedAssetTransaction, AuthorizedExtensionTransaction, AuthorizedTransaction,
        CoinIntent, SpendOutput,
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

    fn new_account_key_weight(&self, public_key_known: bool) -> Result<u64, String> {
        if public_key_known {
            Ok(0)
        } else {
            profile_key_state_weight(&self.0.public_key).map_err(|error| error.to_string())
        }
    }

    fn sign_onchain_spend(
        &self,
        intent: CoinIntent,
        public_key_known: bool,
    ) -> Result<xparq::transaction::AuthorizedAccountIntent<CoinIntent>, String> {
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
    available: u64,
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

#[derive(Deserialize)]
struct ExtensionPreviewResponse {
    #[serde(rename = "height")]
    _height: u64,
    created_state_weight: u64,
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
        Some("coin-deposit") => sign_spend(&args[1..]),
        Some("asset-register") => asset_register(&args[1..]),
        Some("asset-mint") => asset_mint(&args[1..]),
        Some("asset-burn") => asset_burn(&args[1..]),
        Some("asset-transfer") => asset_transfer(&args[1..]),
        Some("asset-deposit") => asset_deposit(&args[1..]),
        Some("asset-info") => asset_info(&args[1..]),
        Some("asset-balance") => asset_balance(&args[1..]),
        Some("wasm-deploy") => wasm_deploy(&args[1..]),
        Some("wasm-call") => wasm_call(&args[1..]),
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
    let asset_id = AssetHash::derive(authority, &symbol);
    let mint_authority = if has_flag(args, "--fixed-supply") {
        if option(args, "--mint-program").is_some() {
            return Err("--fixed-supply and --mint-program cannot be used together".into());
        }
        None
    } else if let Some(program) = option(args, "--mint-program") {
        Some(Authority::Extension(parse_extension_id(program)?))
    } else {
        Some(Authority::Address(authority))
    };
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
    println!("asset_id: {asset_id}");
    Ok(())
}

fn normalize_asset_name(name: &str) -> Result<String, String> {
    let normalized = name.trim().to_string();
    if normalized.is_empty()
        || normalized.len() > xparq::asset::ASSET_NAME_MAX_LEN
        || !normalized
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
    {
        return Err(format!(
            "invalid token name; use 1-{} printable ASCII characters",
            xparq::asset::ASSET_NAME_MAX_LEN
        ));
    }
    Ok(normalized)
}

fn normalize_asset_symbol(symbol: &str) -> Result<String, String> {
    let normalized = symbol.to_ascii_uppercase();
    if normalized.is_empty()
        || normalized.len() > xparq::asset::ASSET_SYMBOL_MAX_LEN
        || !normalized
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(format!(
            "invalid token symbol; use 1-{} ASCII letters A-Z or digits",
            xparq::asset::ASSET_SYMBOL_MAX_LEN
        ));
    }
    Ok(normalized)
}

fn asset_mint(args: &[String]) -> Result<(), String> {
    submit_asset_instruction(
        args,
        AssetInstruction::Mint {
            asset_id: parse_asset_id(args)?,
            recipient: Authority::Address(address_option(args, "--to")?),
            amount: parse_asset_amount(args, "--amount")?,
        },
    )
}

fn asset_burn(args: &[String]) -> Result<(), String> {
    submit_asset_instruction(
        args,
        AssetInstruction::Burn {
            asset_id: parse_asset_id(args)?,
            inputs: asset_inputs(args)?,
        },
    )
}

fn asset_transfer(args: &[String]) -> Result<(), String> {
    submit_asset_instruction(
        args,
        AssetInstruction::Transfer {
            asset_id: parse_asset_id(args)?,
            inputs: asset_inputs(args)?,
            outputs: vec![xparq::asset::AssetTransferOutput {
                recipient: Authority::Address(address_option(args, "--to")?),
                amount: parse_asset_amount(args, "--amount")?,
            }],
        },
    )
}

fn asset_deposit(args: &[String]) -> Result<(), String> {
    submit_asset_instruction(
        args,
        AssetInstruction::Transfer {
            asset_id: parse_asset_id(args)?,
            inputs: asset_inputs(args)?,
            outputs: vec![xparq::asset::AssetTransferOutput {
                recipient: Authority::Extension(parse_extension_id(
                    option(args, "--extension").ok_or("missing --extension")?,
                )?),
                amount: parse_asset_amount(args, "--amount")?,
            }],
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

fn submit_asset_instruction(args: &[String], instruction: AssetInstruction) -> Result<(), String> {
    reject_manual_fee(args)?;
    let wallet = load_wallet(option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH))?;
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let address = xparq::crypto::address_to_string(&wallet.address());
    let nonce = http_get_json::<AssetNonceResponse>(rpc, &format!("/asset/nonce/{address}"))?.nonce;
    let public_key_known = account_public_key_registered(rpc, &wallet);
    let call = wallet
        .0
        .sign_asset_intent(instruction, nonce, public_key_known)?;
    let extension_created_weight = call
        .intent
        .created_state_weight_from_presence(nonce > 0)
        .map_err(|error| format!("calculate asset state weight: {error:?}"))?;
    let transaction = automatic_fee_transaction(|fee, archival_burn| {
        let (inputs, _total, state_burn, change) = select_account_inputs_with_state_burn(
            rpc,
            &wallet,
            fee,
            1,
            extension_created_weight,
            archival_burn,
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
        let fee_intent = CoinIntent::new(wallet.address(), inputs, outputs)
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
    let extension_created_weight = preview_extension_created_weight(rpc, &call)?;
    let public_key_known = account_public_key_registered(rpc, &wallet);
    let transaction = automatic_fee_transaction(|fee, archival_burn| {
        let (inputs, _total, state_burn, change) = select_account_inputs_with_state_burn(
            rpc,
            &wallet,
            fee,
            1,
            extension_created_weight,
            archival_burn,
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
        let fee_intent = CoinIntent::new(wallet.address(), inputs, outputs)
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

fn wasm_call(args: &[String]) -> Result<(), String> {
    reject_manual_fee(args)?;
    let extension_id =
        parse_extension_id(option(args, "--extension").ok_or("missing --extension")?)?;
    let payload = match (
        option(args, "--payload-hex"),
        option(args, "--payload-file"),
    ) {
        (Some(payload), None) => hex::decode(payload).map_err(|_| "invalid --payload-hex")?,
        (None, Some(path)) => {
            fs::read(path).map_err(|error| format!("read WASM call payload `{path}`: {error}"))?
        }
        (Some(_), Some(_)) => return Err("use only one of --payload-hex or --payload-file".into()),
        (None, None) => return Err("missing --payload-hex or --payload-file".into()),
    };
    let wallet = load_wallet(option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH))?;
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let address = xparq::crypto::address_to_string(&wallet.address());
    let nonce = http_get_json::<AssetNonceResponse>(
        rpc,
        &format!(
            "/wasm-app/nonce/{}/{}",
            hex::encode(extension_id.as_bytes()),
            address
        ),
    )?
    .nonce;
    let call = wallet.0.sign_wasm_app_call(extension_id, payload, nonce)?;
    let extension_created_weight = preview_extension_created_weight(rpc, &call)?;
    let public_key_known = account_public_key_registered(rpc, &wallet);
    let transaction = automatic_fee_transaction(|fee, archival_burn| {
        let (inputs, _total, state_burn, change) = select_account_inputs_with_state_burn(
            rpc,
            &wallet,
            fee,
            1,
            extension_created_weight,
            archival_burn,
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
        let fee_intent = CoinIntent::new(wallet.address(), inputs, outputs)
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

fn preview_extension_created_weight(
    rpc: &str,
    call: &xparq::common::ExtensionCall,
) -> Result<u64, String> {
    let bytes = canonical_bytes(call).map_err(|error| error.to_string())?;
    let preview = http_post_bytes::<ExtensionPreviewResponse>(rpc, "/extension/preview", &bytes)?;
    Ok(preview.created_state_weight)
}

fn parse_extension_id(value: &str) -> Result<xparq::common::ExtensionHash, String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("extension ID must be 64 hexadecimal characters".into());
    }
    let bytes = hex::decode(value).map_err(|_| "invalid extension ID")?;
    Ok(xparq::common::ExtensionHash::from_bytes(
        bytes
            .try_into()
            .map_err(|_| "extension ID must be 32 bytes")?,
    ))
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

fn parse_asset_id(args: &[String]) -> Result<AssetHash, String> {
    option(args, "--asset")
        .ok_or_else(|| "missing --asset".to_string())?
        .parse::<AssetHash>()
        .map_err(|_| "invalid --asset id".to_string())
}

fn asset_inputs(args: &[String]) -> Result<Vec<xparq::asset::AssetShareHash>, String> {
    let inputs = args
        .windows(2)
        .filter(|pair| pair[0] == "--input")
        .map(|pair| {
            pair[1]
                .parse::<xparq::asset::AssetShareHash>()
                .map_err(|_| "invalid --input asset object id".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if inputs.is_empty() {
        return Err("missing --input asset object id".into());
    }
    Ok(inputs)
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
        println!("8. Block explorer");
        println!("9. Assets");
        println!("10. Exit");

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
    let burn: NodeBurnResponse = http_get_json(rpc, "/status")?;

    println!("address: {address}");
    println!("total: {}", format_amount(balance.total));
    println!("available: {}", format_amount(balance.available));
    println!("reserved: {}", format_amount(balance.reserved));
    println!("utxos: {}", balance.utxo_count);
    println!("burned supply: {}", format_amount(burn.total_burned));
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
    let recipient = option(args, "--to")
        .map(|value| address_from_string(value).map_err(|error| error.to_string()))
        .transpose()?;
    let extension = option(args, "--extension")
        .map(parse_extension_id)
        .transpose()?;
    if recipient.is_some() == extension.is_some() {
        return Err("provide exactly one of --to or --extension".into());
    }
    let amount = parse_amount(option(args, "--amount").ok_or("missing --amount")?)?;
    let inputs = repeated_options(args, "--input")
        .into_iter()
        .map(xparq::coin::CoinHash::from_str)
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
        let (selected, change, state_burn, change_address) = if inputs.is_empty() {
            let (selected, _total, state_burn, change) =
                select_account_inputs_with_state_burn(rpc, &wallet, required, 2, 0, archival_burn)?;
            (selected, change, state_burn, wallet.address())
        } else {
            let gross_change = explicit_change.map_or(0, Amount::as_zeno);
            let created = 2_u64 + u64::from(gross_change > fee);
            let state_burn = StateTransitionWeight {
                created_coin_utxos: created,
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
        let mut outputs = vec![match (recipient, extension) {
            (Some(recipient), None) => SpendOutput::new(recipient, amount),
            (None, Some(extension)) => SpendOutput::extension(extension, amount),
            _ => unreachable!("recipient choice validated above"),
        }];
        if change > 0 {
            outputs.push(SpendOutput::new(change_address, Amount::from_zeno(change)));
        }
        outputs.push(SpendOutput::block_miner(Amount::from_zeno(fee)));
        if state_burn > 0 {
            outputs.push(SpendOutput::burn(Amount::from_zeno(state_burn)));
        }
        let intent = CoinIntent::new(wallet.address(), selected, outputs)
            .map_err(|error| error.to_string())?;
        let signed = wallet.sign_onchain_spend(intent, known)?;
        Ok(AuthorizedTransaction::Coin(Box::new(signed)))
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
    extension_created_weight: u64,
    archival_burn: u64,
) -> Result<(Vec<xparq::coin::CoinHash>, u64, u64, u64), String> {
    let created_account_key_weight =
        wallet.new_account_key_weight(account_public_key_registered(rpc, wallet))?;
    let candidates = account_input_candidates(rpc, wallet)?;
    let mut selected = Vec::new();
    let mut total = 0_u64;
    for utxo in candidates {
        selected.push(
            xparq::coin::CoinHash::from_str(&utxo.id)
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
                created_account_key_weight,
                extension_created_weight,
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
    let address = xparq::crypto::address_to_string(&wallet.address());
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
        "wallet [menu]\nwallet new [--wallet PATH] [--words 12|24] [--profile PROFILE]\nwallet restore --mnemonic PHRASE [--wallet PATH] [--profile PROFILE]\nwallet address [--wallet PATH]\nwallet balance [--wallet PATH] [--rpc ADDRESS]\nwallet history [--wallet PATH] [--rpc ADDRESS]\nwallet utxos [--wallet PATH] [--rpc ADDRESS]\nwallet sign-spend [--input COIN_ID...] --to ADDRESS --amount XPQ [--change XPQ --change-to ADDRESS] [--rpc ADDRESS] [--wallet PATH] [--offline]\nwallet version\n\nAll signature profiles are active from genesis. Signed transactions are submitted to node RPC automatically. Use --offline to print canonical transaction hex instead. The wallet automatically pays the node policy fee of 1 zeno per canonical transaction byte; manual --miner fee input is not supported. History reports canonical address activity; UTXO tracker reads the wallet account endpoint and follows paginated UTXOs.\nRunning without a command opens the interactive menu.\nWithout --input, spend selects active XPQ inputs and calculates change through node RPC."
    );
    println!(
        "wallet coin-deposit --extension EXTENSION_ID --amount XPQ [--rpc ADDRESS] [--wallet PATH] [--offline]"
    );
    println!(
        "\nAsset commands:\nwallet asset-register --name NAME --symbol SYMBOL --decimals N --max-supply UNITS --initial-mint UNITS [--mint-program EXTENSION_ID | --fixed-supply] [--wallet PATH] [--rpc ADDRESS]\nwallet asset-mint --asset ID --to ADDRESS --amount UNITS [--wallet PATH] [--rpc ADDRESS]\nwallet asset-burn --asset ID --amount UNITS [--wallet PATH] [--rpc ADDRESS]\nwallet asset-transfer --asset ID --to ADDRESS --amount UNITS [--wallet PATH] [--rpc ADDRESS]\nwallet asset-deposit --asset ID --extension EXTENSION_ID --amount UNITS [--wallet PATH] [--rpc ADDRESS]\nwallet asset-info --asset ID [--rpc ADDRESS]\nwallet asset-balance --asset ID [--address ADDRESS | --wallet PATH] [--rpc ADDRESS]\n\nAsset amounts are integer base units. Registration atomically credits the initial mint to the signing creator address. Use asset-deposit to transfer assets into extension custody."
    );
    println!(
        "\nWASM commands:\nwallet wasm-deploy --name NAME --wasm MODULE [--wallet PATH] [--rpc ADDRESS] [--offline]\nwallet wasm-call --extension ID (--payload-hex HEX | --payload-file PATH) [--wallet PATH] [--rpc ADDRESS] [--offline]\nwallet wasm-info --extension ID [--rpc ADDRESS]\n\nWASM deploys are immutable and activate automatically after 100 blocks. Signed generic WASM calls and WASM persistent-state burn are active from genesis."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

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
            _utxo_snapshot: "test-snapshot".into(),
            next_utxo_offset: None,
            next_utxo_cursor: None,
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
}
