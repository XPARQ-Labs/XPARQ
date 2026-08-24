use std::{
    collections::BTreeSet,
    fs,
    io::{self, Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    str::FromStr,
};

use serde::Deserialize;
use xparq::{
    codec::canonical_bytes,
    consensus::{Amount, COIN, DECIMALS, MAX_QCASH_TRANSACTION_LIFETIME},
    crypto::{Address, QCashPublicKey, address_from_string},
    ledger::{
        merge_qcash_output_id, redeem_qcash_change_output_id, split_qcash_output_id,
        withdraw_qcash_output_id,
    },
    qcash::{
        QCash, QCashFile, QCashSigningSeed, canonical_qcash_file_name, validate_qcash_file_name,
    },
    transaction::{
        AuthorizedQCashIntent, AuthorizedTransaction, MergeIntent, OnChainSpendIntent,
        QCashAuthorization, QCashIntent, QCashOutput, RedeemIntent, SpendOutput, SplitIntent,
        WithdrawIntent,
    },
};
use xparq_wallet::{
    Wallet, generate_xparq_mnemonic, wallet_address_from_file_bytes, wallet_address_string,
    wallet_file_bytes, wallet_from_file_bytes, wallet_from_xparq_mnemonic,
};
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_WALLET_PATH: &str = "wallet.json";
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
struct AccountUtxo {
    id: String,
    amount: u64,
    spendable_height: u64,
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

#[derive(Debug, PartialEq, Eq)]
struct BalanceSummary {
    total: u64,
    spendable: u64,
    locked: u64,
    reserved: u64,
}

fn utxo_status(utxo: &AccountUtxo, next_height: u64) -> &'static str {
    if utxo.reserved {
        "reserved"
    } else if utxo.spendable_height > next_height {
        "locked"
    } else {
        "spendable"
    }
}

#[derive(Deserialize)]
struct StatusResponse {
    next_height: u64,
}

#[derive(Deserialize)]
struct SubmitTransactionResponse {
    transaction_id: String,
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
        println!("13. Exit");

        match prompt("Select")?.as_str() {
            "1" => {
                let path = prompt_default("Wallet file", DEFAULT_WALLET_PATH)?;
                let words = prompt_default("Mnemonic words (12 or 24)", "12")?;
                create_wallet(&["--wallet".into(), path, "--words".into(), words])?;
            }
            "2" => {
                let path = prompt_default("Wallet file", DEFAULT_WALLET_PATH)?;
                let phrase = prompt("Mnemonic")?;
                restore_wallet(&["--wallet".into(), path, "--mnemonic".into(), phrase])?;
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
            "13" | "exit" | "quit" => return Ok(()),
            choice => println!("Unknown selection `{choice}`"),
        }
    }
}

fn interactive_wallet_query(query: fn(&[String]) -> Result<(), String>) -> Result<(), String> {
    let path = prompt_default("Wallet file", DEFAULT_WALLET_PATH)?;
    let rpc = prompt_default("Node RPC address", DEFAULT_RPC_ADDR)?;
    query(&["--wallet".into(), path, "--rpc".into(), rpc])
}

fn interactive_spend() -> Result<(), String> {
    let rpc = prompt_default("Node RPC address", DEFAULT_RPC_ADDR)?;
    let expiry = automatic_expiry_height(&rpc)?;
    let mut args = vec![
        "--to".into(),
        prompt("Recipient address")?,
        "--amount".into(),
        prompt("Amount XPQ")?,
        "--expiry".into(),
        expiry.to_string(),
        "--rpc".into(),
        rpc,
    ];
    append_optional_argument(&mut args, "--miner", "Miner output XPQ (blank for none)")?;
    args.extend([
        "--wallet".into(),
        prompt_default("Wallet file", DEFAULT_WALLET_PATH)?,
    ]);
    sign_spend(&args)
}

fn interactive_withdraw() -> Result<(), String> {
    let rpc = prompt_default("Node RPC address", DEFAULT_RPC_ADDR)?;
    let expiry = automatic_expiry_height(&rpc)?;
    let mut args = vec!["--qcash".into(), prompt("Amount to withdraw in XPQ")?];
    args.extend(["--expiry".into(), expiry.to_string(), "--rpc".into(), rpc]);
    append_optional_argument(&mut args, "--miner", "Miner output XPQ (blank for none)")?;
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
    append_optional_argument(&mut args, "--miner", "Miner output XPQ (blank for none)")?;
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
        "Recipient XPQ (blank for all minus miner output)",
    )?;
    append_optional_argument(&mut args, "--miner", "Miner output XPQ (blank for none)")?;
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
    append_optional_argument(&mut args, "--miner", "Miner output XPQ (blank for none)")?;
    append_optional_argument(&mut args, "--cash-dir", "Output directory (blank for cash)")?;
    merge_qcash(&args)
}

fn automatic_expiry_height(rpc: &str) -> Result<u64, String> {
    let status: StatusResponse = http_get_json(rpc, "/status")?;
    status
        .next_height
        .checked_add(MAX_QCASH_TRANSACTION_LIFETIME)
        .ok_or_else(|| "automatic expiry height overflow".to_string())
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
    let mut wallet = wallet_from_xparq_mnemonic(&mnemonic)?;
    wallet.mnemonic = Some(mnemonic.to_string());
    write_wallet(path, &wallet)?;
    println!("address: {}", wallet_address_string(&wallet));
    println!("mnemonic: {}", mnemonic.as_str());
    println!("wallet: {path}");
    Ok(())
}

fn restore_wallet(args: &[String]) -> Result<(), String> {
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let phrase = option(args, "--mnemonic").ok_or("missing --mnemonic")?;
    let mut wallet = wallet_from_xparq_mnemonic(phrase)?;
    wallet.mnemonic = Some(phrase.to_string());
    write_wallet(path, &wallet)?;
    println!("address: {}", wallet_address_string(&wallet));
    println!("wallet: {path}");
    Ok(())
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
    let account = fetch_account(rpc, &address)?;
    let balance = summarize_balance(&account)?;

    println!("address: {address}");
    println!("total: {}", format_amount(balance.total));
    println!("spendable: {}", format_amount(balance.spendable));
    println!("locked: {}", format_amount(balance.locked));
    println!("reserved: {}", format_amount(balance.reserved));
    println!("utxos: {}", account.utxos.len());
    let mut utxos = account.utxos.iter().collect::<Vec<_>>();
    utxos.sort_by(|left, right| left.id.cmp(&right.id));
    for utxo in utxos {
        println!(
            "- id={} amount={} status={} spendable_height={}",
            utxo.id,
            format_amount(utxo.amount),
            utxo_status(utxo, account.next_height),
            utxo.spendable_height,
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
            "- id={} amount={} status={} spendable_height={}",
            utxo.id,
            format_amount(utxo.amount),
            utxo_status(utxo, account.next_height),
            utxo.spendable_height,
        );
    }
    Ok(())
}

fn summarize_balance(account: &AccountResponse) -> Result<BalanceSummary, String> {
    let mut summary = BalanceSummary {
        total: 0,
        spendable: 0,
        locked: 0,
        reserved: 0,
    };
    for utxo in &account.utxos {
        summary.total = summary
            .total
            .checked_add(utxo.amount)
            .ok_or("wallet balance overflow")?;
        let category = match utxo_status(utxo, account.next_height) {
            "reserved" => &mut summary.reserved,
            "locked" => &mut summary.locked,
            _ => &mut summary.spendable,
        };
        *category = category
            .checked_add(utxo.amount)
            .ok_or("wallet balance overflow")?;
    }
    Ok(summary)
}

fn sign_spend(args: &[String]) -> Result<(), String> {
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let recipient = address_option(args, "--to")?;
    let amount = parse_amount(option(args, "--amount").ok_or("missing --amount")?)?;
    let expiry_height = option(args, "--expiry")
        .ok_or("missing --expiry")?
        .parse::<u64>()
        .map_err(|_| "invalid --expiry".to_string())?;
    let mut inputs = repeated_options(args, "--input")
        .into_iter()
        .map(xparq::coin::CoinId::from_str)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid --input coin id".to_string())?;
    let wallet = load_wallet(path)?;
    let miner_fee = option(args, "--miner").map(parse_amount).transpose()?;
    let required = amount
        .checked_add(miner_fee.unwrap_or(Amount(0)))
        .ok_or_else(|| "transaction amount overflow".to_string())?
        .0;
    let mut outputs = vec![SpendOutput::new(recipient, amount)];
    if inputs.is_empty() {
        if option(args, "--change").is_some() || option(args, "--change-to").is_some() {
            return Err("automatic input selection also calculates change automatically".into());
        }
        let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
        let (selected, selected_total) = select_account_inputs(rpc, &wallet, required)?;
        inputs = selected;
        let change = selected_total - required;
        if change > 0 {
            outputs.push(SpendOutput::new(wallet.address, Amount(change)));
        }
    } else if let Some(change) = option(args, "--change") {
        outputs.push(SpendOutput::new(
            address_option(args, "--change-to")?,
            parse_amount(change)?,
        ));
    }
    if let Some(fee) = miner_fee {
        outputs.push(SpendOutput::block_miner(fee));
    }
    let intent = OnChainSpendIntent::new(wallet.address, inputs, outputs, expiry_height)
        .map_err(|error| error.to_string())?;
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let known = account_public_key_registered(rpc, &wallet);
    let signed = if known {
        wallet.sign_known_onchain_spend(intent)?
    } else {
        wallet.sign_onchain_spend(intent)?
    };
    let transaction = AuthorizedTransaction::OnChainSpend(Box::new(signed));
    submit_or_print_transaction(args, &transaction)
}

fn select_account_inputs(
    rpc: &str,
    wallet: &Wallet,
    required: u64,
) -> Result<(Vec<xparq::coin::CoinId>, u64), String> {
    let address = wallet_address_string(wallet);
    let response = fetch_account(rpc, &address)?;
    let mut candidates = response
        .utxos
        .into_iter()
        .filter(|utxo| !utxo.reserved && utxo.spendable_height <= response.next_height)
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        right
            .amount
            .cmp(&left.amount)
            .then_with(|| left.id.cmp(&right.id))
    });
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
        if total >= required {
            return Ok((selected, total));
        }
    }
    Err(format!(
        "insufficient spendable balance: required {required} units, available {total} units"
    ))
}

fn account_public_key_registered(rpc: &str, wallet: &Wallet) -> bool {
    let address = wallet_address_string(wallet);
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
        return Err(format!(
            "node RPC rejected request: {}",
            status.lines().next().unwrap_or(status)
        ));
    }
    serde_json::from_slice(&response[body_offset..])
        .map_err(|error| format!("invalid node RPC response: {error}"))
}

fn sign_withdraw(args: &[String]) -> Result<(), String> {
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let cash_dir = PathBuf::from(option(args, "--cash-dir").unwrap_or("cash"));
    let expiry_height = option(args, "--expiry")
        .ok_or("missing --expiry")?
        .parse::<u64>()
        .map_err(|_| "invalid --expiry".to_string())?;
    let mut inputs = repeated_options(args, "--input")
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
    let qcash_outputs = amounts
        .iter()
        .zip(&secrets)
        .map(|(amount, secret)| QCashOutput::new(*amount, secret.public_key()))
        .collect();
    let mut public_outputs = Vec::new();
    if let Some(change) = option(args, "--change") {
        public_outputs.push(SpendOutput::new(
            address_option(args, "--change-to")?,
            parse_amount(change)?,
        ));
    }
    if let Some(fee) = option(args, "--miner") {
        public_outputs.push(SpendOutput::block_miner(parse_amount(fee)?));
    }
    let wallet = load_wallet(path)?;
    if inputs.is_empty() {
        if option(args, "--change").is_some() || option(args, "--change-to").is_some() {
            return Err("automatic input selection also calculates change automatically".into());
        }
        let qcash_total = checked_amount_sum(amounts.iter().copied())?;
        let miner_total = option(args, "--miner")
            .map(parse_amount)
            .transpose()?
            .map_or(0, |amount| amount.0);
        let required = qcash_total
            .checked_add(miner_total)
            .ok_or("withdraw amount overflow")?;
        let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
        let (selected, selected_total) = select_account_inputs(rpc, &wallet, required)?;
        inputs = selected;
        let change = selected_total - required;
        if change > 0 {
            public_outputs.push(SpendOutput::new(wallet.address, Amount(change)));
        }
    }
    let intent = WithdrawIntent::new(
        wallet.address,
        inputs,
        qcash_outputs,
        public_outputs,
        expiry_height,
    )
    .map_err(|error| error.to_string())?;
    let chain = xparq::genesis::chain_context().map_err(|error| error.to_string())?;
    let commitment = intent
        .commitment(chain)
        .map_err(|error| error.to_string())?;
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let known = account_public_key_registered(rpc, &wallet);
    let signed = if known {
        wallet.sign_known_withdraw(intent)?
    } else {
        wallet.sign_withdraw(intent)?
    };
    let transaction = AuthorizedTransaction::Withdraw(Box::new(signed));

    let mut files = Vec::with_capacity(amounts.len());
    for (index, (amount, secret)) in amounts.into_iter().zip(secrets).enumerate() {
        let id = withdraw_qcash_output_id(commitment, index).map_err(|error| error.to_string())?;
        files.push(QCashFile::new(QCash::new(id, amount), secret));
    }
    write_qcash_files(&cash_dir, &files)?;
    submit_or_print_transaction(args, &transaction)
}

fn redeem_qcash(args: &[String]) -> Result<(), String> {
    let input_path = option(args, "--file").ok_or("missing --file")?;
    let input = load_qcash_file(Path::new(input_path))?;
    let recipient = address_option(args, "--to")?;
    let miner_output = miner_output_option(args)?;
    let miner_amount = miner_output.map_or(0, |output| output.amount.0);
    let available = input
        .qcash
        .amount()
        .0
        .checked_sub(miner_amount)
        .filter(|amount| *amount > 0)
        .ok_or("redeem miner output must be smaller than the QCash amount")?;
    let recipient_amount = option(args, "--amount")
        .map(parse_amount)
        .transpose()?
        .map_or(available, |amount| amount.0);
    let change_amount = available
        .checked_sub(recipient_amount)
        .ok_or("redeem amount plus miner output exceeds the QCash amount")?;

    let mut outputs = vec![SpendOutput::new(recipient, Amount(recipient_amount))];
    if let Some(miner_output) = miner_output {
        outputs.push(miner_output);
    }
    let change_secret = if change_amount > 0 {
        Some(
            QCashSigningSeed::random()
                .map_err(|error| format!("secure random generation failed: {error}"))?,
        )
    } else {
        None
    };
    let qcash_outputs = change_secret
        .as_ref()
        .map(|secret| QCashOutput::new(Amount(change_amount), secret.public_key()))
        .into_iter()
        .collect();
    let chain = xparq::genesis::chain_context().map_err(|error| error.to_string())?;
    let intent = RedeemIntent::new(
        vec![input.qcash],
        outputs,
        qcash_outputs,
        qcash_expiry_height(args)?,
    )
    .map_err(|error| error.to_string())?;
    let commitment = intent
        .commitment(chain)
        .map_err(|error| error.to_string())?;
    let authorized = authorize_qcash_intent(intent, std::slice::from_ref(&input), chain)?;

    if let Some(secret) = change_secret {
        let id = redeem_qcash_change_output_id(commitment, 0).map_err(|error| error.to_string())?;
        let change_file = QCashFile::new(QCash::new(id, Amount(change_amount)), secret);
        write_qcash_files(&cash_dir_option(args), &[change_file])?;
    }
    submit_or_print_transaction(args, &AuthorizedTransaction::Redeem(Box::new(authorized)))
}

fn split_qcash(args: &[String]) -> Result<(), String> {
    let input_path = option(args, "--file").ok_or("missing --file")?;
    let input = load_qcash_file(Path::new(input_path))?;
    let mut amounts = repeated_options(args, "--qcash")
        .into_iter()
        .map(parse_amount)
        .collect::<Result<Vec<_>, _>>()?;
    if amounts.is_empty() {
        return Err("QCash split requires at least one --qcash amount".into());
    }
    let expiry_height = qcash_expiry_height(args)?;
    let miner_output = miner_output_option(args)?;
    let requested = checked_amount_sum(amounts.iter().copied())?;
    let miner_amount = miner_output.map_or(0, |output| output.amount.0);
    let available = input
        .qcash
        .amount()
        .0
        .checked_sub(miner_amount)
        .ok_or("split miner output exceeds the QCash amount")?;
    let remainder = available
        .checked_sub(requested)
        .ok_or("split outputs plus miner output exceed the QCash amount")?;
    if remainder > 0 {
        amounts.push(Amount(remainder));
    }
    if amounts.len() < 2 {
        return Err(
            "QCash split must produce at least two outputs; request less than the available amount"
                .into(),
        );
    }
    let secrets = fresh_qcash_secrets(
        amounts.len(),
        std::iter::once(input.signing_seed.public_key()),
    )?;
    let outputs = amounts
        .iter()
        .zip(&secrets)
        .map(|(amount, secret)| QCashOutput::new(*amount, secret.public_key()))
        .collect::<Vec<_>>();
    let intent = SplitIntent::new(input.qcash, outputs, miner_output, expiry_height)
        .map_err(|error| error.to_string())?;
    let chain = xparq::genesis::chain_context().map_err(|error| error.to_string())?;
    let commitment = intent
        .commitment(chain)
        .map_err(|error| error.to_string())?;
    let authorized = authorize_qcash_intent(intent, std::slice::from_ref(&input), chain)?;
    let files = amounts
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
    submit_or_print_transaction(args, &AuthorizedTransaction::Split(Box::new(authorized)))
}

fn merge_qcash(args: &[String]) -> Result<(), String> {
    let paths = repeated_options(args, "--file");
    if paths.len() < 2 {
        return Err("QCash merge requires at least two --file inputs".into());
    }
    let inputs = paths
        .iter()
        .map(|path| load_qcash_file(Path::new(path)))
        .collect::<Result<Vec<_>, _>>()?;
    let total = checked_amount_sum(inputs.iter().map(|file| file.qcash.amount()))?;
    let miner_output = miner_output_option(args)?;
    let miner_amount = miner_output.map_or(0, |output| output.amount.0);
    let output_amount = total
        .checked_sub(miner_amount)
        .filter(|amount| *amount > 0)
        .ok_or("merge miner output must be smaller than the merged QCash amount")?;
    let forbidden = inputs.iter().map(|file| file.signing_seed.public_key());
    let secret = fresh_qcash_secrets(1, forbidden)?.remove(0);
    let intent = MergeIntent::new(
        inputs.iter().map(|file| file.qcash).collect(),
        QCashOutput::new(Amount(output_amount), secret.public_key()),
        miner_output,
        qcash_expiry_height(args)?,
    )
    .map_err(|error| error.to_string())?;
    let chain = xparq::genesis::chain_context().map_err(|error| error.to_string())?;
    let commitment = intent
        .commitment(chain)
        .map_err(|error| error.to_string())?;
    let authorized = authorize_qcash_intent(intent, &inputs, chain)?;
    let id = merge_qcash_output_id(commitment).map_err(|error| error.to_string())?;
    write_qcash_files(
        &cash_dir_option(args),
        &[QCashFile::new(
            QCash::new(id, Amount(output_amount)),
            secret,
        )],
    )?;
    submit_or_print_transaction(args, &AuthorizedTransaction::Merge(Box::new(authorized)))
}

fn expiry_option(args: &[String]) -> Result<u64, String> {
    option(args, "--expiry")
        .ok_or("missing --expiry")?
        .parse::<u64>()
        .map_err(|_| "invalid --expiry".to_string())
}

fn qcash_expiry_height(args: &[String]) -> Result<u64, String> {
    if option(args, "--expiry").is_some() {
        return expiry_option(args);
    }
    automatic_expiry_height(option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR))
}

fn miner_output_option(args: &[String]) -> Result<Option<SpendOutput>, String> {
    option(args, "--miner")
        .map(parse_amount)
        .transpose()
        .map(|amount| amount.map(SpendOutput::block_miner))
}

fn cash_dir_option(args: &[String]) -> PathBuf {
    PathBuf::from(option(args, "--cash-dir").unwrap_or("cash"))
}

fn checked_amount_sum(mut amounts: impl Iterator<Item = Amount>) -> Result<u64, String> {
    amounts
        .try_fold(Amount(0), |sum, amount| {
            sum.checked_add(amount)
                .ok_or_else(|| "QCash amount overflow".to_string())
        })
        .map(|amount| amount.0)
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
    let encoded = files
        .iter()
        .map(|file| {
            let path = directory.join(canonical_qcash_file_name(file.qcash));
            if path.exists() {
                return Err(format!("QCash file already exists: {}", path.display()));
            }
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

fn load_wallet(path: &str) -> Result<Wallet, String> {
    let bytes =
        Zeroizing::new(fs::read(path).map_err(|error| format!("failed to read {path}: {error}"))?);
    wallet_from_file_bytes(&bytes)
}

fn write_wallet(path: &str, wallet: &Wallet) -> Result<(), String> {
    let bytes = wallet_file_bytes(wallet)?;
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
    Ok(Amount(units))
}

fn format_amount(units: u64) -> String {
    let whole = units / COIN;
    let fraction = units % COIN;
    let width = DECIMALS as usize;
    format!("{whole}.{fraction:0width$} XPQ")
}

fn print_help() {
    println!(
        "wallet [menu]\nwallet new [--wallet PATH] [--words 12|24]\nwallet restore --mnemonic PHRASE [--wallet PATH]\nwallet address [--wallet PATH]\nwallet balance [--wallet PATH] [--rpc ADDRESS]\nwallet history [--wallet PATH] [--rpc ADDRESS]\nwallet utxos [--wallet PATH] [--rpc ADDRESS]\nwallet sign-spend [--input COIN_ID...] --to ADDRESS --amount XPQ --expiry HEIGHT [--change XPQ --change-to ADDRESS] [--miner XPQ] [--rpc ADDRESS] [--wallet PATH] [--offline]\nwallet sign-withdraw --qcash XPQ... --expiry HEIGHT [--input COIN_ID...] [--change XPQ --change-to ADDRESS] [--miner XPQ] [--rpc ADDRESS] [--cash-dir PATH] [--wallet PATH] [--offline]\nwallet qcash-redeem --file FILE --to ADDRESS [--amount XPQ] [--miner XPQ] [--rpc ADDRESS] [--cash-dir PATH] [--offline]\nwallet qcash-split --file FILE --qcash XPQ [--qcash XPQ...] [--miner XPQ] [--rpc ADDRESS] [--cash-dir PATH] [--offline]\nwallet qcash-merge --file FILE --file FILE... [--miner XPQ] [--rpc ADDRESS] [--cash-dir PATH] [--offline]\nwallet version\n\nSigned transactions are submitted to node RPC automatically. Use --offline to print canonical transaction hex instead. History reports canonical address activity; UTXO tracker reads the wallet account endpoint and follows paginated UTXOs. A split automatically creates QCash change when requested outputs are smaller than the input after miner output. QCash operations use ML-DSA-44 bearer authorization, and block-miner value is deducted from QCash inputs. Keep input QCash files until the transaction is canonically confirmed.\nRunning without a command opens the interactive menu.\nWithout --input, spend and withdraw select active XPQ inputs and calculate change through node RPC."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn balance_separates_spendable_locked_and_reserved_outputs() {
        let account = AccountResponse {
            next_height: 100,
            public_key_registered: false,
            next_utxo_offset: None,
            utxos: vec![
                AccountUtxo {
                    id: "spendable".into(),
                    amount: 2 * COIN,
                    spendable_height: 100,
                    reserved: false,
                },
                AccountUtxo {
                    id: "locked".into(),
                    amount: 3 * COIN,
                    spendable_height: 101,
                    reserved: false,
                },
                AccountUtxo {
                    id: "reserved".into(),
                    amount: COIN,
                    spendable_height: 0,
                    reserved: true,
                },
            ],
        };

        assert_eq!(
            summarize_balance(&account),
            Ok(BalanceSummary {
                total: 6 * COIN,
                spendable: 2 * COIN,
                locked: 3 * COIN,
                reserved: COIN,
            })
        );
        assert_eq!(format_amount(2 * COIN + 1), "2.000001 XPQ");
        assert_eq!(
            utxo_status(&account.utxos[0], account.next_height),
            "spendable"
        );
        assert_eq!(
            utxo_status(&account.utxos[1], account.next_height),
            "locked"
        );
        assert_eq!(
            utxo_status(&account.utxos[2], account.next_height),
            "reserved"
        );
    }

    #[test]
    fn core_qcash_file_name_contains_canonical_amount_and_full_coin_id() {
        let id = xparq::coin::CoinId::from_bytes([0xab; xparq::coin::CoinId::SIZE]);
        let full_id = "ab".repeat(xparq::coin::CoinId::SIZE);

        assert_eq!(
            canonical_qcash_file_name(QCash::new(id, Amount(5 * COIN))),
            format!("5XPQ_{full_id}.QCash")
        );
        assert_eq!(
            canonical_qcash_file_name(QCash::new(id, Amount(29 * COIN + 900_000))),
            format!("29.9XPQ_{full_id}.QCash")
        );
        assert_eq!(
            canonical_qcash_file_name(QCash::new(id, Amount(1))),
            format!("0.000001XPQ_{full_id}.QCash")
        );
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
                Amount(5 * COIN),
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
            "--expiry".into(),
            "100".into(),
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
            "--expiry".into(),
            "101".into(),
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
        assert_eq!(
            load_qcash_file(&merged_paths[0]).unwrap().qcash.amount(),
            Amount(5 * COIN)
        );

        let mnemonic = xparq_wallet::encode_xparq_mnemonic(&[7; 16]).unwrap();
        let recipient = wallet_from_xparq_mnemonic(&mnemonic).unwrap();
        redeem_qcash(&[
            "--file".into(),
            merged_paths[0].to_string_lossy().into_owned(),
            "--to".into(),
            wallet_address_string(&recipient),
            "--amount".into(),
            "4".into(),
            "--expiry".into(),
            "102".into(),
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
        assert_eq!(
            load_qcash_file(&redeem_paths[0]).unwrap().qcash.amount(),
            Amount(COIN)
        );

        fs::remove_dir_all(root).unwrap();
    }
}
