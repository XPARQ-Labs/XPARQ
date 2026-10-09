use super::history::{fetch_program_id_history, parse_history_limit, print_history_page};
use super::*;

pub(super) fn interactive_menu() -> Result<(), String> {
    loop {
        println!();
        println!("XPARQ Wallet");
        println!("1. Create Wallet");
        println!("2. Import Wallet");
        println!("3. Show Program ID");
        println!("4. Show Balance");
        println!("5. Transaction History");
        println!("6. UTXO");
        println!("7. Transfer");
        println!("8. Consolidate UTXOs");
        println!("9. Explorer");
        println!("10. Program Assets");
        println!("11. Deploy Program");
        println!("12. Exit");
        println!("13. Manage Accounts");

        match prompt("Select")?.as_str() {
            "1" => {
                let path = prompt_default("Wallet file", DEFAULT_WALLET_PATH)?;
                let account = prompt_signature_account()?;
                let default_words = "24";
                let words = prompt_default("Mnemonic words (12 or 24)", default_words)?;
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
                print_program_id(&["--wallet".into(), path])?;
            }
            "4" => {
                let path = prompt_default("Wallet file", DEFAULT_WALLET_PATH)?;
                let rpc = prompt_default("RPC", DEFAULT_RPC_ADDR)?;
                print_balance(&["--wallet".into(), path, "--rpc".into(), rpc])?;
            }
            "5" => interactive_history()?,
            "6" => interactive_wallet_query(print_utxo_tracker)?,
            "7" => interactive_spend()?,
            "8" => interactive_wallet_query(consolidate_coin_utxos)?,
            "9" => interactive_block_explorer()?,
            "10" => interactive_program_assets()?,
            "11" => {
                let mut args = interactive_asset_wallet_rpc()?;
                args.extend(["--code".into(), prompt("XPVM bytecode file")?]);
                args.extend(["--nonce".into(), prompt("Deploy nonce")?]);
                super::deploy::deploy_program(&args)?;
            }
            "13" => {
                let path = prompt_default("Wallet file", DEFAULT_WALLET_PATH)?;
                manage_accounts("accounts", &["--wallet".into(), path.clone()])?;
                match prompt("Account action (add/use/back)")?.as_str() {
                    "add" => {
                        manage_accounts("account-add", &["--wallet".into(), path])?;
                    }
                    "use" => {
                        manage_accounts(
                            "account-use",
                            &[
                                "--wallet".into(),
                                path,
                                "--salt".into(),
                                prompt("Account salt")?,
                            ],
                        )?;
                    }
                    "back" => {}
                    choice => return Err(format!("unknown account action `{choice}`")),
                }
            }
            "12" | "exit" | "quit" => return Ok(()),
            choice => println!("Unknown selection `{choice}`"),
        }
    }
}

fn interactive_program_assets() -> Result<(), String> {
    println!(
        "Program Assets: 1 Create, 2 Mint, 3 Transfer, 4 Burn, 5 Info, 6 Balance, 7 Consolidate, 8 Back"
    );
    let choice = prompt("Select")?;
    let command = match choice.as_str() {
        "1" => "program-register",
        "2" => "program-mint",
        "3" => "program-transfer",
        "4" => "program-burn",
        "5" => "program-info",
        "6" => "program-balance",
        "7" => "program-consolidate",
        "8" | "back" => return Ok(()),
        _ => return Err("unknown Program selection".into()),
    };
    let mut args = interactive_asset_wallet_rpc()?;
    if choice == "1" {
        args.extend([
            "--name".into(),
            prompt("Asset Name")?,
            "--max-supply".into(),
            prompt("Maximum Supply")?,
            "--initial-mint".into(),
            prompt("Initial Mint")?,
        ]);
    } else {
        args.extend(["--asset".into(), prompt("Program Asset Contract")?]);
    }
    if choice == "2" || choice == "3" {
        args.extend(interactive_asset_recipient()?);
    }
    if matches!(choice.as_str(), "2" | "3" | "4") {
        args.extend(["--amount".into(), prompt("Amount")?]);
    }
    super::program::command(command, &args)
}

fn interactive_asset_recipient() -> Result<[String; 2], String> {
    let recipient = prompt("Recipient Program ID")?;
    program_id_from_string(&recipient).map_err(|error| error.to_string())?;
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
            "Signature account (mldsa44, mldsa65, mldsa87, slhdsa-shake128s, slhdsa-shake192s, slhdsa-shake256s)",
            "mldsa44",
        )?;
        if let Ok(scheme) = value.parse::<Signature>() {
            return Ok(scheme.as_str().to_string());
        }
        println!("Unknown signature account `{value}`");
    }
}

fn interactive_history() -> Result<(), String> {
    let path = prompt_default("Wallet file", DEFAULT_WALLET_PATH)?;
    let rpc = prompt_default("RPC", DEFAULT_RPC_ADDR)?;
    let limit_text = prompt_default("Entries per page", &DEFAULT_HISTORY_LIMIT.to_string())?;
    let limit = parse_history_limit(&limit_text)?;
    let bytes =
        Zeroizing::new(fs::read(&path).map_err(|error| format!("failed to read {path}: {error}"))?);
    let program_id =
        kernel::crypto::program_id_to_string(&wallet_program_id_from_file_bytes(&bytes)?);

    let mut before: Option<String> = None;
    let mut previous = Vec::<Option<String>>::new();

    loop {
        println!();
        let history = fetch_program_id_history(&rpc, &program_id, limit, before.as_deref())?;
        let next_cursor = print_history_page(history);

        println!();
        if next_cursor.is_some() {
            println!("N. Next Page");
        }
        if before.is_some() {
            println!("P. Previous Page");
        }
        println!("Q. Back");

        match prompt("Select")?.to_ascii_lowercase().as_str() {
            "n" | "next" if next_cursor.is_some() => {
                previous.push(before.clone());
                before = next_cursor;
            }
            "p" | "previous" if before.is_some() => {
                before = previous.pop().unwrap_or(None);
            }
            "q" | "back" | "quit" => return Ok(()),
            choice => println!("Unknown selection `{choice}`"),
        }
    }
}

fn interactive_wallet_query(query: fn(&[String]) -> Result<(), String>) -> Result<(), String> {
    let path = prompt_default("Wallet file", DEFAULT_WALLET_PATH)?;
    let rpc = prompt_default("RPC", DEFAULT_RPC_ADDR)?;
    query(&["--wallet".into(), path, "--rpc".into(), rpc])
}

fn interactive_spend() -> Result<(), String> {
    let rpc = prompt_default("RPC", DEFAULT_RPC_ADDR)?;
    let recipient = prompt("Recipient Program ID")?;
    program_id_from_string(&recipient).map_err(|error| error.to_string())?;
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
    println!("1. Program activity");
    println!("2. Transaction by Hash");
    println!("3. Latest blocks");
    println!("4. Block by height");
    let response: serde_json::Value = match prompt("Select")?.as_str() {
        "1" => {
            let program_id = prompt("Program ID")?;
            program_id_from_string(&program_id).map_err(|_| "invalid program_id".to_string())?;
            http_get_json(&rpc, &format!("/explorer/program/{program_id}"))?
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
    print_human_json(&response);
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

pub(super) fn create_wallet(args: &[String]) -> Result<(), String> {
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let account = signature_account_option(args)?.unwrap_or(Signature::MlDsa44);
    let words = option(args, "--words")
        .unwrap_or("24")
        .parse::<usize>()
        .map_err(|_| "--words must be 12 or 24".to_string())?;
    let mnemonic = generate_bip39_mnemonic(words)?;
    let mut wallet = account_wallet_from_bip39_mnemonic(&mnemonic, account)?;
    wallet.mnemonic = Some(mnemonic.to_string());
    if let Some(value) = option(args, "--salt") {
        wallet.select_account(wallet::account_salt_from_string(value)?)?;
    }
    let program_id = wallet.program_id;
    write_account_wallet(path, &wallet)?;
    println!("signature_account: {account}");
    println!(
        "Program ID: {}",
        kernel::crypto::program_id_to_string(&program_id)
    );
    println!("mnemonic: {}", mnemonic.as_str());
    println!("wallet: {path}");
    Ok(())
}

pub(super) fn restore_wallet(args: &[String]) -> Result<(), String> {
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let phrase = option(args, "--mnemonic").ok_or("missing --mnemonic")?;
    let account = signature_account_option(args)?.unwrap_or(Signature::MlDsa44);
    let mut wallet = account_wallet_from_bip39_mnemonic(phrase, account)?;
    wallet.mnemonic = Some(phrase.to_string());
    if let Some(value) = option(args, "--salt") {
        wallet.select_account(wallet::account_salt_from_string(value)?)?;
    }
    let program_id = wallet.program_id;
    write_account_wallet(path, &wallet)?;
    println!("signature_account: {account}");
    println!(
        "Program ID: {}",
        kernel::crypto::program_id_to_string(&program_id)
    );
    println!("wallet: {path}");
    Ok(())
}

fn signature_account_option(args: &[String]) -> Result<Option<Signature>, String> {
    option(args, "--account")
        .map(|value| {
            value
                .parse::<Signature>()
                .map_err(|_| "invalid --account; use mldsa44, mldsa65, mldsa87, slhdsa-shake128s, slhdsa-shake192s, or slhdsa-shake256s".to_string())
        })
        .transpose()
}

pub(super) fn manage_accounts(command: &str, args: &[String]) -> Result<(), String> {
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let original = Zeroizing::new(fs::read(path).map_err(|error| format!("read wallet: {error}"))?);
    let mut loaded = LoadedWallet(account_wallet_from_file_bytes(&original)?);
    if command == "accounts" {
        for salt in &loaded.0.account_salts {
            let id =
                kernel::crypto::program_id_from_public_key_with_salt(&loaded.0.public_key, salt)
                    .map_err(|error| error.to_string())?;
            println!(
                "{} Program ID: {id} Salt: {}",
                if *salt == loaded.0.account_salt {
                    "*"
                } else {
                    " "
                },
                hex::encode(salt)
            );
        }
        return Ok(());
    }
    let salt = if let Some(value) = option(args, "--salt") {
        wallet::account_salt_from_string(value)?
    } else if command == "account-add" {
        let mut salt = [0; 32];
        getrandom::fill(&mut salt).map_err(|error| format!("generate account salt: {error}"))?;
        salt
    } else {
        return Err("account-use requires --salt HEX64".into());
    };
    if command == "account-use" && !loaded.0.account_salts.contains(&salt) {
        return Err("account salt is not in this wallet; use account-add first".into());
    }
    let id = loaded.0.select_account(salt)?;
    super::wallet_file::update_account_wallet(path, &loaded.0, &original)?;
    println!("Program ID: {id}");
    println!("Salt: {}", hex::encode(salt));
    Ok(())
}

pub(super) fn print_program_id(args: &[String]) -> Result<(), String> {
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let bytes =
        Zeroizing::new(fs::read(path).map_err(|error| format!("failed to read {path}: {error}"))?);
    let program_id = wallet_program_id_from_file_bytes(&bytes)?;
    println!("Program ID: {program_id}");
    Ok(())
}

pub(super) fn format_asset_amount(value: &str, decimals: u8) -> Result<String, String> {
    let units = value
        .parse::<u128>()
        .map_err(|error| format!("invalid asset amount: {error}"))?;

    if decimals == 0 {
        return Ok(units.to_string());
    }

    let scale = 10_u128
        .checked_pow(decimals as u32)
        .ok_or("asset decimals are too large")?;

    let whole = units / scale;
    let fractional = units % scale;

    Ok(format!(
        "{whole}.{fractional:0width$}",
        width = decimals as usize
    ))
}

fn human_label(key: &str) -> String {
    if key == "signer" {
        return "Signer Program ID".into();
    }
    key.split('_')
        .map(|part| match part {
            "id" => "ID".to_string(),
            "tx" => "TX".to_string(),
            "utxo" => "UTXO".to_string(),
            "xpq" => "XPQ".to_string(),
            other => {
                let mut chars = other.chars();
                match chars.next() {
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                    None => String::new(),
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub(super) fn print_human_json(value: &serde_json::Value) {
    print_human_json_value(None, value, 0);
}

fn print_human_json_value(label: Option<&str>, value: &serde_json::Value, indent: usize) {
    let padding = " ".repeat(indent);

    match value {
        serde_json::Value::Null => {
            if let Some(label) = label {
                println!("{padding}{}: -", human_label(label));
            } else {
                println!("{padding}-");
            }
        }
        serde_json::Value::Bool(value) => {
            if let Some(label) = label {
                println!("{padding}{}: {value}", human_label(label));
            } else {
                println!("{padding}{value}");
            }
        }
        serde_json::Value::Number(value) => {
            if label == Some("program_id") {
                let name = match value.as_u64() {
                    Some(0) => Some("monetary"),
                    Some(1) => Some("monetary legacy route"),
                    Some(2) => Some("VM"),
                    _ => None,
                };
                match name {
                    Some(name) => println!("{padding}System Program: {name} ({value})"),
                    None => println!("{padding}System Program: {value}"),
                }
                return;
            }
            if let Some(label) = label {
                println!("{padding}{}: {value}", human_label(label));
            } else {
                println!("{padding}{value}");
            }
        }
        serde_json::Value::String(value) => {
            if label == Some("coin_contract")
                && value.len() == 64
                && value.bytes().all(|byte| byte == b'0')
            {
                println!("{padding}Currency: XPQ (native coin)");
                return;
            }
            if let Some(label) = label {
                println!("{padding}{}: {value}", human_label(label));
            } else {
                println!("{padding}{value}");
            }
        }
        serde_json::Value::Array(values) => {
            let child_indent = if let Some(label) = label {
                println!("{padding}{}:", human_label(label));
                indent + 2
            } else {
                indent
            };

            if values.is_empty() {
                println!("{}None", " ".repeat(child_indent));
                return;
            }

            for (index, value) in values.iter().enumerate() {
                let item = format!("Item {}", index + 1);
                print_human_json_value(Some(&item), value, child_indent);
            }
        }
        serde_json::Value::Object(values) => {
            let child_indent = if let Some(label) = label {
                println!("{padding}{}:", human_label(label));
                indent + 2
            } else {
                indent
            };

            if values.len() == 2 && values.get("type").and_then(|v| v.as_str()) == Some("program") {
                if let Some(id) = values.get("value").and_then(|v| v.as_str()) {
                    println!("{}Owner Program ID: {id}", " ".repeat(child_indent));
                    return;
                }
            }

            for (key, value) in values {
                print_human_json_value(Some(key), value, child_indent);
            }
        }
    }
}

#[cfg(test)]
mod account_cli_tests {
    use super::*;
    #[test]
    fn account_commands_persist_selection_and_recover_salted_identity() {
        let tick = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("xparq-account-cli-{}-{tick}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("wallet.json");
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mut wallet = account_wallet_from_bip39_mnemonic(phrase, Signature::MlDsa44).unwrap();
        wallet.mnemonic = Some(phrase.into());
        let zero = wallet.program_id;
        write_account_wallet(path.to_str().unwrap(), &wallet).unwrap();
        drop(wallet);
        let base = vec!["--wallet".into(), path.to_str().unwrap().into()];
        let mut selected = base.clone();
        selected.extend(["--salt".into(), hex::encode([7; 32])]);
        manage_accounts("account-add", &selected).unwrap();
        let active = load_wallet(path.to_str().unwrap()).unwrap().0.program_id;
        assert_ne!(active, zero);
        assert_eq!(
            wallet_program_id_from_file_bytes(&fs::read(&path).unwrap()).unwrap(),
            active
        );
        manage_accounts("accounts", &base).unwrap();
        let mut reset = base.clone();
        reset.extend(["--salt".into(), hex::encode([0; 32])]);
        manage_accounts("account-use", &reset).unwrap();
        assert_eq!(
            load_wallet(path.to_str().unwrap()).unwrap().0.program_id,
            zero
        );
        let recovered = directory.join("restored.json");
        restore_wallet(&[
            "--wallet".into(),
            recovered.to_str().unwrap().into(),
            "--mnemonic".into(),
            phrase.into(),
            "--salt".into(),
            hex::encode([7; 32]),
        ])
        .unwrap();
        assert_eq!(
            load_wallet(recovered.to_str().unwrap())
                .unwrap()
                .0
                .program_id,
            active
        );
        let mut unknown = base.clone();
        unknown.extend(["--salt".into(), hex::encode([8; 32])]);
        assert!(manage_accounts("account-use", &unknown).is_err());
        assert_eq!(
            load_wallet(path.to_str().unwrap()).unwrap().0.program_id,
            zero
        );
        let before = Zeroizing::new(fs::read(&path).unwrap());
        let mut candidate = account_wallet_from_file_bytes(&before).unwrap();
        candidate.select_account([9; 32]).unwrap();
        manage_accounts("account-use", &selected).unwrap();
        assert!(
            super::super::wallet_file::update_account_wallet(
                path.to_str().unwrap(),
                &candidate,
                &before
            )
            .is_err()
        );
        assert_eq!(
            load_wallet(path.to_str().unwrap()).unwrap().0.program_id,
            active
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(directory).unwrap();
    }
}
