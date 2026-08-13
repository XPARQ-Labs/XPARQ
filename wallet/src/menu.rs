fn interactive_menu() -> Result<(), String> {
    cli_log("INFO", format_args!("interactive session started"));
    loop {
        println!();
        println!("XPARQ Wallet CLI");
        println!("1. Create wallet");
        println!("2. Import wallet");
        println!("3. Accounts");
        println!("4. Global chain stats");
        println!("5. Send coin");
        println!("6. QCash");
        println!("7. RPC");
        println!("8. Block explorer");
        println!("9. Mempool");
        println!("10. Hashrate");
        println!("11. Protocol events");
        println!("13. Trusted proof/checkpoint");
        println!("14. Exit");
        println!("Type b/back to return from prompts.");

        let choice = prompt("Select")?;
        if choice == "14" {
            return Ok(());
        }
        match handle_menu_choice(&choice) {
            Ok(true) => pause_for_menu()?,
            Ok(false) => {}
            Err(error) => {
                cli_log("ERROR", format_args!("{error}"));
                println!("Returning to menu.");
                pause_for_menu()?;
            }
        }
    }
}

fn handle_menu_choice(choice: &str) -> Result<bool, String> {
    match choice {
        "b" | "back" => {}
        "1" => {
            let Some(path) = prompt_default_back("Wallet file", DEFAULT_WALLET_PATH)? else {
                return Ok(false);
            };
            println!("Mnemonic length");
            println!("1. 12 words");
            println!("2. 24 words");
            let Some(words_choice) = prompt_default_back("Select", "1")? else {
                return Ok(false);
            };
            let words = mnemonic_words_from_menu_selection(&words_choice)?.to_string();
            wallet_new(&[path, "--words".to_string(), words])?;
            return Ok(true);
        }
        "2" => {
            let Some(path) = prompt_default_back("Wallet file", DEFAULT_IMPORTED_WALLET_PATH)?
            else {
                return Ok(false);
            };
            let mnemonic = prompt_hidden("Mnemonic")?;
            if is_back(&mnemonic) {
                return Ok(false);
            }
            wallet_restore_mnemonic(&[path, "--mnemonic".to_string(), mnemonic.to_string()])?;
            return Ok(true);
        }
        "3" => return menu_accounts(),
        "4" => {
            let rpc_addr = default_rpc_addr();
            print_global_stats(&rpc_addr)?;
            return Ok(true);
        }
        "5" => return menu_send_coin(),
        "6" => return menu_qcash(),
        "7" => return menu_rpc_explorer(),
        "8" => return menu_block_explorer(),
        "9" => menu_rpc_get("/mempool")?,
        "10" => menu_hashrate()?,
        "11" => return menu_protocol_events(),
        "13" => return menu_trusted_proof(),
        value => return Err(format!("unknown menu `{value}`; choose 1-14")),
    }
    Ok(true)
}

fn menu_accounts() -> Result<bool, String> {
    println!("Accounts");
    println!("1. My Accounts");
    println!("2. Wallet balance");
    println!("3. Wallet activity and statistics");
    println!("4. Global Accounts");
    println!("5. Address Explorer");
    let Some(choice) = prompt_back("Select")? else {
        return Ok(false);
    };
    match choice.as_str() {
        "1" => menu_my_accounts(),
        "2" => {
            let Some(wallet) = prompt_default_back("Wallet file", DEFAULT_WALLET_PATH)? else {
                return Ok(false);
            };
            wallet_balance(&["--wallet".into(), wallet, "--rpc".into(), default_rpc_addr()])?;
            Ok(true)
        }
        "3" => {
            let Some(wallet) = prompt_default_back("Wallet file", DEFAULT_WALLET_PATH)? else {
                return Ok(false);
            };
            wallet_address_stats(&[
                "--wallet".into(),
                wallet,
                "--rpc".into(),
                default_rpc_addr(),
            ])?;
            Ok(true)
        }
        "4" => {
            menu_rpc_get("/accounts")?;
            Ok(true)
        }
        "5" => {
            let Some(address) =
                prompt_default_back("Address", &default_wallet_address_or_empty())?
            else {
                return Ok(false);
            };
            if address.is_empty() {
                return Err("address is required and no default wallet could be loaded".into());
            }
            menu_rpc_get(&format!("/address/{address}"))?;
            Ok(true)
        }
        value => Err(format!("unknown accounts selection `{value}`; choose 1-5")),
    }
}

fn menu_rpc_explorer() -> Result<bool, String> {
    println!("RPC");
    println!("1. Health");
    println!("2. Status");
    println!("3. Peers");
    println!("4. Chain");
    println!("5. Change RPC for this session");
    let Some(choice) = prompt_back("Select")? else {
        return Ok(false);
    };
    match choice.as_str() {
        "1" => menu_rpc_get("/health")?,
        "2" => menu_rpc_get("/status")?,
        "3" => menu_rpc_get("/peers")?,
        "4" => menu_rpc_get("/chain")?,
        "5" => {
            let Some(rpc_addr) = prompt_default_back("RPC address", &default_rpc_addr())? else {
                return Ok(false);
            };
            // SAFETY: This CLI is single-threaded while the menu is active.
            unsafe {
                env::set_var(RPC_ADDR_ENV, rpc_addr);
            }
            println!("RPC address set to {}", default_rpc_addr());
        }
        value => return Err(format!("unknown RPC selection `{value}`; choose 1-5")),
    }
    Ok(true)
}

fn menu_block_explorer() -> Result<bool, String> {
    println!("Block Explorer");
    println!("1. Latest blocks");
    println!("2. Block by height");
    println!("3. Block by hash");
    println!("4. Transaction by hash");
    let Some(choice) = prompt_back("Select")? else {
        return Ok(false);
    };
    match choice.as_str() {
        "1" => menu_rpc_get("/blocks/latest")?,
        "2" => {
            let Some(height) = prompt_back("Block height")? else {
                return Ok(false);
            };
            menu_rpc_get(&format!("/blocks/{height}"))?;
        }
        "3" => {
            let Some(hash) = prompt_back("Block hash")? else {
                return Ok(false);
            };
            menu_rpc_get(&format!("/blocks/hash/{hash}"))?;
        }
        "4" => {
            let Some(hash) = prompt_back("Transaction hash")? else {
                return Ok(false);
            };
            menu_rpc_get(&format!("/tx/{hash}"))?;
        }
        value => return Err(format!("unknown block explorer selection `{value}`; choose 1-4")),
    }
    Ok(true)
}

fn menu_trusted_proof() -> Result<bool, String> {
    println!("Trusted Proof / Checkpoint");
    println!("1. Verify my account and update checkpoint");
    println!("2. Verify QCash coin and update checkpoint");
    println!("3. Show checkpoint");
    let Some(choice) = prompt_back("Select")? else {
        return Ok(false);
    };
    let Some(wallet) = prompt_default_back("Wallet file", DEFAULT_WALLET_PATH)? else {
        return Ok(false);
    };
    match choice.as_str() {
        "1" => wallet_proof(&[
            "account".into(),
            "--wallet".into(),
            wallet,
            "--rpc".into(),
            default_rpc_addr(),
        ])?,
        "2" => {
            let Some(coin_id) = prompt_back("QCash coin id")? else {
                return Ok(false);
            };
            wallet_proof(&[
                "qcash".into(),
                coin_id,
                "--wallet".into(),
                wallet,
                "--rpc".into(),
                default_rpc_addr(),
            ])?;
        }
        "3" => wallet_proof(&["status".into(), "--wallet".into(), wallet])?,
        _ => return Err(format!("unknown trusted proof selection `{choice}`")),
    }
    Ok(true)
}

fn menu_protocol_events() -> Result<bool, String> {
    println!("Protocol Event Explorer");
    println!("1. Events by block height");
    println!("2. Events by transaction hash");
    println!("3. Events by address");
    println!("4. Event by event ID");
    let Some(choice) = prompt_back("Select")? else {
        return Ok(false);
    };
    let (scope, label, default_value) = match choice.as_str() {
        "1" => ("block", "Block height", String::new()),
        "2" => ("tx", "Transaction hash", String::new()),
        "3" => ("address", "Address", default_wallet_address_or_empty()),
        "4" => ("id", "Event ID", String::new()),
        _ => return Err(format!("unknown event explorer selection `{choice}`; choose 1-4")),
    };
    let Some(value) = prompt_default_back(label, &default_value)? else {
        return Ok(false);
    };
    if value.is_empty() {
        return Err(format!("{label} is required"));
    }
    let mut args = vec![scope.to_string(), value];
    if scope != "id" {
        println!("Event kind filter");
        println!("0. All events");
        println!("1. Transfer");
        println!("2. QCash withdrawn");
        println!("3. QCash redeemed");
        println!("4. QCash split");
        println!("5. Emission distributed");
        let Some(selection) = prompt_default_back("Select kind", "0")? else {
            return Ok(false);
        };
        let kind = event_kind_from_menu_selection(&selection)?;
        if let Some(kind) = kind {
            args.extend(["--kind".to_string(), kind]);
        }
        let Some(limit) = prompt_default_back("Limit", "100")? else {
            return Ok(false);
        };
        args.extend(["--limit".to_string(), limit]);
        let Some(offset) = prompt_default_back("Offset", "0")? else {
            return Ok(false);
        };
        args.extend(["--offset".to_string(), offset]);
        let Some(from_height) = prompt_back("From height (optional)")? else {
            return Ok(false);
        };
        if !from_height.is_empty() {
            args.extend(["--from-height".to_string(), from_height]);
        }
        let Some(to_height) = prompt_back("To height (optional)")? else {
            return Ok(false);
        };
        if !to_height.is_empty() {
            args.extend(["--to-height".to_string(), to_height]);
        }
    }
    args.extend(["--rpc".to_string(), default_rpc_addr()]);
    wallet_events(&args)?;
    Ok(true)
}

fn event_kind_from_menu_selection(selection: &str) -> Result<Option<String>, String> {
    match selection.trim() {
        "" | "0" => Ok(None),
        "1" => Ok(Some("transfer".to_string())),
        "2" => Ok(Some("qcash_withdrawn".to_string())),
        "3" => Ok(Some("qcash_redeemed".to_string())),
        "4" => Ok(Some("qcash_split".to_string())),
        "5" => Ok(Some("emission_distributed".to_string())),
        value => Err(format!("unknown event kind selection `{value}`; choose 0-5")),
    }
}

fn mnemonic_words_from_menu_selection(selection: &str) -> Result<usize, String> {
    match selection.trim() {
        "" | "1" => Ok(12),
        "2" => Ok(24),
        value => Err(format!("unknown mnemonic length selection `{value}`; choose 1-2")),
    }
}

fn menu_my_accounts() -> Result<bool, String> {
    println!("My Accounts");
    let Some(directory) = prompt_default_back("Wallet directory", ".")? else {
        return Ok(false);
    };
    let Some(cash_dir) = prompt_default_back("Cash directory", "./cash")? else {
        return Ok(false);
    };
    let rpc_addr = default_rpc_addr();
    let wallets = discover_wallet_files(&directory)?;
    if wallets.is_empty() {
        println!("No wallet .json files found in {directory}.");
        return Ok(true);
    }
    for wallet_path in wallets {
        match load_wallet_address(&wallet_path) {
            Ok(address) => {
                println!();
                println!("wallet: {wallet_path}");
                println!("address: {}", address_to_string(&address));
                if let Err(error) = print_wallet_balance_summary(&rpc_addr, &address, &cash_dir) {
                    println!("balance: unavailable ({error})");
                }
            }
            Err(error) => {
                println!("wallet: {wallet_path}");
                println!("status: skipped ({error})");
            }
        }
    }
    Ok(true)
}

fn discover_wallet_files(directory: &str) -> Result<Vec<String>, String> {
    let mut wallets = Vec::new();
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("failed to read wallet directory {directory}: {error}"))?
    {
        let entry = entry.map_err(|error| format!("failed to read directory entry: {error}"))?;
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let path_string = path.to_string_lossy().into_owned();
        if load_wallet_address(&path_string).is_ok() {
            wallets.push(path_string);
        }
    }
    wallets.sort();
    Ok(wallets)
}

fn menu_qcash() -> Result<bool, String> {
    println!("QCash");
    println!("1. Withdraw QCash");
    println!("2. Redeem QCash");
    println!("3. Inspect QCash");
    println!("4. List QCash");
    println!("5. Backup QCash");
    println!("6. Recover QCash");
    println!("7. Track QCash");
    println!("8. QCash UTXO Explorer");
    println!("9. Split QCash");
    let Some(choice) = prompt_back("Select")? else {
        return Ok(false);
    };
    match choice.as_str() {
        "1" => {
            let Some(amount) = prompt_back("Amount XPQ")? else {
                return Ok(false);
            };
            println!("QCash file mode");
            println!("1. One file for the full amount");
            println!("2. Enter exact file amounts");
            let Some(amount_mode) = prompt_default_back("Select", "1")? else {
                return Ok(false);
            };
            let amounts = match amount_mode.trim() {
                "" | "1" => None,
                "2" => {
                    println!("Example: 50,20,29.9 (must total the requested amount)");
                    let Some(value) = prompt_back("File amounts XPQ, separated by commas")? else {
                        return Ok(false);
                    };
                    Some(value)
                }
                value => return Err(format!("unknown QCash file mode `{value}`; choose 1-2")),
            };
            let Some(output) = prompt_default_back("Cash directory", "./cash")? else {
                return Ok(false);
            };
            println!("Miner fee output");
            println!("1. Automatic (recommended)");
            println!("2. Custom XPQ amount");
            let Some(fee_choice) = prompt_default_back("Select", "1")? else {
                return Ok(false);
            };
            let fee = match fee_choice.trim() {
                "" | "1" => "auto".to_string(),
                "2" => {
                    let Some(value) = prompt_back("Custom fee XPQ")? else {
                        return Ok(false);
                    };
                    value
                }
                value => return Err(format!("unknown fee selection `{value}`; choose 1-2")),
            };
            let Some(wallet) = prompt_default_back("Wallet file", DEFAULT_WALLET_PATH)? else {
                return Ok(false);
            };
            let mut withdraw_args = vec![
                amount,
                "--out".into(),
                output,
                "--fee".into(),
                fee,
                "--wallet".into(),
                wallet,
                "--rpc".into(),
                default_rpc_addr(),
            ];
            if let Some(amounts) = amounts {
                withdraw_args.push("--amounts".into());
                withdraw_args.push(amounts);
            }
            wallet_cash_withdraw(&withdraw_args)?;
        }
        "2" => {
            let Some(file) = prompt_back("QCash file (.QCash)")? else {
                return Ok(false);
            };
            let Some(recipient) =
                prompt_default_back("Recipient", &default_wallet_address_or_empty())?
            else {
                return Ok(false);
            };
            if recipient.is_empty() {
                return Err("recipient address is required".to_string());
            }
            let Some(redeem_amount) =
                prompt_default_back("Recipient amount XPQ (blank = full value)", "")?
            else {
                return Ok(false);
            };
            println!("Miner fee output");
            println!("1. Automatic (recommended)");
            println!("2. Custom XPQ amount");
            let Some(fee_choice) = prompt_default_back("Select", "1")? else {
                return Ok(false);
            };
            let fee = match fee_choice.trim() {
                "" | "1" => "auto".to_string(),
                "2" => {
                    let Some(value) = prompt_back("Custom fee XPQ")? else {
                        return Ok(false);
                    };
                    value
                }
                value => return Err(format!("unknown fee selection `{value}`; choose 1-2")),
            };
            let Some(wallet) = prompt_default_back("Signing wallet", DEFAULT_WALLET_PATH)? else {
                return Ok(false);
            };
            let mut redeem_args = vec![
                file,
                "--to".into(),
                recipient,
                "--fee".into(),
                fee,
                "--wallet".into(),
                wallet,
                "--rpc".into(),
                default_rpc_addr(),
            ];
            if !redeem_amount.trim().is_empty() {
                redeem_args.push("--amount".into());
                redeem_args.push(redeem_amount);
                redeem_args.push("--out".into());
                redeem_args.push("./cash".into());
            }
            wallet_cash_redeem(&redeem_args)?;
        }
        "3" => {
            let Some(path) = prompt_back("Cash file")? else {
                return Ok(false);
            };
            wallet_cash(&["inspect".into(), path])?;
        }
        "4" => {
            let Some(path) = prompt_default_back("Cash directory", "./cash")? else {
                return Ok(false);
            };
            wallet_cash_list(&[path])?;
        }
        "5" => {
            let Some(source) = prompt_default_back("Cash directory", "./cash")? else {
                return Ok(false);
            };
            let Some(destination) = prompt_back("New backup directory")? else {
                return Ok(false);
            };
            wallet_cash_backup(&[source, destination])?;
        }
        "6" => {
            let Some(backup) = prompt_back("Backup directory")? else {
                return Ok(false);
            };
            let Some(destination) = prompt_default_back("Cash directory", "./cash")? else {
                return Ok(false);
            };
            wallet_cash_recover(&[backup, destination])?;
        }
        "7" => {
            let Some(name) = prompt_back("QCash file name or full coin id")? else {
                return Ok(false);
            };
            wallet_cash_track(&[name, "--rpc".into(), default_rpc_addr()])?;
        }
        "8" => {
            wallet_cash_utxos(&["--rpc".into(), default_rpc_addr()])?;
        }
        "9" => {
            let Some(file) = prompt_back("QCash file (.QCash)")? else {
                return Ok(false);
            };
            println!("The remaining value after these amounts and the fee becomes another file.");
            let Some(amounts) = prompt_back("New file amounts XPQ, separated by commas")? else {
                return Ok(false);
            };
            println!("Miner fee output");
            println!("1. Automatic (recommended)");
            println!("2. Custom XPQ amount");
            let Some(fee_choice) = prompt_default_back("Select", "1")? else {
                return Ok(false);
            };
            let fee = match fee_choice.trim() {
                "" | "1" => "auto".to_string(),
                "2" => {
                    let Some(value) = prompt_back("Custom fee XPQ")? else {
                        return Ok(false);
                    };
                    value
                }
                value => return Err(format!("unknown fee selection `{value}`; choose 1-2")),
            };
            let Some(output) = prompt_default_back("Cash directory", "./cash")? else {
                return Ok(false);
            };
            let Some(wallet) = prompt_default_back("Signing wallet", DEFAULT_WALLET_PATH)? else {
                return Ok(false);
            };
            wallet_cash_split(&[
                file,
                "--amounts".into(),
                amounts,
                "--fee".into(),
                fee,
                "--out".into(),
                output,
                "--wallet".into(),
                wallet,
                "--rpc".into(),
                default_rpc_addr(),
            ])?;
        }
        value => return Err(format!("unknown QCash selection `{value}`; choose 1-9")),
    }
    Ok(true)
}

fn menu_send_coin() -> Result<bool, String> {
    menu_transfer()
}

fn menu_transfer() -> Result<bool, String> {
    println!("Transfer");
    let Some(to) = prompt_back("Recipient address")? else {
        return Ok(false);
    };
    let Some(amount) = prompt_back("Amount XPQ")? else {
        return Ok(false);
    };
    submit_menu_transfer(to, amount)
}

fn submit_menu_transfer(to: String, amount: String) -> Result<bool, String> {
    println!("Miner fee output");
    println!("1. Automatic (recommended)");
    println!("2. Custom XPQ amount");
    let Some(fee_choice) = prompt_default_back("Select", "1")? else {
        return Ok(false);
    };
    let fee = match fee_choice.trim() {
        "" | "1" => DEFAULT_TRANSACTION_FEE_XPQ.to_string(),
        "2" => {
            let Some(value) = prompt_back("Custom fee XPQ")? else {
                return Ok(false);
            };
            value
        }
        value => return Err(format!("unknown fee selection `{value}`; choose 1-2")),
    };
    let Some(wallet_path) = prompt_default_back("Wallet file", DEFAULT_WALLET_PATH)? else {
        return Ok(false);
    };
    let rpc_addr = default_rpc_addr();
    let mut args = vec![to, amount];
    if fee != "auto" {
        args.push("--fee".to_string());
        args.push(fee);
    }
    args.push("--wallet".to_string());
    args.push(wallet_path);
    args.push("--rpc".to_string());
    args.push(rpc_addr);
    let Some(confirm) = prompt_default_back("Submit transaction? (yes/no)", "no")? else {
        return Ok(false);
    };
    if !matches!(confirm.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        return Err("transaction cancelled before signing".to_string());
    }
    wallet_send_short(&args)?;
    Ok(true)
}

fn menu_rpc_get(path: &str) -> Result<(), String> {
    let rpc_addr = default_rpc_addr();
    print_rpc_get(&rpc_addr, path)
}

fn menu_hashrate() -> Result<(), String> {
    let rpc_addr = default_rpc_addr();
    print_hashrate(&status_value(&rpc_addr)?);
    Ok(())
}
