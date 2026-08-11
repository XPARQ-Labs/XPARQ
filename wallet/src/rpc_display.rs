fn print_rpc_get(rpc_addr: &str, path: &str) -> Result<(), String> {
    let body = http_get(rpc_addr, path)?;
    print_rpc_response(path, &body)
}

fn status_value(rpc_addr: &str) -> Result<serde_json::Value, String> {
    let body = http_get(rpc_addr, "/status")?;
    serde_json::from_str(&body)
        .map_err(|error| format!("failed to parse rpc status response: {error}: {body}"))
}

fn print_rpc_response(path: &str, body: &str) -> Result<(), String> {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|error| format!("failed to parse rpc response: {error}: {body}"))?;
    let route = path.split('?').next().unwrap_or(path);
    if route.ends_with("/events") || route.starts_with("/events/") {
        print_protocol_events(&value);
    } else if route == "/health" {
        print_health(&value);
    } else if route == "/status" {
        print_status(&value);
    } else if path == "/chain" {
        print_chain(&value);
    } else if path == "/stats" || path == "/chain/stats" {
        print_chain_stats(&value);
    } else if path == "/peers" {
        print_peers(&value);
    } else if path.starts_with("/balance/") {
        print_balance(&value);
    } else if path == "/blocks/latest" {
        print_latest_blocks(&value);
    } else if route.starts_with("/blocks/") || route.starts_with("/blocks/hash/") {
        print_block(&value);
    } else if path.starts_with("/tx/") {
        print_transaction(&value);
    } else if path.starts_with("/address/") {
        print_address(&value);
    } else if path == "/accounts" {
        print_accounts(&value);
    } else if path == "/mempool" {
        print_mempool(&value);
    } else {
        print_pretty_json(&value);
    }
    Ok(())
}

fn print_protocol_events(value: &serde_json::Value) {
    if let Some(events) = value.get("events").and_then(serde_json::Value::as_array) {
        println!("Protocol Events ({})", value_text(value.get("total")));
        print_field("Offset", value_text(value.get("offset")));
        print_field("Limit", value_text(value.get("limit")));
        for (index, event) in events.iter().enumerate() {
            println!();
            println!("Event #{}", index + 1);
            print_protocol_event(event);
        }
    } else {
        println!("Protocol Event");
        print_protocol_event(value);
    }
}

fn print_protocol_event(response: &serde_json::Value) {
    let event = response.get("event").unwrap_or(response);
    print_field("Event ID", short_value(response.get("id")));
    print_field("Version", value_text(event.get("version")));
    print_field("Height", value_text(event.get("block_height")));
    print_field("Block", short_value(event.get("block_hash")));
    print_field("Transaction", short_value(event.get("transaction_hash")));
    print_field("Event index", value_text(event.get("event_index")));

    let Some(kind) = event.get("kind").and_then(serde_json::Value::as_object) else {
        print_field("Kind", "unknown");
        return;
    };
    let Some((name, fields)) = kind.iter().next() else {
        print_field("Kind", "unknown");
        return;
    };
    print_field("Kind", protocol_event_label(name));
    match name.as_str() {
        "Transfer" => {
            print_field("From", event_address_value(fields.get("from")));
            print_field("To", event_address_value(fields.get("to")));
            print_amount_field("Amount", fields.get("amount"));
        }
        "QCashWithdrawn" => {
            print_field("Signer", event_address_value(fields.get("signer")));
            print_amount_field("Amount", fields.get("amount"));
        }
        "QCashRedeemed" => {
            print_field("Signer", event_address_value(fields.get("signer")));
            print_field("Recipient", event_address_value(fields.get("recipient")));
            print_amount_field("Amount", fields.get("amount"));
        }
        "QCashRecoverRedeemed" => {
            print_field("Signer", event_address_value(fields.get("signer")));
            print_field("Claimant", event_address_value(fields.get("claimant")));
            print_amount_field("Amount", fields.get("amount"));
        }
        "EmissionDistributed" => {
            print_field("Miner", event_address_value(fields.get("miner")));
            print_amount_field("Subsidy", fields.get("subsidy"));
        }
        _ => print_pretty_json(fields),
    }
}

fn protocol_event_label(name: &str) -> &'static str {
    match name {
        "Transfer" => "transfer",
        "QCashWithdrawn" => "qcash withdrawn",
        "QCashRedeemed" => "qcash redeemed",
        "QCashRecoverRedeemed" => "legacy qcash recovery redeemed",
        "EmissionDistributed" => "emission distributed",
        _ => "unknown",
    }
}

fn print_health(value: &serde_json::Value) {
    println!("Health");
    print_field("OK", bool_text(value.get("ok")));
}

fn print_status(value: &serde_json::Value) {
    println!("Node Status");
    print_field("Chain", str_value(value.get("chain")));
    print_field("Stage", str_value(value.get("stage")));
    print_field("Protocol", value_text(value.get("protocol_version")));
    if let Some(memory_kib) = value
        .get("pow_memory_kib")
        .and_then(serde_json::Value::as_u64)
    {
        print_field("PoW memory", format!("{} MiB", memory_kib / 1024));
    }
    print_field("PoW passes", value_text(value.get("pow_iterations")));
    print_field("PoW lanes", value_text(value.get("pow_lanes")));
    print_field("Height", value_text(value.get("height")));
    print_field("Tip", short_value(value.get("tip_hash")));
    print_field(
        "Known",
        value_text(value.get("known_peers").or(value.get("peers"))),
    );
    print_field("Outbound", value_text(value.get("outbound_peers")));
    print_field("Inbound", value_text(value.get("inbound_peers")));
    print_field("Mining", bool_text(value.get("mining")));
    print_field("Hashrate", hashrate_text(value.get("hashrate_hps")));
    print_field("Last attempts", value_text(value.get("last_mine_attempts")));
}

fn print_hashrate(value: &serde_json::Value) {
    println!("Hashrate");
    print_field("Mining", bool_text(value.get("mining")));
    print_field("Hashrate", hashrate_text(value.get("hashrate_hps")));
    print_field("Last attempts", value_text(value.get("last_mine_attempts")));
}

fn print_chain(value: &serde_json::Value) {
    println!("Chain");
    print_field("Name", str_value(value.get("chain")));
    print_field("Coin", str_value(value.get("coin")));
    print_field("Stage", str_value(value.get("stage")));
    print_field("Protocol", value_text(value.get("protocol_version")));
    print_field("Confirmation", value_text(value.get("confirmation_depth")));
    print_field("Finality", value_text(value.get("finality_depth")));
    print_field("Difficulty", value_text(value.get("difficulty_start")));
}

fn print_chain_stats(value: &serde_json::Value) {
    println!("Global Chain Stats");
    print_field("Chain", str_value(value.get("chain")));
    print_field("Coin", str_value(value.get("coin")));
    print_field("Tip height", value_text(value.get("height")));
    print_field("Block count", value_text(value.get("blocks")));
    println!();
    print_amount_field("Current supply", value.get("current_supply"));
    print_amount_field("On-chain", value.get("onchain_supply"));
    print_amount_field("Off-chain", value.get("qcash_offchain_supply"));
    print_amount_field("QCash ready", value.get("qcash_redeemable_supply"));
    print_amount_field("QCash pending", value.get("qcash_pending_supply"));
    print_amount_field("Total known", value.get("total_known_supply"));
    print_amount_field("Genesis premine", value.get("genesis_premine"));
    print_amount_field("Cumulative subsidy", value.get("mined_supply"));
    println!();
    print_amount_field("Service revenue", value.get("service_revenue"));
    print_amount_field("Miner income", value.get("miner_income"));
    print_field("Tx count", value_text(value.get("total_transactions")));
    print_field(
        "Transfer tx",
        value_text(value.get("transfer_transactions")),
    );
    print_field("Pending tx", value_text(value.get("pending_transactions")));
    print_amount_field("Transfer vol", value.get("total_transfer_volume"));
    print_amount_field("Declared fees", value.get("total_transaction_fees"));
    print_amount_field("Avg transfer", value.get("average_transfer_amount"));
}

fn print_peers(value: &serde_json::Value) {
    let Some(peers) = value.as_array() else {
        print_pretty_json(value);
        return;
    };
    println!("Peers ({})", peers.len());
    for (index, peer) in peers.iter().enumerate() {
        println!();
        println!("Peer #{}", index + 1);
        print_field("Address", str_value(peer.get("addr")));
        print_field("Failures", value_text(peer.get("failures")));
        print_field("Last tip", value_text(peer.get("last_tip")));
    }
}

fn print_balance(value: &serde_json::Value) {
    println!("Balance");
    print_field("Address", short_value(value.get("address")));
    print_field("Height", value_text(value.get("height")));
    print_field("Exists", bool_text(value.get("exists")));
    print_field(
        "Authorization",
        authorization_text(value.get("authorization_registered")),
    );
    print_amount_field("Confirmed", value.get("confirmed"));
    print_amount_field("Available", value.get("available"));
    print_amount_field("Incoming", value.get("pending_incoming"));
    print_amount_field("Outgoing", value.get("pending_outgoing"));
    print_field("UTXOs", value_text(value.get("utxos")));
    print_amount_field("Unspendable", value.get("unspendable"));
}

fn print_wallet_balance_summary(
    rpc_addr: &str,
    address: &Address,
    cash_dir: &str,
) -> Result<(), String> {
    let address_text = address_to_string(address);
    let body = http_get(rpc_addr, &format!("/balance/{address_text}"))?;
    let balance: WalletBalanceRpcResponse = serde_json::from_str(&body)
        .map_err(|error| format!("failed to parse balance rpc response: {error}: {body}"))?;
    let draft = http_get(rpc_addr, &format!("/draft-basis/{address_text}"))
        .ok()
        .and_then(|body| serde_json::from_str::<DraftBasisRpcResponse>(&body).ok());
    let offchain = qcash_local_totals(std::path::Path::new(cash_dir), rpc_addr)?;
    let total_available = balance.available.saturating_add(offchain.redeemable);
    let total_known = balance.confirmed.saturating_add(offchain.known);

    println!("Wallet Balance");
    print_field("Address", short_text(&balance.address));
    print_field("Height", balance.height);
    print_field(
        "Authorization",
        if balance.authorization_registered {
            "registered"
        } else {
            "registration required"
        },
    );
    println!();
    print_field("On-chain", format_xpq(balance.confirmed));
    print_field("Available", format_xpq(balance.available));
    print_field("Incoming", format_xpq(balance.pending_incoming));
    print_field("Outgoing", format_xpq(balance.pending_outgoing));
    print_field("Locked", format_xpq(balance.unspendable));
    println!();
    print_field("QCash Balance", format_xpq(offchain.unredeemed));
    print_field("QCash files", offchain.files);
    print_field("QCash pending", format_xpq(offchain.pending));
    print_field("QCash redeemable", format_xpq(offchain.redeemable));
    print_field("QCash redeemed history", format_xpq(offchain.redeemed));
    println!();
    print_field("Total ready", format_xpq(total_available));
    print_field("Total known", format_xpq(total_known));
    if let Some(draft) = draft {
        println!();
        print_field(
            "After pending",
            format_xpq(draft.spendable_after_pending),
        );
        print_field("Finalized height", draft.finalized_height);
        if !draft.pending_outgoing_hashes.is_empty() {
            print_field(
            "Pending transactions",
                draft
                    .pending_outgoing_hashes
                    .iter()
                    .map(|hash| short_text(hash))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
    }
    Ok(())
}

fn print_latest_blocks(value: &serde_json::Value) {
    let Some(blocks) = value.as_array() else {
        print_pretty_json(value);
        return;
    };
    println!("Latest Blocks ({})", blocks.len());
    let tip_height = blocks
        .iter()
        .filter_map(|block| block.get("height").and_then(serde_json::Value::as_u64))
        .max();
    for (index, block) in blocks.iter().enumerate() {
        let previous_timestamp = blocks
            .get(index + 1)
            .and_then(|previous_block| previous_block.get("timestamp"))
            .and_then(serde_json::Value::as_u64);
        println!();
        print_block_with_context(block, tip_height, previous_timestamp);
    }
}

fn print_block(value: &serde_json::Value) {
    print_block_with_context(value, None, None);
}

fn print_block_with_context(
    value: &serde_json::Value,
    tip_height: Option<u64>,
    previous_timestamp: Option<u64>,
) {
    println!("Block #{}", value_text(value.get("height")));
    print_field("Hash", short_value(value.get("hash")));
    print_field("Previous", short_value(value.get("previous_hash")));
    print_field("Miner", short_value(value.get("miner_address")));
    print_field("Difficulty", value_text(value.get("difficulty")));
    print_field("Confirmations", confirmations_text(value, tip_height));
    if value
        .get("timestamp")
        .and_then(serde_json::Value::as_u64)
        .is_some_and(|timestamp| timestamp > 0)
    {
        print_field("Age", block_age_text(value));
        print_field("Block Mined", block_mined_text(value, previous_timestamp));
    }
    print_amount_text_field("Value Moved", value_moved_text(value));
    print_field("Nonce", value_text(value.get("nonce")));
    print_field("Tx count", value_text(value.get("tx_count")));
    print_field("Size", format!("{} bytes", value_text(value.get("size"))));
    if let Some(coinbase) = value.get("coinbase").and_then(serde_json::Value::as_object) {
        let subsidy = amount_text(coinbase.get("subsidy"));
        let to = short_value(coinbase.get("to"));
        print_field("Coinbase", format!("{subsidy} to {to}"));
        print_amount_field("Fees", coinbase.get("fees"));
        print_amount_field("Miner payout", coinbase.get("total"));
    }
    if value
        .get("timestamp")
        .and_then(serde_json::Value::as_u64)
        .is_some_and(|timestamp| timestamp > 0)
    {
        print_field("Timestamp", value_text(value.get("timestamp")));
    }
    print_transactions(value.get("transactions"));
}

fn print_transaction(value: &serde_json::Value) {
    println!("Transaction");
    print_tx_fields(value);
}

fn print_address(value: &serde_json::Value) {
    println!("Address");
    print_field("Address", short_value(value.get("address")));
    if let Some(balance) = value.get("balance") {
        println!();
        print_balance(balance);
    }
    print_mined_blocks(value.get("mined_blocks"));
    print_transactions(value.get("transactions"));
}

fn print_mined_blocks(value: Option<&serde_json::Value>) {
    let Some(blocks) = value.and_then(serde_json::Value::as_array) else {
        return;
    };
    println!();
    println!("Mined Blocks ({})", blocks.len());
    for (index, block) in blocks.iter().enumerate() {
        println!();
        println!("Mined #{}", index + 1);
        print_field("Height", value_text(block.get("height")));
        print_field("Hash", short_value(block.get("hash")));
        print_field("Matured", bool_text(block.get("matured")));
        print_field("Matures at", value_text(block.get("maturity_height")));
        print_amount_field("Subsidy", block.get("subsidy"));
        print_amount_field("Fees", block.get("fees"));
        print_amount_field("Total", block.get("total"));
        print_field("Tx count", value_text(block.get("tx_count")));
    }
}

fn print_accounts(value: &serde_json::Value) {
    let Some(accounts) = value.as_array() else {
        print_pretty_json(value);
        return;
    };
    println!("Accounts ({})", accounts.len());
    for (index, account) in accounts.iter().enumerate() {
        println!();
        println!("Account #{}", index + 1);
        print_account(account);
    }
}

fn print_account(account: &serde_json::Value) {
    print_field("Address", short_value(account.get("address")));
    print_amount_field("Confirmed", account.get("confirmed"));
    print_amount_field("Available", account.get("available"));
    print_amount_field("Unspendable", account.get("unspendable"));
    print_amount_field("Incoming", account.get("pending_incoming"));
    print_amount_field("Outgoing", account.get("pending_outgoing"));
    print_field(
        "Authorization",
        authorization_text(account.get("authorization_registered")),
    );
    print_field("UTXOs", value_text(account.get("utxos")));
}

fn print_mempool(value: &serde_json::Value) {
    println!("Mempool");
    print_field("Size", value_text(value.get("size")));
    print_transactions(value.get("transactions"));
}

fn print_transactions(value: Option<&serde_json::Value>) {
    let Some(transactions) = value.and_then(serde_json::Value::as_array) else {
        return;
    };
    println!();
    println!("Transactions ({}, newest first)", transactions.len());
    for tx in transactions {
        println!();
        print_tx_fields(tx);
    }
}

fn print_tx_fields(value: &serde_json::Value) {
    print_field("Family", str_value(value.get("family")));
    print_field("Operation", str_value(value.get("operation")));
    print_field(
        "Txid",
        short_value(value.get("txid").or_else(|| value.get("hash"))),
    );
    print_field(
        "Signer",
        short_value(
            value
                .get("signer")
                .or_else(|| value.get("from"))
                .or_else(|| value.get("address")),
        ),
    );
    print_field(
        "Recipient",
        short_value(value.get("recipient").or_else(|| value.get("to"))),
    );
    print_amount_field("Amount", value.get("amount"));
    if value
        .get("valid_from")
        .and_then(serde_json::Value::as_u64)
        .is_some_and(|height| height > 0)
    {
        print_field("Valid from", value_text(value.get("valid_from")));
    }
    if value
        .get("valid_until")
        .and_then(serde_json::Value::as_u64)
        .is_some_and(|height| height > 0)
    {
        print_field("Valid until", value_text(value.get("valid_until")));
    }
    print_field("Virtual size", value_text(value.get("virtual_size")));
    if value.get("age_secs").and_then(serde_json::Value::as_u64).is_some() {
        print_field("Age", tx_age_text(value));
    }
    if value
        .get("timestamp")
        .and_then(serde_json::Value::as_u64)
        .is_some_and(|timestamp| timestamp > 0)
    {
        print_field("Timestamp", value_text(value.get("timestamp")));
    }
    print_field("Height", value_text(value.get("block_height")));
    print_field("Block", short_value(value.get("block_hash")));
    print_field("Confirmations", value_text(value.get("confirmations")));
    print_field("Depth", value_text(value.get("depth")));
    if let (Some(confirmation_depth), Some(finality_depth)) = (
        value
            .get("confirmation_depth")
            .and_then(serde_json::Value::as_u64),
        value
            .get("finality_depth")
            .and_then(serde_json::Value::as_u64),
    ) {
        print_field(
            "Thresholds",
            format!("confirmed ≥ {confirmation_depth}, finalized ≥ {finality_depth} depth"),
        );
    }
    print_field("Status", transaction_status_text(value));
}

fn transaction_status_text(value: &serde_json::Value) -> String {
    match value
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
    {
        "pending" => "pending — waiting in mempool".to_string(),
        "included" => "included — in canonical block, awaiting confirmation".to_string(),
        "confirmed" => "confirmed — confirmation threshold reached".to_string(),
        "finalized" => "finalized — finality threshold reached".to_string(),
        "rejected" => "rejected — node did not accept transaction".to_string(),
        "expired" => "expired — validity window ended".to_string(),
        "dropped" => "dropped — removed from mempool".to_string(),
        "reverted" => "reverted — removed by chain reorganization".to_string(),
        "conflicted" => "conflicted — canonical chain already consumed an input coin".to_string(),
        status => format!("unknown ({status})"),
    }
}

fn print_field(label: &str, value: impl std::fmt::Display) {
    println!("{label:<13} : {value}");
}

fn print_amount_field(label: &str, value: Option<&serde_json::Value>) {
    print_field(label, amount_text(value));
}

fn print_amount_text_field(label: &str, value: impl AsRef<str>) {
    print_field(label, amount_units_text(value.as_ref()));
}

fn print_pretty_json(value: &serde_json::Value) {
    match serde_json::to_string_pretty(value) {
        Ok(pretty) => println!("{pretty}"),
        Err(_) => println!("{value}"),
    }
}

fn value_text(value: Option<&serde_json::Value>) -> String {
    match value {
        Some(serde_json::Value::Null) | None => "none".to_string(),
        Some(serde_json::Value::String(value)) => value.clone(),
        Some(value) => value.to_string(),
    }
}

fn amount_text(value: Option<&serde_json::Value>) -> String {
    match value {
        Some(serde_json::Value::Number(number)) => amount_units_text(&number.to_string()),
        Some(serde_json::Value::String(value)) => amount_units_text(value),
        Some(serde_json::Value::Null) | None => "none".to_string(),
        Some(value) => amount_units_text(&value.to_string()),
    }
}

fn amount_units_text(value: &str) -> String {
    let Ok(units) = value.parse::<u64>() else {
        return value.to_string();
    };
    format_xpq(units)
}

fn format_xpq(units: u64) -> String {
    let whole = units / XPQ;
    let fractional = units % XPQ;
    format!(
        "{}.{fractional:0width$} XPQ",
        format_grouped_u64(whole),
        width = DECIMALS as usize
    )
}

fn format_grouped_u64(value: u64) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

fn block_age_text(value: &serde_json::Value) -> String {
    if let Some(age_secs) = value.get("age_secs").and_then(serde_json::Value::as_u64) {
        return format!("{} ago", format_duration(age_secs));
    }

    let Some(timestamp) = value.get("timestamp").and_then(serde_json::Value::as_u64) else {
        return "unknown".to_string();
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(timestamp);
    format!("{} ago", format_duration(now.saturating_sub(timestamp)))
}

fn tx_age_text(value: &serde_json::Value) -> String {
    if let Some(age_secs) = value.get("age_secs").and_then(serde_json::Value::as_u64) {
        return format!("{} ago", format_duration(age_secs));
    }

    let Some(timestamp) = value.get("timestamp").and_then(serde_json::Value::as_u64) else {
        return "unknown".to_string();
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(timestamp);
    format!("{} ago", format_duration(now.saturating_sub(timestamp)))
}

fn confirmations_text(value: &serde_json::Value, tip_height: Option<u64>) -> String {
    if let Some(confirmations) = value
        .get("confirmations")
        .and_then(serde_json::Value::as_u64)
    {
        return confirmations.to_string();
    }

    let Some(height) = value.get("height").and_then(serde_json::Value::as_u64) else {
        return "unknown".to_string();
    };
    tip_height
        .map(|tip| tip.saturating_sub(height).saturating_add(1).to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn block_mined_text(value: &serde_json::Value, previous_timestamp: Option<u64>) -> String {
    let seconds = value
        .get("timestamp")
        .and_then(serde_json::Value::as_u64)
        .and_then(|timestamp| Some(timestamp.saturating_sub(previous_timestamp?)));
    let Some(seconds) = seconds else {
        return "unknown".to_string();
    };
    format_duration(seconds)
}

fn value_moved_text(value: &serde_json::Value) -> String {
    if let Some(value_moved) = value.get("value_moved").and_then(serde_json::Value::as_u64) {
        return value_moved.to_string();
    }

    value
        .get("transactions")
        .and_then(serde_json::Value::as_array)
        .map(|transactions| {
            transactions
                .iter()
                .filter_map(|transaction| {
                    transaction
                        .get("amount")
                        .and_then(serde_json::Value::as_u64)
                })
                .sum::<u64>()
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn hashrate_text(value: Option<&serde_json::Value>) -> String {
    let Some(hashrate) = value.and_then(serde_json::Value::as_u64) else {
        return "unknown".to_string();
    };
    format_hashrate(hashrate)
}

fn format_hashrate(hashrate: u64) -> String {
    let units = ["H/s", "KH/s", "MH/s", "GH/s", "TH/s", "PH/s"];
    let mut value = hashrate as f64;
    let mut unit = units[0];
    for next_unit in units.iter().skip(1) {
        if value < 1_000.0 {
            break;
        }
        value /= 1_000.0;
        unit = next_unit;
    }

    if unit == units[0] {
        format!("{hashrate} {unit}")
    } else {
        format!("{value:.2} {unit}")
    }
}

fn format_duration(seconds: u64) -> String {
    match seconds {
        0..=59 => format!("{seconds} sec"),
        60..=3_599 => {
            let minutes = seconds / 60;
            if minutes == 1 {
                "1 minute".to_string()
            } else {
                format!("{minutes} minutes")
            }
        }
        3_600..=86_399 => {
            let hours = seconds / 3_600;
            if hours == 1 {
                "1 hour".to_string()
            } else {
                format!("{hours} hours")
            }
        }
        _ => {
            let days = seconds / 86_400;
            if days == 1 {
                "1 day".to_string()
            } else {
                format!("{days} days")
            }
        }
    }
}

fn str_value(value: Option<&serde_json::Value>) -> String {
    value
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| value_text(value))
}

fn short_value(value: Option<&serde_json::Value>) -> String {
    if let Some(bytes) = value.and_then(json_byte_array) {
        return hex::encode(bytes);
    }
    str_value(value)
}

fn event_address_value(value: Option<&serde_json::Value>) -> String {
    let Some(bytes) = value.and_then(json_byte_array) else {
        return short_value(value);
    };
    let Ok(bytes) = <[u8; 20]>::try_from(bytes.as_slice()) else {
        return hex::encode(bytes);
    };
    address_to_string(&Address(bytes))
}

fn json_byte_array(value: &serde_json::Value) -> Option<Vec<u8>> {
    value
        .as_array()?
        .iter()
        .map(|byte| byte.as_u64().and_then(|byte| u8::try_from(byte).ok()))
        .collect()
}

fn bool_text(value: Option<&serde_json::Value>) -> &'static str {
    match value.and_then(serde_json::Value::as_bool) {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

fn authorization_text(value: Option<&serde_json::Value>) -> &'static str {
    match value.and_then(serde_json::Value::as_bool) {
        Some(true) => "registered",
        Some(false) => "registration required",
        None => "unknown",
    }
}

fn short_text(value: &str) -> String {
    value.to_string()
}
