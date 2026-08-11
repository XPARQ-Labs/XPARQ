async fn rpc_tx(
    State(state): State<RpcState>,
    AxumPath(hash): AxumPath<String>,
) -> impl IntoResponse {
    let hash = match parse_hash_hex(&hash) {
        Ok(hash) => TransactionHash(hash.0),
        Err(error) => return rpc_error(StatusCode::BAD_REQUEST, error),
    };
    let node = Arc::clone(&state.node);
    match state.state_pipeline.run(move || match node.lock() {
        Ok(node) => {
            for transaction in node.mempool.transactions() {
                if transaction.hash().is_ok_and(|txid| txid == hash) {
                    return match protocol_tx_response(transaction, None, None, None) {
                        Ok(response) => Json(response).into_response(),
                        Err(error) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error),
                    };
                }
            }
            match node.storage.load_protocol_transaction(&hash) {
                Ok(Some((location, transaction))) => {
                    match protocol_tx_response(
                        &transaction,
                        Some(location.block_height),
                        Some(location.block_hash),
                        node.tip_height(),
                    ) {
                        Ok(response) => Json(response).into_response(),
                        Err(error) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error),
                    }
                }
                Ok(None) => rpc_error(StatusCode::NOT_FOUND, "transaction_not_found"),
                Err(error) => rpc_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to load transaction: {error}"),
                ),
            }
        }
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }).await {
        Ok(response) => response,
        Err(error) => rpc_state_pipeline_error(error),
    }
}

async fn rpc_address(
    State(state): State<RpcState>,
    AxumPath(address): AxumPath<String>,
) -> impl IntoResponse {
    let address = match parse_address_string(&address) {
        Ok(address) => address,
        Err(error) => return rpc_error(StatusCode::BAD_REQUEST, error),
    };
    match state.node.lock() {
        Ok(node) => {
            Json(AddressResponse {
                address: address_to_string(&address),
                balance: balance_value(&node, &address),
                mined_blocks: Vec::new(),
                transactions: Vec::new(),
            })
            .into_response()
        }
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}

async fn rpc_accounts(
    State(state): State<RpcState>,
    Query(query): Query<ListQuery>,
) -> impl IntoResponse {
    match state.node.lock() {
        Ok(node) => {
            let height = node.tip_height().unwrap_or(Height(0));
            let accounts = node
                .ledger
                .accounts()
                .values()
                .skip(query.bounds().0)
                .take(query.bounds().1)
                .map(|account| {
                    let pending = node.pending_balance(&account.address);
                    account_response(&node, account, height, pending)
                })
                .collect::<Vec<_>>();
            Json(accounts).into_response()
        }
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}


fn account_response(
    node: &Node,
    account: &xparq::state::Account,
    height: Height,
    pending: crate::runtime::node::node::PendingBalance,
) -> AccountResponse {
    let confirmed = node
        .ledger
        .xpq_utxos
        .balance(account.address)
        .unwrap_or(xparq::consensus::supply::Amount(0));
    let available = node
        .ledger
        .xpq_utxos
        .available_balance(account.address, height)
        .unwrap_or(xparq::consensus::supply::Amount(0));
    AccountResponse {
        address: address_to_string(&account.address),
        confirmed: confirmed.0,
        available: available.0,
        unspendable: confirmed.0.saturating_sub(available.0),
        pending_incoming: pending.incoming.0,
        pending_outgoing: pending.outgoing.0,
        authorization_registered: account.authorization.is_some(),
        utxos: node
            .ledger
            .xpq_utxos
            .coins_for_owner(account.address)
            .count(),
    }
}


async fn rpc_mempool(
    State(state): State<RpcState>,
    Query(query): Query<ListQuery>,
) -> impl IntoResponse {
    match state.node.lock() {
        Ok(node) => {
            let total = node.mempool.len();
            let (offset, limit) = query.bounds();
            let transactions = node
                .mempool
                .transactions()
                .skip(offset)
                .take(limit)
                .filter_map(|transaction| protocol_tx_response(transaction, None, None, None).ok())
                .collect::<Vec<_>>();
            Json(MempoolResponse {
                size: total,
                transactions,
            })
            .into_response()
        }
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}

async fn rpc_qcash_mempool(State(_state): State<RpcState>) -> impl IntoResponse {
    Json(serde_json::json!({ "size": 0, "transactions": [] })).into_response()
}

async fn rpc_xpq_utxos(
    State(state): State<RpcState>,
    Query(query): Query<ListQuery>,
) -> impl IntoResponse {
    match state.node.lock() {
        Ok(node) => {
            let height = node.tip_height().unwrap_or(Height(0));
            let total = node.ledger.xpq_utxos.coins().len();
            let (offset, limit) = query.bounds();
            let coins = node
                .ledger
                .xpq_utxos
                .coins()
                .values()
                .skip(offset)
                .take(limit)
                .map(|coin| xpq_coin_json(coin, height))
                .collect::<Vec<_>>();
            Json(serde_json::json!({ "size": total, "offset": offset, "limit": limit, "coins": coins })).into_response()
        }
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}

async fn rpc_xpq_coin(
    State(state): State<RpcState>,
    AxumPath(coin_id): AxumPath<String>,
) -> impl IntoResponse {
    let hash = match parse_hash_hex(&coin_id) {
        Ok(hash) => xparq::state::XpqCoinId(hash.0),
        Err(error) => return rpc_error(StatusCode::BAD_REQUEST, error),
    };
    match state.node.lock() {
        Ok(node) => {
            let height = node.tip_height().unwrap_or(Height(0));
            match node.ledger.xpq_utxos.coin(hash) {
                Some(coin) => Json(xpq_coin_json(coin, height)).into_response(),
                None => rpc_error(StatusCode::NOT_FOUND, "xpq_coin_not_found_or_spent"),
            }
        }
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}

fn xpq_coin_json(coin: &xparq::state::XpqUtxo, height: Height) -> serde_json::Value {
    serde_json::json!({
        "coin_id": hex::encode(coin.id.0),
        "transaction_hash": hex::encode(coin.outpoint.transaction_hash.0),
        "output_index": coin.outpoint.output_index,
        "owner": address_to_string(&coin.owner),
        "amount": coin.amount.0,
        "maturity_height": coin.maturity_height.0,
        "spendable": coin.maturity_height.0 <= height.0,
        "source": coin.source.as_str(),
    })
}

fn balance_json(node: &Node, address: &Address) -> String {
    balance_value(node, address).to_string()
}

fn balance_value(node: &Node, address: &Address) -> serde_json::Value {
    let height = node.tip_height().unwrap_or(Height(0));
    let pending = node.pending_balance(address);
    match node.ledger.account(address) {
        Some(account) => serde_json::json!({
            "address": address_to_string(address),
            "height": height.0,
            "exists": true,
            "confirmed": node.ledger.xpq_utxos.balance(*address).map(|value| value.0).unwrap_or(0),
            "available": node.ledger.xpq_utxos.available_balance(*address, height).map(|value| value.0).unwrap_or(0),
            "pending_incoming": pending.incoming.0,
            "pending_outgoing": pending.outgoing.0,
            "authorization_registered": account.authorization.is_some(),
            "utxos": node.ledger.xpq_utxos.coins_for_owner(*address).count(),
            "spendable_utxos": node.ledger.xpq_utxos.coins_for_owner(*address)
                .filter(|coin| coin.maturity_height.0 <= height.0)
                .map(|coin| serde_json::json!({
                    "coin_id": hex::encode(coin.id.0),
                    "amount": coin.amount.0,
                    "maturity_height": coin.maturity_height.0,
                }))
                .collect::<Vec<_>>(),
            "unspendable": node.ledger.xpq_utxos.balance(*address).map(|total| total.0.saturating_sub(node.ledger.xpq_utxos.available_balance(*address, height).map(|value| value.0).unwrap_or(0))).unwrap_or(0)
        }),
        None => serde_json::json!({
            "address": address_to_string(address),
            "height": height.0,
            "exists": false,
            "confirmed": 0,
            "available": 0,
            "pending_incoming": 0,
            "pending_outgoing": 0,
            "authorization_registered": false,
            "utxos": 0,
            "spendable_utxos": Vec::<serde_json::Value>::new(),
            "unspendable": 0
        }),
    }
}

fn chain_stats(node: &Node) -> Result<ChainStatsResponse, String> {
    let height = node.tip_height().map(|height| height.0).unwrap_or(0);
    let onchain_supply = node
        .ledger
        .total_supply()
        .map_err(|error| format!("failed to calculate on-chain supply: {error}"))?
        .0;
    let qcash_offchain_supply = node
        .ledger
        .qcash_utxos
        .total_value()
        .map_err(|error| format!("failed to calculate QCash supply: {error}"))?
        .0;
    let qcash_redeemable_supply = node
        .ledger
        .qcash_utxos
        .redeemable_balance_at(Height(height))
        .map_err(|error| format!("failed to calculate redeemable QCash supply: {error}"))?
        .0;
    let qcash_pending_supply = qcash_offchain_supply
        .checked_sub(qcash_redeemable_supply)
        .ok_or_else(|| "redeemable QCash supply exceeds total QCash supply".to_string())?;
    let total_known_supply = onchain_supply
        .checked_add(qcash_offchain_supply)
        .ok_or_else(|| "total known supply overflow".to_string())?;
    let genesis_premine = 0_u64;
    let mined_supply = total_known_supply
        .checked_sub(genesis_premine)
        .ok_or_else(|| "genesis premine exceeds current supply".to_string())?;
    Ok(ChainStatsResponse {
        chain: CHAIN_NAME,
        coin: COIN_NAME,
        height,
        blocks: height.saturating_add(1),
        genesis_premine,
        mined_supply,
        onchain_supply,
        qcash_offchain_supply,
        qcash_redeemable_supply,
        qcash_pending_supply,
        total_known_supply,
        current_supply: total_known_supply,
        miner_income: 0,
        service_revenue: 0,
        total_transactions: 0,
        transfer_transactions: 0,
        pending_transactions: node.mempool.len() as u64,
        total_transfer_volume: 0,
        total_transaction_fees: 0,
        average_transfer_amount: 0,
    })
}

async fn rpc_qcash_utxos(
    State(state): State<RpcState>,
    Query(query): Query<ListQuery>,
) -> impl IntoResponse {
    match state.node.lock() {
        Ok(node) => {
            let height = node.tip_height().unwrap_or(Height(0));
            let total = node.ledger.qcash_utxos.coins().count();
            let (offset, limit) = query.bounds();
            let utxos = node
                .ledger
                .qcash_utxos
                .coins()
                .skip(offset)
                .take(limit)
                .map(|coin| qcash_utxo_value(coin, height))
                .collect::<Vec<_>>();
            Json(serde_json::json!({
                "height": height.0,
                "total": total,
                "offset": offset,
                "limit": limit,
                "utxos": utxos,
            }))
            .into_response()
        }
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}

async fn rpc_qcash_coin(
    State(state): State<RpcState>,
    AxumPath(coin_id): AxumPath<String>,
) -> impl IntoResponse {
    let hash = match parse_hash_hex(&coin_id) {
        Ok(hash) => hash,
        Err(error) => return rpc_error(StatusCode::BAD_REQUEST, error),
    };
    match state.node.lock() {
        Ok(node) => {
            let height = node.tip_height().unwrap_or(Height(0));
            match node
                .ledger
                .qcash_utxos
                .coin(xparq::state::QCashCoinId(hash.0))
            {
                Some(coin) => Json(qcash_utxo_value(coin, height)).into_response(),
                None => pending_qcash_coin_value(&node, xparq::state::QCashCoinId(hash.0), height)
                    .map_or_else(
                        || {
                            Json(serde_json::json!({
                                "coin_id": coin_id.to_ascii_lowercase(),
                                "height": height.0,
                                "status": "redeemed",
                            }))
                            .into_response()
                        },
                        |value| Json(value).into_response(),
                    ),
            }
        }
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}

async fn rpc_qcash_file(
    State(state): State<RpcState>,
    AxumPath(name): AxumPath<String>,
) -> impl IntoResponse {
    let prefix = match qcash_file_lookup_prefix(&name) {
        Ok(prefix) => prefix,
        Err(error) => return rpc_error(StatusCode::BAD_REQUEST, error),
    };
    match state.node.lock() {
        Ok(node) => {
            let height = node.tip_height().unwrap_or(Height(0));
            let matches = node
                .ledger
                .qcash_utxos
                .coins()
                .filter(|coin| {
                    hex::encode_upper(coin.id.0).starts_with(&prefix.to_ascii_uppercase())
                })
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [coin] => {
                    let mut value = qcash_utxo_value(coin, height);
                    if let Some(object) = value.as_object_mut() {
                        object.insert("lookup".into(), serde_json::json!(name));
                    }
                    Json(value).into_response()
                }
                [] => {
                    let pending = pending_qcash_coins_with_prefix(&node, &prefix, height);
                    match pending.as_slice() {
                        [value] => Json(value.clone()).into_response(),
                        [] => Json(serde_json::json!({
                            "lookup": name,
                            "coin_id_prefix": prefix,
                            "height": height.0,
                            "status": "redeemed",
                            "matches": 0,
                        }))
                        .into_response(),
                        _ => rpc_error(StatusCode::CONFLICT, "ambiguous_qcash_coin_id_prefix"),
                    }
                }
                _ => rpc_error(StatusCode::CONFLICT, "ambiguous_qcash_coin_id_prefix"),
            }
        }
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}

fn pending_qcash_coin_value(
    node: &Node,
    wanted: xparq::state::QCashCoinId,
    height: Height,
) -> Option<serde_json::Value> {
    let wanted = hex::encode(wanted.0);
    pending_qcash_coins(node, height)
        .into_iter()
        .find(|value| {
            value.get("coin_id").and_then(serde_json::Value::as_str) == Some(wanted.as_str())
        })
}

fn pending_qcash_coins_with_prefix(
    node: &Node,
    prefix: &str,
    height: Height,
) -> Vec<serde_json::Value> {
    pending_qcash_coins(node, height)
        .into_iter()
        .filter(|value| {
            value
                .get("coin_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|coin_id| coin_id.starts_with(&prefix.to_ascii_lowercase()))
        })
        .collect()
}

fn pending_qcash_coins(node: &Node, height: Height) -> Vec<serde_json::Value> {
    let mut coins = Vec::new();
    for transaction in node.mempool.transactions() {
        let xparq::transaction::SignedProtocolTransaction::QCash(signed) = transaction else {
            continue;
        };
        let xparq::transaction::QCashTransactionKind::Withdraw { metadata, .. } =
            &signed.transaction.kind
        else {
            continue;
        };
        let Ok(withdraw_tx_hash) = signed.hash() else {
            continue;
        };
        for output in &metadata.outputs {
            let Ok(id) = xparq::state::QCashCoinId::derive(withdraw_tx_hash, output) else {
                continue;
            };
            coins.push(serde_json::json!({
                "coin_id": hex::encode(id.0),
                "short_coin_id": id.short_id(),
                "file_name": id.file_name(output.denomination),
                "denomination": output.denomination.xpq(),
                "status": "unredeemed",
                "redeemability": "pending",
                "transaction_status": "pending",
                "height": height.0,
                "remaining_redeem_delay_blocks": xparq::ledger::QCASH_REDEEM_DELAY,
                "output_index": output.coin_index,
                "withdraw_tx_hash": hex::encode(withdraw_tx_hash.0),
                "withdrawer": address_to_string(&signed.transaction.signer),
            }));
        }
    }
    coins
}

pub(crate) fn qcash_file_lookup_prefix(name: &str) -> Result<String, String> {
    let stem = name
        .strip_suffix(".QCash")
        .unwrap_or(name);
    let prefix = stem.rsplit_once('_').map_or(stem, |(_, suffix)| suffix);
    if !(9..=64).contains(&prefix.len()) || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid_qcash_file_name_or_coin_id_prefix".to_string());
    }
    Ok(prefix.to_ascii_uppercase())
}

pub(crate) fn qcash_utxo_value(
    coin: &xparq::state::QCashUtxo,
    height: Height,
) -> serde_json::Value {
    let redeemable_height = coin
        .issued_height
        .0
        .saturating_add(xparq::ledger::QCASH_REDEEM_DELAY as u64);
    let redeemability = if height.0 >= redeemable_height {
        "redeemable"
    } else {
        "pending"
    };
    serde_json::json!({
        "coin_id": hex::encode(coin.id.0),
        "short_coin_id": coin.id.short_id(),
        "file_name": coin.id.file_name(coin.denomination),
        "denomination": coin.denomination.xpq(),
        "status": "unredeemed",
        "redeemability": redeemability,
        "height": height.0,
        "issued_height": coin.issued_height.0,
        "maturity_height": redeemable_height,
        "redeemable_height": redeemable_height,
        "remaining_redeem_delay_blocks": redeemable_height.saturating_sub(height.0),
        "output_index": coin.outpoint.output_index,
        "withdraw_tx_hash": hex::encode(coin.outpoint.transaction_hash.0),
        "withdrawer": address_to_string(&coin.withdrawer),
    })
}

pub(crate) fn block_response(node: &Node, block: &Block) -> Result<BlockResponse, String> {
    let hash = block.hash().map_err(|error| error.to_string())?;
    let tip = node.tip_height().unwrap_or(block.height());
    let confirmations = tip.0.saturating_sub(block.height().0).saturating_add(1);
    let transactions = block
        .transactions()
        .iter()
        .map(|transaction| {
            protocol_tx_response(
                transaction,
                Some(block.height()),
                Some(hash),
                Some(tip),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let value_moved = block
        .transactions()
        .iter()
        .filter_map(|transaction| match transaction {
            SignedProtocolTransaction::Transfer(tx) => Some(xparq::consensus::supply::Amount(
                tx.transaction
                    .outputs
                    .iter()
                    .filter(|output| output.to.address() != Some(tx.transaction.from))
                    .fold(0_u64, |sum, output| sum.saturating_add(output.amount.0)),
            )),
            _ => None,
        })
        .map(|amount| amount.0)
        .sum();
    Ok(BlockResponse {
        version: block.header.version,
        height: block.height().0,
        hash: hex::encode(hash.0),
        short_hash: short_hash(Some(hash)),
        previous_hash: hex::encode(block.previous_hash().0),
        merkle_root: hex::encode(block.header.merkle_root.0),
        state_root: hex::encode(block.state_root().0),
        miner_address: address_to_string(&block.miner_address()),
        difficulty: block.difficulty(),
        confirmations,
        value_moved,
        nonce: block.header.nonce.0,
        tx_count: block.transaction_count(),
        size: block_bytes(block).map_err(|error| error.to_string())?.len(),
        payload_size: block_bytes(block).map_err(|error| error.to_string())?.len(),
        weight: block.block_weight() as usize,
        coinbase: block.coinbase().as_ref().map(|coinbase| CoinbaseResponse {
            to: address_to_string(&coinbase.to),
            subsidy: coinbase.subsidy.0,
            fees: 0,
            total: coinbase.total().0,
        }),
        transactions,
    })
}

pub(crate) fn protocol_tx_response(
    transaction: &SignedProtocolTransaction,
    block_height: Option<Height>,
    block_hash: Option<BlockHash>,
    tip_height: Option<Height>,
) -> Result<ProtocolTxResponse, String> {
    let txid = transaction.hash().map_err(|error| error.to_string())?;
    let signer = transaction.signer();
    let (operation, recipient, amount) = match transaction {
        SignedProtocolTransaction::Transfer(tx) => {
            let primary = tx
                .transaction
                .outputs
                .iter()
                .find(|output| output.to.address() != Some(tx.transaction.from));
            (
            if primary.is_some_and(|output| output.to == xparq::transaction::OutputTarget::BlockMiner) {
                "fee"
            } else {
                "transfer"
            },
            primary.map(|output|
                output
                    .to
                    .address()
                    .map(|address| address_to_string(&address))
                    .unwrap_or_else(|| "block_miner".to_string())
            ),
            primary.map(|output| output.amount.0),
        )},
        SignedProtocolTransaction::QCash(tx) => match &tx.transaction.kind {
            xparq::transaction::QCashTransactionKind::Withdraw { amount, .. } => {
                ("qcash_withdraw", None, Some(amount.0))
            }
            xparq::transaction::QCashTransactionKind::Redeem { .. } => {
                let recipient = tx.transaction.redeem_recipient();
                (
                    "qcash_redeem",
                    recipient.map(|(address, _)| address_to_string(&address)),
                    recipient.map(|(_, amount)| amount.0),
                )
            }
        },
    };
    let depth = block_height
        .zip(tip_height)
        .map(|(height, tip)| tip.0.saturating_sub(height.0).saturating_add(1))
        .unwrap_or(0);
    let lifecycle = if block_height.is_some() {
        canonical_transaction_lifecycle(depth)
    } else {
        xparq::ledger::TransactionLifecycle::Pending
    };
    Ok(ProtocolTxResponse {
        family: match transaction.family() {
            xparq::transaction::TransactionFamily::Transfer => "transfer",
            xparq::transaction::TransactionFamily::QCash => "qcash",
        },
        operation,
        txid: hex::encode(txid.0),
        signer: address_to_string(&signer),
        authorization_addresses: transaction
            .authorization_proof_addresses()
            .into_iter()
            .map(|address| address_to_string(&address))
            .collect(),
        recipient,
        amount,
        payload_size: transaction.to_bytes().map_err(|error| error.to_string())?.len(),
        proof_size: 0,
        virtual_size: transaction.to_bytes().map_err(|error| error.to_string())?.len(),
        block_height: block_height.map(|height| height.0),
        block_hash: block_hash.map(|hash| hex::encode(hash.0)),
        confirmations: depth,
        depth,
        confirmation_depth: CONFIRMATION_DEPTH,
        finality_depth: FINALITY_DEPTH,
        confirmed: lifecycle != xparq::ledger::TransactionLifecycle::Pending,
        finalized: lifecycle == xparq::ledger::TransactionLifecycle::Finalized,
        status: lifecycle.as_str(),
    })
}
