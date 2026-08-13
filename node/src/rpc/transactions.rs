async fn rpc_submit_qcash_tx(
    State(state): State<RpcState>,
    Json(request): Json<SubmitTxRequest>,
) -> impl IntoResponse {
    let transaction = match signed_qcash_transaction_from_hex(&request.tx) {
        Ok(transaction) => transaction,
        Err(error) => return rpc_transaction_rejected("rejected", error),
    };
    let hash = match transaction.hash() {
        Ok(hash) => hash,
        Err(error) => return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    };
    let node = Arc::clone(&state.node);
    let submission = state
        .state_pipeline
        .run(move || match node.lock() {
        Ok(mut node) => {
            let already_pending = node.mempool.contains(&hash);
            if let Err(error) = node.submit_qcash_transaction(transaction) {
                if already_pending && is_duplicate_submission(&error) {
                    return Ok(true);
                }
                return Err((
                    transaction_rejection_status(&error),
                    error.to_string(),
                ));
            }
            Ok(false)
        }
        Err(_) => Err(("internal", "state_lock_failed".to_string())),
    })
        .await;
    match submission {
        Ok(Ok(already_pending)) => Json(serde_json::json!({
                "accepted": true,
                "already_pending": already_pending,
                "hash": hex::encode(hash.0),
                "status": "pending",
            }))
            .into_response(),
        Ok(Err(("internal", error))) => {
            rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error)
        }
        Ok(Err((status, error))) => rpc_transaction_rejected(status, error),
        Err(error) => rpc_state_pipeline_error(error),
    }
}

#[cfg(any(feature = "devnet", feature = "testnet"))]
async fn rpc_faucet(
    State(state): State<RpcState>,
    Json(request): Json<FaucetRequest>,
) -> impl IntoResponse {
    use xparq::consensus::supply::{Amount, XPQ};
    use xparq::genesis::{FAUCET_MAX_REQUEST, faucet_address, faucet_keypair};
    use xparq::transaction::{SignedTransfer as SignedTransaction, Transfer as Transaction};

    let recipient = match parse_address_string(&request.address) {
        Ok(address) => address,
        Err(error) => return rpc_transaction_rejected("invalid_address", error),
    };
    let amount_xpq = request.amount_xpq.unwrap_or(100);
    let amount = match amount_xpq.checked_mul(XPQ) {
        Some(amount) if amount > 0 && amount <= FAUCET_MAX_REQUEST => Amount(amount),
        _ => {
            return rpc_transaction_rejected(
                "invalid_amount",
                format!(
                    "faucet amount must be between 1 and {} XPQ",
                    FAUCET_MAX_REQUEST / XPQ
                ),
            );
        }
    };

    let owner = faucet_keypair();
    let faucet = faucet_address();
    let transaction = match state.node.lock() {
        Ok(node) => {
            let Ok(balance) = node.ledger.xpq_utxos.balance(faucet) else {
                return rpc_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "faucet account is absent; reset this test-network database to the faucet genesis",
                );
            };
            if balance.0 < amount.0 {
                return rpc_error(StatusCode::SERVICE_UNAVAILABLE, "faucet balance exhausted");
            }
            let height = node.tip_height().unwrap_or(xparq::block::Height(0));
            let mut inputs = Vec::new();
            let mut total = 0_u64;
            for coin in node
                .ledger
                .xpq_utxos
                .coins_for_owner(faucet)
                .filter(|coin| coin.maturity_height.0 <= height.0)
            {
                inputs.push(coin.id);
                total = total.saturating_add(coin.amount.0);
                if total >= amount.0 {
                    break;
                }
            }
            if total < amount.0 {
                return rpc_error(StatusCode::SERVICE_UNAVAILABLE, "faucet balance exhausted");
            }
            let mut outputs = vec![xparq::transaction::TransferOutput::new(recipient, amount)];
            if total > amount.0 {
                outputs.push(xparq::transaction::TransferOutput::new(
                    faucet,
                    xparq::consensus::supply::Amount(total - amount.0),
                ));
            }
            Transaction::from_outputs(faucet, inputs, outputs)
        }
        Err(_) => return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    };

    let payload = match transaction.signing_bytes() {
        Ok(payload) => payload,
        Err(error) => return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    };
    let signed = SignedTransaction::new(
        transaction,
        owner.public_key,
        xparq::crypto::sign(&owner.secret_key, &payload),
    );
    let hash = match signed.hash() {
        Ok(hash) => hash,
        Err(error) => return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    };

    match state.node.lock() {
        Ok(mut node) => {
            if let Err(error) = node.submit_transaction(signed.clone()) {
                return rpc_transaction_rejected(
                    transaction_rejection_status(&error),
                    error.to_string(),
                );
            }
        }
        Err(_) => return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
    let _ = broadcast_to_peers(
        &state.peers,
        &state.peer_connections,
        &state.inbound_connections,
        NetworkMessage::Transaction(signed.into()),
    );
    #[cfg(feature = "devnet")]
    let coin = "dXPQ";
    #[cfg(feature = "testnet")]
    let coin = "tXPQ";
    Json(serde_json::json!({
        "accepted": true,
        "coin": coin,
        "amount_xpq": amount_xpq,
        "recipient": request.address,
        "hash": hex::encode(hash.0),
        "status": "pending",
    }))
    .into_response()
}
async fn rpc_submit_tx(
    State(state): State<RpcState>,
    Json(request): Json<SubmitTxRequest>,
) -> impl IntoResponse {
    let transaction = match signed_transaction_from_hex(&request.tx) {
        Ok(transaction) => transaction,
        Err(error) => return rpc_transaction_rejected("rejected", error),
    };
    let hash = match transaction.hash() {
        Ok(hash) => hash,
        Err(error) => return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    };
    let node = Arc::clone(&state.node);
    let peers = Arc::clone(&state.peers);
    let peer_connections = Arc::clone(&state.peer_connections);
    let inbound_connections = Arc::clone(&state.inbound_connections);
    let transaction_for_job = transaction.clone();
    let submission = state.state_pipeline.run(move || match node.lock() {
        Ok(mut node) => {
            let already_pending = node.mempool.contains(&hash);
            if let Err(error) = node.submit_transaction(transaction_for_job.clone()) {
                if already_pending && is_duplicate_submission(&error) {
                    return Ok(false);
                }
                return Err((
                    transaction_rejection_status(&error),
                    error.to_string(),
                ));
            }
            drop(node);
            let _ = broadcast_to_peers(
                &peers,
                &peer_connections,
                &inbound_connections,
                NetworkMessage::Transaction(transaction_for_job.into()),
            );
            Ok(true)
        }
        Err(_) => Err(("internal", "state_lock_failed".to_string())),
    }).await;
    let broadcasted = match submission {
        Ok(Ok(broadcasted)) => broadcasted,
        Ok(Err(("internal", error))) => {
            return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error);
        }
        Ok(Err((status, error))) => return rpc_transaction_rejected(status, error),
        Err(error) => return rpc_state_pipeline_error(error),
    };
    if broadcasted {
        state
            .log_counters
            .accepted_tx_total
            .fetch_add(1, Ordering::Relaxed);
        state
            .log_counters
            .broadcast_tx_total
            .fetch_add(1, Ordering::Relaxed);
    }
    Json(SubmitTxResponse {
        accepted: true,
        hash: hex::encode(hash.0),
    })
    .into_response()
}

async fn rpc_submit_protocol_tx(
    State(state): State<RpcState>,
    Json(request): Json<SubmitTxRequest>,
) -> impl IntoResponse {
    let transaction = match signed_protocol_transaction_from_hex(&request.tx) {
        Ok(transaction) => transaction,
        Err(error) => return rpc_transaction_rejected("rejected", error),
    };
    let hash = match transaction.hash() {
        Ok(hash) => hash,
        Err(error) => return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    };
    let node = Arc::clone(&state.node);
    let peers = Arc::clone(&state.peers);
    let peer_connections = Arc::clone(&state.peer_connections);
    let inbound_connections = Arc::clone(&state.inbound_connections);
    let transaction_for_job = transaction.clone();
    let submission = state.state_pipeline.run(move || match node.lock() {
        Ok(mut node) => {
            let already_pending = node.mempool.contains(&hash);
            if let Err(error) = node.submit_protocol_transaction(transaction_for_job.clone()) {
                if already_pending && is_duplicate_submission(&error) {
                    return Ok(());
                }
                return Err((
                    transaction_rejection_status(&error),
                    error.to_string(),
                ));
            }
            drop(node);
            let _ = broadcast_to_peers(
                &peers,
                &peer_connections,
                &inbound_connections,
                NetworkMessage::Transaction(transaction_for_job),
            );
            Ok(())
        }
        Err(_) => Err(("internal", "state_lock_failed".to_string())),
    }).await;
    match submission {
        Ok(Ok(())) => {}
        Ok(Err(("internal", error))) => {
            return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error);
        }
        Ok(Err((status, error))) => return rpc_transaction_rejected(status, error),
        Err(error) => return rpc_state_pipeline_error(error),
    }
    Json(SubmitTxResponse {
        accepted: true,
        hash: hex::encode(hash.0),
    })
    .into_response()
}

fn is_duplicate_submission(error: &crate::runtime::node::NodeError) -> bool {
    matches!(
        error,
        crate::runtime::node::NodeError::Mempool(
            crate::runtime::mempool::MempoolError::DuplicateTransaction
        )
    )
}

fn transaction_rejection_status(error: &crate::runtime::node::NodeError) -> &'static str {
    use crate::runtime::mempool::MempoolError;
    use crate::runtime::node::NodeError;
    use xparq::ledger::LedgerError;
    use xparq::transaction::TransactionError;

    match error {
        NodeError::Mempool(MempoolError::InvalidTransaction(TransactionError::ValidityExpired))
        | NodeError::Mempool(MempoolError::InvalidLedgerState(LedgerError::InvalidTransaction(
            TransactionError::ValidityExpired,
        ))) => "expired",
        _ => "rejected",
    }
}

fn rpc_transaction_rejected(
    status: &'static str,
    error: impl Into<String>,
) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "accepted": false,
            "status": status,
            "error": error.into(),
        })),
    )
        .into_response()
}
