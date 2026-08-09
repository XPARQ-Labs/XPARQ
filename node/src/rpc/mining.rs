async fn rpc_mining_template(
    State(state): State<RpcState>,
    Query(query): Query<MiningTemplateQuery>,
) -> impl IntoResponse {
    let miner = match address_from_string(&query.miner) {
        Ok(miner) => miner,
        Err(_) => return rpc_error(StatusCode::BAD_REQUEST, "invalid_miner_address"),
    };
    let now = match unix_timestamp() {
        Ok(timestamp) => timestamp,
        Err(error) => return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error),
    };
    let candidate = match state.node.lock() {
        Ok(mut node) => {
            if let Err(error) = node.mempool.evict_by_policy(now) {
                return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string());
            }
            let timestamp = crate::mining::candidate_timestamp(&node, now);
            let difficulty = match node.next_difficulty_at(timestamp) {
                Ok(difficulty) => difficulty,
                Err(error) => {
                    return rpc_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("difficulty_unavailable: {error}"),
                    );
                }
            };
            match prepare_candidate_block(
                &node.mempool,
                &node.ledger,
                miner,
                timestamp,
                MAX_BLOCK_TXS,
                node.mempool.dynamic_market_fee_rate(),
                difficulty,
            ) {
                Ok(candidate) => candidate,
                Err(error) => {
                    return rpc_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("template_failed: {error}"),
                    );
                }
            }
        }
        Err(_) => return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    };
    let (candidate_hash, candidate_bytes) = match (candidate.hash(), block_bytes(&candidate)) {
        (Ok(hash), Ok(bytes)) => (hash, bytes),
        (Err(error), _) | (_, Err(error)) => {
            return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string());
        }
    };
    let job_id = hex::encode(candidate_hash.0);
    Json(MiningTemplateResponse {
        job_id,
        block: hex::encode(candidate_bytes),
        height: candidate.height().0,
        previous_hash: hex::encode(candidate.previous_hash().0),
        difficulty: candidate.difficulty(),
        algorithm: CURRENT_CHAIN_PARAMS.pow_algorithm,
    })
    .into_response()
}
async fn rpc_submit_mined_block(
    State(state): State<RpcState>,
    Json(request): Json<SubmitBlockRequest>,
) -> impl IntoResponse {
    let bytes = match hex::decode(&request.block) {
        Ok(bytes) => bytes,
        Err(_) => return rpc_error(StatusCode::BAD_REQUEST, "invalid_block_hex"),
    };
    let block = match decode_block(&bytes) {
        Ok(block) => block,
        Err(error) => {
            return rpc_error(StatusCode::BAD_REQUEST, format!("invalid_block: {error}"));
        }
    };
    let height = block.height().0;
    let hash = match block.hash() {
        Ok(hash) => hash,
        Err(error) => return rpc_error(StatusCode::BAD_REQUEST, error.to_string()),
    };
    match state.node.lock() {
        Ok(mut node) => {
            if let Err(error) = node.apply_block(block.clone()) {
                return rpc_error(StatusCode::BAD_REQUEST, format!("block_rejected: {error}"));
            }
            if let Err(error) = node.flush_to_storage() {
                return rpc_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("block_flush_failed: {error}"),
                );
            }
        }
        Err(_) => return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
    let _report = broadcast_to_peers(
        &state.peers,
        &state.peer_connections,
        &state.inbound_connections,
        NetworkMessage::Block(block),
    );
    Json(SubmitBlockResponse {
        accepted: true,
        height,
        hash: hex::encode(hash.0),
    })
    .into_response()
}
