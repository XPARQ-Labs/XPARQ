fn protocol_event_response(
    event: ProtocolEvent,
) -> Result<ProtocolEventResponse, xparq::error::CodecError> {
    Ok(ProtocolEventResponse {
        id: hex::encode(event.id()?.0),
        event,
    })
}
fn protocol_event_kind_name(kind: &ProtocolEventKind) -> &'static str {
    match kind {
        ProtocolEventKind::Transfer { .. } => "transfer",
        ProtocolEventKind::QCashWithdrawn { .. } => "qcash_withdrawn",
        ProtocolEventKind::QCashRedeemed { .. } => "qcash_redeemed",
        ProtocolEventKind::QCashSplit { .. } => "qcash_split",
        ProtocolEventKind::EmissionDistributed { .. } => "emission_distributed",
    }
}

pub(crate) fn is_protocol_event_kind(kind: &str) -> bool {
    matches!(
        kind,
        "transfer"
            | "qcash_withdrawn"
            | "qcash_redeemed"
            | "qcash_split"
            | "emission_distributed"
    )
}

pub(crate) fn protocol_event_list(
    events: Vec<ProtocolEvent>,
    query: EventQuery,
) -> Result<ProtocolEventListResponse, String> {
    const DEFAULT_LIMIT: usize = 100;
    const MAX_LIMIT: usize = 500;

    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if limit == 0 || limit > MAX_LIMIT {
        return Err("event_limit_must_be_between_1_and_500".to_string());
    }
    if query
        .from_height
        .zip(query.to_height)
        .is_some_and(|(from, to)| from > to)
    {
        return Err("event_height_range_is_invalid".to_string());
    }
    let kind = query.kind.map(|kind| kind.to_ascii_lowercase());
    if kind
        .as_deref()
        .is_some_and(|kind| !is_protocol_event_kind(kind))
    {
        return Err("unknown_event_kind".to_string());
    }

    let filtered: Vec<_> = events
        .into_iter()
        .filter(|event| {
            query
                .from_height
                .is_none_or(|height| event.block_height.0 >= height)
                && query
                    .to_height
                    .is_none_or(|height| event.block_height.0 <= height)
                && kind
                    .as_deref()
                    .is_none_or(|kind| protocol_event_kind_name(&event.kind) == kind)
        })
        .collect();
    let total = filtered.len();
    let events = filtered
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(protocol_event_response)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    Ok(ProtocolEventListResponse {
        total,
        offset,
        limit,
        events,
    })
}

pub(crate) fn protocol_event_involves_address(kind: &ProtocolEventKind, address: &Address) -> bool {
    match kind {
        ProtocolEventKind::Transfer { from, to, .. } => from == address || to == address,
        ProtocolEventKind::QCashWithdrawn { signer, .. } => signer == address,
        ProtocolEventKind::QCashRedeemed {
            signer, recipient, ..
        } => signer == address || recipient == address,
        ProtocolEventKind::QCashSplit { signer, .. } => signer == address,
        ProtocolEventKind::EmissionDistributed { miner, .. } => miner == address,
    }
}

pub(crate) fn finalized_event_height(tip: Option<Height>) -> Option<u64> {
    tip.and_then(|height| height.0.checked_sub(u64::from(FINALITY_DEPTH)))
}

async fn rpc_event_stream(
    State(state): State<RpcState>,
    Query(query): Query<EventStreamQuery>,
) -> impl IntoResponse {
    let kind = query.kind.map(|kind| kind.to_ascii_lowercase());
    if kind
        .as_deref()
        .is_some_and(|kind| !is_protocol_event_kind(kind))
    {
        return rpc_error(StatusCode::BAD_REQUEST, "unknown_event_kind");
    }
    let address = match query.address {
        Some(address) => match parse_address_string(&address) {
            Ok(address) => Some(address),
            Err(error) => return rpc_error(StatusCode::BAD_REQUEST, error),
        },
        None => None,
    };
    let next_height = match query.from_height {
        Some(height) => height,
        None => match state.node.lock() {
            Ok(node) => finalized_event_height(node.tip_height())
                .map(|height| height.saturating_add(1))
                .unwrap_or(0),
            Err(_) => {
                return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed");
            }
        },
    };
    let stream_state = ProtocolEventStreamState {
        rpc: state,
        next_height,
        kind,
        address,
        pending: VecDeque::new(),
        poll_immediately: true,
    };
    let events = stream::unfold(stream_state, |mut state| async move {
        loop {
            if let Some(event) = state.pending.pop_front() {
                let id = match event.id() {
                    Ok(id) => hex::encode(id.0),
                    Err(_) => return None,
                };
                let event_name = protocol_event_kind_name(&event.kind);
                let data = serde_json::to_string(&protocol_event_response(event).ok())
                    .unwrap_or_else(|_| "{\"error\":\"event_encode_failed\"}".to_string());
                let message = SseEvent::default().id(id).event(event_name).data(data);
                return Some((Ok::<_, Infallible>(message), state));
            }

            if !state.poll_immediately {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            state.poll_immediately = false;

            let reached_tip = {
                let node = match state.rpc.node.lock() {
                    Ok(node) => node,
                    Err(_) => return None,
                };
                let finalized_height = finalized_event_height(node.tip_height());
                if finalized_height.is_none_or(|height| state.next_height > height) {
                    true
                } else {
                    let height = Height(state.next_height);
                    state.next_height = state.next_height.saturating_add(1);
                    match node.storage.load_block_by_height(height) {
                        Ok(Some(block)) => match block.hash().map_err(crate::runtime::storage::StorageError::from).and_then(|hash| node.storage.load_block_events(&hash)) {
                            Ok(events) => {
                                state.pending.extend(events.into_iter().filter(|event| {
                                    state.kind.as_deref().is_none_or(|kind| {
                                        protocol_event_kind_name(&event.kind) == kind
                                    }) && state.address.as_ref().is_none_or(|address| {
                                        protocol_event_involves_address(&event.kind, address)
                                    })
                                }));
                            }
                            Err(error) => node_warn!(
                                "RPC",
                                "protocol_events_load_failed height={} error={error:?}",
                                height.0
                            ),
                        },
                        Ok(None) => {}
                        Err(error) => node_warn!(
                            "RPC",
                            "protocol_event_block_load_failed height={} error={error:?}",
                            height.0
                        ),
                    }
                    false
                }
            };

            if !state.pending.is_empty() {
                continue;
            }
            if !reached_tip {
                state.poll_immediately = true;
            }
        }
    });

    Sse::new(events)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keep-alive"),
        )
        .into_response()
}

async fn rpc_event(
    State(state): State<RpcState>,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    let id = match parse_hash_hex(&id) {
        Ok(hash) => EventId(hash.0),
        Err(error) => return rpc_error(StatusCode::BAD_REQUEST, error),
    };
    let node = Arc::clone(&state.node);
    match state.state_pipeline.run(move || match node.lock() {
        Ok(node) => match node.storage.load_protocol_event(&id) {
            Ok(Some(event)) => match protocol_event_response(event) {
                Ok(response) => Json(response).into_response(),
                Err(error) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
            },
            Ok(None) => rpc_error(StatusCode::NOT_FOUND, "event_not_found"),
            Err(error) => rpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load event: {error}"),
            ),
        },
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }).await {
        Ok(response) => response,
        Err(error) => rpc_state_pipeline_error(error),
    }
}

async fn rpc_block_events(
    State(state): State<RpcState>,
    AxumPath(height): AxumPath<u64>,
    Query(query): Query<EventQuery>,
) -> impl IntoResponse {
    let node = Arc::clone(&state.node);
    match state.state_pipeline.run(move || match node.lock() {
        Ok(node) => {
            let block = match node.storage.load_block_by_height(Height(height)) {
                Ok(Some(block)) => block,
                Ok(None) => return rpc_error(StatusCode::NOT_FOUND, "block_not_found"),
                Err(error) => {
                    return rpc_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("failed to load block: {error}"),
                    );
                }
            };
            let block_hash = match block.hash() {
                Ok(hash) => hash,
                Err(error) => {
                    return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string());
                }
            };
            match node.storage.load_block_events(&block_hash) {
                Ok(events) => match protocol_event_list(events, query) {
                    Ok(response) => Json(response).into_response(),
                    Err(error) => rpc_error(StatusCode::BAD_REQUEST, error),
                },
                Err(error) => rpc_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to load block events: {error}"),
                ),
            }
        }
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }).await {
        Ok(response) => response,
        Err(error) => rpc_state_pipeline_error(error),
    }
}

async fn rpc_transaction_events(
    State(state): State<RpcState>,
    AxumPath(hash): AxumPath<String>,
    Query(query): Query<EventQuery>,
) -> impl IntoResponse {
    let hash = match parse_hash_hex(&hash) {
        Ok(hash) => TransactionHash::from(hash),
        Err(error) => return rpc_error(StatusCode::BAD_REQUEST, error),
    };
    let node = Arc::clone(&state.node);
    match state.state_pipeline.run(move || match node.lock() {
        Ok(node) => match node.storage.load_transaction_events(&hash) {
            Ok(events) => match protocol_event_list(events, query) {
                Ok(response) => Json(response).into_response(),
                Err(error) => rpc_error(StatusCode::BAD_REQUEST, error),
            },
            Err(error) => rpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load transaction events: {error}"),
            ),
        },
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }).await {
        Ok(response) => response,
        Err(error) => rpc_state_pipeline_error(error),
    }
}

async fn rpc_address_events(
    State(state): State<RpcState>,
    AxumPath(address): AxumPath<String>,
    Query(query): Query<EventQuery>,
) -> impl IntoResponse {
    let address = match parse_address_string(&address) {
        Ok(address) => address,
        Err(error) => return rpc_error(StatusCode::BAD_REQUEST, error),
    };
    let node = Arc::clone(&state.node);
    match state.state_pipeline.run(move || match node.lock() {
        Ok(node) => match node.storage.load_address_events(&address) {
            Ok(events) => match protocol_event_list(events, query) {
                Ok(response) => Json(response).into_response(),
                Err(error) => rpc_error(StatusCode::BAD_REQUEST, error),
            },
            Err(error) => rpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load address events: {error}"),
            ),
        },
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }).await {
        Ok(response) => response,
        Err(error) => rpc_state_pipeline_error(error),
    }
}
