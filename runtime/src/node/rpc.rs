use super::*;
use super::{config::*, explorer::*, mempool::*, mining::*, state::*, util::*};

pub(super) fn serve_rpc(path: Option<&str>, listen: &str) -> Result<(), String> {
    let database = database_path(path);
    serve_rpc_database(database, listen)
}

pub(super) fn serve_rpc_database(database: PathBuf, listen: &str) -> Result<(), String> {
    load_or_initialize(&database)?;
    let listener = TcpListener::bind(listen).map_err(|error| format!("bind RPC: {error}"))?;
    println!("rpc: http://{listen}");

    let active = Arc::new(AtomicUsize::new(0));
    let active_by_ip = Arc::new(Mutex::new(std::collections::BTreeMap::new()));

    for connection in listener.incoming() {
        match connection {
            Ok(mut stream) => {
                if active.fetch_add(1, Ordering::AcqRel) >= MAX_RPC_CONNECTIONS {
                    active.fetch_sub(1, Ordering::AcqRel);
                    let _ = write_http_response(
                        &mut stream,
                        503,
                        &serde_json::json!({"error": "RPC connection limit reached"}),
                    );
                    continue;
                }

                let peer_ip = stream.peer_addr().ok().map(|address| address.ip());
                if let Some(ip) = peer_ip {
                    let mut by_ip = match active_by_ip.lock() {
                        Ok(by_ip) => by_ip,
                        Err(_) => {
                            active.fetch_sub(1, Ordering::AcqRel);
                            let _ = write_http_response(
                                &mut stream,
                                503,
                                &serde_json::json!({"error": "RPC connection accounting unavailable"}),
                            );
                            continue;
                        }
                    };
                    let count = by_ip.entry(ip).or_insert(0_usize);
                    if *count >= MAX_RPC_CONNECTIONS_PER_IP {
                        active.fetch_sub(1, Ordering::AcqRel);
                        let _ = write_http_response(
                            &mut stream,
                            429,
                            &serde_json::json!({"error": "RPC per-IP connection limit reached"}),
                        );
                        continue;
                    }
                    *count += 1;
                }

                let database = database.clone();
                let active = Arc::clone(&active);
                let active_by_ip = Arc::clone(&active_by_ip);
                thread::spawn(move || {
                    if let Err(error) = handle_rpc_connection(&database, &mut stream) {
                        let _ = write_http_response(
                            &mut stream,
                            400,
                            &serde_json::json!({"error": error}),
                        );
                    }

                    active.fetch_sub(1, Ordering::AcqRel);
                    if let Some(ip) = peer_ip
                        && let Ok(mut by_ip) = active_by_ip.lock()
                        && let Some(count) = by_ip.get_mut(&ip)
                    {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            by_ip.remove(&ip);
                        }
                    }
                });
            }
            Err(error) => eprintln!("node: accept RPC connection: {error}"),
        }
    }
    Ok(())
}

pub(super) fn handle_rpc_connection(database: &Path, stream: &mut TcpStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(RPC_TIMEOUT))
        .and_then(|_| stream.set_write_timeout(Some(RPC_TIMEOUT)))
        .map_err(|error| format!("configure RPC timeout: {error}"))?;
    let request = read_http_request(stream)?;
    let request_line = request.headers.lines().next().ok_or("empty RPC request")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("missing RPC method")?;
    let route = parts.next().ok_or("missing RPC route")?;
    if method == "POST" && route == "/transaction" {
        let transaction: Transaction = canonical_decode(&request.body)
            .map_err(|error| format!("invalid submitted transaction: {error}"))?;
        let hash = insert_mempool_transaction(database, transaction, false)?;
        return write_http_response(stream, 200, &serde_json::json!({"hash": hex::encode(hash)}));
    }
    if method == "POST" && route == "/program/deploy" {
        let deploy: kernel::operation::AuthorizedDeployProgram = canonical_decode(&request.body)
            .map_err(|error| format!("invalid submitted deploy: {error}"))?;
        let id = insert_pending_operation(
            database,
            kernel::operation::BlockOperation::DeployProgram(Box::new(deploy)),
            false,
        )?;
        return write_http_response(
            stream,
            200,
            &serde_json::json!({"operation_id": hex::encode(id)}),
        );
    }
    if method == "POST" && route == "/program/deploy/quote" {
        if request.body.len() > kernel::block::MAX_OPERATION_SIZE {
            return Err("deploy quote exceeds operation size limit".into());
        }
        let deploy: kernel::operation::AuthorizedDeployProgram = canonical_decode(&request.body)
            .map_err(|error| format!("invalid deploy quote: {error}"))?;
        let (ledger, _, _, _) = load_or_initialize_header_snapshot(database)?;
        let height = Height(ledger.tip_height().map_or(0, |h| h.0.saturating_add(1)));
        let (id, burn) = kernel::consensus::quote_deploy_burn(&deploy, height, ledger.state())
            .map_err(|error| format!("invalid deploy quote: {error:?}"))?;
        let chain = kernel::genesis::chain_context().map_err(|error| error.to_string())?;
        let commitment = deploy
            .commitment(chain)
            .map_err(|error| error.to_string())?;
        return write_http_response(
            stream,
            200,
            &serde_json::json!({
                "program_id": hex::encode(id.into_bytes()),
                "required_protocol_burn": burn.as_zeno(),
                "authorization_commitment": hex::encode(commitment.into_bytes()),
                "height": height.0,
                "tip_hash": ledger.tip_hash().map(|hash| hex::encode(hash.0)),
            }),
        );
    }
    if method == "POST" && route == "/program/quote" {
        if request.body.len() > kernel::program::MAX_PROGRAM_INVOCATION_SIZE {
            return Err("quote transaction exceeds consensus size limit".into());
        }
        let tx: Transaction = canonical_decode(&request.body)
            .map_err(|e| format!("invalid quote transaction: {e}"))?;
        let AuthorizedProgramEnvelope::Program(tx) = tx;
        let (ledger, _, _, _) = load_or_initialize_header_snapshot(database)?;
        let chain = kernel::genesis::chain_context().map_err(|e| e.to_string())?;
        let height = ledger.tip_height().map_or(0, |h| h.0.saturating_add(1));
        if !tx
            .verify_authorizations(chain, height)
            .map_err(|e| e.to_string())?
        {
            return Err("invalid quote authorization".into());
        }
        let mut vm_quote = kernel::program::vm_transfer::TransferQuote::default();
        let mut vm_return_value = None;
        let vm_fuel = match kernel::program::system::script::execute::decode_program(&tx.call)
            .map_err(|e| format!("invalid program call: {e:?}"))?
        {
            kernel::program::system::script::execute::DecodedProgramCall::Vm(id) => {
                let _ = id;
                let commitment = kernel::program::program_invocation_commitment(
                    tx.signer,
                    &tx.call,
                    &tx.payment,
                    chain,
                )
                .map_err(|e| e.to_string())?;
                // Quotes authenticate ownership as well as signatures before exposing deposit context.
                kernel::consensus::validate_coin_inputs_for_quote(&tx, ledger.state())
                    .map_err(|e| e.to_string())?;
                let result = kernel::program::vm_app::preview(
                    ledger.state(),
                    &tx,
                    height,
                    commitment,
                    &extension::SystemApplications,
                )
                .map_err(|e| format!("VM quote failed: {e:?}"))?;
                vm_quote = result.quote;
                vm_return_value = Some(result.value.to_string());
                result.fuel_used
            }
            _ => 0,
        };
        let weight = kernel::program::program_created_state_weight_with_applications(
            &tx,
            chain,
            ledger.state().extensions(),
            &extension::SystemApplications,
        )
        .map_err(|e| e.to_string())?;
        return write_http_response(
            stream,
            200,
            &serde_json::json!({
                "created_state_weight":weight + vm_quote.created_state_weight, "vm_fuel":vm_fuel, "vm_return_value":vm_return_value,
                "vm_created_coin_utxos":vm_quote.created_coin_utxos, "vm_consumed_coin_utxos":vm_quote.consumed_coin_utxos, "tip_hash": ledger.tip_hash().map(|h|hex::encode(h.0)),
            }),
        );
    }
    if method != "GET" {
        return Err("unsupported RPC method".into());
    }
    if !request.body.is_empty() {
        return Err("GET request body is not allowed".into());
    }
    match route {
        "/openapi.json" => {
            return write_http_bytes(stream, 200, "application/json", OPENAPI_JSON);
        }
        "/docs" | "/docs/" => {
            return write_http_bytes(stream, 200, "text/html; charset=utf-8", API_DOCS_HTML);
        }
        _ => {}
    }

    let (ledger, _header_checkpoints, cumulative_work, cumulative_weight) =
        load_or_initialize_header_snapshot(database)?;

    let response = match route {
        "/status" => {
            let mut response = status_response(&ledger, cumulative_work, cumulative_weight)?;
            let minimums = super::chain_minimums::configured(database)?;
            response["minimum_chain_work"] =
                serde_json::json!(format_work(minimums.work.to_be_limbs()));
            response["minimum_chain_weight"] = serde_json::json!(minimums.weight.to_string());
            response["meets_chain_minimums"] =
                serde_json::json!(minimums.allows(cumulative_work, cumulative_weight));
            response
        }
        "/fee-policy" => {
            let emission = expected_next_emission(&ledger)?;
            serde_json::json!({
                "minimum_fee_rate_zeno_per_byte": MIN_RELAY_FEE_ZENO_PER_BYTE,
                "state_burn_algorithm": kernel::consensus::STATE_BURN_ALGORITHM,
                "next_block_emission": emission.as_zeno(),
                "state_burn_rate_zeno_per_weight": kernel::consensus::STATE_BURN_RATE_ZENO_PER_BYTE,
                "empty_block_archival_bytes": kernel::consensus::EMPTY_BLOCK_ARCHIVAL_BYTES,
                "coin_utxo_state_weight": kernel::consensus::COIN_UTXO_STATE_WEIGHT,
                "empty_block_archival_burn": kernel::consensus::EMPTY_BLOCK_ARCHIVAL_BURN.as_zeno(),
                "emission_utxo_state_growth_burn": kernel::consensus::EMISSION_UTXO_STATE_GROWTH_BURN.as_zeno(),
                "miner_protocol_burn": kernel::consensus::MINER_PROTOCOL_BURN.as_zeno(),
            })
        }
        "/blocks/latest" => latest_blocks_response(database, &ledger)?,
        route if route.starts_with("/coin-origin/") => {
            let share = route.trim_start_matches("/coin-origin/");
            if share.is_empty() || share.contains(['/', '?', '#']) {
                return Err("invalid coin origin route".into());
            }
            let share = share
                .parse::<kernel::monetary::coin::CoinShare>()
                .map_err(|_| "invalid coin share")?;
            let origin = index::coin_origin(database, &ledger, share)?;
            serde_json::json!({
                "coin_share": share.to_string(),
                "origin": origin.map(|origin| serde_json::json!({
                    "created_at": origin.created_at.map(|id| hex::encode(id.into_bytes())),
                    "deploy_operation_id": origin.deploy_operation_id.map(hex::encode),
                    "created_in": origin.created_in.0,
                })),
            })
        }
        route if route.starts_with("/program/state/") => program_state_response(&ledger, route)?,
        route if route.starts_with("/program/asset/") => program_asset_response(&ledger, route)?,

        route if route.starts_with("/program/balance/") => {
            let program_id = route.trim_start_matches("/program/balance/");
            if program_id.is_empty() || program_id.contains(['/', '?', '#']) {
                return Err("invalid balance route".into());
            }
            balance_response(
                &ledger,
                &read_pending_operations(database)?,
                parse_program_id(program_id)?,
            )?
        }
        route if route.starts_with("/block/") => {
            let height = route
                .trim_start_matches("/block/")
                .parse::<u64>()
                .map_err(|_| "invalid block height")?;
            stored_block_response(
                database,
                &ledger,
                &canonical_block(database, &ledger, Height(height))?,
            )?
        }
        route if route.starts_with("/program/account/") || route.starts_with("/program/coins/") => {
            let coins_only = route.starts_with("/program/coins/");
            let prefix = if coins_only {
                "/program/coins/"
            } else {
                "/program/account/"
            };
            let account_route = route.strip_prefix(prefix).ok_or("invalid account route")?;
            let (program_id, query) = account_route.split_once('?').unwrap_or((account_route, ""));
            if program_id.is_empty() || program_id.contains(['/', '#']) {
                return Err("invalid account route".into());
            }
            let mut utxo_offset = 0;
            let mut utxo_after = None;
            if !query.is_empty() {
                let (name, value) = query.split_once('=').ok_or("invalid account query")?;
                if value.is_empty() || value.contains('&') {
                    return Err("invalid account query".into());
                }
                match name {
                    "utxo_offset" => {
                        utxo_offset = value
                            .parse::<usize>()
                            .map_err(|_| "invalid account UTXO offset")?;
                    }
                    "utxo_after" => {
                        utxo_after = Some(
                            value
                                .parse::<kernel::monetary::coin::CoinShare>()
                                .map_err(|_| "invalid account UTXO cursor")?,
                        );
                    }
                    _ => return Err("invalid account query".into()),
                }
            }
            let pending = read_pending_operations(database)?;
            let program_id = parse_program_id(program_id)?;
            if coins_only {
                coin_account_response(
                    ledger.state(),
                    ledger.tip_height(),
                    &pending,
                    program_id,
                    utxo_offset,
                    utxo_after,
                )?
            } else {
                account_response(&ledger, &pending, program_id, utxo_offset, utxo_after)?
            }
        }
        route if route.starts_with("/explorer/program/") => {
            let value = route.trim_start_matches("/explorer/program/");
            let (program_id, query) = value.split_once('?').unwrap_or((value, ""));

            if program_id.is_empty() || program_id.contains(['/', '#']) {
                return Err("invalid explorer program route".into());
            }

            let mut include_emissions = true;
            let mut limit = DEFAULT_PROGRAM_ACTIVITY_LIMIT;
            let mut before = None;

            let mut seen_include_emissions = false;
            let mut seen_limit = false;
            let mut seen_before = false;

            if !query.is_empty() {
                for parameter in query.split('&') {
                    let (name, value) = parameter
                        .split_once('=')
                        .ok_or("invalid explorer program query")?;

                    match name {
                        "include_emissions" => {
                            if seen_include_emissions {
                                return Err("duplicate include_emissions query".into());
                            }

                            seen_include_emissions = true;

                            include_emissions = match value {
                                "true" => true,
                                "false" => false,
                                _ => return Err("invalid include_emissions query".into()),
                            };
                        }

                        "limit" => {
                            if seen_limit {
                                return Err("duplicate limit query".into());
                            }

                            seen_limit = true;

                            limit = value
                                .parse::<usize>()
                                .map_err(|_| "invalid explorer program limit")?;

                            if limit == 0 || limit > MAX_PROGRAM_ACTIVITY_LIMIT {
                                return Err("explorer program limit is out of range".into());
                            }
                        }

                        "before" => {
                            if seen_before {
                                return Err("duplicate before query".into());
                            }

                            seen_before = true;

                            if value.len() != crate::storage::PROGRAM_ACTIVITY_CURSOR_SIZE * 2 {
                                return Err("invalid explorer program cursor".into());
                            }

                            let bytes = hex::decode(value)
                                .map_err(|_| "invalid explorer program cursor")?;

                            let cursor: [u8; crate::storage::PROGRAM_ACTIVITY_CURSOR_SIZE] = bytes
                                .try_into()
                                .map_err(|_| "invalid explorer program cursor")?;

                            before = Some(cursor);
                        }

                        _ => return Err("invalid explorer program query".into()),
                    }
                }
            }

            explorer_program_response(
                database,
                &ledger,
                &read_pending_operations(database)?,
                parse_program_id(program_id)?,
                include_emissions,
                limit,
                before,
            )?
        }
        route if route.starts_with("/explorer/transaction/") => {
            let hash = route.trim_start_matches("/explorer/transaction/");
            explorer_transaction_response(database, &ledger, parse_hash(hash)?)?
        }
        _ => return Err("unknown RPC route".into()),
    };
    write_http_response(stream, 200, &response)
}

pub(super) fn read_http_request(stream: &mut impl Read) -> Result<HttpRequest, String> {
    let mut bytes = Vec::new();
    let header_end = loop {
        if bytes.len() >= MAX_RPC_HEADER_SIZE {
            return Err("RPC headers exceed size limit".into());
        }
        let mut chunk = [0_u8; 1024];
        let length = stream
            .read(&mut chunk)
            .map_err(|error| format!("read RPC: {error}"))?;
        if length == 0 {
            return Err("RPC connection closed before headers completed".into());
        }
        bytes.extend_from_slice(&chunk[..length]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| "RPC headers are not UTF-8")?
        .to_string();
    let mut content_length = None;
    for line in headers.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err("malformed RPC header".into());
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("RPC Transfer-Encoding is not supported".into());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err("duplicate RPC Content-Length".into());
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "invalid RPC Content-Length")?,
            );
        }
    }
    let content_length = content_length.unwrap_or(0);
    if content_length > MAX_STORED_TRANSACTION_SIZE {
        return Err("RPC request body exceeds transaction size limit".into());
    }
    let total = header_end
        .checked_add(content_length)
        .ok_or("RPC request size overflow")?;
    if bytes.len() > total {
        bytes.truncate(total);
    }
    while bytes.len() < total {
        let remaining = total - bytes.len();
        let mut chunk = vec![0_u8; remaining.min(8 * 1024)];
        let length = stream
            .read(&mut chunk)
            .map_err(|error| format!("read RPC body: {error}"))?;
        if length == 0 {
            return Err("RPC body is truncated".into());
        }
        bytes.extend_from_slice(&chunk[..length]);
    }
    Ok(HttpRequest {
        headers,
        body: bytes[header_end..].to_vec(),
    })
}

pub(super) fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    value: &serde_json::Value,
) -> Result<(), String> {
    let body = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    write_http_bytes(stream, status, "application/json", &body)
}

pub(super) fn write_http_bytes(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<(), String> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n",
        body.len()
    )
    .and_then(|_| stream.write_all(body))
    .map_err(|error| format!("write RPC: {error}"))
}
