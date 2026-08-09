use crate::*;
use axum::extract::ConnectInfo;
use axum::http::{HeaderValue, Method};
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use zeroize::Zeroizing;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitTxRequest {
    tx: String,
}

#[cfg(any(feature = "devnet", feature = "testnet"))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FaucetRequest {
    address: String,
    #[serde(default)]
    amount_xpq: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct MiningTemplateQuery {
    miner: String,
}

#[derive(Debug, Default, Deserialize)]
struct ProofQuery {
    checkpoint_height: Option<u64>,
    checkpoint_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitBlockRequest {
    block: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AddPeerRequest {
    peer: String,
}

#[derive(Serialize)]
struct MiningTemplateResponse {
    job_id: String,
    block: String,
    height: u64,
    previous_hash: String,
    difficulty: u32,
    algorithm: &'static str,
}

#[derive(Serialize)]
struct SubmitBlockResponse {
    accepted: bool,
    height: u64,
    hash: String,
}

#[derive(Serialize)]
struct DraftBasisResponse {
    signer: String,
    live_balance: u64,
    available_balance: u64,
    spendable_after_pending: u64,
    tip_height: u64,
    finalized_height: u64,
    pending_incoming: u64,
    pending_outgoing: u64,
    pending_outgoing_hashes: Vec<String>,
    transaction_kinds: DraftTransactionKindsResponse,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftTransferRequest {
    signer: String,
    to: String,
    amount: u64,
    #[serde(default)]
    fee_rate_per_byte: Option<u64>,
    #[serde(default)]
    fee_amount: Option<u64>,
    #[serde(default)]
    allow_pending: bool,
}

#[derive(Serialize)]
struct DraftTransferResponse {
    family: &'static str,
    operation: &'static str,
    signer: String,
    transaction: String,
    signing_bytes: String,
    encoding: &'static str,
    recipient: String,
    amount: u64,
    pending_outgoing: u64,
    pending_outgoing_hashes: Vec<String>,
    authorization_registered: bool,
    estimated_virtual_size: usize,
    selected_fee_rate_per_byte: u64,
    fee_amount: u64,
    submit_path: &'static str,
}

#[derive(Serialize)]
struct DraftTransactionKindsResponse {
    transfer: DraftTransactionKindResponse,
    qcash_withdraw: DraftTransactionKindResponse,
    qcash_redeem: DraftTransactionKindResponse,
}

#[derive(Serialize)]
struct DraftTransactionKindResponse {
    supported: bool,
    input_model: &'static str,
    fee_mode: &'static str,
}

#[derive(Clone)]
pub(crate) struct RpcState {
    pub(crate) node: Arc<Mutex<Node>>,
    pub(crate) peers: Arc<Mutex<HashMap<SocketAddr, PeerState>>>,
    pub(crate) peer_connections: Arc<Mutex<HashMap<SocketAddr, PeerConnection>>>,
    pub(crate) inbound_connections: Arc<Mutex<HashMap<SocketAddr, PeerConnection>>>,
    pub(crate) mining: bool,
    pub(crate) log_counters: Arc<LogCounters>,
    pub(crate) mining_stats: Arc<MiningStats>,
    pub(crate) metrics: Arc<RpcMetrics>,
    pub(crate) db_path: String,
}

#[derive(Default)]
pub(crate) struct RpcMetrics {
    pub(crate) requests_total: AtomicU64,
    pub(crate) errors_total: AtomicU64,
    pub(crate) latency_micros_total: AtomicU64,
}

#[derive(Clone)]
pub(crate) struct RpcServerConfig {
    pub(crate) public_addr: SocketAddr,
    pub(crate) admin_addr: Option<SocketAddr>,
    pub(crate) admin_token: Option<Arc<Zeroizing<String>>>,
    pub(crate) tls_cert: Option<String>,
    pub(crate) tls_key: Option<String>,
    pub(crate) cors_origins: Vec<String>,
    pub(crate) max_body_bytes: usize,
    pub(crate) timeout: Duration,
    pub(crate) max_concurrent_requests: usize,
    pub(crate) max_connections: usize,
    pub(crate) rate_limit_per_second: u64,
    pub(crate) rate_limit_burst: u64,
}

struct RateBucket {
    tokens: f64,
    updated_at: Instant,
}

struct RpcRateLimiter {
    buckets: Mutex<HashMap<IpAddr, RateBucket>>,
    rate_per_second: f64,
    burst: f64,
}

#[derive(Clone)]
struct ConnectionLimitAcceptor {
    permits: Arc<Semaphore>,
}

impl ConnectionLimitAcceptor {
    fn new(max_connections: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(max_connections)),
        }
    }
}

struct LimitedStream {
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
}

impl AsyncRead for LimitedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for LimitedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

impl<S> axum_server::accept::Accept<TcpStream, S> for ConnectionLimitAcceptor {
    type Stream = LimitedStream;
    type Service = S;
    type Future = std::future::Ready<std::io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        std::future::ready(
            self.permits
                .clone()
                .try_acquire_owned()
                .map(|permit| {
                    (
                        LimitedStream {
                            stream,
                            _permit: permit,
                        },
                        service,
                    )
                })
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "RPC connection limit reached",
                    )
                }),
        )
    }
}

impl RpcRateLimiter {
    fn new(rate_per_second: u64, burst: u64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            rate_per_second: rate_per_second as f64,
            burst: burst as f64,
        }
    }

    fn allow(&self, ip: IpAddr) -> bool {
        let Ok(mut buckets) = self.buckets.lock() else {
            return false;
        };
        let now = Instant::now();
        let bucket = buckets.entry(ip).or_insert(RateBucket {
            tokens: self.burst,
            updated_at: now,
        });
        let elapsed = now.duration_since(bucket.updated_at).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate_per_second).min(self.burst);
        bucket.updated_at = now;
        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        true
    }
}

#[derive(Default)]
pub(crate) struct LogCounters {
    pub(crate) accepted_tx_total: AtomicU64,
    pub(crate) broadcast_tx_total: AtomicU64,
}

#[derive(Serialize)]
struct StatusResponse {
    chain: &'static str,
    stage: &'static str,
    protocol_version: u8,
    pow_algorithm: &'static str,
    difficulty_algorithm: &'static str,
    height: u64,
    tip_hash: String,
    peers: usize,
    known_peers: usize,
    outbound_peers: usize,
    inbound_peers: usize,
    mining: bool,
    hashrate_hps: u64,
    last_mine_attempts: u64,
    min_relay_fee_rate_per_byte: u64,
    market_fee_rate_per_byte: u64,
    dynamic_market_fee_rate_per_byte: u64,
}

#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
}

#[derive(Serialize)]
struct PeerResponse {
    addr: String,
    failures: u32,
    last_tip: Option<u64>,
}

#[derive(Serialize)]
struct AddPeerResponse {
    accepted: bool,
    peer: String,
    known_peers: usize,
}

#[derive(Serialize)]
struct SubmitTxResponse {
    accepted: bool,
    hash: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct ChainResponse {
    chain: &'static str,
    coin: &'static str,
    stage: &'static str,
    protocol_version: u8,
    pow_algorithm: &'static str,
    pow_memory_kib: u32,
    pow_iterations: u32,
    pow_lanes: u32,
    difficulty_algorithm: &'static str,
    difficulty_step_interval: u64,
    confirmation_depth: u32,
    finality_depth: u32,
    block_reward_maturity: u32,
    difficulty_start: u32,
}

#[derive(Serialize)]
struct ChainStatsResponse {
    chain: &'static str,
    coin: &'static str,
    height: u64,
    blocks: u64,
    genesis_premine: u64,
    mined_supply: u64,
    onchain_supply: u64,
    qcash_offchain_supply: u64,
    qcash_redeemable_supply: u64,
    qcash_pending_supply: u64,
    total_known_supply: u64,
    current_supply: u64,
    miner_income: u64,
    service_revenue: u64,
    total_transactions: u64,
    transfer_transactions: u64,
    pending_transactions: u64,
    total_transfer_volume: u64,
    total_transaction_fees: u64,
    average_transfer_amount: u64,
}

#[derive(Serialize)]
struct AccountProofResponse {
    encoding: &'static str,
    proof_kind: &'static str,
    exists: bool,
    address: String,
    height: u64,
    block_hash: String,
    protocol_state_root: String,
    account_state_root: String,
    authorization_registered: Option<bool>,
    checkpoint_height: Option<u64>,
    checkpoint_hash: Option<String>,
    bundle: String,
}

#[derive(Serialize)]
struct QCashProofResponse {
    encoding: &'static str,
    proof_kind: &'static str,
    exists: bool,
    coin_id: String,
    height: u64,
    block_hash: String,
    protocol_state_root: String,
    qcash_state_root: String,
    denomination_xpq: Option<u64>,
    issued_height: Option<u64>,
    checkpoint_height: Option<u64>,
    checkpoint_hash: Option<String>,
    terminal_depth: u16,
    bundle: String,
}

#[derive(Serialize)]
struct HeaderChainChunkResponse {
    encoding: &'static str,
    node_tip_height: u64,
    start_height: Option<u64>,
    end_height: Option<u64>,
    header_count: usize,
    has_more: bool,
    chunk: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct ProtocolTxResponse {
    family: &'static str,
    operation: &'static str,
    txid: String,
    signer: String,
    authorization_addresses: Vec<String>,
    recipient: Option<String>,
    amount: Option<u64>,
    payload_size: usize,
    proof_size: usize,
    virtual_size: usize,
    block_height: Option<u64>,
    block_hash: Option<String>,
    confirmations: u64,
    depth: u64,
    confirmation_depth: u32,
    finality_depth: u32,
    confirmed: bool,
    finalized: bool,
    status: &'static str,
}

#[derive(Serialize)]
struct CoinbaseResponse {
    to: String,
    subsidy: u64,
    fees: u64,
    total: u64,
}

#[derive(Serialize)]
pub(crate) struct BlockResponse {
    version: u8,
    height: u64,
    hash: String,
    short_hash: String,
    previous_hash: String,
    merkle_root: String,
    state_root: String,
    miner_address: String,
    difficulty: u32,
    confirmations: u64,
    value_moved: u64,
    nonce: u64,
    tx_count: usize,
    size: usize,
    payload_size: usize,
    weight: usize,
    coinbase: Option<CoinbaseResponse>,
    transactions: Vec<ProtocolTxResponse>,
}

#[derive(Serialize)]
struct MinedBlockResponse {
    height: u64,
    hash: String,
    confirmations: u64,
    maturity_height: u64,
    matured: bool,
    subsidy: u64,
    fees: u64,
    total: u64,
    tx_count: usize,
    timestamp: u64,
}

#[derive(Serialize)]
struct AddressResponse {
    address: String,
    balance: serde_json::Value,
    mined_blocks: Vec<MinedBlockResponse>,
    transactions: Vec<ProtocolTxResponse>,
}

#[derive(Serialize)]
struct AccountResponse {
    address: String,
    confirmed: u64,
    available: u64,
    unspendable: u64,
    pending_incoming: u64,
    pending_outgoing: u64,
    authorization_registered: bool,
    utxos: usize,
}

#[derive(Serialize)]
struct MempoolResponse {
    size: usize,
    transactions: Vec<ProtocolTxResponse>,
}

#[derive(Serialize)]
pub(crate) struct ProtocolEventResponse {
    id: String,
    pub(crate) event: ProtocolEvent,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct EventQuery {
    pub(crate) offset: Option<usize>,
    pub(crate) limit: Option<usize>,
    pub(crate) kind: Option<String>,
    pub(crate) from_height: Option<u64>,
    pub(crate) to_height: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct EventStreamQuery {
    from_height: Option<u64>,
    kind: Option<String>,
    address: Option<String>,
}

struct ProtocolEventStreamState {
    rpc: RpcState,
    next_height: u64,
    kind: Option<String>,
    address: Option<Address>,
    pending: VecDeque<ProtocolEvent>,
    poll_immediately: bool,
}

#[derive(Serialize)]
pub(crate) struct ProtocolEventListResponse {
    pub(crate) total: usize,
    offset: usize,
    limit: usize,
    pub(crate) events: Vec<ProtocolEventResponse>,
}

pub(crate) fn start_rpc_servers(
    state: RpcState,
    config: RpcServerConfig,
) -> Result<Vec<thread::JoinHandle<()>>, String> {
    let metrics = state.metrics.clone();
    let public = Router::new()
        .route("/", get(rpc_status))
        .route("/status", get(rpc_status))
        .route("/health", get(rpc_health))
        .route("/metrics", get(rpc_metrics))
        .route("/chain", get(rpc_chain))
        .route("/stats", get(rpc_stats))
        .route("/fee-policy", get(rpc_fee_policy))
        .route("/chain/stats", get(rpc_stats))
        .route("/peers", get(rpc_peers))
        .route("/balance/{address}", get(rpc_balance))
        .route("/draft-basis/{address}", get(rpc_draft_basis))
        .route("/draft/transfer", post(rpc_draft_transfer))
        .route("/proof/account/{address}", get(rpc_account_proof))
        .route("/proof/qcash/{coin_id}", get(rpc_qcash_proof))
        .route("/proof/headers", get(rpc_header_chain_chunk))
        .route("/blocks/latest", get(rpc_latest_blocks))
        .route("/blocks/{height}", get(rpc_block_by_height))
        .route("/blocks/hash/{hash}", get(rpc_block_by_hash))
        .route("/blocks/{height}/events", get(rpc_block_events))
        .route("/tx/{hash}", get(rpc_tx))
        .route("/tx/{hash}/events", get(rpc_transaction_events))
        .route("/address/{address}", get(rpc_address))
        .route("/address/{address}/events", get(rpc_address_events))
        .route(
            "/account/{address}/rollback-issues",
            get(rpc_account_rollback_issues),
        )
        .route("/rollback-issues/{id}", get(rpc_rollback_issue))
        .route("/events/stream", get(rpc_event_stream))
        .route("/events/{id}", get(rpc_event))
        .route("/accounts", get(rpc_accounts))
        .route("/mempool", get(rpc_mempool))
        .route("/xpq/utxos", get(rpc_xpq_utxos))
        .route("/xpq/coin/{coin_id}", get(rpc_xpq_coin))
        .route("/qcash/mempool", get(rpc_qcash_mempool))
        .route("/qcash/utxos", get(rpc_qcash_utxos))
        .route("/qcash/file/{name}", get(rpc_qcash_file))
        .route("/qcash/coin/{coin_id}", get(rpc_qcash_coin))
        .route("/tx", post(rpc_submit_tx))
        .route("/transaction", post(rpc_submit_tx))
        .route("/protocol/transaction", post(rpc_submit_protocol_tx))
        .route("/qcash/tx", post(rpc_submit_qcash_tx));
    #[cfg(any(feature = "devnet", feature = "testnet"))]
    let public = public.route("/faucet", post(rpc_faucet));

    let public = secure_router(public, &config)?
        .layer(middleware::from_fn_with_state(
            metrics.clone(),
            track_rpc_request,
        ))
        .with_state(state.clone());

    let mut handles = vec![spawn_rpc_listener(
        "xparq-rpc-public",
        "public",
        config.public_addr,
        public,
        config.tls_cert.clone(),
        config.tls_key.clone(),
        config.max_connections,
    )?];

    if let Some(admin_addr) = config.admin_addr {
        let token = config.admin_token.clone().ok_or_else(|| {
            "RPC admin listener requires --rpc-admin-token or rpc_admin_token".to_string()
        })?;
        let admin = Router::new()
            .route("/health", get(rpc_health))
            .route("/peers/add", post(rpc_add_peer))
            .route(
                "/rollback-issues/{id}/retry",
                post(rpc_retry_rollback_issue),
            )
            .route("/mining/template", get(rpc_mining_template))
            .route("/mining/submit", post(rpc_submit_mined_block))
            .layer(middleware::from_fn_with_state(token, require_admin_auth));
        let admin = secure_router(admin, &config)?
            .layer(middleware::from_fn_with_state(metrics, track_rpc_request))
            .with_state(state);
        handles.push(spawn_rpc_listener(
            "xparq-rpc-admin",
            "admin",
            admin_addr,
            admin,
            config.tls_cert,
            config.tls_key,
            config.max_connections,
        )?);
    }

    Ok(handles)
}

fn secure_router(
    router: Router<RpcState>,
    config: &RpcServerConfig,
) -> Result<Router<RpcState>, String> {
    let rate_limiter = Arc::new(RpcRateLimiter::new(
        config.rate_limit_per_second,
        config.rate_limit_burst,
    ));
    let mut router = router
        .layer(middleware::from_fn_with_state(
            rate_limiter,
            enforce_rate_limit,
        ))
        .layer(ConcurrencyLimitLayer::new(config.max_concurrent_requests))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            config.timeout,
        ))
        .layer(RequestBodyLimitLayer::new(config.max_body_bytes));

    if !config.cors_origins.is_empty() {
        let origins = config
            .cors_origins
            .iter()
            .map(|origin| {
                HeaderValue::from_str(origin)
                    .map_err(|_| format!("invalid RPC CORS origin `{origin}`"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        router = router.layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods([Method::GET, Method::POST])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                ]),
        );
    }
    Ok(router)
}

fn spawn_rpc_listener(
    thread_name: &str,
    label: &'static str,
    addr: SocketAddr,
    app: Router,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    max_connections: usize,
) -> Result<thread::JoinHandle<()>, String> {
    if !addr.ip().is_loopback() && (tls_cert.is_none() || tls_key.is_none()) {
        return Err(format!(
            "{label} RPC listener {addr} is non-loopback and requires --rpc-tls-cert and --rpc-tls-key"
        ));
    }

    thread::Builder::new()
        .name(thread_name.to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(runtime) => runtime,
                Err(error) => {
                    eprintln!("[RPC] runtime_failed error=\"{error}\"");
                    return;
                }
            };
            runtime.block_on(async move {
                if let (Some(cert), Some(key)) = (tls_cert, tls_key) {
                    let tls = match axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                        .await
                    {
                        Ok(tls) => tls,
                        Err(error) => {
                            eprintln!(
                                "[RPC] tls_failed label={label} addr={addr} error=\"{error}\""
                            );
                            return;
                        }
                    };
                    println!("[RPC] listening label={label} addr={addr} tls=true");
                    let acceptor = axum_server::tls_rustls::RustlsAcceptor::new(tls)
                        .acceptor(ConnectionLimitAcceptor::new(max_connections));
                    if let Err(error) = axum_server::bind(addr)
                        .acceptor(acceptor)
                        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                        .await
                    {
                        eprintln!("[RPC] server_failed label={label} error=\"{error}\"");
                    }
                } else {
                    println!("[RPC] listening label={label} addr={addr} tls=false");
                    if let Err(error) = axum_server::bind(addr)
                        .acceptor(ConnectionLimitAcceptor::new(max_connections))
                        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                        .await
                    {
                        eprintln!("[RPC] server_failed label={label} error=\"{error}\"");
                    }
                }
            });
        })
        .map_err(|error| format!("failed to spawn rpc server: {error}"))
}

async fn enforce_rate_limit(
    State(limiter): State<Arc<RpcRateLimiter>>,
    request: Request<Body>,
    next: Next,
) -> axum::response::Response {
    let ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|peer| peer.0.ip())
        .unwrap_or(IpAddr::from([0, 0, 0, 0]));
    if !limiter.allow(ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "RPC rate limit exceeded".to_string(),
            }),
        )
            .into_response();
    }
    next.run(request).await
}

async fn require_admin_auth(
    State(expected): State<Arc<Zeroizing<String>>>,
    request: Request<Body>,
    next: Next,
) -> axum::response::Response {
    let supplied = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if !supplied.is_some_and(|token| constant_time_eq(token.as_bytes(), expected.as_bytes())) {
        return (
            StatusCode::UNAUTHORIZED,
            [(axum::http::header::WWW_AUTHENTICATE, "Bearer")],
            Json(ErrorResponse {
                error: "admin authentication required".to_string(),
            }),
        )
            .into_response();
    }
    next.run(request).await
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let length = left.len().max(right.len());
    for index in 0..length {
        difference |= usize::from(
            left.get(index).copied().unwrap_or_default()
                ^ right.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

async fn track_rpc_request(
    State(metrics): State<Arc<RpcMetrics>>,
    request: Request<Body>,
    next: Next,
) -> axum::response::Response {
    let started = Instant::now();
    let response = next.run(request).await;
    metrics.requests_total.fetch_add(1, Ordering::Relaxed);
    metrics.latency_micros_total.fetch_add(
        started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        Ordering::Relaxed,
    );
    if response.status().is_client_error() || response.status().is_server_error() {
        metrics.errors_total.fetch_add(1, Ordering::Relaxed);
    }
    response
}

async fn rpc_metrics(State(state): State<RpcState>) -> impl IntoResponse {
    let (height, mempool_size, validation_failures, reorgs) = state
        .node
        .lock()
        .map(|node| {
            (
                node.tip_height().unwrap_or(Height(0)).0,
                node.mempool.len(),
                node.block_validation_failures_total(),
                node.reorgs_total(),
            )
        })
        .unwrap_or_default();
    let peer_count = state
        .peer_connections
        .lock()
        .map(|peers| peers.len())
        .unwrap_or_default()
        + state
            .inbound_connections
            .lock()
            .map(|peers| peers.len())
            .unwrap_or_default();
    let database_bytes = fs::metadata(std::path::Path::new(&state.db_path).join("data.mdb"))
        .map(|metadata| metadata.len())
        .unwrap_or_default();
    let network = crate::runtime::network::metrics::NETWORK_METRICS.snapshot();
    let mut body = format!(
        concat!(
            "# TYPE xparq_chain_height gauge\nxparq_chain_height {height}\n",
            "# TYPE xparq_peer_count gauge\nxparq_peer_count {peer_count}\n",
            "# TYPE xparq_mempool_size gauge\nxparq_mempool_size {mempool_size}\n",
            "# TYPE xparq_block_validation_failures_total counter\nxparq_block_validation_failures_total {validation_failures}\n",
            "# TYPE xparq_reorgs_total counter\nxparq_reorgs_total {reorgs}\n",
            "# TYPE xparq_rpc_requests_total counter\nxparq_rpc_requests_total {requests}\n",
            "# TYPE xparq_rpc_errors_total counter\nxparq_rpc_errors_total {errors}\n",
            "# TYPE xparq_rpc_latency_seconds summary\nxparq_rpc_latency_seconds_sum {latency_seconds:.6}\nxparq_rpc_latency_seconds_count {requests}\n",
            "# TYPE xparq_mining_hashrate_hps gauge\nxparq_mining_hashrate_hps {hashrate}\n",
            "# TYPE xparq_database_size_bytes gauge\nxparq_database_size_bytes {database_bytes}\n",
            "# TYPE xparq_tx_duplicate_total counter\nxparq_tx_duplicate_total {duplicate_transactions}\n",
            "# TYPE xparq_compact_block_success_total counter\nxparq_compact_block_success_total {compact_success}\n",
            "# TYPE xparq_compact_block_fallback_total counter\nxparq_compact_block_fallback_total {compact_fallback}\n",
            "# TYPE xparq_compact_block_missing_tx_total counter\nxparq_compact_block_missing_tx_total {compact_missing}\n"
        ),
        height = height,
        peer_count = peer_count,
        mempool_size = mempool_size,
        validation_failures = validation_failures,
        reorgs = reorgs,
        requests = state.metrics.requests_total.load(Ordering::Relaxed),
        errors = state.metrics.errors_total.load(Ordering::Relaxed),
        latency_seconds =
            state.metrics.latency_micros_total.load(Ordering::Relaxed) as f64 / 1_000_000.0,
        hashrate = state.mining_stats.last_hashrate_hps.load(Ordering::Relaxed),
        database_bytes = database_bytes,
        duplicate_transactions = crate::runtime::network::metrics::NETWORK_METRICS
            .duplicate_transactions
            .load(Ordering::Relaxed),
        compact_success = crate::runtime::network::metrics::NETWORK_METRICS
            .compact_success
            .load(Ordering::Relaxed),
        compact_fallback = crate::runtime::network::metrics::NETWORK_METRICS
            .compact_fallback
            .load(Ordering::Relaxed),
        compact_missing = crate::runtime::network::metrics::NETWORK_METRICS
            .compact_missing_transactions
            .load(Ordering::Relaxed),
    );
    body.push_str("# TYPE xparq_network_rx_bytes_total counter\n");
    body.push_str("# TYPE xparq_network_tx_bytes_total counter\n");
    for (index, category) in crate::runtime::network::metrics::NETWORK_CATEGORIES
        .iter()
        .enumerate()
    {
        body.push_str(&format!(
            "xparq_network_rx_bytes_total{{type=\"{category}\"}} {}\nxparq_network_tx_bytes_total{{type=\"{category}\"}} {}\n",
            network[index].0, network[index].1
        ));
    }
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body)
}

async fn rpc_status(State(state): State<RpcState>) -> impl IntoResponse {
    match (
        state.node.lock(),
        state.peers.lock(),
        state.peer_connections.lock(),
        state.inbound_connections.lock(),
    ) {
        (Ok(node), Ok(peers), Ok(outbound), Ok(inbound)) => {
            let fee_market = node.mempool.fee_market_snapshot();
            Json(StatusResponse {
                chain: CHAIN_NAME,
                stage: PROTOCOL_STAGE,
                protocol_version: PROTOCOL_VERSION,
                pow_algorithm: CURRENT_CHAIN_PARAMS.pow_algorithm,
                difficulty_algorithm: CURRENT_CHAIN_PARAMS.difficulty_algorithm,
                height: node.tip_height().unwrap_or(Height(0)).0,
                tip_hash: format_hash(node.tip_hash()),
                peers: peers.len(),
                known_peers: peers.len(),
                outbound_peers: outbound.len(),
                inbound_peers: inbound.len(),
                mining: state.mining,
                hashrate_hps: state.mining_stats.last_hashrate_hps.load(Ordering::Relaxed),
                last_mine_attempts: state.mining_stats.last_attempts.load(Ordering::Relaxed),
                min_relay_fee_rate_per_byte: fee_market.min_relay_fee_rate,
                market_fee_rate_per_byte: fee_market.configured_market_fee_rate,
                dynamic_market_fee_rate_per_byte: fee_market.recommended_fee_rate,
            })
            .into_response()
        }
        _ => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}

async fn rpc_fee_policy(State(state): State<RpcState>) -> impl IntoResponse {
    match state.node.lock() {
        Ok(node) => {
            let fee_market = node.mempool.fee_market_snapshot();
            Json(serde_json::json!({
                "unit": "xparq/vByte",
                "min_relay_fee_rate": fee_market.min_relay_fee_rate,
                "market_fee_rate": fee_market.configured_market_fee_rate,
                "dynamic_market_fee_rate": fee_market.recommended_fee_rate,
                "recommended_fee_rate": fee_market.recommended_fee_rate,
                "pressure_bps": fee_market.pressure_bps,
                "mempool": {
                    "transactions": fee_market.transaction_count,
                    "bytes": fee_market.total_bytes,
                    "max_transactions": fee_market.max_transactions,
                    "max_bytes": fee_market.max_bytes
                },
                "estimates": {
                    "next_block": fee_market.next_block_clearing_fee_rate,
                    "median": fee_market.median_fee_rate,
                    "p75": fee_market.p75_fee_rate,
                    "p90": fee_market.p90_fee_rate
                },
                "services": {
                    "transfer": fee_market.recommended_fee_rate,
                    "qcash": fee_market.recommended_fee_rate
                },
                "required_fee": "ceil(virtual_size * selected_rate)",
                "consensus_enforced": false
            }))
            .into_response()
        }
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}

async fn rpc_health() -> impl IntoResponse {
    Json(HealthResponse { ok: true })
}

async fn rpc_chain() -> impl IntoResponse {
    Json(ChainResponse {
        chain: CHAIN_NAME,
        coin: COIN_NAME,
        stage: PROTOCOL_STAGE,
        protocol_version: PROTOCOL_VERSION,
        pow_algorithm: CURRENT_CHAIN_PARAMS.pow_algorithm,
        pow_memory_kib: CURRENT_CHAIN_PARAMS.pow_memory_kib,
        pow_iterations: CURRENT_CHAIN_PARAMS.pow_iterations,
        pow_lanes: CURRENT_CHAIN_PARAMS.pow_lanes,
        difficulty_algorithm: CURRENT_CHAIN_PARAMS.difficulty_algorithm,
        difficulty_step_interval: 0,
        confirmation_depth: CONFIRMATION_DEPTH,
        finality_depth: FINALITY_DEPTH,
        block_reward_maturity: BLOCK_REWARD_MATURITY,
        difficulty_start: DIFFICULTY_START,
    })
}

async fn rpc_stats(State(state): State<RpcState>) -> impl IntoResponse {
    match state.node.lock() {
        Ok(node) => match chain_stats(&node) {
            Ok(stats) => Json(stats).into_response(),
            Err(error) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error),
        },
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}

async fn rpc_peers(State(state): State<RpcState>) -> impl IntoResponse {
    match state.peers.lock() {
        Ok(peers) => {
            let peers = peers
                .values()
                .map(|peer| PeerResponse {
                    addr: peer.addr.to_string(),
                    failures: peer.failures,
                    last_tip: peer.last_tip.map(|height| height.0),
                })
                .collect::<Vec<_>>();
            Json(peers).into_response()
        }
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}

async fn rpc_add_peer(
    State(state): State<RpcState>,
    Json(request): Json<AddPeerRequest>,
) -> impl IntoResponse {
    let peer = match request.peer.parse::<SocketAddr>() {
        Ok(peer) => peer,
        Err(error) => {
            return rpc_error(
                StatusCode::BAD_REQUEST,
                format!("invalid peer address: {error}"),
            );
        }
    };
    match state.peers.lock() {
        Ok(mut peers) => {
            peers.entry(peer).or_insert_with(|| PeerState::new(peer));
            Json(AddPeerResponse {
                accepted: true,
                peer: peer.to_string(),
                known_peers: peers.len(),
            })
            .into_response()
        }
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}

async fn rpc_balance(
    State(state): State<RpcState>,
    AxumPath(address): AxumPath<String>,
) -> impl IntoResponse {
    let address = match parse_address_string(&address) {
        Ok(address) => address,
        Err(error) => return rpc_error(StatusCode::BAD_REQUEST, error),
    };
    match state.node.lock() {
        Ok(node) => (
            StatusCode::OK,
            [("content-type", "application/json")],
            balance_json(&node, &address),
        )
            .into_response(),
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}

async fn rpc_draft_basis(
    State(state): State<RpcState>,
    AxumPath(address): AxumPath<String>,
) -> impl IntoResponse {
    let address = match parse_address_string(&address) {
        Ok(address) => address,
        Err(error) => return rpc_error(StatusCode::BAD_REQUEST, error),
    };
    match state.node.lock() {
        Ok(node) => {
            let Some(basis) = node.draft_basis(&address) else {
                return rpc_error(StatusCode::NOT_FOUND, "account_not_found");
            };
            Json(DraftBasisResponse {
                signer: address_to_string(&basis.signer),
                live_balance: basis.live_balance.0,
                available_balance: basis.available_balance.0,
                spendable_after_pending: basis.spendable_after_pending.0,
                tip_height: basis.tip_height.0,
                finalized_height: basis.finalized_height.0,
                pending_incoming: basis.pending_incoming.0,
                pending_outgoing: basis.pending_outgoing.0,
                pending_outgoing_hashes: basis
                    .pending_outgoing_hashes
                    .iter()
                    .map(|hash| hex::encode(hash.0))
                    .collect(),
                transaction_kinds: DraftTransactionKindsResponse {
                    transfer: DraftTransactionKindResponse {
                        supported: true,
                        input_model: "owned_utxo",
                        fee_mode: "block_miner_output",
                    },
                    qcash_withdraw: DraftTransactionKindResponse {
                        supported: true,
                        input_model: "owned_utxo",
                        fee_mode: "none",
                    },
                    qcash_redeem: DraftTransactionKindResponse {
                        supported: true,
                        input_model: "qcash_bearer_utxo",
                        fee_mode: "block_miner_output",
                    },
                },
            })
            .into_response()
        }
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}

async fn rpc_draft_transfer(
    State(state): State<RpcState>,
    Json(request): Json<DraftTransferRequest>,
) -> impl IntoResponse {
    let signer = match parse_address_string(&request.signer) {
        Ok(address) => address,
        Err(error) => return rpc_error(StatusCode::BAD_REQUEST, error),
    };
    if request.amount == 0 {
        return rpc_error(StatusCode::BAD_REQUEST, "transfer_amount_must_be_positive");
    }
    let target = match request.to.as_str() {
        "block_miner" | "miner" => xparq::transaction::OutputTarget::BlockMiner,
        value => match parse_address_string(value) {
            Ok(address) => address.into(),
            Err(error) => return rpc_error(StatusCode::BAD_REQUEST, error),
        },
    };

    match state.node.lock() {
        Ok(node) => {
            let Some(basis) = node.draft_basis(&signer) else {
                return rpc_error(StatusCode::NOT_FOUND, "account_not_found");
            };
            if !request.allow_pending
                && (basis.pending_outgoing.0 > 0 || !basis.pending_outgoing_hashes.is_empty())
            {
                return rpc_error(StatusCode::CONFLICT, "pending_outgoing_transaction");
            }
            let authorization_registered = node
                .ledger
                .account(&basis.signer)
                .map(|account| account.authorization.is_some())
                .unwrap_or(false);
            let selected_fee_rate = if request.fee_amount.is_some() {
                0
            } else {
                match request.fee_rate_per_byte {
                    Some(rate) => rate,
                    None => node
                        .mempool
                        .dynamic_market_fee_rate()
                        .max(node.mempool.config().min_relay_fee)
                        .max(1),
                }
            };
            let tip_height = node.tip_height().unwrap_or(xparq::block::Height(0));
            let mut reserved = std::collections::BTreeSet::new();
            for pending in node.mempool.transactions() {
                match pending {
                    SignedProtocolTransaction::Transfer(tx) => {
                        reserved.extend(tx.transaction.inputs.iter().copied());
                    }
                    SignedProtocolTransaction::QCash(tx) => {
                        if let xparq::transaction::QCashTransactionKind::Withdraw {
                            inputs, ..
                        } = &tx.transaction.kind
                        {
                            reserved.extend(inputs.iter().copied());
                        }
                    }
                }
            }
            let available = node
                .ledger
                .xpq_utxos
                .coins_for_owner(signer)
                .filter(|coin| coin.maturity_height.0 <= tip_height.0)
                .filter(|coin| !reserved.contains(&coin.id))
                .cloned()
                .collect::<Vec<_>>();
            let select = |required: u64| {
                let mut ids = Vec::new();
                let mut total = 0_u64;
                for coin in &available {
                    ids.push(coin.id);
                    total = total.checked_add(coin.amount.0)?;
                    if total >= required {
                        return Some((ids, total));
                    }
                }
                None
            };
            let mut fee_amount = 0_u64;
            let mut estimated_virtual_size = 0_usize;
            let mut transaction = None;
            for _ in 0..3 {
                let Some(required) = request.amount.checked_add(fee_amount) else {
                    return rpc_error(StatusCode::BAD_REQUEST, "transfer_amount_overflow");
                };
                let Some((inputs, input_total)) = select(required) else {
                    return rpc_error(StatusCode::CONFLICT, "insufficient_spendable_utxos");
                };
                let mut outputs = vec![xparq::transaction::TransferOutput::new(
                    target,
                    xparq::consensus::supply::Amount(request.amount),
                )];
                if fee_amount > 0 {
                    outputs.push(xparq::transaction::TransferOutput::new(
                        xparq::transaction::OutputTarget::BlockMiner,
                        xparq::consensus::supply::Amount(fee_amount),
                    ));
                }
                let change = input_total.saturating_sub(required);
                if change > 0 {
                    outputs.push(xparq::transaction::TransferOutput::new(
                        signer,
                        xparq::consensus::supply::Amount(change),
                    ));
                }
                let candidate = Transaction::from_outputs(signer, inputs, outputs);
                let size_template = if authorization_registered {
                    xparq::transaction::SignedTransfer::new_stored_authorized(
                        candidate.clone(),
                        xparq::crypto::Signature([1; xparq::crypto::SIGNATURE_SIZE]),
                        xparq::crypto::Signature([1; xparq::crypto::SIGNATURE_SIZE]),
                    )
                } else {
                    xparq::transaction::SignedTransfer::new_authorized(
                        candidate.clone(),
                        xparq::crypto::PublicKey([1; xparq::crypto::PUBLIC_KEY_SIZE]),
                        xparq::crypto::Signature([1; xparq::crypto::SIGNATURE_SIZE]),
                        xparq::crypto::PublicKey([2; xparq::crypto::PUBLIC_KEY_SIZE]),
                        xparq::crypto::Signature([2; xparq::crypto::SIGNATURE_SIZE]),
                    )
                };
                estimated_virtual_size =
                    match SignedProtocolTransaction::from(size_template).virtual_size() {
                        Ok(size) => size,
                        Err(error) => {
                            return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string());
                        }
                    };
                let next_fee = match request.fee_amount {
                    Some(amount) => amount,
                    None => {
                        let Some(amount) =
                            selected_fee_rate.checked_mul(estimated_virtual_size as u64)
                        else {
                            return rpc_error(StatusCode::BAD_REQUEST, "fee_amount_overflow");
                        };
                        amount
                    }
                };
                transaction = Some(candidate);
                if next_fee == fee_amount {
                    break;
                }
                fee_amount = next_fee;
            }
            let transaction = transaction.expect("draft loop always constructs a transaction");
            if let Err(error) = transaction.validate() {
                return rpc_error(
                    StatusCode::BAD_REQUEST,
                    format!("invalid_transaction: {error}"),
                );
            }
            let transaction_payload = match transaction_bytes(&transaction) {
                Ok(bytes) => bytes,
                Err(error) => {
                    return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string());
                }
            };
            let signing_payload = match transaction.signing_bytes() {
                Ok(bytes) => bytes,
                Err(error) => {
                    return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string());
                }
            };
            Json(DraftTransferResponse {
                family: "transfer",
                operation: "unsigned-draft",
                signer: address_to_string(&basis.signer),
                transaction: hex::encode(transaction_payload),
                signing_bytes: hex::encode(signing_payload),
                encoding: "xparq-canonical-borsh-hex-v1",
                recipient: request.to,
                amount: request.amount,
                pending_outgoing: basis.pending_outgoing.0,
                pending_outgoing_hashes: basis
                    .pending_outgoing_hashes
                    .iter()
                    .map(|hash| hex::encode(hash.0))
                    .collect(),
                authorization_registered,
                estimated_virtual_size,
                selected_fee_rate_per_byte: selected_fee_rate,
                fee_amount,
                submit_path: "/tx",
            })
            .into_response()
        }
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}

async fn rpc_header_chain_chunk(
    State(state): State<RpcState>,
    Query(query): Query<ProofQuery>,
) -> impl IntoResponse {
    let node = match state.node.lock() {
        Ok(node) => node,
        Err(_) => return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    };
    let Some(tip_height) = node.tip_height() else {
        return rpc_error(StatusCode::SERVICE_UNAVAILABLE, "chain_has_no_tip");
    };
    let start_height = match query.checkpoint_height {
        Some(height) if height <= tip_height.0 => {
            let header = match node.storage.load_header_by_height(Height(height)) {
                Ok(Some(header)) => header,
                _ => return rpc_error(StatusCode::BAD_REQUEST, "checkpoint_header_missing"),
            };
            let hash = match header.hash() {
                Ok(hash) => hash,
                Err(error) => {
                    return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string());
                }
            };
            if query.checkpoint_hash.as_deref().is_none_or(|expected| {
                hex::decode(expected).ok().as_deref() != Some(hash.0.as_slice())
            }) {
                return rpc_error(StatusCode::BAD_REQUEST, "checkpoint_hash_mismatch");
            }
            height.saturating_add(1)
        }
        Some(_) => return rpc_error(StatusCode::BAD_REQUEST, "checkpoint_above_tip"),
        None => 0,
    };
    if start_height > tip_height.0 {
        return Json(HeaderChainChunkResponse {
            encoding: "xparq-header-chain-chunk-borsh-hex-v1",
            node_tip_height: tip_height.0,
            start_height: None,
            end_height: None,
            header_count: 0,
            has_more: false,
            chunk: None,
        })
        .into_response();
    }
    let end_height = start_height
        .saturating_add(xparq::qcash::recovery::MAX_HEADER_CHAIN_CHUNK_HEADERS as u64 - 1)
        .min(tip_height.0);
    let mut headers = Vec::with_capacity((end_height - start_height + 1) as usize);
    for height in start_height..=end_height {
        match node.storage.load_header_proof_by_height(Height(height)) {
            Ok(Some(header)) => headers.push(header),
            Ok(None) => {
                return rpc_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "canonical_header_missing",
                );
            }
            Err(error) => {
                return rpc_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("canonical_header_load_failed: {error}"),
                );
            }
        }
    }
    drop(node);
    let header_count = headers.len();
    let chunk = match xparq::qcash::recovery::HeaderChainChunk::new(headers).and_then(|chunk| {
        xparq::codec::canonical_bytes(&chunk)
            .map_err(xparq::qcash::recovery::HeaderChainChunkError::Serialization)
    }) {
        Ok(bytes) => hex::encode(bytes),
        Err(error) => {
            return rpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("header_chunk_encode_failed: {error}"),
            );
        }
    };
    Json(HeaderChainChunkResponse {
        encoding: "xparq-header-chain-chunk-borsh-hex-v1",
        node_tip_height: tip_height.0,
        start_height: Some(start_height),
        end_height: Some(end_height),
        header_count,
        has_more: end_height < tip_height.0,
        chunk: Some(chunk),
    })
    .into_response()
}

async fn rpc_account_proof(
    State(state): State<RpcState>,
    AxumPath(address): AxumPath<String>,
    Query(query): Query<ProofQuery>,
) -> impl IntoResponse {
    let address = match parse_address_string(&address) {
        Ok(address) => address,
        Err(error) => return rpc_error(StatusCode::BAD_REQUEST, error),
    };
    let node = match state.node.lock() {
        Ok(node) => node,
        Err(_) => return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    };
    let Some(tip_height) = node.tip_height() else {
        return rpc_error(StatusCode::SERVICE_UNAVAILABLE, "chain_has_no_tip");
    };
    let Some(tip_hash) = node.tip_hash() else {
        return rpc_error(StatusCode::SERVICE_UNAVAILABLE, "chain_has_no_tip");
    };
    let account_proof = node.ledger.create_account_state_proof(&address);
    let absence_proof = account_proof
        .is_none()
        .then(|| node.ledger.create_account_non_membership_proof(&address))
        .flatten();
    let state_commitment = match node.ledger.state_commitment_for_block_hash(tip_hash) {
        Ok(commitment) => commitment,
        Err(error) => {
            return rpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("state_commitment_failed: {error}"),
            );
        }
    };
    if query.checkpoint_height != Some(tip_height.0) {
        return rpc_error(StatusCode::CONFLICT, "header_sync_required");
    }
    let tip_header = match node.storage.load_header_by_height(tip_height) {
        Ok(Some(header)) => header,
        _ => return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "canonical_tip_missing"),
    };
    let checkpoint_hash = match tip_header.hash() {
        Ok(hash) => hash,
        Err(error) => return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    };
    if query.checkpoint_hash.as_deref().is_none_or(|expected| {
        hex::decode(expected).ok().as_deref() != Some(checkpoint_hash.0.as_slice())
    }) {
        return rpc_error(StatusCode::CONFLICT, "header_sync_required");
    }
    drop(node);
    let (
        encoding,
        proof_kind,
        exists,
        protocol_state_root,
        account_state_root,
        authorization_registered,
        encoded,
    ) = if let Some(account_proof) = account_proof {
        let authorization_registered = account_proof.account.authorization.is_some();
        let bundle = AccountStateProofBundle {
            version: ACCOUNT_STATE_PROOF_BUNDLE_VERSION,
            state_commitment,
            account_proof,
        };
        if let Err(error) = bundle.verify_state_binding(tip_height, &tip_header, tip_hash) {
            return rpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("account_proof_self_check_failed: {error}"),
            );
        }
        let encoded = match xparq::codec::canonical_bytes(&bundle) {
            Ok(bytes) => hex::encode(bytes),
            Err(error) => {
                return rpc_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("account_proof_encode_failed: {error}"),
                );
            }
        };
        (
            "xparq-account-state-proof-borsh-hex-v1",
            "membership",
            true,
            bundle.state_commitment.protocol_state_root,
            bundle.state_commitment.account_state_root,
            Some(authorization_registered),
            encoded,
        )
    } else {
        let Some(account_proof) = absence_proof else {
            return rpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "account_absence_proof_failed",
            );
        };
        let bundle = AccountNonMembershipProofBundle {
            version: ACCOUNT_STATE_PROOF_BUNDLE_VERSION,
            state_commitment,
            account_proof,
        };
        if let Err(error) = bundle.verify_state_binding(tip_height, &tip_header, tip_hash) {
            return rpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("account_proof_self_check_failed: {error}"),
            );
        }
        let encoded = match xparq::codec::canonical_bytes(&bundle) {
            Ok(bytes) => hex::encode(bytes),
            Err(error) => {
                return rpc_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("account_proof_encode_failed: {error}"),
                );
            }
        };
        (
            "xparq-account-non-membership-proof-borsh-hex-v1",
            "non_membership",
            false,
            bundle.state_commitment.protocol_state_root,
            bundle.state_commitment.account_state_root,
            None,
            encoded,
        )
    };
    Json(AccountProofResponse {
        encoding,
        proof_kind,
        exists,
        address: address_to_string(&address),
        height: tip_height.0,
        block_hash: hex::encode(tip_hash.0),
        protocol_state_root: hex::encode(protocol_state_root.0),
        account_state_root: hex::encode(account_state_root.0),
        authorization_registered,
        checkpoint_height: query.checkpoint_height,
        checkpoint_hash: Some(hex::encode(checkpoint_hash.0)),
        bundle: encoded,
    })
    .into_response()
}

async fn rpc_qcash_proof(
    State(state): State<RpcState>,
    AxumPath(coin_id): AxumPath<String>,
    Query(query): Query<ProofQuery>,
) -> impl IntoResponse {
    let bytes = match hex::decode(&coin_id) {
        Ok(bytes) => bytes,
        Err(_) => return rpc_error(StatusCode::BAD_REQUEST, "invalid_coin_id"),
    };
    let Ok(bytes) = <[u8; xparq::crypto::HASH_SIZE]>::try_from(bytes.as_slice()) else {
        return rpc_error(StatusCode::BAD_REQUEST, "invalid_coin_id");
    };
    let coin_id = xparq::state::QCashCoinId(bytes);
    let node = match state.node.lock() {
        Ok(node) => node,
        Err(_) => return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    };
    let Some(tip_height) = node.tip_height() else {
        return rpc_error(StatusCode::SERVICE_UNAVAILABLE, "chain_has_no_tip");
    };
    let Some(tip_hash) = node.tip_hash() else {
        return rpc_error(StatusCode::SERVICE_UNAVAILABLE, "chain_has_no_tip");
    };
    let qcash_proof = match node.ledger.qcash_utxos.create_state_proof(coin_id) {
        Ok(proof) => proof,
        Err(error) => {
            return rpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("qcash_proof_failed: {error}"),
            );
        }
    };
    let state_commitment = match node.ledger.state_commitment_for_block_hash(tip_hash) {
        Ok(commitment) => commitment,
        Err(error) => {
            return rpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("state_commitment_failed: {error}"),
            );
        }
    };
    if query.checkpoint_height != Some(tip_height.0) {
        return rpc_error(StatusCode::CONFLICT, "header_sync_required");
    }
    let tip_header = match node.storage.load_header_by_height(tip_height) {
        Ok(Some(header)) => header,
        _ => return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "canonical_tip_missing"),
    };
    let checkpoint_hash = match tip_header.hash() {
        Ok(hash) => hash,
        Err(error) => return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    };
    if query.checkpoint_hash.as_deref().is_none_or(|expected| {
        hex::decode(expected).ok().as_deref() != Some(checkpoint_hash.0.as_slice())
    }) {
        return rpc_error(StatusCode::CONFLICT, "header_sync_required");
    }
    drop(node);
    let bundle = QCashStateProofBundle {
        version: ACCOUNT_STATE_PROOF_BUNDLE_VERSION,
        state_commitment,
        qcash_proof,
    };
    if let Err(error) = bundle.verify_state_binding(tip_height, &tip_header, tip_hash) {
        return rpc_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("qcash_proof_self_check_failed: {error}"),
        );
    }
    let encoded = match xparq::codec::canonical_bytes(&bundle) {
        Ok(bytes) => hex::encode(bytes),
        Err(error) => {
            return rpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("qcash_proof_encode_failed: {error}"),
            );
        }
    };
    let coin = bundle.qcash_proof.coin.as_ref();
    Json(QCashProofResponse {
        encoding: "xparq-qcash-state-proof-borsh-hex-v1",
        proof_kind: if coin.is_some() {
            "membership"
        } else {
            "non_membership"
        },
        exists: coin.is_some(),
        coin_id: hex::encode(coin_id.0),
        height: tip_height.0,
        block_hash: hex::encode(tip_hash.0),
        protocol_state_root: hex::encode(bundle.state_commitment.protocol_state_root.0),
        qcash_state_root: hex::encode(bundle.state_commitment.qcash_state_root.0),
        denomination_xpq: coin.map(|coin| coin.denomination.xpq()),
        issued_height: coin.map(|coin| coin.issued_height.0),
        checkpoint_height: query.checkpoint_height,
        checkpoint_hash: Some(hex::encode(checkpoint_hash.0)),
        terminal_depth: bundle.qcash_proof.terminal_depth,
        bundle: encoded,
    })
    .into_response()
}

async fn rpc_latest_blocks(State(state): State<RpcState>) -> impl IntoResponse {
    match state.node.lock() {
        Ok(node) => {
            let tip = node.tip_height().unwrap_or(Height(0)).0;
            let start = tip.saturating_sub(9);
            let mut blocks = Vec::new();
            for height in (start..=tip).rev() {
                match node.storage.load_block_by_height(Height(height)) {
                    Ok(Some(block)) => match block_response(&node, &block) {
                        Ok(block) => blocks.push(block),
                        Err(error) => {
                            return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error);
                        }
                    },
                    Ok(None) => {}
                    Err(error) => {
                        return rpc_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("failed to load block: {error}"),
                        );
                    }
                }
            }
            Json(blocks).into_response()
        }
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}

async fn rpc_block_by_height(
    State(state): State<RpcState>,
    AxumPath(height): AxumPath<u64>,
) -> impl IntoResponse {
    match state.node.lock() {
        Ok(node) => match node.storage.load_block_by_height(Height(height)) {
            Ok(Some(block)) => match block_response(&node, &block) {
                Ok(response) => Json(response).into_response(),
                Err(error) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error),
            },
            Ok(None) => rpc_error(StatusCode::NOT_FOUND, "block_not_found"),
            Err(error) => rpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load block: {error}"),
            ),
        },
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}

async fn rpc_block_by_hash(
    State(state): State<RpcState>,
    AxumPath(hash): AxumPath<String>,
) -> impl IntoResponse {
    let hash = match parse_hash_hex(&hash) {
        Ok(hash) => hash,
        Err(error) => return rpc_error(StatusCode::BAD_REQUEST, error),
    };
    let block_hash = BlockHash::from(hash);
    match state.node.lock() {
        Ok(node) => match node.storage.load_block_by_hash(&block_hash) {
            Ok(Some(block)) => match block_response(&node, &block) {
                Ok(response) => Json(response).into_response(),
                Err(error) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, error),
            },
            Ok(None) => rpc_error(StatusCode::NOT_FOUND, "block_not_found"),
            Err(error) => rpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load block: {error}"),
            ),
        },
        Err(_) => rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "state_lock_failed"),
    }
}

fn rpc_error(status: StatusCode, error: impl Into<String>) -> axum::response::Response {
    (
        status,
        Json(ErrorResponse {
            error: error.into(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn admin_token_comparison_rejects_partial_and_wrong_tokens() {
        assert!(constant_time_eq(b"correct-token", b"correct-token"));
        assert!(!constant_time_eq(b"correct-token", b"correct"));
        assert!(!constant_time_eq(b"correct-token", b"wrong-token"));
    }

    #[test]
    fn rate_limiter_enforces_burst_capacity() {
        let limiter = RpcRateLimiter::new(1, 2);
        let ip = IpAddr::from([127, 0, 0, 1]);
        assert!(limiter.allow(ip));
        assert!(limiter.allow(ip));
        assert!(!limiter.allow(ip));
    }

    #[test]
    fn transaction_requests_reject_secret_fields() {
        let request = r#"{"tx":"00","private_key":"do-not-accept"}"#;
        assert!(serde_json::from_str::<SubmitTxRequest>(request).is_err());
    }
}

include!("events.rs");
include!("explorer.rs");
include!("transactions.rs");
include!("mining.rs");
include!("recovery.rs");
