use crate::command::parse::{address, address_string, secret_key};
use crate::runtime;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use xparq::crypto::{
    Address, PublicKey, SecretKey, derive_public_key, dual_address_from_public_keys,
};
use zeroize::{Zeroize, Zeroizing};

#[cfg(any(
    all(feature = "mainnet", feature = "testnet"),
    all(feature = "mainnet", feature = "devnet"),
    all(feature = "testnet", feature = "devnet"),
))]
compile_error!("mainnet, testnet, and devnet features are mutually exclusive");
#[cfg(not(any(feature = "mainnet", feature = "testnet", feature = "devnet")))]
compile_error!("one network feature must be enabled");

pub(crate) const NODE_RPC_LISTEN_ADDR_ENV: &str = "XPARQ_NODE_RPC_LISTEN_ADDR";
pub(crate) const NODE_P2P_LISTEN_ADDR_ENV: &str = "XPARQ_NODE_P2P_LISTEN_ADDR";
pub(crate) const PUBLIC_ADDR_ENV: &str = "XPARQ_PUBLIC_ADDR";
pub(crate) const CONFIG_FILE_ENV: &str = "XPARQ_CONFIG";

#[cfg(feature = "mainnet")]
pub(crate) const DEFAULT_P2P_PORT: u16 = 5555;
#[cfg(feature = "testnet")]
pub(crate) const DEFAULT_P2P_PORT: u16 = 15555;
#[cfg(feature = "devnet")]
pub(crate) const DEFAULT_P2P_PORT: u16 = 25555;

#[cfg(feature = "mainnet")]
pub(crate) const DEFAULT_RPC_PORT: u16 = 6666;
#[cfg(feature = "testnet")]
pub(crate) const DEFAULT_RPC_PORT: u16 = 16666;
#[cfg(feature = "devnet")]
pub(crate) const DEFAULT_RPC_PORT: u16 = 26666;

#[cfg(feature = "mainnet")]
const DEFAULT_NODE_DB: &str = "./data/mainnet";
#[cfg(feature = "testnet")]
const DEFAULT_NODE_DB: &str = "./data/testnet";
#[cfg(feature = "devnet")]
const DEFAULT_NODE_DB: &str = "./data/devnet";
#[cfg(feature = "mainnet")]
pub(crate) const DEFAULT_CONFIG_FILE: &str = "./data/mainnet/config.json";
#[cfg(feature = "testnet")]
pub(crate) const DEFAULT_CONFIG_FILE: &str = "./data/testnet/config.json";
#[cfg(feature = "devnet")]
pub(crate) const DEFAULT_CONFIG_FILE: &str = "./data/devnet/config.json";
#[cfg(feature = "mainnet")]
const DEFAULT_PEERS_FILE: &str = "./data/mainnet/peers.json";
#[cfg(feature = "testnet")]
const DEFAULT_PEERS_FILE: &str = "./data/testnet/peers.json";
#[cfg(feature = "devnet")]
const DEFAULT_PEERS_FILE: &str = "./data/devnet/peers.json";
#[cfg(feature = "mainnet")]
const DEFAULT_SHUTDOWN_FILE: &str = "./data/mainnet/STOP";
#[cfg(feature = "testnet")]
const DEFAULT_SHUTDOWN_FILE: &str = "./data/testnet/STOP";
#[cfg(feature = "devnet")]
const DEFAULT_SHUTDOWN_FILE: &str = "./data/devnet/STOP";
const RPC_ADMIN_TOKEN_ENV: &str = "XPARQ_RPC_ADMIN_TOKEN";
const DEFAULT_MAX_PEERS: usize = 128;
const DEFAULT_GATEWAY_HEARTBEAT: Duration = Duration::from_secs(60);

pub struct RunConfig {
    pub network: String,
    pub db_path: String,
    pub listen_addrs: Vec<SocketAddr>,
    pub rpc_addrs: Vec<SocketAddr>,
    pub rpc_admin_addrs: Vec<SocketAddr>,
    pub rpc_admin_token: Option<Zeroizing<String>>,
    pub rpc_tls_cert: Option<String>,
    pub rpc_tls_key: Option<String>,
    pub rpc_cors_origins: Vec<String>,
    pub rpc_max_body_bytes: usize,
    pub rpc_timeout: Duration,
    pub rpc_max_concurrent_requests: usize,
    pub rpc_max_connections: usize,
    pub rpc_rate_limit_per_second: u64,
    pub rpc_rate_limit_burst: u64,
    pub peers: Vec<SocketAddr>,
    pub peers_file: Option<String>,
    pub dns_seeds: Vec<String>,
    pub gateway_url: Option<String>,
    pub public_addrs: Vec<SocketAddr>,
    pub gateway_heartbeat: Duration,
    pub nat_traversal: bool,
    pub nat_lease: Duration,
    pub grpc_addrs: Vec<SocketAddr>,
    pub shutdown_file: String,
    pub max_peers: usize,
    pub fast_sync: bool,
    pub min_relay_fee: u64,
    pub market_fee: u64,
    pub low_fee_expiry: Duration,
    pub mempool_expiry: Duration,
    pub miner_address: Option<Address>,
    pub miner_secret_key: Option<SecretKey>,
    pub miner_min_fee_rate: Option<u64>,
    pub mine: bool,
    pub mine_interval: Duration,
    pub mine_attempts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunConfigFile {
    #[serde(default = "current_network_string")]
    network: String,
    db_path: String,
    listen_addr_ipv4: OneOrMany<String>,
    listen_addr_ipv6: OneOrMany<String>,
    #[serde(default)]
    rpc_addr_ipv4: Option<String>,
    #[serde(default)]
    rpc_addr_ipv6: Option<String>,
    #[serde(default)]
    rpc_admin_addr_ipv4: Option<String>,
    #[serde(default)]
    rpc_admin_addr_ipv6: Option<String>,
    #[serde(default)]
    rpc_admin_token: Option<SensitiveString>,
    #[serde(default)]
    rpc_tls_cert: Option<String>,
    #[serde(default)]
    rpc_tls_key: Option<String>,
    #[serde(default)]
    rpc_cors_origins: Vec<String>,
    #[serde(default = "default_rpc_max_body_bytes")]
    rpc_max_body_bytes: usize,
    #[serde(default = "default_rpc_timeout_secs")]
    rpc_timeout_secs: u64,
    #[serde(default = "default_rpc_max_concurrent_requests")]
    rpc_max_concurrent_requests: usize,
    #[serde(default = "default_rpc_max_connections")]
    rpc_max_connections: usize,
    #[serde(default = "default_rpc_rate_limit_per_second")]
    rpc_rate_limit_per_second: u64,
    #[serde(default = "default_rpc_rate_limit_burst")]
    rpc_rate_limit_burst: u64,
    #[serde(default)]
    peers_ipv4: Vec<String>,
    #[serde(default)]
    peers_ipv6: Vec<String>,
    peers_file: Option<String>,
    #[serde(default)]
    dns_seeds: Vec<String>,
    gateway_url: Option<String>,
    public_addr_ipv4: Option<OneOrMany<String>>,
    #[serde(default)]
    public_addr_ipv6: Option<OneOrMany<String>>,
    gateway_heartbeat_secs: u64,
    #[serde(default)]
    nat_traversal: bool,
    #[serde(default = "default_nat_lease_secs")]
    nat_lease_secs: u64,
    #[serde(default)]
    grpc_addr_ipv4: Option<String>,
    #[serde(default)]
    grpc_addr_ipv6: Option<String>,
    shutdown_file: String,
    max_peers: usize,
    #[serde(default)]
    fast_sync: bool,
    #[serde(default)]
    min_relay_fee: Option<u64>,
    #[serde(default)]
    market_fee: Option<u64>,
    #[serde(default)]
    low_fee_expiry_secs: Option<u64>,
    #[serde(default)]
    mempool_expiry_secs: Option<u64>,
    wallet: Option<String>,
    miner_address: Option<String>,
    miner_secret_key: Option<SensitiveString>,
    #[serde(default)]
    miner_min_fee_rate: Option<u64>,
    mine: bool,
    mine_interval_secs: u64,
    mine_attempts: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct SensitiveString(String);

impl std::fmt::Debug for SensitiveString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Drop for SensitiveString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    fn into_vec(self) -> Vec<T> {
        match self {
            Self::One(value) => vec![value],
            Self::Many(values) => values,
        }
    }
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            network: current_network().to_string(),
            db_path: DEFAULT_NODE_DB.to_string(),
            listen_addrs: vec![
                std::net::SocketAddr::from(([0, 0, 0, 0], DEFAULT_P2P_PORT)),
                std::net::SocketAddr::from(([0_u16; 8], DEFAULT_P2P_PORT)),
            ],
            rpc_addrs: vec![
                std::net::SocketAddr::from(([127, 0, 0, 1], DEFAULT_RPC_PORT)),
                std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], DEFAULT_RPC_PORT)),
            ],
            rpc_admin_addrs: Vec::new(),
            rpc_admin_token: None,
            rpc_tls_cert: None,
            rpc_tls_key: None,
            rpc_cors_origins: Vec::new(),
            rpc_max_body_bytes: default_rpc_max_body_bytes(),
            rpc_timeout: Duration::from_secs(default_rpc_timeout_secs()),
            rpc_max_concurrent_requests: default_rpc_max_concurrent_requests(),
            rpc_max_connections: default_rpc_max_connections(),
            rpc_rate_limit_per_second: default_rpc_rate_limit_per_second(),
            rpc_rate_limit_burst: default_rpc_rate_limit_burst(),
            peers: Vec::new(),
            peers_file: Some(DEFAULT_PEERS_FILE.to_string()),
            dns_seeds: Vec::new(),
            gateway_url: None,
            public_addrs: Vec::new(),
            gateway_heartbeat: DEFAULT_GATEWAY_HEARTBEAT,
            nat_traversal: false,
            nat_lease: Duration::from_secs(default_nat_lease_secs()),
            grpc_addrs: Vec::new(),
            shutdown_file: DEFAULT_SHUTDOWN_FILE.to_string(),
            max_peers: DEFAULT_MAX_PEERS,
            fast_sync: false,
            min_relay_fee: runtime::params::DEFAULT_MIN_RELAY_FEE,
            market_fee: runtime::params::DEFAULT_MARKET_FEE,
            low_fee_expiry: Duration::from_secs(runtime::params::LOW_FEE_EXPIRY_SECS),
            mempool_expiry: Duration::from_secs(runtime::params::MEMPOOL_EXPIRY_SECS),
            miner_address: None,
            miner_secret_key: None,
            miner_min_fee_rate: None,
            mine: false,
            mine_interval: Duration::from_secs(1),
            mine_attempts: 1_000_000,
        }
    }
}

impl Default for RunConfigFile {
    fn default() -> Self {
        let defaults = RunConfig::default();
        Self {
            network: defaults.network,
            db_path: defaults.db_path,
            listen_addr_ipv4: OneOrMany::Many(vec![format!("0.0.0.0:{DEFAULT_P2P_PORT}")]),
            listen_addr_ipv6: OneOrMany::Many(vec![format!("[::]:{DEFAULT_P2P_PORT}")]),
            rpc_addr_ipv4: Some(format!("127.0.0.1:{DEFAULT_RPC_PORT}")),
            rpc_addr_ipv6: Some(format!("[::1]:{DEFAULT_RPC_PORT}")),
            rpc_admin_addr_ipv4: None,
            rpc_admin_addr_ipv6: None,
            rpc_admin_token: None,
            rpc_tls_cert: None,
            rpc_tls_key: None,
            rpc_cors_origins: Vec::new(),
            rpc_max_body_bytes: defaults.rpc_max_body_bytes,
            rpc_timeout_secs: defaults.rpc_timeout.as_secs(),
            rpc_max_concurrent_requests: defaults.rpc_max_concurrent_requests,
            rpc_max_connections: defaults.rpc_max_connections,
            rpc_rate_limit_per_second: defaults.rpc_rate_limit_per_second,
            rpc_rate_limit_burst: defaults.rpc_rate_limit_burst,
            peers_ipv4: Vec::new(),
            peers_ipv6: Vec::new(),
            peers_file: Some(DEFAULT_PEERS_FILE.to_string()),
            dns_seeds: defaults.dns_seeds,
            gateway_url: None,
            public_addr_ipv4: None,
            public_addr_ipv6: None,
            gateway_heartbeat_secs: defaults.gateway_heartbeat.as_secs(),
            nat_traversal: defaults.nat_traversal,
            nat_lease_secs: defaults.nat_lease.as_secs(),
            grpc_addr_ipv4: None,
            grpc_addr_ipv6: None,
            shutdown_file: defaults.shutdown_file,
            max_peers: defaults.max_peers,
            fast_sync: false,
            min_relay_fee: Some(defaults.min_relay_fee),
            market_fee: Some(defaults.market_fee),
            low_fee_expiry_secs: Some(defaults.low_fee_expiry.as_secs()),
            mempool_expiry_secs: Some(defaults.mempool_expiry.as_secs()),
            wallet: Some("wallet.json".to_string()),
            miner_address: None,
            miner_secret_key: None,
            miner_min_fee_rate: defaults.miner_min_fee_rate,
            mine: true,
            mine_interval_secs: defaults.mine_interval.as_secs(),
            mine_attempts: defaults.mine_attempts,
        }
    }
}

pub fn write_default(path: &str) -> Result<(), String> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create config directory: {error}"))?;
    }
    let contents = serde_json::to_string_pretty(&RunConfigFile::default())
        .map_err(|error| format!("failed to encode default config: {error}"))?;
    fs::write(path, contents).map_err(|error| format!("failed to write config {path}: {error}"))
}

pub fn parse(args: &[String]) -> Result<RunConfig, String> {
    let args = Zeroizing::new(
        args.iter()
            .map(|arg| arg.trim().to_string())
            .collect::<Vec<_>>(),
    );
    let mut config = RunConfig::default();
    let environment_config_path = std::env::var(CONFIG_FILE_ENV).ok();
    let config_path = config_path_arg(&args)
        .or(environment_config_path.as_deref())
        .unwrap_or(DEFAULT_CONFIG_FILE);
    if let Some(file_config) = load_file(config_path)? {
        apply_file(&mut config, file_config)?;
    }
    apply_environment(&mut config)?;
    let mut listen_overridden = false;
    let mut rpc_overridden = false;
    let mut public_overridden = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--network" => {
                index += 1;
                config.network = required(&args, index, "--network")?.to_ascii_lowercase();
            }
            "--config" => {
                index += 1;
                args.get(index)
                    .ok_or_else(|| "missing value for --config".to_string())?;
            }
            "--db" | "--db-path" => {
                index += 1;
                config.db_path = required(&args, index, "--db")?.clone();
            }
            "--listen" => {
                index += 1;
                if !listen_overridden {
                    config.listen_addrs.clear();
                    listen_overridden = true;
                }
                config
                    .listen_addrs
                    .push(socket(args.get(index), "--listen")?);
            }
            "--rpc-listen" => {
                index += 1;
                if !rpc_overridden {
                    config.rpc_addrs.clear();
                    rpc_overridden = true;
                }
                config
                    .rpc_addrs
                    .push(socket(args.get(index), "--rpc-listen")?);
            }
            "--rpc-admin-listen" => {
                index += 1;
                config
                    .rpc_admin_addrs
                    .push(socket(args.get(index), "--rpc-admin-listen")?);
            }
            "--rpc-admin-token" => {
                index += 1;
                config.rpc_admin_token = Some(Zeroizing::new(
                    required(&args, index, "--rpc-admin-token")?.clone(),
                ));
            }
            "--rpc-tls-cert" => {
                index += 1;
                config.rpc_tls_cert = Some(required(&args, index, "--rpc-tls-cert")?.clone());
            }
            "--rpc-tls-key" => {
                index += 1;
                config.rpc_tls_key = Some(required(&args, index, "--rpc-tls-key")?.clone());
            }
            "--rpc-cors-origin" => {
                index += 1;
                config
                    .rpc_cors_origins
                    .push(required(&args, index, "--rpc-cors-origin")?.clone());
            }
            "--rpc-max-body-bytes" => {
                index += 1;
                config.rpc_max_body_bytes = number(&args, index, "--rpc-max-body-bytes")? as usize;
            }
            "--rpc-timeout-secs" => {
                index += 1;
                config.rpc_timeout =
                    Duration::from_secs(number(&args, index, "--rpc-timeout-secs")?);
            }
            "--rpc-max-concurrent-requests" => {
                index += 1;
                config.rpc_max_concurrent_requests =
                    number(&args, index, "--rpc-max-concurrent-requests")? as usize;
            }
            "--rpc-max-connections" => {
                index += 1;
                config.rpc_max_connections =
                    number(&args, index, "--rpc-max-connections")? as usize;
            }
            "--rpc-rate-limit-per-second" => {
                index += 1;
                config.rpc_rate_limit_per_second =
                    number(&args, index, "--rpc-rate-limit-per-second")?;
            }
            "--rpc-rate-limit-burst" => {
                index += 1;
                config.rpc_rate_limit_burst = number(&args, index, "--rpc-rate-limit-burst")?;
            }
            "--peer" => {
                index += 1;
                config.peers.push(socket(args.get(index), "--peer")?);
            }
            "--peers-file" => {
                index += 1;
                config.peers_file = Some(required(&args, index, "--peers-file")?.clone());
            }
            "--dns-seed" => {
                index += 1;
                config
                    .dns_seeds
                    .push(required(&args, index, "--dns-seed")?.clone());
            }
            "--gateway" | "--gateway-url" => {
                index += 1;
                config.gateway_url = Some(required(&args, index, "--gateway")?.clone());
            }
            "--public-addr" => {
                index += 1;
                if !public_overridden {
                    config.public_addrs.clear();
                    public_overridden = true;
                }
                config
                    .public_addrs
                    .push(socket(args.get(index), "--public-addr")?);
            }
            "--gateway-heartbeat-secs" => {
                index += 1;
                config.gateway_heartbeat =
                    Duration::from_secs(number(&args, index, "--gateway-heartbeat-secs")?.max(1));
            }
            "--nat-traversal" => config.nat_traversal = true,
            "--nat-lease-secs" => {
                index += 1;
                config.nat_lease =
                    Duration::from_secs(number(&args, index, "--nat-lease-secs")?.max(60));
            }
            "--grpc-listen" => {
                index += 1;
                config
                    .grpc_addrs
                    .push(socket(args.get(index), "--grpc-listen")?);
            }
            "--shutdown-file" => {
                index += 1;
                config.shutdown_file = required(&args, index, "--shutdown-file")?.clone();
            }
            "--max-peers" => {
                index += 1;
                config.max_peers = number(&args, index, "--max-peers")? as usize;
                config.max_peers = config.max_peers.max(1);
            }
            "--fast-sync" => config.fast_sync = true,
            "--min-relay-fee" => {
                index += 1;
                config.min_relay_fee = number(&args, index, "--min-relay-fee")?;
            }
            "--market-fee" => {
                index += 1;
                config.market_fee = number(&args, index, "--market-fee")?;
            }
            "--low-fee-expiry-secs" => {
                index += 1;
                config.low_fee_expiry =
                    Duration::from_secs(number(&args, index, "--low-fee-expiry-secs")?);
            }
            "--mempool-expiry-secs" => {
                index += 1;
                config.mempool_expiry =
                    Duration::from_secs(number(&args, index, "--mempool-expiry-secs")?);
            }
            "--miner" => {
                index += 1;
                config.miner_address = Some(address(args.get(index))?);
            }
            "--wallet" => {
                index += 1;
                config.miner_address = Some(wallet_address(required(&args, index, "--wallet")?)?);
            }
            "--miner-secret-key" => {
                index += 1;
                config.miner_secret_key = Some(secret_key(args.get(index))?);
            }
            "--miner-min-fee-rate" => {
                index += 1;
                config.miner_min_fee_rate = Some(number(&args, index, "--miner-min-fee-rate")?);
            }
            "--premine" => {
                return Err(
                    "premine address is fixed by protocol and cannot be overridden".to_string(),
                );
            }
            "--mine" => config.mine = true,
            "--mine-interval-secs" => {
                index += 1;
                config.mine_interval =
                    Duration::from_secs(number(&args, index, "--mine-interval-secs")?);
            }
            "--mine-attempts" => {
                index += 1;
                config.mine_attempts = number(&args, index, "--mine-attempts")?;
            }
            value if !value.starts_with('-') && config.db_path == DEFAULT_NODE_DB => {
                config.db_path = value.to_string()
            }
            value => return Err(format!("unknown node run option `{value}`")),
        }
        index += 1;
    }
    dedupe(&mut config.listen_addrs);
    dedupe(&mut config.rpc_addrs);
    dedupe(&mut config.rpc_admin_addrs);
    dedupe(&mut config.public_addrs);
    dedupe(&mut config.grpc_addrs);
    if config.rpc_admin_token.is_none()
        && let Ok(token) = std::env::var(RPC_ADMIN_TOKEN_ENV)
    {
        // SAFETY: configuration parsing runs before worker threads are
        // started, so no other thread can concurrently access the environment.
        unsafe {
            std::env::remove_var(RPC_ADMIN_TOKEN_ENV);
        }
        config.rpc_admin_token = Some(Zeroizing::new(token));
    }
    normalize(&mut config);
    validate_network(&config.network)?;
    Ok(config)
}

pub fn format_socket_addrs(addrs: &[SocketAddr]) -> String {
    addrs
        .iter()
        .map(SocketAddr::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn required<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a String, String> {
    args.get(index)
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn number(args: &[String], index: usize, flag: &str) -> Result<u64, String> {
    required(args, index, flag)?
        .parse::<u64>()
        .map_err(|error| format!("invalid {flag}: {error}"))
}

fn socket(value: Option<&String>, flag: &str) -> Result<SocketAddr, String> {
    value
        .ok_or_else(|| format!("missing value for {flag}"))?
        .parse()
        .map_err(|error| format!("invalid socket address for {flag}: {error}"))
}

fn config_path_arg(args: &[String]) -> Option<&str> {
    args.windows(2)
        .find_map(|window| (window[0] == "--config").then_some(window[1].as_str()))
}

fn load_file(path: &str) -> Result<Option<RunConfigFile>, String> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => Zeroizing::new(contents),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("failed to read config {path}: {error}")),
    };
    serde_json::from_str(&contents)
        .map(Some)
        .map_err(|error| format!("failed to parse config {path}: {error}"))
}

fn apply_file(config: &mut RunConfig, file: RunConfigFile) -> Result<(), String> {
    config.network = file.network.to_ascii_lowercase();
    config.db_path = file.db_path;
    config.listen_addrs = parse_family_sockets(
        file.listen_addr_ipv4.into_vec(),
        "listen_addr_ipv4",
        IpFamily::V4,
    )?;
    config.listen_addrs.extend(parse_family_sockets(
        file.listen_addr_ipv6.into_vec(),
        "listen_addr_ipv6",
        IpFamily::V6,
    )?);
    config.rpc_addrs =
        parse_optional_family_socket(file.rpc_addr_ipv4, "rpc_addr_ipv4", IpFamily::V4)?;
    config.rpc_addrs.extend(parse_optional_family_socket(
        file.rpc_addr_ipv6,
        "rpc_addr_ipv6",
        IpFamily::V6,
    )?);
    config.rpc_admin_addrs = parse_optional_family_socket(
        file.rpc_admin_addr_ipv4,
        "rpc_admin_addr_ipv4",
        IpFamily::V4,
    )?;
    config.rpc_admin_addrs.extend(parse_optional_family_socket(
        file.rpc_admin_addr_ipv6,
        "rpc_admin_addr_ipv6",
        IpFamily::V6,
    )?);
    config.rpc_admin_token = file
        .rpc_admin_token
        .map(|value| Zeroizing::new(value.0.clone()));
    config.rpc_tls_cert = file.rpc_tls_cert;
    config.rpc_tls_key = file.rpc_tls_key;
    config.rpc_cors_origins = file.rpc_cors_origins;
    config.rpc_max_body_bytes = file.rpc_max_body_bytes;
    config.rpc_timeout = Duration::from_secs(file.rpc_timeout_secs);
    config.rpc_max_concurrent_requests = file.rpc_max_concurrent_requests;
    config.rpc_max_connections = file.rpc_max_connections;
    config.rpc_rate_limit_per_second = file.rpc_rate_limit_per_second;
    config.rpc_rate_limit_burst = file.rpc_rate_limit_burst;
    config.peers = parse_family_sockets(file.peers_ipv4, "peers_ipv4", IpFamily::V4)?;
    config.peers.extend(parse_family_sockets(
        file.peers_ipv6,
        "peers_ipv6",
        IpFamily::V6,
    )?);
    config.peers_file = file.peers_file;
    config.dns_seeds = file.dns_seeds;
    config.gateway_url = file.gateway_url;
    config.public_addrs = parse_family_sockets(
        file.public_addr_ipv4
            .map(OneOrMany::into_vec)
            .unwrap_or_default(),
        "public_addr_ipv4",
        IpFamily::V4,
    )?;
    config.public_addrs.extend(parse_family_sockets(
        file.public_addr_ipv6
            .map(OneOrMany::into_vec)
            .unwrap_or_default(),
        "public_addr_ipv6",
        IpFamily::V6,
    )?);
    config.gateway_heartbeat = Duration::from_secs(file.gateway_heartbeat_secs.max(1));
    config.nat_traversal = file.nat_traversal;
    config.nat_lease = Duration::from_secs(file.nat_lease_secs.max(60));
    config.grpc_addrs =
        parse_optional_family_socket(file.grpc_addr_ipv4, "grpc_addr_ipv4", IpFamily::V4)?;
    config.grpc_addrs.extend(parse_optional_family_socket(
        file.grpc_addr_ipv6,
        "grpc_addr_ipv6",
        IpFamily::V6,
    )?);
    config.shutdown_file = file.shutdown_file;
    config.max_peers = file.max_peers.max(1);
    config.fast_sync = file.fast_sync;
    config.min_relay_fee = file.min_relay_fee.unwrap_or(config.min_relay_fee);
    config.market_fee = file.market_fee.unwrap_or(config.market_fee);
    if let Some(secs) = file.low_fee_expiry_secs {
        config.low_fee_expiry = Duration::from_secs(secs);
    }
    if let Some(secs) = file.mempool_expiry_secs {
        config.mempool_expiry = Duration::from_secs(secs);
    }
    config.mine = file.mine;
    config.mine_interval = Duration::from_secs(file.mine_interval_secs);
    config.mine_attempts = file.mine_attempts;
    if let Some(path) = file.wallet {
        config.miner_address = Some(wallet_address(&path)?);
    }
    if let Some(value) = file.miner_address {
        config.miner_address = Some(address(Some(&value))?);
    }
    if let Some(value) = file.miner_secret_key {
        config.miner_secret_key = Some(secret_key(Some(&value.0))?);
    }
    config.miner_min_fee_rate = file.miner_min_fee_rate;
    Ok(())
}

pub const fn current_network() -> &'static str {
    #[cfg(feature = "mainnet")]
    return "mainnet";
    #[cfg(feature = "testnet")]
    return "testnet";
    #[cfg(feature = "devnet")]
    return "devnet";
}

fn current_network_string() -> String {
    current_network().to_string()
}

fn validate_network(network: &str) -> Result<(), String> {
    match network {
        "mainnet" | "testnet" | "devnet" if network == current_network() => Ok(()),
        "mainnet" | "testnet" | "devnet" => Err(format!(
            "this binary is built for {}; rebuild with `--no-default-features --features {},sqisign-blockchain-test`",
            current_network(),
            network
        )),
        _ => Err(format!(
            "invalid network `{network}`; expected devnet, testnet, or mainnet"
        )),
    }
}

fn parse_sockets(values: Vec<String>, label: &str) -> Result<Vec<SocketAddr>, String> {
    values
        .into_iter()
        .map(|value| {
            value
                .parse()
                .map_err(|error| format!("invalid {label} `{value}` in config: {error}"))
        })
        .collect()
}

#[derive(Clone, Copy)]
enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    const fn label(self) -> &'static str {
        match self {
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        }
    }

    const fn matches(self, addr: &SocketAddr) -> bool {
        matches!(
            (self, addr),
            (Self::V4, SocketAddr::V4(_)) | (Self::V6, SocketAddr::V6(_))
        )
    }
}

fn parse_family_sockets(
    values: Vec<String>,
    label: &str,
    family: IpFamily,
) -> Result<Vec<SocketAddr>, String> {
    let addrs = parse_sockets(values, label)?;
    for addr in &addrs {
        if !family.matches(addr) {
            return Err(format!(
                "invalid {label} `{addr}` in config: expected {} address",
                family.label()
            ));
        }
    }
    Ok(addrs)
}

fn parse_optional_family_socket(
    value: Option<String>,
    label: &str,
    family: IpFamily,
) -> Result<Vec<SocketAddr>, String> {
    parse_family_sockets(value.into_iter().collect(), label, family)
}

fn apply_environment(config: &mut RunConfig) -> Result<(), String> {
    if let Ok(value) = std::env::var(NODE_RPC_LISTEN_ADDR_ENV) {
        config.rpc_addrs = parse_environment_sockets(&value, NODE_RPC_LISTEN_ADDR_ENV)?;
    }
    if let Ok(value) = std::env::var(NODE_P2P_LISTEN_ADDR_ENV) {
        config.listen_addrs = parse_environment_sockets(&value, NODE_P2P_LISTEN_ADDR_ENV)?;
    }
    if let Ok(value) = std::env::var(PUBLIC_ADDR_ENV) {
        config.public_addrs = parse_environment_sockets(&value, PUBLIC_ADDR_ENV)?;
    }
    Ok(())
}

fn parse_environment_sockets(value: &str, name: &str) -> Result<Vec<SocketAddr>, String> {
    let values = value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Err(format!("{name} must contain at least one socket address"));
    }
    parse_sockets(values, name)
}

pub fn dedupe(addrs: &mut Vec<SocketAddr>) {
    let mut seen = HashSet::new();
    addrs.retain(|addr| seen.insert(*addr));
}

fn normalize(config: &mut RunConfig) {
    config.market_fee = config.market_fee.max(config.min_relay_fee);
    if config.mempool_expiry.as_secs() != 0 && config.low_fee_expiry > config.mempool_expiry {
        config.low_fee_expiry = config.mempool_expiry;
    }
    config.rpc_max_body_bytes = config.rpc_max_body_bytes.max(1);
    config.rpc_timeout = config.rpc_timeout.max(Duration::from_secs(1));
    config.rpc_max_concurrent_requests = config.rpc_max_concurrent_requests.max(1);
    config.rpc_max_connections = config.rpc_max_connections.max(1);
    config.rpc_rate_limit_per_second = config.rpc_rate_limit_per_second.max(1);
    config.rpc_rate_limit_burst = config
        .rpc_rate_limit_burst
        .max(config.rpc_rate_limit_per_second);
}

const fn default_rpc_max_body_bytes() -> usize {
    2 * 1024 * 1024
}

const fn default_rpc_timeout_secs() -> u64 {
    30
}

const fn default_rpc_max_concurrent_requests() -> usize {
    256
}

const fn default_rpc_max_connections() -> usize {
    128
}

const fn default_rpc_rate_limit_per_second() -> u64 {
    50
}

const fn default_rpc_rate_limit_burst() -> u64 {
    100
}

const fn default_nat_lease_secs() -> u64 {
    3600
}

#[derive(Deserialize)]
struct WalletFile {
    version: u8,
    address: String,
    secret_key: String,
    auth_public_key: String,
}

impl Drop for WalletFile {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_config_separates_every_socket_ip_family() {
        let value = serde_json::to_value(RunConfigFile::default()).unwrap();
        let object = value.as_object().unwrap();

        for key in [
            "listen_addr_ipv4",
            "listen_addr_ipv6",
            "rpc_addr_ipv4",
            "rpc_addr_ipv6",
            "rpc_admin_addr_ipv4",
            "rpc_admin_addr_ipv6",
            "peers_ipv4",
            "peers_ipv6",
            "public_addr_ipv4",
            "public_addr_ipv6",
            "grpc_addr_ipv4",
            "grpc_addr_ipv6",
        ] {
            assert!(
                object.contains_key(key),
                "generated config is missing {key}"
            );
        }
        for legacy in [
            "listen_addr",
            "rpc_addr",
            "rpc_admin_addr",
            "peers",
            "public_addr",
            "grpc_addr",
        ] {
            assert!(
                !object.contains_key(legacy),
                "legacy field {legacy} remains"
            );
        }
    }

    #[test]
    fn split_config_combines_families_for_runtime() {
        let mut file = RunConfigFile::default();
        file.peers_ipv4 = vec!["198.51.100.8:5555".to_string()];
        file.peers_ipv6 = vec!["[2001:db8::8]:5555".to_string()];
        file.public_addr_ipv4 = Some(OneOrMany::One("198.51.100.9:5555".to_string()));
        file.public_addr_ipv6 = Some(OneOrMany::One("[2001:db8::9]:5555".to_string()));
        file.wallet = None;
        file.mine = false;

        let mut config = RunConfig::default();
        apply_file(&mut config, file).unwrap();

        assert_eq!(config.listen_addrs.len(), 2);
        assert_eq!(config.rpc_addrs.len(), 2);
        assert_eq!(config.peers.len(), 2);
        assert_eq!(config.public_addrs.len(), 2);
        assert!(config.peers.iter().any(SocketAddr::is_ipv4));
        assert!(config.peers.iter().any(SocketAddr::is_ipv6));
    }

    #[test]
    fn split_config_rejects_address_in_wrong_family() {
        let error =
            parse_family_sockets(vec!["[::1]:5555".to_string()], "peers_ipv4", IpFamily::V4)
                .unwrap_err();
        assert!(error.contains("expected IPv4"));
    }

    #[test]
    fn legacy_combined_address_fields_are_rejected() {
        let mut value = serde_json::to_value(RunConfigFile::default()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("peers".to_string(), serde_json::json!([]));
        let error = serde_json::from_value::<RunConfigFile>(value).unwrap_err();
        assert!(error.to_string().contains("unknown field `peers`"));
    }
}

pub fn wallet_address(path: &str) -> Result<Address, String> {
    let bytes = Zeroizing::new(
        fs::read(path)
            .map_err(|error| format!("failed to read mining wallet `{path}`: {error}"))?,
    );
    let wallet: WalletFile = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid plaintext mining wallet `{path}`: {error}"))?;
    if wallet.version != 1 {
        return Err(format!("unsupported plaintext mining wallet `{path}`"));
    }
    let address = address_string(&wallet.address)
        .map_err(|_| format!("invalid address in mining wallet `{path}`"))?;
    let secret_key = secret_key(Some(&wallet.secret_key))
        .map_err(|error| format!("invalid secret_key in mining wallet `{path}`: {error}"))?;
    let public_key = derive_public_key(&secret_key);
    let auth_public_key_bytes = hex::decode(&wallet.auth_public_key)
        .map_err(|_| format!("invalid auth_public_key in mining wallet `{path}`"))?;
    let auth_public_key = PublicKey(
        auth_public_key_bytes
            .try_into()
            .map_err(|_| format!("invalid auth_public_key in mining wallet `{path}`"))?,
    );
    let derived_address = dual_address_from_public_keys(&public_key, &auth_public_key);
    if derived_address != address {
        return Err(format!(
            "mining wallet `{path}` address does not match secret_key"
        ));
    }
    Ok(address)
}
