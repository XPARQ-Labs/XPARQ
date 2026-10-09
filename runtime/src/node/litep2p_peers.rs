//! Bounded transport-specific endpoint discovery. DNS is resolved only when dialing.
use super::super::peer::{PeerAddress, is_admissible_discovered_peer};
use litep2p::PeerId;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    net::{SocketAddr, ToSocketAddrs},
    path::Path,
    sync::{Arc, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(super) const MAX_RECORDS: usize = 128;
pub(super) const MAX_ANNOUNCED: usize = 16;
pub(super) const MAX_MESSAGE: usize = 8192;
const MAX_ENDPOINT: usize = 512;
const STORE_KEY: &str = "litep2p-peers-v1";
const DISCOVERY_TTL: u64 = 3600;
const SUCCESS_TTL: u64 = 7 * 24 * 3600;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Endpoint {
    pub address: PeerAddress,
    pub peer: PeerId,
}
impl Endpoint {
    pub fn parse(value: &str) -> Result<Self, String> {
        if value.len() > MAX_ENDPOINT {
            return Err("litep2p endpoint exceeds length limit".into());
        }
        let (host, peer) = value
            .split_once('@')
            .ok_or("litep2p peer must use HOST:PORT@PEER_ID")?;
        let address = host.parse::<PeerAddress>().or_else(|error| {
            if let Some(port) = host.strip_prefix("localhost:") {
                return port
                    .parse::<u16>()
                    .map(|port| PeerAddress::Dns {
                        hostname: "localhost".into(),
                        port,
                    })
                    .map_err(|_| "invalid localhost port".into());
            }
            Err(error)
        })?;
        let peer = peer
            .parse()
            .map_err(|error| format!("invalid litep2p peer ID: {error}"))?;
        if !usable(&address) {
            return Err("litep2p endpoint has an unusable address or port".into());
        }
        Ok(Self { address, peer })
    }
    pub fn key(&self) -> String {
        format!("{}@{}", self.address, self.peer)
    }
}

fn usable(address: &PeerAddress) -> bool {
    match address {
        PeerAddress::Ip(socket) => {
            socket.port() != 0
                && !socket.ip().is_unspecified()
                && !socket.ip().is_multicast()
                && !matches!(socket.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
        }
        PeerAddress::Dns { port, .. } => *port != 0,
    }
}

pub(super) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(super) fn filter_resolved(
    addresses: impl Iterator<Item = SocketAddr>,
    public_only: bool,
) -> Vec<SocketAddr> {
    let mut result = Vec::new();
    for address in addresses.take(32) {
        if usable(&PeerAddress::Ip(address))
            && (!public_only || is_admissible_discovered_peer(&address))
            && !result.contains(&address)
        {
            result.push(address);
        }
        if result.len() == 4 {
            break;
        }
    }
    result
}

pub(super) async fn resolve(
    endpoint: &Endpoint,
    public_only: bool,
) -> Result<Vec<SocketAddr>, String> {
    let addresses = match &endpoint.address {
        PeerAddress::Ip(address) => filter_resolved(std::iter::once(*address), public_only),
        PeerAddress::Dns { hostname, port } => {
            static RESOLVERS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
            let limit = RESOLVERS
                .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(4)))
                .clone();
            let hostname = hostname.clone();
            let port = *port;
            tokio::time::timeout(Duration::from_secs(3), async move {
                let permit = limit
                    .acquire_owned()
                    .await
                    .map_err(|_| "litep2p resolver limit closed")?;
                tokio::task::spawn_blocking(move || {
                    // Native DNS cannot be cancelled: keep its permit in the worker
                    // even if the network loop stops waiting after the timeout.
                    let _permit = permit;
                    (hostname.as_str(), port)
                        .to_socket_addrs()
                        .map(|answers| filter_resolved(answers, public_only))
                        .map_err(|error| format!("resolve litep2p endpoint: {error}"))
                })
                .await
                .map_err(|error| format!("litep2p resolver worker: {error}"))?
            })
            .await
            .map_err(|_| "litep2p DNS lookup timed out")??
        }
    };
    if addresses.is_empty() {
        return Err("litep2p endpoint has no admissible resolved address".into());
    }
    Ok(addresses)
}

pub(super) struct Record {
    pub endpoint: Endpoint,
    pub trusted: bool,
    pub seen: u64,
    pub success: Option<u64>,
    pub retry: Instant,
    failures: u32,
}
#[derive(Default)]
pub(super) struct PeerBook {
    pub records: BTreeMap<String, Record>,
    pub private_discovery: bool,
}
#[derive(Serialize, Deserialize)]
struct Stored {
    endpoint: String,
    trusted: bool,
    success: u64,
}
impl PeerBook {
    pub fn load(
        database: &Path,
        configured: &[String],
        private_discovery: bool,
        now: Instant,
    ) -> Result<Self, String> {
        let mut book = Self {
            private_discovery,
            ..Self::default()
        };
        for endpoint in configured {
            book.insert(Endpoint::parse(endpoint)?, true, now_unix(), now);
        }
        if let Some(bytes) = crate::storage::auxiliary_get(database, STORE_KEY)? {
            if bytes.len() > 128 * 1024 {
                return Err("litep2p peer store exceeds size limit".into());
            }
            let stored: Vec<Stored> = serde_json::from_slice(&bytes)
                .map_err(|error| format!("decode litep2p peer store: {error}"))?;
            for stored in stored.into_iter().take(MAX_RECORDS) {
                if stored.success > now_unix()
                    || now_unix().saturating_sub(stored.success) >= SUCCESS_TTL
                {
                    continue;
                }
                if let Ok(endpoint) = Endpoint::parse(&stored.endpoint) {
                    let key = endpoint.key();
                    if (book.insert(endpoint, stored.trusted, stored.success, now)
                        || book.records.contains_key(&key))
                        && let Some(record) = book.records.get_mut(&key)
                    {
                        record.success = Some(stored.success);
                    }
                }
            }
        }
        Ok(book)
    }
    pub fn insert(&mut self, endpoint: Endpoint, trusted: bool, seen: u64, now: Instant) -> bool {
        if !trusted && !self.private_discovery && !endpoint.address.is_admissible() {
            return false;
        }
        let key = endpoint.key();
        // Third-party advertisements cannot refresh or overwrite an existing record.
        if self.records.contains_key(&key) || self.records.len() >= MAX_RECORDS {
            return false;
        }
        self.records.insert(
            key,
            Record {
                endpoint,
                trusted,
                seen,
                success: None,
                retry: now,
                failures: 0,
            },
        );
        true
    }
    pub fn prune(&mut self, unix: u64) {
        self.records.retain(|_, record| {
            record.trusted
                || unix.saturating_sub(record.success.unwrap_or(record.seen))
                    < if record.success.is_some() {
                        SUCCESS_TTL
                    } else {
                        DISCOVERY_TTL
                    }
        });
    }
    pub fn candidates(
        &self,
        connected: &HashSet<PeerId>,
        busy: &HashSet<PeerId>,
        local: PeerId,
        now: Instant,
    ) -> Vec<Endpoint> {
        let mut records = self
            .records
            .values()
            .filter(|record| {
                record.endpoint.peer != local
                    && !connected.contains(&record.endpoint.peer)
                    && !busy.contains(&record.endpoint.peer)
                    && record.retry <= now
            })
            .collect::<Vec<_>>();
        records.sort_by_key(|record| (!record.trusted, record.success.is_none(), record.retry));
        let mut ids = HashSet::new();
        records
            .into_iter()
            .filter(|record| ids.insert(record.endpoint.peer))
            .take(4)
            .map(|record| record.endpoint.clone())
            .collect()
    }
    pub fn dial_offset(&self, endpoint: &Endpoint) -> usize {
        self.records
            .get(&endpoint.key())
            .map_or(0, |record| record.failures as usize)
    }
    pub fn failed(&mut self, endpoint: &Endpoint, now: Instant) {
        if let Some(record) = self.records.get_mut(&endpoint.key()) {
            record.failures = record.failures.saturating_add(1);
            record.retry = now + Duration::from_secs(10 * (1_u64 << record.failures.min(7)));
        }
    }
    pub fn succeeded(&mut self, endpoint: &Endpoint, now: Instant) {
        if let Some(record) = self.records.get_mut(&endpoint.key()) {
            record.success = Some(now_unix());
            record.failures = 0;
            record.retry = now;
        }
    }
    pub fn save(&self, database: &Path) -> Result<(), String> {
        let stored = self
            .records
            .values()
            .filter_map(|record| {
                record.success.map(|success| Stored {
                    endpoint: record.endpoint.key(),
                    trusted: record.trusted,
                    success,
                })
            })
            .collect::<Vec<_>>();
        crate::storage::auxiliary_put(
            database,
            STORE_KEY,
            &serde_json::to_vec(&stored).map_err(|error| error.to_string())?,
        )
    }
    pub fn relay(&self, own: Option<&Endpoint>, local: PeerId) -> Result<Vec<u8>, String> {
        let mut endpoints = Vec::new();
        if let Some(own) = own {
            endpoints.push(own.key());
        }
        endpoints.extend(
            self.records
                .values()
                .filter(|record| {
                    record.success.is_some()
                        && record.endpoint.peer != local
                        && (self.private_discovery || record.endpoint.address.is_admissible())
                })
                .map(|record| record.endpoint.key())
                .take(MAX_ANNOUNCED - endpoints.len()),
        );
        let encoded = super::canonical_bytes(&endpoints).map_err(|error| error.to_string())?;
        if encoded.len() > MAX_MESSAGE {
            return Err("outbound discovery exceeds size limit".into());
        }
        Ok(encoded)
    }
}

/// Decode lengths before allocation; network input never triggers DNS resolution.
pub(super) fn decode(bytes: &[u8]) -> Result<Vec<Endpoint>, String> {
    if bytes.len() > MAX_MESSAGE {
        return Err("litep2p discovery exceeds size limit".into());
    }
    fn take<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], String> {
        let value = bytes.get(..length).ok_or("truncated litep2p discovery")?;
        *bytes = &bytes[length..];
        Ok(value)
    }
    fn length(bytes: &mut &[u8]) -> Result<usize, String> {
        Ok(u32::from_le_bytes(
            take(bytes, 4)?
                .try_into()
                .map_err(|_| "invalid discovery length")?,
        ) as usize)
    }
    let mut bytes = bytes;
    let count = length(&mut bytes)?;
    if count > MAX_ANNOUNCED {
        return Err("litep2p discovery exceeds endpoint count".into());
    }
    let mut result = Vec::new();
    for _ in 0..count {
        let size = length(&mut bytes)?;
        if size > MAX_ENDPOINT {
            return Err("discovered endpoint exceeds length limit".into());
        }
        let value =
            std::str::from_utf8(take(&mut bytes, size)?).map_err(|_| "invalid endpoint UTF-8")?;
        if let Ok(endpoint) = Endpoint::parse(value)
            && !result.contains(&endpoint)
        {
            result.push(endpoint);
        }
    }
    if !bytes.is_empty() {
        return Err("trailing litep2p discovery bytes".into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn endpoint(host: &str) -> Endpoint {
        Endpoint::parse(&format!("{host}@{}", PeerId::random())).unwrap()
    }
    #[test]
    fn endpoint_parser_and_discovery_lengths_are_bounded_without_dns() {
        let peer = PeerId::random();
        assert_eq!(
            Endpoint::parse(&format!("BOOTSTRAP.Example.COM.:1234@{peer}"))
                .unwrap()
                .address
                .to_string(),
            "bootstrap.example.com:1234"
        );
        assert!(Endpoint::parse(&format!("0.0.0.0:1234@{peer}")).is_err());
        assert!(Endpoint::parse(&format!("127.0.0.1:0@{peer}")).is_err());
        assert!(decode(&u32::MAX.to_le_bytes()).is_err());
        let mut bad = 1_u32.to_le_bytes().to_vec();
        bad.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode(&bad).is_err());
        assert!(decode(&vec![0; MAX_MESSAGE + 1]).is_err());
        let endpoint = endpoint("bootstrap.example.com:1234");
        let encoded = super::super::canonical_bytes(&vec![endpoint.key(), endpoint.key()]).unwrap();
        assert_eq!(decode(&encoded).unwrap(), vec![endpoint]);
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode(&trailing).is_err());
    }
    #[test]
    fn dns_rebinding_filter_drops_private_mapped_and_reserved_addresses() {
        let answers = [
            "127.0.0.1:1234",
            "10.0.0.1:1234",
            "[::ffff:127.0.0.1]:1234",
            "192.0.2.1:1234",
            "8.8.8.8:1234",
            "8.8.8.8:1234",
            "1.1.1.1:1234",
        ]
        .map(|value| value.parse::<SocketAddr>().unwrap());
        assert_eq!(
            filter_resolved(answers.into_iter(), true),
            vec![
                "8.8.8.8:1234".parse::<SocketAddr>().unwrap(),
                "1.1.1.1:1234".parse().unwrap()
            ]
        );
        // Each attempt uses its new DNS answer, rather than retaining a previous IP.
        assert!(
            filter_resolved(std::iter::once("127.0.0.1:1234".parse().unwrap()), true).is_empty()
        );
        assert_eq!(
            filter_resolved(std::iter::once("9.9.9.9:1234".parse().unwrap()), true).len(),
            1
        );
    }
    #[test]
    fn book_deduplicates_caps_expires_and_does_not_replace_configured_endpoints() {
        let now = Instant::now();
        let mut book = PeerBook::default();
        let private = endpoint("127.0.0.1:1234");
        assert!(!book.insert(private.clone(), false, 1, now));
        assert!(book.insert(private.clone(), true, 1, now));
        assert!(!book.insert(private.clone(), false, 100, now));
        assert_eq!(book.records[&private.key()].seen, 1);
        for _ in 1..MAX_RECORDS {
            assert!(book.insert(endpoint("bootstrap.example.com:1234"), false, 1, now));
        }
        assert!(!book.insert(endpoint("bootstrap.example.com:1234"), false, 1, now));
        assert_eq!(book.records.len(), MAX_RECORDS);
        book.prune(DISCOVERY_TTL + 1);
        assert_eq!(book.records.len(), 1);
        book.failed(&private, now);
        assert!(
            book.candidates(&HashSet::new(), &HashSet::new(), PeerId::random(), now)
                .is_empty()
        );
        assert_eq!(
            book.candidates(
                &HashSet::new(),
                &HashSet::new(),
                PeerId::random(),
                now + Duration::from_secs(20)
            ),
            vec![private]
        );
    }
    #[test]
    fn only_verified_success_is_persisted_and_dns_identity_survives_reload() {
        let database = std::env::temp_dir().join(format!(
            "litep2p-peer-store-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let now = Instant::now();
        let good = endpoint("bootstrap.example.com:1234");
        let pending = endpoint("other.example.com:1234");
        let mut book = PeerBook::load(&database, &[good.key()], false, now).unwrap();
        book.insert(pending, false, now_unix(), now);
        book.succeeded(&good, now);
        book.save(&database).unwrap();
        let loaded = PeerBook::load(&database, &[], false, now).unwrap();
        assert_eq!(loaded.records.len(), 1);
        assert!(loaded.records.contains_key(&good.key()));
        assert!(loaded.records[&good.key()].trusted);
        assert_eq!(
            decode(&loaded.relay(None, PeerId::random()).unwrap()).unwrap(),
            vec![good]
        );
        std::fs::remove_dir_all(database).unwrap();
    }
    #[test]
    fn candidate_selection_is_bounded_deduplicates_ids_and_skips_connected() {
        let now = Instant::now();
        let mut book = PeerBook::default();
        let first = endpoint("8.8.8.8:1234");
        book.insert(first.clone(), false, now_unix(), now);
        book.insert(
            Endpoint {
                peer: first.peer,
                address: "1.1.1.1:1234".parse().unwrap(),
            },
            false,
            now_unix(),
            now,
        );
        for _ in 0..10 {
            book.insert(
                endpoint("bootstrap.example.com:1234"),
                false,
                now_unix(),
                now,
            );
        }
        let local = PeerId::random();
        let selected = book.candidates(&HashSet::from([first.peer]), &HashSet::new(), local, now);
        assert_eq!(selected.len(), 4);
        assert!(selected.iter().all(|endpoint| endpoint.peer != first.peer));
        assert_eq!(
            selected
                .iter()
                .map(|endpoint| endpoint.peer)
                .collect::<HashSet<_>>()
                .len(),
            4
        );
    }
    #[test]
    fn explicit_localhost_bootstrap_resolves_but_discovered_localhost_is_rejected() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let endpoint = endpoint("localhost:1234");
        assert!(!endpoint.address.is_admissible());
        assert!(
            !runtime
                .block_on(resolve(&endpoint, false))
                .unwrap()
                .is_empty()
        );
        assert!(runtime.block_on(resolve(&endpoint, true)).is_err());
    }
}
