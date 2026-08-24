use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

const PEERS_KEY: &str = "peers";
pub const MAX_DISCOVERED_PEERS: usize = 128;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerRecord {
    pub address: String,
    pub successes: u32,
    pub failures: u32,
    pub last_success_unix: Option<u64>,
    pub cooldown_until_unix: Option<u64>,
}

#[derive(Default, Serialize, Deserialize)]
struct PeerFile {
    peers: Vec<PeerRecord>,
}

#[derive(Default)]
pub struct PeerStore {
    peers: BTreeMap<SocketAddr, PeerRecord>,
}

impl PeerStore {
    pub fn load(database: &Path) -> Result<Self, String> {
        let contents = match crate::storage::auxiliary_get(database, PEERS_KEY)? {
            Some(contents) => contents,
            None => return Ok(Self::default()),
        };
        let decoded: PeerFile = serde_json::from_slice(&contents)
            .map_err(|error| format!("decode peer store: {error}"))?;
        let mut peers = BTreeMap::new();
        for record in decoded.peers.into_iter().take(MAX_DISCOVERED_PEERS) {
            let Ok(address) = record.address.parse() else {
                continue;
            };
            if is_admissible_discovered_peer(&address) {
                peers.insert(address, record);
            }
        }
        Ok(Self { peers })
    }

    pub fn addresses(&self) -> Vec<SocketAddr> {
        let now = unix_time();
        self.peers
            .iter()
            .filter(|(_, peer)| peer.cooldown_until_unix.is_none_or(|until| until <= now))
            .map(|(address, _)| *address)
            .collect()
    }

    pub fn relay_addresses(&self) -> Vec<String> {
        self.peers
            .iter()
            .filter(|(_, peer)| peer.last_success_unix.is_some())
            .take(MAX_DISCOVERED_PEERS)
            .map(|(address, _)| address.to_string())
            .collect()
    }

    pub fn record_success(&mut self, address: SocketAddr) {
        if !is_admissible_discovered_peer(&address) {
            return;
        }
        let record = self.record(address);
        record.successes = record.successes.saturating_add(1);
        record.failures = 0;
        record.last_success_unix = Some(unix_time());
        record.cooldown_until_unix = None;
    }

    pub fn record_failure(&mut self, address: SocketAddr, malicious: bool) {
        if !is_admissible_discovered_peer(&address) {
            return;
        }
        let record = self.record(address);
        record.failures = record.failures.saturating_add(1);
        let exponent = record.failures.min(8);
        let ordinary = 10_u64.saturating_mul(1_u64 << exponent);
        let delay = if malicious {
            3_600
        } else {
            ordinary.min(1_800)
        };
        record.cooldown_until_unix = Some(unix_time().saturating_add(delay));
    }

    pub fn insert_discovered(&mut self, address: SocketAddr) -> bool {
        if !is_admissible_discovered_peer(&address)
            || self.peers.contains_key(&address)
            || self.peers.len() >= MAX_DISCOVERED_PEERS
        {
            return false;
        }
        self.peers.insert(
            address,
            PeerRecord {
                address: address.to_string(),
                successes: 0,
                failures: 0,
                last_success_unix: None,
                cooldown_until_unix: None,
            },
        );
        true
    }

    pub fn save(&self, database: &Path) -> Result<(), String> {
        let encoded = serde_json::to_vec_pretty(&PeerFile {
            peers: self.peers.values().cloned().collect(),
        })
        .map_err(|error| format!("encode peer store: {error}"))?;
        crate::storage::auxiliary_put(database, PEERS_KEY, &encoded)
    }

    fn record(&mut self, address: SocketAddr) -> &mut PeerRecord {
        self.peers.entry(address).or_insert_with(|| PeerRecord {
            address: address.to_string(),
            successes: 0,
            failures: 0,
            last_success_unix: None,
            cooldown_until_unix: None,
        })
    }
}

pub fn is_admissible_discovered_peer(address: &SocketAddr) -> bool {
    address.port() != 0
        && match address.ip() {
            IpAddr::V4(ip) => admissible_ipv4(ip),
            IpAddr::V6(ip) => admissible_ipv6(ip),
        }
}

fn admissible_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || a == 0
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113))
}

fn admissible_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return admissible_ipv4(ipv4);
    }
    let segments = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_rejects_non_public_addresses() {
        for address in [
            "0.0.0.0:6677",
            "127.0.0.1:6677",
            "10.0.0.1:6677",
            "100.64.0.1:6677",
            "192.0.2.1:6677",
            "[::1]:6677",
            "[fc00::1]:6677",
            "[2001:db8::1]:6677",
        ] {
            assert!(!is_admissible_discovered_peer(&address.parse().unwrap()));
        }
        assert!(is_admissible_discovered_peer(
            &"8.8.8.8:6677".parse().unwrap()
        ));
    }

    #[test]
    fn malicious_failure_applies_a_long_cooldown() {
        let address = "8.8.8.8:6677".parse().unwrap();
        let mut store = PeerStore::default();
        store.record_failure(address, true);
        assert!(store.addresses().is_empty());
    }
}
