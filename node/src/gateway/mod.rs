//! Gateway discovery adapter.

use crate::runtime::network::PeerInfo;
use serde::{Deserialize, Serialize};
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;
use xparq::genesis::CURRENT_CHAIN_PARAMS;

const GATEWAY_HTTP_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Serialize)]
struct RegisterRequest {
    peer_id: Option<String>,
    address: String,
    chain_id: u32,
    chain_name: &'static str,
    protocol_stage: &'static str,
    protocol_version: u8,
    network_magic: String,
    best_height: Option<u64>,
    tip_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct HeartbeatRequest {
    peer_id: Option<String>,
    address: String,
    best_height: Option<u64>,
    tip_hash: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PeersResponse {
    peers: Vec<GatewayPeer>,
}

#[derive(Debug, Clone, Deserialize)]
struct GatewayPeer {
    address: String,
}

#[derive(Debug, Clone)]
struct GatewayEndpoint {
    addr: SocketAddr,
}

impl GatewayEndpoint {
    fn parse(url: &str) -> Result<Self, String> {
        let value = url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))
            .unwrap_or(url)
            .trim_end_matches('/');
        if value.contains('/') {
            return Err("gateway url path is not supported; use host:port".to_string());
        }
        let addr = value
            .parse::<SocketAddr>()
            .map_err(|error| format!("invalid gateway address `{url}`: {error}"))?;
        Ok(Self { addr })
    }
}

pub fn register_peer(
    gateway_url: &str,
    public_addr: SocketAddr,
    best_height: Option<u64>,
    tip_hash: Option<String>,
) -> Result<(), String> {
    let request = RegisterRequest {
        peer_id: None,
        address: public_addr.to_string(),
        chain_id: CURRENT_CHAIN_PARAMS.chain_id,
        chain_name: CURRENT_CHAIN_PARAMS.chain_name,
        protocol_stage: CURRENT_CHAIN_PARAMS.protocol_stage,
        protocol_version: CURRENT_CHAIN_PARAMS.protocol_version,
        network_magic: network_magic_hex(),
        best_height,
        tip_hash,
    };
    post_json(gateway_url, "/v1/node/register", &request).map(|_| ())
}

pub fn heartbeat_peer(
    gateway_url: &str,
    public_addr: SocketAddr,
    best_height: Option<u64>,
    tip_hash: Option<String>,
) -> Result<(), String> {
    let request = HeartbeatRequest {
        peer_id: None,
        address: public_addr.to_string(),
        best_height,
        tip_hash,
    };
    post_json(gateway_url, "/v1/node/heartbeat", &request).map(|_| ())
}

pub fn request_gateway_peers(
    gateway_url: &str,
    limit: usize,
    exclude: Option<SocketAddr>,
) -> Result<Vec<PeerInfo>, String> {
    let mut path = format!(
        "/v1/peers?chain_id={}&chain_name={}&protocol_stage={}&protocol_version={}&network_magic={}&limit={limit}",
        CURRENT_CHAIN_PARAMS.chain_id,
        CURRENT_CHAIN_PARAMS.chain_name,
        CURRENT_CHAIN_PARAMS.protocol_stage,
        CURRENT_CHAIN_PARAMS.protocol_version,
        network_magic_hex()
    );
    if let Some(exclude) = exclude {
        path.push_str("&exclude=");
        path.push_str(&exclude.to_string());
    }

    let body = get(gateway_url, &path)?;
    let response = serde_json::from_str::<PeersResponse>(&body)
        .map_err(|error| format!("failed to parse gateway peers response: {error}: {body}"))?;
    Ok(response
        .peers
        .into_iter()
        .map(|peer| PeerInfo {
            address: peer.address,
        })
        .collect())
}

fn get(gateway_url: &str, path: &str) -> Result<String, String> {
    let endpoint = GatewayEndpoint::parse(gateway_url)?;
    let mut stream = TcpStream::connect_timeout(&endpoint.addr, Duration::from_secs(3))
        .map_err(|error| format!("failed to connect gateway: {error}"))?;
    configure_stream(&stream)?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nhost: {}\r\nconnection: close\r\n\r\n",
        endpoint.addr
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("failed to write gateway request: {error}"))?;
    read_http_response(stream)
}

fn post_json<T: Serialize>(gateway_url: &str, path: &str, value: &T) -> Result<String, String> {
    let endpoint = GatewayEndpoint::parse(gateway_url)?;
    let body = serde_json::to_string(value)
        .map_err(|error| format!("failed to encode gateway request: {error}"))?;
    let mut stream = TcpStream::connect_timeout(&endpoint.addr, Duration::from_secs(3))
        .map_err(|error| format!("failed to connect gateway: {error}"))?;
    configure_stream(&stream)?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nhost: {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        endpoint.addr,
        body.len(),
        body
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("failed to write gateway request: {error}"))?;
    read_http_response(stream)
}

fn configure_stream(stream: &TcpStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(GATEWAY_HTTP_TIMEOUT))
        .map_err(|error| format!("failed to set gateway read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(GATEWAY_HTTP_TIMEOUT))
        .map_err(|error| format!("failed to set gateway write timeout: {error}"))
}

fn read_http_response(mut stream: TcpStream) -> Result<String, String> {
    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes_read) => {
                response.extend_from_slice(&buffer[..bytes_read]);
                if response_body_complete(&response)? {
                    break;
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                if response_body_complete(&response)? {
                    break;
                }
                return Err(
                    "failed to read gateway response: timed out waiting for response".to_string(),
                );
            }
            Err(error) => return Err(format!("failed to read gateway response: {error}")),
        }
    }
    let response = String::from_utf8(response)
        .map_err(|error| format!("failed to decode gateway response: {error}"))?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("invalid gateway response: {response}"))?;
    if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.1 201") {
        return Err(format!("gateway returned error: {body}"));
    }
    Ok(body.to_string())
}

fn response_body_complete(response: &[u8]) -> Result<bool, String> {
    let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Ok(false);
    };
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|error| format!("failed to decode gateway response headers: {error}"))?;
    let Some(content_length) = headers.lines().find_map(content_length) else {
        return Ok(false);
    };
    Ok(response.len() >= header_end + 4 + content_length)
}

fn content_length(line: &str) -> Option<usize> {
    let (name, value) = line.split_once(':')?;
    name.eq_ignore_ascii_case("content-length")
        .then(|| value.trim().parse().ok())
        .flatten()
}

fn network_magic_hex() -> String {
    hex::encode(CURRENT_CHAIN_PARAMS.network_magic)
}
