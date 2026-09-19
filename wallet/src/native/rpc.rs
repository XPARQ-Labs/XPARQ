use std::{
    io::{self, Read, Write},
    net::TcpStream,
};

use serde::Deserialize;

use super::AccountResponse;

pub(super) fn fetch_account(rpc: &str, address: &str) -> Result<AccountResponse, String> {
    let mut response: AccountResponse = http_get_json(rpc, &format!("/account/{address}"))?;
    while let Some(cursor) = response.next_utxo_cursor.clone() {
        let page: AccountResponse =
            http_get_json(rpc, &format!("/account/{address}?utxo_after={cursor}"))?;
        if page.utxos.is_empty() {
            return Err("node returned an invalid empty account page".into());
        }
        response.utxos.extend(page.utxos);
        response.next_utxo_offset = page.next_utxo_offset;
        response.next_utxo_cursor = page.next_utxo_cursor;
    }
    Ok(response)
}

pub(super) fn http_get_json<T: for<'de> Deserialize<'de>>(
    rpc: &str,
    route: &str,
) -> Result<T, String> {
    let mut stream = TcpStream::connect(rpc).map_err(|error| format!("connect RPC: {error}"))?;
    write!(
        stream,
        "GET {route} HTTP/1.1\r\nHost: {rpc}\r\nConnection: close\r\n\r\n"
    )
    .map_err(|error| format!("write RPC request: {error}"))?;
    read_json_response(&mut stream)
}

fn read_json_response<T: for<'de> Deserialize<'de>>(stream: &mut TcpStream) -> Result<T, String> {
    let mut response = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(length) => {
                if response.len().saturating_add(length) > 1024 * 1024 {
                    return Err("RPC response exceeds maximum size".into());
                }
                response.extend_from_slice(&buffer[..length]);
            }
            Err(error)
                if error.kind() == io::ErrorKind::ConnectionReset && !response.is_empty() =>
            {
                break;
            }
            Err(error) => return Err(format!("read RPC response: {error}")),
        }
    }
    let separator = b"\r\n\r\n";
    let body_offset = response
        .windows(separator.len())
        .position(|window| window == separator)
        .map(|offset| offset + separator.len())
        .ok_or("invalid HTTP response")?;
    let status = std::str::from_utf8(&response[..body_offset])
        .map_err(|_| "invalid HTTP response headers")?;
    if !status.starts_with("HTTP/1.1 200 ") {
        let detail = serde_json::from_slice::<serde_json::Value>(&response[body_offset..])
            .ok()
            .and_then(|value| value.get("error")?.as_str().map(str::to_string))
            .or_else(|| {
                std::str::from_utf8(&response[body_offset..])
                    .ok()
                    .map(str::trim)
                    .filter(|body| !body.is_empty())
                    .map(str::to_string)
            });
        let status_line = status.lines().next().unwrap_or(status);
        return Err(format!(
            "node RPC rejected request: {status_line}{}",
            detail.map_or_else(String::new, |detail| format!(": {detail}"))
        ));
    }
    serde_json::from_slice(&response[body_offset..])
        .map_err(|error| format!("invalid node RPC response: {error}"))
}

pub(super) fn http_post_bytes<T: for<'de> Deserialize<'de>>(
    rpc: &str,
    route: &str,
    body: &[u8],
) -> Result<T, String> {
    let mut stream = TcpStream::connect(rpc).map_err(|error| format!("connect RPC: {error}"))?;
    write!(
        stream,
        "POST {route} HTTP/1.1\r\nHost: {rpc}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .and_then(|_| stream.write_all(body))
    .map_err(|error| format!("write RPC request: {error}"))?;
    read_json_response(&mut stream)
}
