use std::{
    io::{self, Read, Write},
    net::TcpStream,
};

use serde::Deserialize;

use super::AccountResponse;

pub(super) fn fetch_account(rpc: &str, program_id: &str) -> Result<AccountResponse, String> {
    let mut response: AccountResponse =
        http_get_json(rpc, &format!("/program/coins/{program_id}"))?;
    while let Some(cursor) = response.next_utxo_cursor.clone() {
        let page: AccountResponse = http_get_json(
            rpc,
            &format!("/program/coins/{program_id}?utxo_after={cursor}"),
        )?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_fetch_uses_coin_endpoint_for_every_page() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let program = "a".repeat(64);
        let expected_program = program.clone();
        let server = std::thread::spawn(move || {
            let cursor = "1".repeat(64);
            for page in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                    assert!(request.len() < 2048);
                }
                let suffix = if page == 0 {
                    String::new()
                } else {
                    format!("?utxo_after={cursor}")
                };
                assert!(String::from_utf8(request).unwrap().starts_with(&format!(
                    "GET /program/coins/{expected_program}{suffix} HTTP/1.1\r\n"
                )));
                let body = serde_json::to_vec(&serde_json::json!({
                    "next_height": 11,
                    "utxo_snapshot": "snapshot",
                    "utxos": [{"id": if page == 0 { cursor.clone() } else { "2".repeat(64) }, "amount": 100, "reserved": page == 1}],
                    "next_utxo_offset": if page == 0 { Some(1) } else { None },
                    "next_utxo_cursor": if page == 0 { Some(cursor.clone()) } else { None }
                })).unwrap();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        let account = fetch_account(&address, &program).unwrap();
        server.join().unwrap();
        assert_eq!(account.next_height, 11);
        assert_eq!(account.utxos.len(), 2);
        assert_eq!(account.utxos[0].id, "1".repeat(64));
        assert_eq!(account.utxos[0].amount, 100);
        assert!(!account.utxos[0].reserved);
        assert!(account.utxos[1].reserved);
        assert!(account.next_utxo_cursor.is_none());
    }
}
