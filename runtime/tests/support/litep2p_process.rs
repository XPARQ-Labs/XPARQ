// Shared real-process helpers for litep2p integration and stress tests.
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use kernel::{
    crypto::{Signature, SigningSeed, program_id_from_public_key, program_id_to_string, canonical_bytes},
    monetary::coin::{CoinOutput, CoinShare, Zeno},
    program::{AuthorizedProgramEnvelope, CoinTransition, ProgramEnvelope as Transaction},
};
use serde_json::Value;
use wallet::{AccountWallet, account_wallet_from_bip39_mnemonic, encode_bip39_mnemonic};

const WAIT: Duration = Duration::from_secs(120);

struct NodeProcess(Child);

impl Drop for NodeProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn node_binary() -> &'static str {
    env!("CARGO_BIN_EXE_node")
}

fn temp_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "xparq-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn free_address() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

fn miner_program_id() -> String {
    program_id_to_string(&sender_wallet().program_id)
}

fn sender_wallet() -> AccountWallet {
    let mnemonic = encode_bip39_mnemonic(&[42; 16]).unwrap();
    account_wallet_from_bip39_mnemonic(&mnemonic, Signature::MlDsa44).unwrap()
}

fn mine(database: &Path, blocks: u64) {
    mine_to(database, blocks, &miner_program_id());
}

fn mine_to(database: &Path, blocks: u64, address: &str) {
    for _ in 0..blocks {
        let status = Command::new(node_binary())
            .args(["mine-block", database.to_str().unwrap(), address])
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "single-block miner failed");
    }
}

fn start_node(
    database: &Path,
    p2p: &str,
    rpc: &str,
    peers: &[&str],
    miner: Option<&str>,
) -> NodeProcess {
    start_node_with_discovery(database, p2p, rpc, peers, miner, false)
}

fn start_node_with_discovery(
    database: &Path,
    p2p: &str,
    rpc: &str,
    peers: &[&str],
    miner: Option<&str>,
    private_discovery: bool,
) -> NodeProcess {
    let mut command = Command::new(node_binary());
    command.args([
        "run",
        "--litep2p",
        "--data",
        database.to_str().unwrap(),
        "--p2p",
        p2p,
        "--rpc",
        rpc,
    ]);
    if private_discovery {
        command.arg("--litep2p-private-discovery");
    }
    for peer in peers {
        command.args(["--peer", peer]);
    }
    if let Some(miner) = miner {
        command.args(["--miner", miner]);
    }
    NodeProcess(
        command
            .stdout(Stdio::from(
                fs::File::create(database.with_extension("litep2p.log")).unwrap(),
            ))
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}

fn status(rpc: &str) -> Result<Value, String> {
    http_get(rpc, "/status")
}

fn http_get(rpc: &str, route: &str) -> Result<Value, String> {
    let mut stream = TcpStream::connect(rpc).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    stream
        .write_all(
            format!("GET {route} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .map_err(|error| error.to_string())?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| error.to_string())?;
    let body = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| &response[position + 4..])
        .ok_or("HTTP response has no body")?;
    serde_json::from_slice(body).map_err(|error| error.to_string())
}

fn post_transaction(rpc: &str, transaction: &Transaction) -> Value {
    post_program_rpc(rpc, "/transaction", transaction)
}

fn post_program_rpc(rpc: &str, route: &str, transaction: &Transaction) -> Value {
    let body = canonical_bytes(transaction).unwrap();
    let mut stream = TcpStream::connect(rpc).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "POST {route} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(&body).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "transaction submission failed: {}",
        String::from_utf8_lossy(&response)
    );
    let body = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| &response[position + 4..])
        .unwrap();
    serde_json::from_slice(body).unwrap()
}

fn account(rpc: &str, address: &str) -> Result<Value, String> {
    http_get(rpc, &format!("/program/account/{address}"))
}

fn wait_for_status(rpc: &str, predicate: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Ok(value) = status(rpc)
            && predicate(&value)
        {
            return value;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {rpc}");
        thread::sleep(Duration::from_millis(100));
    }
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn peer_endpoint(database: &Path, address: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(log) = fs::read_to_string(database.with_extension("litep2p.log"))
            && let Some(peer) = log.lines().find_map(|line| {
                line.strip_prefix("litep2p: peer=")
                    .and_then(|tail| tail.split_whitespace().next())
            })
        {
            return format!("{address}@{peer}");
        }
        assert!(
            Instant::now() < deadline,
            "node did not print litep2p identity"
        );
        thread::sleep(Duration::from_millis(50));
    }
}
