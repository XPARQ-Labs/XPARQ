//! Run after `cargo build -p node --bins`; exercises the actual CLI and redb node.
use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
struct Node(Child);
impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn get(rpc: &str, route: &str) -> Value {
    let mut stream = TcpStream::connect(rpc).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "GET {route} HTTP/1.1\r\nHost: {rpc}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    let start = bytes.windows(4).position(|s| s == b"\r\n\r\n").unwrap() + 4;
    let value: Value = serde_json::from_slice(&bytes[start..]).unwrap();
    assert!(bytes.starts_with(b"HTTP/1.1 200"), "{value}");
    value
}
fn free() -> String {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}

fn assert_rejected_get(rpc: &str, route: &str) {
    let mut stream = TcpStream::connect(rpc).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "GET {route} HTTP/1.1\r\nHost: {rpc}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 400"),
        "legacy/invalid identity route accepted: {route}"
    );
}
fn start(binary: &Path, db: &Path, rpc: &str, p2p: &str) -> Node {
    let child = Command::new(binary)
        .args([
            "run",
            "--data",
            db.to_str().unwrap(),
            "--rpc",
            rpc,
            "--p2p",
            p2p,
        ])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let mut node = Node(child);
    // Restart validates the persisted PoW chain before opening RPC.
    let deadline = Instant::now() + Duration::from_secs(120);
    while TcpStream::connect(rpc).is_err() {
        assert!(node.0.try_wait().unwrap().is_none(), "node exited");
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(50));
    }
    node
}
fn mine(binary: &Path, db: &Path, program_id: &str) {
    eprintln!("confirming pending operations with a mined block");
    let result = Command::new(binary)
        .args(["mine-block", db.to_str().unwrap(), program_id])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
fn cli(wallet: &Path, rpc: &str, command: &str, args: &[&str]) -> String {
    eprintln!("wallet command: {command}");
    let result = Command::new(env!("CARGO_BIN_EXE_wallet"))
        .args([command, "--wallet", wallet.to_str().unwrap(), "--rpc", rpc])
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}

fn read_request_headers(reader: &mut impl Read) -> std::io::Result<Vec<u8>> {
    const MAX_HEADERS: usize = 4096;
    let mut headers = Vec::new();
    let mut buffer = [0; 256];
    while headers.len() < MAX_HEADERS {
        let remaining = (MAX_HEADERS - headers.len()).min(buffer.len());
        let count = match reader.read(&mut buffer[..remaining]) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "RPC request ended before its headers were complete",
            ));
        }
        headers.extend_from_slice(&buffer[..count]);
        if let Some(end) = headers.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            headers.truncate(end + 4);
            return Ok(headers);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "RPC request headers exceed the test server limit",
    ))
}

#[test]
fn mock_rpc_waits_for_fragmented_headers_and_rejects_incomplete_requests() {
    struct Fragmented<'a>(&'a [u8]);
    impl Read for Fragmented<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let size = buffer.len().min(1);
            self.0.read(&mut buffer[..size])
        }
    }
    let request = b"GET /history HTTP/1.1\r\nHost: localhost\r\n\r\n";
    assert_eq!(
        read_request_headers(&mut Fragmented(request)).unwrap(),
        request
    );
    assert_eq!(
        read_request_headers(&mut Fragmented(&request[..request.len() - 1]))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    assert_eq!(
        read_request_headers(&mut &[b'x'; 4097][..])
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidData
    );
}
#[test]
#[ignore = "requires node binary; cargo build -p node --bins then run explicitly"]
fn program_wallet_cli_lifecycle_and_recipient_history_survive_restart() {
    let node_binary = Path::new(env!("CARGO_BIN_EXE_wallet")).with_file_name(if cfg!(windows) {
        "node.exe"
    } else {
        "node"
    });
    assert!(node_binary.exists(), "build the node binary first");
    let root = std::env::temp_dir().join(format!(
        "xparq-wallet-program-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let db = root.join("data");
    let file = root.join("wallet.json");
    let words = wallet::encode_bip39_mnemonic(&[63; 16]).unwrap();
    let mut owner =
        wallet::account_wallet_from_bip39_mnemonic(&words, kernel::crypto::Signature::MlDsa44)
            .unwrap();
    owner.mnemonic = Some(words.clone());
    fs::write(&file, &*wallet::account_wallet_file_bytes(&owner).unwrap()).unwrap();
    let program_id = kernel::crypto::program_id_to_string(&owner.program_id);
    let receiver = wallet::account_wallet_from_bip39_mnemonic(
        &wallet::encode_bip39_mnemonic(&[64; 16]).unwrap(),
        kernel::crypto::Signature::MlDsa44,
    )
    .unwrap();
    let to = kernel::crypto::program_id_to_string(&receiver.program_id);
    mine(&node_binary, &db, &program_id);
    let rpc = free();
    let p2p = free();
    let mut node = start(&node_binary, &db, &rpc, &p2p);
    let account_id = hex::encode(owner.program_id.into_bytes());
    let display = cli(&file, &rpc, "program-id", &[]);
    assert!(display.contains(&format!("Program ID: {account_id}")));
    let account = get(&rpc, &format!("/program/account/{account_id}"));
    for route in [
        format!("/account/{account_id}"),
        format!("/balance/{account_id}"),
        format!("/explorer/address/{account_id}"),
        format!("/program/account/{}", "0".repeat(45)),
    ] {
        assert_rejected_get(&rpc, &route);
    }
    assert_eq!(account["policy"], "signature");
    assert_eq!(
        account["coin_balance"],
        get(&rpc, &format!("/program/account/{program_id}"))["total"]
    );
    let output = cli(
        &file,
        &rpc,
        "program-register",
        &[
            "--name",
            "CLIPROGRAM",
            "--max-supply",
            "100",
            "--initial-mint",
            "40",
        ],
    );
    let asset = output
        .lines()
        .find_map(|line| line.strip_prefix("program asset: "))
        .unwrap()
        .to_string();
    drop(node);
    mine(&node_binary, &db, &program_id);
    node = start(&node_binary, &db, &rpc, &p2p);
    for (command, args) in [
        (
            "program-mint",
            vec![
                "--asset",
                asset.as_str(),
                "--to",
                program_id.as_str(),
                "--amount",
                "20",
            ],
        ),
        (
            "program-transfer",
            vec![
                "--asset",
                asset.as_str(),
                "--to",
                to.as_str(),
                "--amount",
                "15",
            ],
        ),
        // Transfer leaves two owner shares. Burning first could consume an
        // exact five-unit change share, leaving nothing to consolidate.
        ("program-consolidate", vec!["--asset", asset.as_str()]),
        (
            "program-burn",
            vec!["--asset", asset.as_str(), "--amount", "5"],
        ),
    ] {
        cli(&file, &rpc, command, &args);
        drop(node);
        mine(&node_binary, &db, &program_id);
        node = start(&node_binary, &db, &rpc, &p2p);
    }
    let metadata = get(&rpc, &format!("/program/asset/{asset}"));
    assert_eq!(metadata["program_id"], 0);
    assert_eq!(metadata["creator"]["type"], "program");
    assert_eq!(metadata["creator"]["value"], account_id);
    assert_eq!(metadata["mint_authority"], metadata["creator"]);
    assert_eq!(metadata["supply"], "5500000000");
    assert_eq!(metadata["total_minted"], "6000000000");
    assert_eq!(metadata["total_burned"], "500000000");
    let balance = get(
        &rpc,
        &format!("/program/asset/{asset}/balance/{program_id}"),
    );
    assert_eq!(balance["balance"], "4000000000");
    assert_eq!(balance["shares"].as_array().unwrap().len(), 1);
    assert_eq!(
        get(&rpc, &format!("/program/asset/{asset}/balance/{to}"))["balance"],
        "1500000000"
    );
    let history = get(
        &rpc,
        &format!("/explorer/program/{to}?include_emissions=false"),
    );
    let activity = history["activities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["program"]["operation"] == "transfer")
        .unwrap();
    assert_eq!(activity["program"]["amount"], "1500000000");
    assert_eq!(activity["program"]["program_id"], 0);
    assert_eq!(activity["program"]["opcode"], 1);
    assert_eq!(activity["direction"], "in");
    assert!(
        get(&rpc, &format!("/program/account/{to}"))["program_assets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["asset"] == asset)
    );
    assert!(cli(&file, &rpc, "balance", &[]).contains("CLIPROGRAM"));
    assert!(cli(&file, &rpc, "program-info", &["--asset", &asset]).contains("CLIPROGRAM"));
    cli(&file, &rpc, "program-balance", &["--asset", &asset]);
    let offline = cli(
        &file,
        &rpc,
        "program-transfer",
        &["--asset", &asset, "--to", &to, "--amount", "1", "--offline"],
    );
    assert!(offline.contains("Transaction Hex:"));
    assert!(!offline.contains("Tx Hash:"));
    let recovered = get(&rpc, "/status")["tip_hash"].clone();
    drop(node);
    node = start(&node_binary, &db, &rpc, &p2p);
    assert_eq!(get(&rpc, "/status")["tip_hash"], recovered);
    drop(node);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn program_history_cli_displays_asset_units_as_decimal_amounts() {
    let root = std::env::temp_dir().join(format!("xparq-program-history-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let file = root.join("wallet.json");
    let words = wallet::encode_bip39_mnemonic(&[65; 16]).unwrap();
    let mut owner =
        wallet::account_wallet_from_bip39_mnemonic(&words, kernel::crypto::Signature::MlDsa44)
            .unwrap();
    owner.mnemonic = Some(words);
    fs::write(&file, &*wallet::account_wallet_file_bytes(&owner).unwrap()).unwrap();
    let program_id = kernel::crypto::program_id_to_string(&owner.program_id);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let rpc = listener.local_addr().unwrap().to_string();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        read_request_headers(&mut stream).unwrap();
        let body=serde_json::json!({"program_id":program_id,"tip_height":5,"emission_count":0,"activities":[{"height":4,"block_hash":"11","hash":"22","type":"program","direction":"in","amount":0,"size_bytes":3000,"program":{"operation":"transfer","asset":"33","amount":"1500000000"}}]}).to_string();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    let output = cli(&file, &rpc, "history", &[]);
    assert!(output.contains("Asset Operation: transfer"));
    assert!(output.contains("Asset Amount: 15.00000000"));
    server.join().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires node binary; cargo build -p node -p wallet --bins then run explicitly"]
fn xpq_program_wallet_cli_spend_and_consolidation() {
    let binary = Path::new(env!("CARGO_BIN_EXE_wallet")).with_file_name(if cfg!(windows) {
        "node.exe"
    } else {
        "node"
    });
    assert!(binary.exists(), "build the node binary first");
    let root = std::env::temp_dir().join(format!(
        "xparq-native-program-cli-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let db = root.join("data");
    let file = root.join("wallet.json");
    let words = wallet::encode_bip39_mnemonic(&[74; 16]).unwrap();
    let mut owner =
        wallet::account_wallet_from_bip39_mnemonic(&words, kernel::crypto::Signature::MlDsa44)
            .unwrap();
    owner.mnemonic = Some(words);
    fs::write(&file, &*wallet::account_wallet_file_bytes(&owner).unwrap()).unwrap();
    let program_id = kernel::crypto::program_id_to_string(&owner.program_id);
    let receiver = wallet::account_wallet_from_bip39_mnemonic(
        &wallet::encode_bip39_mnemonic(&[75; 16]).unwrap(),
        kernel::crypto::Signature::MlDsa44,
    )
    .unwrap();
    let to = kernel::crypto::program_id_to_string(&receiver.program_id);
    mine(&binary, &db, &program_id);
    let rpc = free();
    let p2p = free();
    let mut node = start(&binary, &db, &rpc, &p2p);
    let output = cli(&file, &rpc, "sign-spend", &["--to", &to, "--amount", "1"]);
    let hash = output
        .lines()
        .find_map(|line| line.strip_prefix("Tx Hash: "))
        .unwrap()
        .to_string();
    drop(node);
    mine(&binary, &db, &program_id);
    node = start(&binary, &db, &rpc, &p2p);
    let transaction = get(&rpc, &format!("/explorer/transaction/{hash}"));
    assert_eq!(transaction["transaction"]["program_id"], 0);
    assert_eq!(transaction["transaction"]["opcode"], 1);
    assert_eq!(transaction["transaction"]["type"], "transfer");
    assert_eq!(
        get(&rpc, &format!("/program/account/{to}"))["total"],
        100_000_000
    );
    let output = cli(&file, &rpc, "consolidate", &[]);
    let hash = output
        .lines()
        .find_map(|line| line.strip_prefix("Tx Hash: "))
        .unwrap()
        .to_string();
    drop(node);
    mine(&binary, &db, &program_id);
    node = start(&binary, &db, &rpc, &p2p);
    let transaction = get(&rpc, &format!("/explorer/transaction/{hash}"));
    assert_eq!(transaction["transaction"]["program_id"], 0);
    assert!(
        transaction["transaction"]["inputs"]
            .as_array()
            .unwrap()
            .len()
            >= 2
    );
    assert_eq!(
        transaction["transaction"]["outputs"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let tip = get(&rpc, "/status")["tip_hash"].clone();
    drop(node);
    node = start(&binary, &db, &rpc, &p2p);
    assert_eq!(get(&rpc, "/status")["tip_hash"], tip);
    assert_eq!(
        get(&rpc, &format!("/program/account/{to}"))["total"],
        100_000_000
    );
    drop(node);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires node binary; cargo build -p node -p wallet --bins then run explicitly"]
fn counter_deploy_and_call_cli_survive_restart() {
    let node_binary = Path::new(env!("CARGO_BIN_EXE_wallet")).with_file_name(if cfg!(windows) {
        "node.exe"
    } else {
        "node"
    });
    assert!(node_binary.exists(), "build the node binary first");
    let root = std::env::temp_dir().join(format!(
        "xparq-counter-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let db = root.join("data");
    let file = root.join("wallet.json");
    let words = wallet::encode_bip39_mnemonic(&[71; 16]).unwrap();
    let mut owner =
        wallet::account_wallet_from_bip39_mnemonic(&words, kernel::crypto::Signature::MlDsa44)
            .unwrap();
    owner.mnemonic = Some(words);
    fs::write(&file, &*wallet::account_wallet_file_bytes(&owner).unwrap()).unwrap();
    let program_id = kernel::crypto::program_id_to_string(&owner.program_id);
    let code = root.join("counter.xpvm");
    fs::write(&code, include_bytes!("../../examples/counter/counter.xpvm")).unwrap();
    mine(&node_binary, &db, &program_id);
    let rpc = free();
    let p2p = free();
    let mut node = start(&node_binary, &db, &rpc, &p2p);
    let output = cli(
        &file,
        &rpc,
        "program-deploy",
        &["--code", code.to_str().unwrap(), "--nonce", "1"],
    );
    let program_id = output
        .lines()
        .find_map(|line| line.strip_prefix("Program ID: "))
        .unwrap()
        .to_string();
    assert!(output.contains("Operation ID:"));
    drop(node);
    mine(&node_binary, &db, &program_id);
    node = start(&node_binary, &db, &rpc, &p2p);
    let offline = cli(
        &file,
        &rpc,
        "program-call",
        &["--program-id", &program_id, "--offline"],
    );
    assert!(offline.contains("Transaction Hex:"));
    assert!(!offline.contains("Tx Hash:"));
    for _ in 0..2 {
        let output = cli(&file, &rpc, "program-call", &["--program-id", &program_id]);
        let hash = output
            .lines()
            .find_map(|line| line.strip_prefix("Tx Hash: "))
            .unwrap()
            .to_string();
        drop(node);
        mine(&node_binary, &db, &program_id);
        node = start(&node_binary, &db, &rpc, &p2p);
        let history = get(
            &rpc,
            &format!("/explorer/program/{program_id}?include_emissions=false"),
        );
        assert!(
            history.to_string().contains(&hash),
            "VM invocation was not committed: {history}"
        );
    }
    let tip = get(&rpc, "/status")["tip_hash"].clone();
    let history = get(
        &rpc,
        &format!("/explorer/program/{program_id}?include_emissions=false"),
    );
    drop(node);
    node = start(&node_binary, &db, &rpc, &p2p);
    assert_eq!(get(&rpc, "/status")["tip_hash"], tip);
    assert_eq!(
        get(
            &rpc,
            &format!("/explorer/program/{program_id}?include_emissions=false")
        ),
        history
    );
    drop(node);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires node binary; cargo build -p node -p wallet --bins then run explicitly"]
fn deployed_contract_receives_and_sends_coin_and_asset_through_cli() {
    let node_binary = Path::new(env!("CARGO_BIN_EXE_wallet")).with_file_name(if cfg!(windows) {
        "node.exe"
    } else {
        "node"
    });
    assert!(node_binary.exists(), "build the node binary first");
    let root = std::env::temp_dir().join(format!(
        "xparq-contract-cli-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let db = root.join("data");
    let file = root.join("wallet.json");
    let words = wallet::encode_bip39_mnemonic(&[63; 16]).unwrap();
    let mut owner =
        wallet::account_wallet_from_bip39_mnemonic(&words, kernel::crypto::Signature::MlDsa44)
            .unwrap();
    owner.mnemonic = Some(words);
    fs::write(&file, &*wallet::account_wallet_file_bytes(&owner).unwrap()).unwrap();
    let program_id = kernel::crypto::program_id_to_string(&owner.program_id);
    let receiver = wallet::account_wallet_from_bip39_mnemonic(
        &wallet::encode_bip39_mnemonic(&[64; 16]).unwrap(),
        kernel::crypto::Signature::MlDsa44,
    )
    .unwrap();
    let to = kernel::crypto::program_id_to_string(&receiver.program_id);
    mine(&node_binary, &db, &program_id);
    let rpc = free();
    let p2p = free();
    let mut node = start(&node_binary, &db, &rpc, &p2p);
    let registered = cli(
        &file,
        &rpc,
        "program-register",
        &[
            "--name",
            "VAULT",
            "--max-supply",
            "10",
            "--initial-mint",
            "3",
        ],
    );
    let asset = registered
        .lines()
        .find_map(|line| line.strip_prefix("program asset: "))
        .unwrap()
        .to_string();
    drop(node);
    mine(&node_binary, &db, &program_id);
    node = start(&node_binary, &db, &rpc, &p2p);
    // Deploy a contract that pays one coin and two asset units to the receiver.
    let mut code = b"XPVM".to_vec();
    code.extend_from_slice(&[2, 1, 0, 0, 0, 0, 0, 0, 0]);
    code.push(6);
    code.extend(
        borsh::to_vec(&kernel::program::vm::TransferRequest {
            recipient: kernel::common::Owner::Program(receiver.program_id),
            amount: 100_000_000,
        })
        .unwrap(),
    );
    code.push(7);
    code.extend(hex::decode(&asset).unwrap());
    code.extend(
        borsh::to_vec(&kernel::program::vm::TransferRequest {
            recipient: kernel::common::Owner::Program(receiver.program_id),
            amount: 200_000_000,
        })
        .unwrap(),
    );
    code.push(1);
    code.extend_from_slice(&0i64.to_le_bytes());
    code.push(3);
    let code_path = root.join("vault.xpvm");
    fs::write(&code_path, code).unwrap();
    let deployment = cli(
        &file,
        &rpc,
        "program-deploy",
        &["--code", code_path.to_str().unwrap(), "--nonce", "2"],
    );
    let contract = deployment
        .lines()
        .find_map(|line| line.strip_prefix("Program ID: "))
        .unwrap()
        .to_string();
    drop(node);
    mine(&node_binary, &db, &program_id);
    node = start(&node_binary, &db, &rpc, &p2p);
    let recipient = format!("program:{contract}");
    for (command, args) in [
        (
            "sign-spend",
            vec!["--to", recipient.as_str(), "--amount", "2"],
        ),
        (
            "program-transfer",
            vec![
                "--asset",
                asset.as_str(),
                "--to",
                recipient.as_str(),
                "--amount",
                "3",
            ],
        ),
        ("program-call", vec!["--program-id", contract.as_str()]),
    ] {
        cli(&file, &rpc, command, &args);
        drop(node);
        mine(&node_binary, &db, &program_id);
        node = start(&node_binary, &db, &rpc, &p2p);
    }
    assert_eq!(
        get(&rpc, &format!("/program/account/{to}"))["total"],
        100_000_000
    );
    assert_eq!(
        get(&rpc, &format!("/program/asset/{asset}/balance/{to}"))["balance"],
        "200000000"
    );
    let contract_state = get(&rpc, &format!("/program/account/{contract}"));
    assert_eq!(contract_state["coin_balance"], 100_000_000);
    assert_eq!(contract_state["asset_shares"][0]["amount"], "100000000");
    assert!(
        cli(&file, &rpc, "program-account", &["--program-id", &contract])
            .contains("Coin Balance: 100000000")
    );

    // The second call has enough coin but insufficient asset. No leg commits.
    let failed = Command::new(env!("CARGO_BIN_EXE_wallet"))
        .args([
            "program-call",
            "--wallet",
            file.to_str().unwrap(),
            "--rpc",
            &rpc,
            "--program-id",
            &contract,
        ])
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert_eq!(
        get(&rpc, &format!("/program/account/{contract}")),
        contract_state
    );
    drop(node);
    node = start(&node_binary, &db, &rpc, &p2p);
    assert_eq!(
        get(&rpc, &format!("/program/account/{contract}")),
        contract_state
    );
    assert_eq!(
        get(&rpc, &format!("/program/account/{to}"))["total"],
        100_000_000
    );
    assert_eq!(
        get(&rpc, &format!("/program/asset/{asset}/balance/{to}"))["balance"],
        "200000000"
    );
    drop(node);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires node binary; cargo build -p node -p wallet --bins then run explicitly"]
fn deployed_contract_registers_and_mints_asset_through_cli() {
    use kernel::{
        common::Owner,
        monetary::asset::{AssetContract, Metadata, Unit},
        program::ProgramId,
    };
    let node_binary = Path::new(env!("CARGO_BIN_EXE_wallet")).with_file_name(if cfg!(windows) {
        "node.exe"
    } else {
        "node"
    });
    assert!(node_binary.exists(), "build the node binary first");
    let root = std::env::temp_dir().join(format!(
        "xparq-issuer-cli-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let db = root.join("data");
    let file = root.join("wallet.json");
    let words = wallet::encode_bip39_mnemonic(&[65; 16]).unwrap();
    let mut owner =
        wallet::account_wallet_from_bip39_mnemonic(&words, kernel::crypto::Signature::MlDsa44)
            .unwrap();
    owner.mnemonic = Some(words);
    fs::write(&file, &*wallet::account_wallet_file_bytes(&owner).unwrap()).unwrap();
    let program_id = kernel::crypto::program_id_to_string(&owner.program_id);
    let receiver = wallet::account_wallet_from_bip39_mnemonic(
        &wallet::encode_bip39_mnemonic(&[66; 16]).unwrap(),
        kernel::crypto::Signature::MlDsa44,
    )
    .unwrap();
    let to = kernel::crypto::program_id_to_string(&receiver.program_id);
    let code_path = root.join("issuer.xpvm");
    let builder = Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/asset_issuer/build.py");
    let built = Command::new("python3")
        .arg(builder)
        .args([
            "--recipient-hex",
            &hex::encode(receiver.program_id.0),
            "--name",
            "LAUNCH",
            "--max-supply-units",
            "1100000000",
            "--initial-mint-units",
            "100000000",
            "--mint-units",
            "500000000",
            "--output",
            code_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    mine(&node_binary, &db, &program_id);
    let rpc = free();
    let p2p = free();
    let mut node = start(&node_binary, &db, &rpc, &p2p);
    let deployment = cli(
        &file,
        &rpc,
        "program-deploy",
        &["--code", code_path.to_str().unwrap(), "--nonce", "1"],
    );
    let contract = deployment
        .lines()
        .find_map(|line| line.strip_prefix("Program ID: "))
        .unwrap()
        .to_string();
    let id = ProgramId::from_bytes(hex::decode(&contract).unwrap().try_into().unwrap());
    let actor = Owner::Program(id);
    let asset = AssetContract::derive(
        &Metadata::new(
            "LAUNCH".into(),
            Unit::from_units(1_100_000_000),
            actor,
            actor,
        )
        .unwrap(),
        1,
    )
    .unwrap()
    .to_string();
    drop(node);
    mine(&node_binary, &db, &program_id);
    node = start(&node_binary, &db, &rpc, &p2p);
    // No coin deposit: the signed caller payment covers registration, mint and fuel.
    for (nonce, supply) in [(1, "600000000"), (2, "1100000000")] {
        cli(&file, &rpc, "program-call", &["--program-id", &contract]);
        drop(node);
        mine(&node_binary, &db, &program_id);
        node = start(&node_binary, &db, &rpc, &p2p);
        let record = get(&rpc, &format!("/program/asset/{asset}"));
        assert_eq!(record["supply"], supply);
        assert_eq!(record["total_minted"], supply);
        assert_eq!(record["mint_nonce"], nonce);
        assert_eq!(record["creator"]["type"], "program");
        assert_eq!(record["creator"]["value"], contract);
        assert_eq!(record["mint_authority"], record["creator"]);
        let account = get(&rpc, &format!("/program/account/{contract}"));
        assert_eq!(account["coin_balance"], 0);
        assert_eq!(account["asset_shares"][0]["amount"], "100000000");
        assert_eq!(
            get(&rpc, &format!("/program/asset/{asset}/balance/{to}"))["balance"],
            (nonce * 500_000_000u64).to_string()
        );
    }
    let record = get(&rpc, &format!("/program/asset/{asset}"));
    let account = get(&rpc, &format!("/program/account/{contract}"));
    let payer = get(&rpc, &format!("/program/account/{program_id}"));
    let failed = Command::new(env!("CARGO_BIN_EXE_wallet"))
        .args([
            "program-call",
            "--wallet",
            file.to_str().unwrap(),
            "--rpc",
            &rpc,
            "--program-id",
            &contract,
        ])
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert_eq!(get(&rpc, &format!("/program/asset/{asset}")), record);
    assert_eq!(get(&rpc, &format!("/program/account/{contract}")), account);
    assert_eq!(get(&rpc, &format!("/program/account/{program_id}")), payer);
    drop(node);
    node = start(&node_binary, &db, &rpc, &p2p);
    assert_eq!(get(&rpc, &format!("/program/asset/{asset}")), record);
    assert_eq!(get(&rpc, &format!("/program/account/{contract}")), account);
    assert_eq!(
        get(&rpc, &format!("/program/asset/{asset}/balance/{to}"))["balance"],
        "1000000000"
    );
    drop(node);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires node binary and localhost sockets"]
fn application_vm_deposit_and_dynamic_withdraw_survive_restart() {
    let node_binary = Path::new(env!("CARGO_BIN_EXE_wallet")).with_file_name(if cfg!(windows) {
        "node.exe"
    } else {
        "node"
    });
    assert!(node_binary.exists(), "build node first");
    let root = std::env::temp_dir().join(format!(
        "xparq-app-vm-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let db = root.join("data");
    let file = root.join("wallet.json");
    let words = wallet::encode_bip39_mnemonic(&[75; 16]).unwrap();
    let mut owner =
        wallet::account_wallet_from_bip39_mnemonic(&words, kernel::crypto::Signature::MlDsa44)
            .unwrap();
    owner.mnemonic = Some(words);
    fs::write(&file, &*wallet::account_wallet_file_bytes(&owner).unwrap()).unwrap();
    let program_id = kernel::crypto::program_id_to_string(&owner.program_id);
    fn int(body: &mut Vec<u8>, n: u128) {
        body.push(1);
        body.extend(n.to_le_bytes());
    }
    fn end(body: &mut Vec<u8>) {
        int(body, 0);
        body.push(3);
    }
    // Test-only contract fixture: balances keyed by authenticated caller, not user input.
    let mut body = vec![0x15, 0x36];
    int(&mut body, 0);
    body.extend([0x19, 0x21]);
    let jump = body.len();
    body.extend([0; 4]);
    body.extend([0x12, 0x33, 0x16, 0x30, 0x29, 0x44, 0x02, 0x2a, 0x31]);
    end(&mut body);
    let withdrawal = body.len() as u32;
    body[jump..jump + 4].copy_from_slice(&withdrawal.to_le_bytes());
    body.extend([
        0x12, 0x33, 0x16, 0x30, 0x29, 0x15, 0x29, 0x24, 0x2a, 0x31, 0x12, 0x15, 0x29, 0x40,
    ]);
    end(&mut body);
    let mut code = b"XPVM".to_vec();
    code.extend([4, 16, 0, 1, 0, 0, 0, 0, 0]);
    code.extend(body);
    let code_file = root.join("fixture.xpvm");
    fs::write(&code_file, code).unwrap();
    mine(&node_binary, &db, &program_id);
    let rpc = free();
    let p2p = free();
    let mut node = start(&node_binary, &db, &rpc, &p2p);
    let output = cli(
        &file,
        &rpc,
        "program-deploy",
        &["--code", code_file.to_str().unwrap(), "--nonce", "1"],
    );
    let id = output
        .lines()
        .find_map(|l| l.strip_prefix("Program ID: "))
        .unwrap()
        .to_string();
    drop(node);
    mine(&node_binary, &db, &program_id);
    node = start(&node_binary, &db, &rpc, &p2p);
    // The offline deposit must be fully signed and quoted without mutating the chain.
    let output = cli(
        &file,
        &rpc,
        "program-call",
        &["--program-id", &id, "--deposit", "0.00000100", "--offline"],
    );
    assert!(output.contains("Transaction Hex:"));
    assert_eq!(
        get(&rpc, &format!("/program/account/{id}"))["coin_balance"],
        0
    );
    cli(
        &file,
        &rpc,
        "program-call",
        &["--program-id", &id, "--deposit", "0.00000100"],
    );
    drop(node);
    mine(&node_binary, &db, &program_id);
    node = start(&node_binary, &db, &rpc, &p2p);
    assert_eq!(
        get(&rpc, &format!("/program/account/{id}"))["coin_balance"],
        100
    );
    let key = hex::encode(
        kernel::crypto::canonical_bytes(&kernel::common::Owner::Program(owner.program_id)).unwrap(),
    );
    let state_route = format!("/program/state/{id}/{key}");
    assert_eq!(
        get(&rpc, &state_route)["value"],
        hex::encode(100u128.to_le_bytes())
    );
    let data = hex::encode(30u128.to_le_bytes());
    cli(
        &file,
        &rpc,
        "program-call",
        &["--program-id", &id, "--data", &data],
    );
    drop(node);
    mine(&node_binary, &db, &program_id);
    node = start(&node_binary, &db, &rpc, &p2p);
    assert_eq!(
        get(&rpc, &format!("/program/account/{id}"))["coin_balance"],
        70
    );
    assert_eq!(
        get(&rpc, &state_route)["value"],
        hex::encode(70u128.to_le_bytes())
    );
    let before = get(&rpc, "/status")["tip_hash"].clone();
    let too_much = hex::encode(71u128.to_le_bytes());
    let rejected = Command::new(env!("CARGO_BIN_EXE_wallet"))
        .args([
            "program-call",
            "--wallet",
            file.to_str().unwrap(),
            "--rpc",
            &rpc,
            "--program-id",
            &id,
            "--data",
            &too_much,
        ])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert_eq!(get(&rpc, "/status")["tip_hash"], before);
    assert_eq!(
        get(&rpc, &format!("/program/account/{id}"))["coin_balance"],
        70
    );
    drop(node);
    node = start(&node_binary, &db, &rpc, &p2p);
    assert_eq!(
        get(&rpc, &format!("/program/account/{id}"))["coin_balance"],
        70
    );
    assert_eq!(
        get(&rpc, &state_route)["value"],
        hex::encode(70u128.to_le_bytes())
    );
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
