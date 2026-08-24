use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde_json::Value;
use xparq::{
    coin::{Amount, CoinId},
    common::canonical_bytes,
    crypto::{address_from_public_key, address_to_string, keypair_from_seed},
    transaction::{AuthorizedTransaction, OnChainSpendIntent, SpendOutput},
};
use xparq_wallet::Wallet;

const WAIT: Duration = Duration::from_secs(120);
const MATURE_FIXTURE: &str = "tests/fixtures/mature";

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

fn miner_address() -> String {
    let keypair = keypair_from_seed(&[42; 32]);
    address_to_string(&address_from_public_key(&keypair.public_key))
}

fn sender_wallet() -> Wallet {
    let keypair = keypair_from_seed(&[42; 32]);
    Wallet::from_keys(keypair.public_key, keypair.secret_key)
}

fn mine(database: &Path, blocks: u64) {
    for _ in 0..blocks {
        let status = Command::new(node_binary())
            .args(["mine-block", database.to_str().unwrap(), &miner_address()])
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
    let mut command = Command::new(node_binary());
    command.args([
        "run",
        "--data",
        database.to_str().unwrap(),
        "--p2p",
        p2p,
        "--rpc",
        rpc,
    ]);
    for peer in peers {
        command.args(["--peer", peer]);
    }
    if let Some(miner) = miner {
        command.args(["--miner", miner]);
    }
    NodeProcess(
        command
            .stdout(Stdio::null())
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

fn post_transaction(rpc: &str, transaction: &AuthorizedTransaction) -> Value {
    let body = canonical_bytes(transaction).unwrap();
    let mut stream = TcpStream::connect(rpc).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "POST /transaction HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
    http_get(rpc, &format!("/account/{address}"))
}

fn wait_for_status(rpc: &str, predicate: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Ok(value) = status(rpc) {
            if predicate(&value) {
                return value;
            }
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

#[test]
fn block_gossip_crosses_three_nodes_and_survives_restart() {
    let root = temp_root("three-node-gossip");
    let a = root.join("a");
    let b = root.join("b");
    let c = root.join("c");
    mine(&a, 1);

    let a_p2p = free_address();
    let a_rpc = free_address();
    let b_p2p = free_address();
    let b_rpc = free_address();
    let c_p2p = free_address();
    let c_rpc = free_address();
    let a_node = start_node(&a, &a_p2p, &a_rpc, &[], None);
    wait_for_status(&a_rpc, |_| true);
    let b_node = start_node(&b, &b_p2p, &b_rpc, &[&a_p2p], None);
    wait_for_status(&b_rpc, |_| true);
    let c_node = start_node(&c, &c_p2p, &c_rpc, &[&b_p2p], None);
    let synced = wait_for_status(&c_rpc, |status| status["tip_height"] == 1);
    let expected_tip = synced["tip_hash"].clone();

    drop(c_node);
    let c_node = start_node(&c, &c_p2p, &c_rpc, &[&b_p2p], None);
    wait_for_status(&c_rpc, |status| {
        status["tip_height"] == 1 && status["tip_hash"] == expected_tip
    });

    drop(c_node);
    drop(b_node);
    drop(a_node);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn lower_work_node_reorgs_to_a_longer_valid_fork() {
    let root = temp_root("higher-work-reorg");
    let common = root.join("common");
    let weaker = root.join("weaker");
    let stronger = root.join("stronger");
    mine(&common, 1);
    copy_tree(&common, &weaker);
    copy_tree(&common, &stronger);
    mine(&weaker, 1);
    mine(&stronger, 2);

    let strong_p2p = free_address();
    let strong_rpc = free_address();
    let weak_p2p = free_address();
    let weak_rpc = free_address();
    let strong_node = start_node(&stronger, &strong_p2p, &strong_rpc, &[], None);
    let expected = wait_for_status(&strong_rpc, |status| status["tip_height"] == 3);
    let expected_tip = expected["tip_hash"].clone();
    let weak_node = start_node(&weaker, &weak_p2p, &weak_rpc, &[&strong_p2p], None);

    wait_for_status(&weak_rpc, |status| {
        status["tip_height"] == 3 && status["tip_hash"] == expected_tip
    });

    drop(weak_node);
    drop(strong_node);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn stronger_outbound_node_makes_weaker_inbound_node_reorg() {
    let root = temp_root("reverse-higher-work-reorg");
    let common = root.join("common");
    let weaker = root.join("weaker");
    let stronger = root.join("stronger");
    mine(&common, 1);
    copy_tree(&common, &weaker);
    copy_tree(&common, &stronger);
    mine(&weaker, 1);
    mine(&stronger, 2);

    let weak_p2p = free_address();
    let weak_rpc = free_address();
    let strong_p2p = free_address();
    let strong_rpc = free_address();
    let weak_node = start_node(&weaker, &weak_p2p, &weak_rpc, &[], None);
    wait_for_status(&weak_rpc, |status| status["tip_height"] == 2);
    let strong_node = start_node(&stronger, &strong_p2p, &strong_rpc, &[&weak_p2p], None);
    let expected = wait_for_status(&strong_rpc, |status| status["tip_height"] == 3);
    let expected_tip = expected["tip_hash"].clone();

    wait_for_status(&weak_rpc, |status| {
        status["tip_height"] == 3 && status["tip_hash"] == expected_tip
    });

    drop(strong_node);
    drop(weak_node);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn signed_wallet_transaction_gossips_is_mined_and_survives_restart() {
    let root = temp_root("signed-transaction");
    let a = root.join("a");
    let b = root.join("b");
    let c = root.join("c");
    let mature_chain = std::env::var_os("XPARQ_E2E_MATURE_CHAIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join(MATURE_FIXTURE));
    assert!(
        mature_chain.join("xparq.redb").is_file(),
        "missing mature E2E fixture at {}",
        mature_chain.display()
    );
    copy_tree(&mature_chain, &a);

    let a_p2p = free_address();
    let a_rpc = free_address();
    let b_p2p = free_address();
    let b_rpc = free_address();
    let c_p2p = free_address();
    let c_rpc = free_address();
    let mut a_node = start_node(&a, &a_p2p, &a_rpc, &[], None);
    wait_for_status(&a_rpc, |status| status["tip_height"] == 51);
    let b_node = start_node(&b, &b_p2p, &b_rpc, &[&a_p2p], None);
    wait_for_status(&b_rpc, |status| status["tip_height"] == 51);
    let mut c_node = start_node(&c, &c_p2p, &c_rpc, &[&b_p2p], None);
    wait_for_status(&c_rpc, |status| status["tip_height"] == 51);

    let sender = sender_wallet();
    let sender_address = address_to_string(&sender.address);
    let recipient_keys = keypair_from_seed(&[43; 32]);
    let recipient = address_from_public_key(&recipient_keys.public_key);
    let recipient_address = address_to_string(&recipient);
    let sender_account = account(&a_rpc, &sender_address).unwrap();
    let input = sender_account["utxos"]
        .as_array()
        .unwrap()
        .iter()
        .find(|utxo| utxo["spendable_height"].as_u64().unwrap() <= 52)
        .expect("mature miner reward is missing");
    let input_id: CoinId = input["id"].as_str().unwrap().parse().unwrap();
    let input_amount = input["amount"].as_u64().unwrap();
    let sent = Amount(1);
    let intent = OnChainSpendIntent::new(
        sender.address,
        vec![input_id],
        vec![
            SpendOutput::new(recipient, sent),
            SpendOutput::new(sender.address, Amount(input_amount - sent.0)),
        ],
        100,
    )
    .unwrap();
    let transaction =
        AuthorizedTransaction::OnChainSpend(Box::new(sender.sign_onchain_spend(intent).unwrap()));
    let submitted = post_transaction(&a_rpc, &transaction);
    assert_eq!(
        submitted["transaction_id"],
        hex::encode(transaction.id().unwrap())
    );

    wait_for_status(&c_rpc, |_| {
        account(&c_rpc, &sender_address).is_ok_and(|account| {
            account["utxos"]
                .as_array()
                .is_some_and(|utxos| utxos.iter().any(|utxo| utxo["reserved"] == true))
        })
    });

    drop(a_node);
    mine(&a, 1);
    a_node = start_node(&a, &a_p2p, &a_rpc, &[], None);
    wait_for_status(&c_rpc, |_| {
        account(&c_rpc, &recipient_address).is_ok_and(|account| {
            account["total"]
                .as_u64()
                .is_some_and(|total| total >= sent.0)
        })
    });
    let included_balance = account(&c_rpc, &recipient_address).unwrap()["total"].clone();

    drop(c_node);
    c_node = start_node(&c, &c_p2p, &c_rpc, &[&b_p2p], None);
    wait_for_status(&c_rpc, |_| {
        account(&c_rpc, &recipient_address)
            .is_ok_and(|account| account["total"] == included_balance)
    });

    drop(c_node);
    drop(b_node);
    drop(a_node);
    fs::remove_dir_all(root).unwrap();
}
