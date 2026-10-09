//! Explicit Linux resource experiment with consensus-valid blocks and real sockets.
#![cfg(all(feature = "litep2p-devnet", target_os = "linux"))]
#![allow(dead_code, unused_imports)]
include!("support/litep2p_process.rs");
#[path = "../src/miner.rs"]
mod miner;
mod storage {
    include!("../src/storage.rs");
    // The fixture writer and the node are different processes. Release the
    // fixture's singleton handle before the child acquires the redb file lock.
    pub(super) fn release_fixture_handle() {
        DATABASE.get().unwrap().lock().unwrap().take();
    }
}

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

struct Fixture {
    height: u64,
    bytes: usize,
    tip: String,
    hashes: Vec<[u8; 32]>,
}

fn build_fixture(path: &Path, deployments: u64) -> Fixture {
    use kernel::{
        block::{Block, Emission, block_bytes},
        common::{Height, Nonce},
        consensus::{
            apply_block, apply_genesis, expected_emission_for_height, expected_next_difficulty,
            new_pow_memory, quote_deploy_burn,
        },
        genesis::{EXPECTED_GENESIS_HASH, genesis_block},
        ledger::Ledger,
        operation::{AuthorizedDeployProgram, BlockOperation},
        program::{AccountAuthorization, CoinCharges, DeployProgram, MAX_PROGRAM_CODE_SIZE},
    };
    let seed = SigningSeed::new(
        kernel::crypto::AccountSignatureScheme::MlDsa44,
        Box::new([0x73; 32]),
    );
    let owner = program_id_from_public_key(&seed.public_key()).unwrap();
    let context = kernel::genesis::chain_context().unwrap();
    let genesis = genesis_block().unwrap();
    let mut ledger = Ledger::new().with_applications(extension::SystemApplications);
    apply_genesis(&mut ledger, genesis, EXPECTED_GENESIS_HASH).unwrap();
    let mut memory = new_pow_memory();
    let mut hashes = Vec::new();
    for number in 1..=deployments + 1 {
        let height = Height(number);
        let mut operations = Vec::new();
        if number > 1 {
            let (input, coin) = ledger
                .state()
                .utxos()
                .coins()
                .find(|(_, coin)| {
                    coin.owner == kernel::common::Owner::Program(owner)
                        && coin.amount.as_zeno() > 50_000_000
                })
                .expect("fixture deployment funding");
            let amount = coin.amount.as_zeno();
            // A valid straight-line XPVM program, with nops before const/return.
            // Deployment validates code; it does not execute its million nops.
            let mut code = b"XPVM".to_vec();
            code.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0, 0]);
            code.resize(MAX_PROGRAM_CODE_SIZE - 10, 0);
            code.push(1);
            code.extend_from_slice(&(number as i64).to_le_bytes());
            code.push(3);
            let deploy = DeployProgram {
                owner,
                nonce: number,
                code: code.into(),
            };
            deploy.validate_structure().unwrap();
            let make = |burn: u64| {
                let payment = CoinTransition::coin_with_charges(
                    owner,
                    vec![input],
                    vec![CoinOutput::new(
                        owner,
                        Zeno::from_zeno(amount - burn - 100_000),
                    )],
                    CoinCharges::new(Zeno::from_zeno(100_000)),
                )
                .unwrap();
                let mut signed = AuthorizedDeployProgram {
                    deploy: deploy.clone(),
                    payment,
                    authorization: AccountAuthorization {
                        salt: [0; 32],
                        public_key: seed.public_key(),
                        signature: seed.sign(&[0; kernel::crypto::HASH_SIZE]),
                    },
                };
                signed.authorization.signature =
                    seed.sign(signed.commitment(context).unwrap().as_bytes());
                signed
            };
            let (_, burn) = quote_deploy_burn(&make(0), height, ledger.state()).unwrap();
            operations.push(BlockOperation::DeployProgram(Box::new(make(
                burn.as_zeno(),
            ))));
        }
        let mut block = Block::from_protocol_operations(
            height,
            ledger.tip_hash().unwrap(),
            expected_next_difficulty(&ledger.chain).unwrap(),
            Nonce(0),
            Some(Emission::new(owner, expected_emission_for_height(height))),
            operations,
        )
        .unwrap();
        let (root, weight) = ledger.preview_block_commitments(&block).unwrap();
        block.set_state_root(root);
        block.set_block_weight(weight);
        let mut nonce = 0;
        loop {
            if miner::mine_range(
                &mut block,
                miner::MiningRange {
                    start_nonce: nonce,
                    attempts: 1000,
                },
                &mut memory,
            )
            .unwrap()
            .is_some()
            {
                break;
            }
            nonce += 1000;
        }
        apply_block(&mut ledger, block.clone()).unwrap();
        if number > 1 {
            hashes.push(block.hash().unwrap().0);
        }
        if number % 8 == 0 {
            eprintln!("stress fixture: validated height {number}");
        }
    }
    let bytes = ledger
        .chain
        .blocks()
        .map(|block| block_bytes(block).unwrap().len())
        .sum();
    storage::replace_blocks_and_mempool_stream(
        path,
        || {
            ledger.chain.blocks().map(|block| {
                Ok(storage::StoredCanonicalBlock {
                    height: block.height().0,
                    hash: block.hash().unwrap().0,
                    bytes: block_bytes(block).unwrap(),
                    transactions: vec![],
                    activities: vec![],
                })
            })
        },
        &[],
    )
    .unwrap();
    storage::release_fixture_handle();
    Fixture {
        height: deployments + 1,
        bytes,
        tip: hex::encode(ledger.tip_hash().unwrap().0),
        hashes,
    }
}

#[derive(Default)]
struct FloodCounts {
    attempts: AtomicU64,
    responses: AtomicU64,
    failures: AtomicU64,
    response_bytes: AtomicU64,
}
struct FloodGroup {
    stop: Arc<AtomicBool>,
    threads: Vec<thread::JoinHandle<()>>,
    counts: Arc<Vec<FloodCounts>>,
}
impl Drop for FloodGroup {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
    }
}
impl FloodGroup {
    fn start(endpoint: String, hashes: Vec<[u8; 32]>, peers: usize) -> Self {
        use futures::StreamExt;
        use litep2p::{
            Litep2p, Litep2pEvent,
            config::ConfigBuilder,
            protocol::{
                notification::{
                    ConfigBuilder as NotificationBuilder, NotificationEvent, ValidationResult,
                },
                request_response::{
                    ConfigBuilder as RequestBuilder, DialOptions, RequestResponseEvent,
                },
            },
            transport::tcp::config::Config as TcpConfig,
            types::protocol::ProtocolName,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let counts = Arc::new(
            (0..peers)
                .map(|_| FloodCounts::default())
                .collect::<Vec<_>>(),
        );
        let mut threads = Vec::new();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        for index in 0..peers {
            let stop = stop.clone();
            let counts = counts.clone();
            let ready_tx = ready_tx.clone();
            let endpoint = endpoint.clone();
            let hashes = hashes.clone();
            threads.push(thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async move {
                    let counts = &counts[index];
                    let mut identity = kernel::genesis::EXPECTED_GENESIS_HASH.0.to_vec();
                    identity.extend_from_slice(&kernel::genesis::chain_spec_hash().unwrap().0);
                    let (config, mut notifications) = NotificationBuilder::new(ProtocolName::from("/xparq/devnet/announce/2"))
                        .with_max_size(2 * 1024 * 1024).with_handshake(identity).build();
                    let (request_config, mut requests) = RequestBuilder::new(ProtocolName::from("/xparq/devnet/blocks/2"))
                        .with_max_size(2 * 1024 * 1024 + 1025).with_timeout(Duration::from_secs(5)).build();
                    let mut network = Litep2p::new(ConfigBuilder::new()
                        .with_tcp(TcpConfig { listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()], ..Default::default() })
                        .with_notification_protocol(config).with_request_response_protocol(request_config).build()).unwrap();
                    network.dial_address(endpoint.parse().unwrap()).await.unwrap();
                    let mut peer = None; let mut active = std::collections::HashSet::new();
                    let mut sequence = index; let mut ticker = tokio::time::interval(Duration::from_millis(10));
                    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    while !stop.load(Ordering::Relaxed) {
                        tokio::select! {
                            event = network.next_event() => match event {
                                Some(Litep2pEvent::ConnectionEstablished { peer, .. }) => { let _ = notifications.open_substream(peer).await; }
                                None => break, _ => {}
                            },
                            event = notifications.next() => match event {
                                Some(NotificationEvent::ValidateSubstream { peer, .. }) => notifications.send_validation_result(peer, ValidationResult::Accept),
                                Some(NotificationEvent::NotificationStreamOpened { peer: accepted, .. }) => { peer = Some(accepted); let _ = ready_tx.send(index); }
                                Some(NotificationEvent::NotificationStreamClosed { .. }) => break,
                                None => break, _ => {}
                            },
                            event = requests.next() => match event {
                                Some(RequestResponseEvent::ResponseReceived { request_id, response, .. }) => {
                                    active.remove(&request_id); counts.responses.fetch_add(1, Ordering::Relaxed);
                                    counts.response_bytes.fetch_add(response.len() as u64, Ordering::Relaxed);
                                },
                                Some(RequestResponseEvent::RequestFailed { request_id, .. }) => { active.remove(&request_id); counts.failures.fetch_add(1, Ordering::Relaxed); },
                                Some(RequestResponseEvent::RequestReceived { request_id, .. }) => requests.reject_request(request_id),
                                None => break,
                            },
                            _ = ticker.tick() => if let Some(peer) = peer {
                                while active.len() < 8 {
                                    let mut payload = vec![2]; // REQUEST_BLOCK, full-size valid stored body.
                                    payload.extend_from_slice(&hashes[sequence % hashes.len()]); sequence += 1;
                                    let Ok(id) = requests.try_send_request(peer, payload, DialOptions::Reject) else { break; };
                                    active.insert(id); counts.attempts.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                });
            }));
        }
        drop(ready_tx);
        let group = Self {
            stop,
            counts,
            threads,
        };
        let mut identities = std::collections::HashSet::new();
        while identities.len() < peers {
            identities.insert(
                ready_rx
                    .recv_timeout(Duration::from_secs(30))
                    .expect("flood peer handshake"),
            );
        }
        group
    }
}

fn process_usage(pid: u32) -> (u64, u64) {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).expect("node process status");
    let rss = status
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse::<u64>().ok())
        })
        .expect("resident memory measurement");
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    let cpu = fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap();
    (rss * 1024, cpu)
}

struct UsageSampler {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Drop for UsageSampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.thread.take() {
            // Cleanup must not cause a second panic while unwinding a failed test.
            let _ = handle.join();
        }
    }
}
impl UsageSampler {
    fn finish(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.thread.take() {
            handle.join().expect("resource sampler failed");
        }
    }

    fn start(path: &Path, source: u32, target: u32, ticks: u64) -> Self {
        let mut file = fs::File::create(path).unwrap();
        writeln!(file, "elapsed_seconds,source_rss_bytes,target_rss_bytes,source_cpu_seconds,target_cpu_seconds").unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let running = stop.clone();
        let handle = thread::spawn(move || {
            let begin = Instant::now();
            let source_start = process_usage(source).1;
            let target_start = process_usage(target).1;
            while !running.load(Ordering::Relaxed) {
                let (source_rss, source_cpu) = process_usage(source);
                let (target_rss, target_cpu) = process_usage(target);
                writeln!(
                    file,
                    "{:.3},{source_rss},{target_rss},{:.3},{:.3}",
                    begin.elapsed().as_secs_f64(),
                    (source_cpu - source_start) as f64 / ticks as f64,
                    (target_cpu - target_start) as f64 / ticks as f64
                )
                .unwrap();
                file.flush().unwrap();
                thread::sleep(Duration::from_millis(200));
            }
        });
        Self {
            stop,
            thread: Some(handle),
        }
    }
}

fn summarize_usage(path: &Path, elapsed: f64) -> Value {
    let rows: Vec<Vec<f64>> = fs::read_to_string(path)
        .unwrap()
        .lines()
        .skip(1)
        .map(|line| line.split(',').map(|cell| cell.parse().unwrap()).collect())
        .collect();
    assert!(
        !rows.is_empty(),
        "resource sampler produced no observations"
    );
    let last = rows.last().unwrap();
    serde_json::json!({"samples": rows.len(),
        "source_peak_sampled_rss_bytes": rows.iter().map(|row| row[1] as u64).max().unwrap(),
        "target_peak_sampled_rss_bytes": rows.iter().map(|row| row[2] as u64).max().unwrap(),
        "source_cpu_seconds": last[3], "target_cpu_seconds": last[4],
        "source_average_cpu_percent": last[3] / elapsed * 100.0,
        "target_average_cpu_percent": last[4] / elapsed * 100.0})
}

fn stress_wait(
    node: &mut NodeProcess,
    rpc: &str,
    height: u64,
    tip: &str,
    timeout: Duration,
) -> Value {
    let begin = Instant::now();
    loop {
        assert!(
            node.0.try_wait().unwrap().is_none(),
            "node exited before reaching the expected canonical tip; inspect stress artifacts"
        );
        if let Ok(value) = status(rpc)
            && value["tip_height"] == height
            && value["tip_hash"] == tip
        {
            return value;
        }
        assert!(
            begin.elapsed() < timeout,
            "large sync failed within {timeout:?}; inspect retained stress artifacts"
        );
        thread::sleep(Duration::from_millis(200));
    }
}

#[test]
#[ignore = "explicit Linux load experiment: mines and transfers over 64 MiB; retains resource artifacts"]
fn large_valid_sync_under_multiple_request_flooders() {
    let root = temp_root("litep2p-stress");
    fs::create_dir_all(&root).unwrap();
    eprintln!("stress artifacts: {}", root.display());
    let deployments: u64 = std::env::var("XPARQ_STRESS_DEPLOYMENTS")
        .unwrap_or_else(|_| "65".into())
        .parse()
        .unwrap();
    assert!(
        (65..=256).contains(&deployments),
        "deployment count must be 65 through 256"
    );
    let timeout = Duration::from_secs(
        std::env::var("XPARQ_STRESS_TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "900".into())
            .parse()
            .unwrap(),
    );
    let ticks: u64 = String::from_utf8(
        Command::new("getconf")
            .arg("CLK_TCK")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .parse()
    .unwrap();
    assert!(ticks > 0);
    fs::write(
        root.join("configuration.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "deployments": deployments, "scenario_timeout_seconds": timeout.as_secs(),
            "cpu_ticks_per_second": ticks, "sampling_interval_ms": 200,
            "debug_assertions": cfg!(debug_assertions), "os": std::env::consts::OS,
            "architecture": std::env::consts::ARCH, "flood_identities": 4,
            "requests_in_flight_per_flood_identity": 8
        }))
        .unwrap(),
    )
    .unwrap();
    let source = root.join("source");
    let fixture = build_fixture(&source, deployments);
    assert!(fixture.bytes > 64 * 1024 * 1024);
    let source_p2p = free_address();
    let source_rpc = free_address();
    let mut source_node = start_node(&source, &source_p2p, &source_rpc, &[], None);
    let source_status = stress_wait(
        &mut source_node,
        &source_rpc,
        fixture.height,
        &fixture.tip,
        timeout,
    );
    let source_peer = peer_endpoint(&source, &source_p2p);
    let endpoint = format!(
        "/ip4/127.0.0.1/tcp/{}/p2p/{}",
        source_p2p.rsplit(':').next().unwrap(),
        source_peer.rsplit('@').next().unwrap()
    );
    let mut reports = Vec::new();
    let mut reference: Option<Value> = None;
    for flooded in [false, true] {
        let label = if flooded { "four-flooders" } else { "baseline" };
        let flood = flooded.then(|| FloodGroup::start(endpoint.clone(), fixture.hashes.clone(), 4));
        let target = root.join(label);
        let rpc = free_address();
        let mut target_node = start_node(&target, &free_address(), &rpc, &[&source_peer], None);
        let sampler = UsageSampler::start(
            &root.join(format!("{label}.csv")),
            source_node.0.id(),
            target_node.0.id(),
            ticks,
        );
        let started = Instant::now();
        let result = stress_wait(
            &mut target_node,
            &rpc,
            fixture.height,
            &fixture.tip,
            timeout,
        );
        let elapsed = started.elapsed().as_secs_f64();
        sampler.finish();
        for key in [
            "tip_hash",
            "tip_height",
            "cumulative_work",
            "cumulative_weight",
            "total_mined",
            "total_burned",
            "supply",
        ] {
            if let Some(ref expected) = reference {
                assert_eq!(
                    result[key], expected[key],
                    "canonical {key} differs under load"
                );
            }
        }
        for key in [
            "tip_hash",
            "tip_height",
            "cumulative_work",
            "cumulative_weight",
            "total_mined",
            "total_burned",
            "supply",
        ] {
            assert_eq!(
                result[key], source_status[key],
                "source and target canonical {key} differ"
            );
        }
        reference = Some(result.clone());
        let mut report =
            serde_json::json!({"scenario": label, "sync_seconds": elapsed, "status": result});
        if let Some(ref flood) = flood {
            let peer_reports: Vec<_> = flood.counts.iter().enumerate().map(|(index, counts)| {
                let attempts = counts.attempts.load(Ordering::Relaxed);
                let responses = counts.responses.load(Ordering::Relaxed);
                assert!(attempts >= 64, "flood identity {index} did not exercise its burst");
                assert!(responses > 0, "flood identity {index} received no valid responses");
                serde_json::json!({"identity_index": index, "attempts": attempts, "responses": responses,
                    "failures": counts.failures.load(Ordering::Relaxed),
                    "response_payload_bytes": counts.response_bytes.load(Ordering::Relaxed)})
            }).collect();
            let bytes: u64 = flood
                .counts
                .iter()
                .map(|counts| counts.response_bytes.load(Ordering::Relaxed))
                .sum();
            assert!(
                bytes > 16 * 1024 * 1024,
                "load did not transfer full block responses"
            );
            report["flood"] = serde_json::json!({"identities": 4, "per_peer": peer_reports});
        }
        drop(flood);
        drop(target_node);
        // A peer-less restart must replay the downloaded canonical bodies successfully.
        let restarted_rpc = free_address();
        let mut restarted = start_node(&target, &free_address(), &restarted_rpc, &[], None);
        let replay = stress_wait(
            &mut restarted,
            &restarted_rpc,
            fixture.height,
            &fixture.tip,
            timeout,
        );
        assert_eq!(replay, reference.clone().unwrap());
        drop(restarted);
        report["resources"] = summarize_usage(&root.join(format!("{label}.csv")), elapsed);
        reports.push(report);
        fs::write(
            root.join("scenarios.json"),
            serde_json::to_vec_pretty(&reports).unwrap(),
        )
        .unwrap();
    }
    drop(source_node);
    let report = serde_json::json!({"network": "localhost TCP/Noise/Yamux devnet", "blocks_after_genesis": fixture.height,
        "canonical_encoded_bytes": fixture.bytes, "deployments": deployments, "sampling_interval_ms": 200,
        "cpu_ticks_per_second": ticks, "scenarios": reports});
    fs::write(
        root.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    eprintln!("stress report: {}", root.join("report.json").display());
}
