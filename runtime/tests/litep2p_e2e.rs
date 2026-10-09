//! Opt-in devnet transport lifecycle; legacy TCP tests remain separate.
#![cfg(feature = "litep2p-devnet")]

include!("support/litep2p_process.rs");

#[test]
fn litep2p_three_node_transaction_sync_reconnect_and_restart() {
    let root = temp_root("litep2p-signed-transaction");
    let a = root.join("a");
    let b = root.join("b");
    let c = root.join("c");

    let a_p2p = free_address();
    let a_rpc = free_address();
    let b_p2p = free_address();
    let b_rpc = free_address();
    let c_p2p = free_address();
    let c_rpc = free_address();
    mine(&a, 2);
    let mut a_node = start_node(&a, &a_p2p, &a_rpc, &[], None);
    wait_for_status(&a_rpc, |status| status["tip_height"] == 2);
    let a_peer = peer_endpoint(&a, &a_p2p);
    let b_node = start_node(&b, &b_p2p, &b_rpc, &[&a_peer], None);
    wait_for_status(&b_rpc, |status| status["tip_height"] == 2);
    let b_peer = peer_endpoint(&b, &b_p2p);
    let mut c_node = start_node(&c, &c_p2p, &c_rpc, &[&b_peer], None);
    wait_for_status(&c_rpc, |status| status["tip_height"] == 2);

    let sender = sender_wallet();
    let sender_program_id = program_id_to_string(&sender.program_id);
    let recipient_keys = SigningSeed::new(Signature::MlDsa44, Box::new([43; 32]));
    let recipient = program_id_from_public_key(&recipient_keys.public_key()).unwrap();
    let recipient_address = program_id_to_string(&recipient);
    let sender_account = account(&a_rpc, &sender_program_id).unwrap();
    let available = sender_account["utxos"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|utxo| !utxo["reserved"].as_bool().unwrap_or(false))
        .collect::<Vec<_>>();
    let input = available
        .first()
        .expect("available miner reward is missing");
    let input_id: CoinShare = input["id"].as_str().unwrap().parse().unwrap();
    let input_amount = input["amount"].as_u64().unwrap();
    let sent = Zeno::from_zeno(1);
    let state_burn = kernel::consensus::StateTransitionWeight {
        created_coin_utxos: 3,
        consumed_coin_utxos: 1,
        ..kernel::consensus::StateTransitionWeight::default()
    }
    .state_growth_burn()
    .unwrap();
    // Both canonical history burn and relay fee depend on the signed size.
    let mut archival_bytes = 0;
    let transaction = loop {
        let burn = state_burn.as_zeno() + archival_bytes;
        let intent = CoinTransition::coin_with_charges(
            sender.program_id,
            vec![input_id],
            vec![
                CoinOutput::new(recipient, sent),
                CoinOutput::new(
                    sender.program_id,
                    Zeno::from_zeno(input_amount - sent.as_zeno() - burn - archival_bytes.max(1)),
                ),
            ],
            kernel::program::CoinCharges::new(Zeno::from_zeno(archival_bytes.max(1))),
        )
        .unwrap();
        let transaction =
            AuthorizedProgramEnvelope::Program(Box::new(sender.sign_xpq_transfer(intent).unwrap()));
        let required = (canonical_bytes(&transaction).unwrap().len() as u64)
            .checked_mul(8)
            .unwrap();
        if required == archival_bytes {
            break transaction;
        }
        archival_bytes = required;
    };
    let transaction_hash = hex::encode(transaction.id().unwrap());
    let submitted = post_transaction(&a_rpc, &transaction);
    assert_eq!(submitted["hash"], transaction_hash);

    wait_for_status(&c_rpc, |_| {
        account(&c_rpc, &sender_program_id).is_ok_and(|account| {
            account["utxos"]
                .as_array()
                .is_some_and(|utxos| utxos.iter().any(|utxo| utxo["reserved"] == true))
        })
    });

    drop(a_node);
    mine(&a, 1);
    a_node = start_node(&a, &a_p2p, &a_rpc, &[], None);
    assert_eq!(peer_endpoint(&a, &a_p2p), a_peer);
    wait_for_status(&c_rpc, |_| {
        account(&c_rpc, &recipient_address).is_ok_and(|account| {
            account["total"]
                .as_u64()
                .is_some_and(|total| u128::from(total) >= u128::from(sent.as_zeno()))
        })
    });
    let included_balance = account(&c_rpc, &recipient_address).unwrap()["total"].clone();

    drop(c_node);
    c_node = start_node(&c, &c_p2p, &c_rpc, &[&b_peer], None);
    wait_for_status(&c_rpc, |_| {
        account(&c_rpc, &recipient_address)
            .is_ok_and(|account| account["total"] == included_balance)
    });

    let transaction_response =
        http_get(&c_rpc, &format!("/explorer/transaction/{transaction_hash}"))
            .expect("transaction explorer lookup after restart");

    assert_eq!(transaction_response["hash"], transaction_hash);
    assert_eq!(transaction_response["status"], "confirmed");
    assert_eq!(transaction_response["height"], 3);

    let program_response = http_get(&c_rpc, &format!("/explorer/program/{recipient_address}"))
        .expect("address explorer lookup after restart");

    let activities = program_response["activities"]
        .as_array()
        .expect("address activities");

    assert!(
        activities.iter().any(|activity| {
            activity["hash"] == transaction_hash
                && activity["direction"] == "in"
                && activity["amount"] == sent.as_zeno()
        }),
        "recipient transaction activity was not rebuilt after restart",
    );

    drop(c_node);
    drop(b_node);
    drop(a_node);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn litep2p_reorgs_to_verified_stronger_fork() {
    let root = temp_root("litep2p-higher-work-reorg");
    let common = root.join("common");
    let weaker = root.join("weaker");
    let stronger = root.join("stronger");
    mine(&common, 1);
    copy_tree(&common, &weaker);
    copy_tree(&common, &stronger);
    let fork_keys = SigningSeed::new(Signature::MlDsa44, Box::new([91; 32]));
    let fork_miner = program_id_to_string(&program_id_from_public_key(&fork_keys.public_key()).unwrap());
    mine_to(&weaker, 1, &fork_miner);
    mine(&stronger, 2);

    let strong_p2p = free_address();
    let strong_rpc = free_address();
    let weak_p2p = free_address();
    let weak_rpc = free_address();
    let strong_node = start_node(&stronger, &strong_p2p, &strong_rpc, &[], None);
    let expected = wait_for_status(&strong_rpc, |status| status["tip_height"] == 3);
    let expected_tip = expected["tip_hash"].clone();
    let strong_peer = peer_endpoint(&stronger, &strong_p2p);
    let weak_node = start_node(&weaker, &weak_p2p, &weak_rpc, &[&strong_peer], None);

    wait_for_status(&weak_rpc, |status| {
        status["tip_height"] == 3 && status["tip_hash"] == expected_tip
    });

    drop(weak_node);
    drop(strong_node);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn litep2p_resumes_durable_prefix_against_a_newer_verified_tip() {
    use redb::{Database, ReadableDatabase, TableDefinition};
    const CANONICAL: TableDefinition<u64, &[u8]> = TableDefinition::new("canonical_blocks");
    const STAGED: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks");
    const META: TableDefinition<u8, &[u8]> = TableDefinition::new("metadata");
    let root = temp_root("litep2p-durable-resume");
    let source = root.join("source");
    let target = root.join("target");
    mine(&source, 3);
    // Seed a real mined prefix as left by an interrupted download at height two.
    // The source now advertises height three; fresh header verification must
    // reuse the matching prefix and fetch only the remaining body.
    let source_database = Database::open(source.join("xparq.redb")).unwrap();
    let read = source_database.begin_read().unwrap();
    let table = read.open_table(CANONICAL).unwrap();
    let prefix = (1..=2)
        .map(|height| table.get(height).unwrap().unwrap().value().to_vec())
        .collect::<Vec<_>>();
    drop(table);
    drop(read);
    drop(source_database);
    fs::create_dir_all(&target).unwrap();
    let stage = Database::create(target.join("litep2p-sync.redb")).unwrap();
    let mut identity = kernel::genesis::EXPECTED_GENESIS_HASH.0.to_vec();
    identity.extend_from_slice(&kernel::genesis::chain_spec_hash().unwrap().0);
    let branch = canonical_bytes(&(identity, kernel::genesis::EXPECTED_GENESIS_HASH)).unwrap();
    let write = stage.begin_write().unwrap();
    write
        .open_table(META)
        .unwrap()
        .insert(0, branch.as_slice())
        .unwrap();
    {
        let mut table = write.open_table(STAGED).unwrap();
        for (index, bytes) in prefix.iter().enumerate() {
            table.insert(index as u64, bytes.as_slice()).unwrap();
        }
    }
    write.commit().unwrap();
    drop(stage);
    let source_p2p = free_address();
    let source_rpc = free_address();
    let target_p2p = free_address();
    let target_rpc = free_address();
    let source_node = start_node(&source, &source_p2p, &source_rpc, &[], None);
    let expected = wait_for_status(&source_rpc, |status| status["tip_height"] == 3);
    let peer = peer_endpoint(&source, &source_p2p);
    let target_node = start_node(&target, &target_p2p, &target_rpc, &[&peer], None);
    wait_for_status(&target_rpc, |status| {
        status["tip_hash"] == expected["tip_hash"]
    });
    let log = fs::read_to_string(target.with_extension("litep2p.log")).unwrap();
    assert!(
        log.contains("staged_blocks=2 staged_bytes="),
        "prefix was not resumed: {log}"
    );
    drop(target_node);
    let target_node = start_node(&target, &target_p2p, &target_rpc, &[], None);
    wait_for_status(&target_rpc, |status| {
        status["tip_hash"] == expected["tip_hash"]
    });
    drop(target_node);
    drop(source_node);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn litep2p_fails_over_from_stalled_peer_and_reuses_its_committed_body() {
    let root = temp_root("litep2p-stalled-peer-failover");
    let a = root.join("a");
    let b = root.join("b");
    let target = root.join("target");
    mine(&a, 3);
    // Copy canonical history before either source creates its transport identity.
    copy_tree(&a, &b);
    let a_p2p = free_address();
    let a_rpc = free_address();
    let b_p2p = free_address();
    let b_rpc = free_address();
    let target_p2p = free_address();
    let target_rpc = free_address();
    let a_node = start_node(&a, &a_p2p, &a_rpc, &[], None);
    let expected = wait_for_status(&a_rpc, |status| status["tip_height"] == 3);
    let a_peer = peer_endpoint(&a, &a_p2p);
    let target_node = start_node(&target, &target_p2p, &target_rpc, &[&a_peer], None);
    let target_peer = peer_endpoint(&target, &target_p2p);
    let deadline = Instant::now() + WAIT;
    loop {
        let log = fs::read_to_string(target.with_extension("litep2p.log")).unwrap_or_default();
        if log.contains("downloaded_blocks=1") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "first body was not staged: {log}"
        );
        thread::sleep(Duration::from_millis(5));
    }
    // Freeze the actual source process while keeping its transport connected.
    // The target must time out its next request and choose the other peer.
    assert!(
        Command::new("kill")
            .args(["-STOP", &a_node.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(status(&target_rpc).unwrap()["tip_height"], 0);
    let b_node = start_node(&b, &b_p2p, &b_rpc, &[&target_peer], None);
    let b_peer = peer_endpoint(&b, &b_p2p);
    assert_ne!(a_peer.split('@').nth(1), b_peer.split('@').nth(1));
    wait_for_status(&target_rpc, |status| {
        status["tip_hash"] == expected["tip_hash"]
    });
    let log = fs::read_to_string(target.with_extension("litep2p.log")).unwrap();
    let b_id = b_peer.split('@').nth(1).unwrap();
    let resumed = log
        .lines()
        .find_map(|line| {
            line.strip_prefix(&format!("litep2p: peer={b_id} staged_blocks="))
                .and_then(|tail| tail.split_whitespace().next())
                .and_then(|count| count.parse::<usize>().ok())
        })
        .expect("replacement peer did not open staging");
    assert!(
        (1..3).contains(&resumed),
        "expected an incomplete durable prefix: {log}"
    );
    assert_eq!(
        account(&target_rpc, &miner_program_id()).unwrap()["total"],
        account(&b_rpc, &miner_program_id()).unwrap()["total"]
    );
    drop(target_node);
    let target_node = start_node(&target, &target_p2p, &target_rpc, &[], None);
    wait_for_status(&target_rpc, |status| {
        status["tip_hash"] == expected["tip_hash"]
    });
    drop(target_node);
    drop(b_node);
    drop(a_node);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn litep2p_hostname_bootstrap_discovers_peer_and_reconnects_without_bootstrap_after_restart() {
    let root = temp_root("litep2p-discovery-bootstrap-restart");
    let bootstrap = root.join("bootstrap");
    let source = root.join("source");
    let target = root.join("target");
    mine(&source, 2);
    let source_p2p = free_address();
    let source_rpc = free_address();
    let bootstrap_p2p = free_address();
    let bootstrap_rpc = free_address();
    let target_p2p = free_address();
    let target_rpc = free_address();
    let mut source_node =
        start_node_with_discovery(&source, &source_p2p, &source_rpc, &[], None, true);
    let source_peer = peer_endpoint(&source, &source_p2p);
    let source_id = source_peer.split('@').nth(1).unwrap();
    let hostname_bootstrap = format!(
        "localhost:{}@{source_id}",
        source_p2p.rsplit(':').next().unwrap()
    );
    let bootstrap_node = start_node_with_discovery(
        &bootstrap,
        &bootstrap_p2p,
        &bootstrap_rpc,
        &[&hostname_bootstrap],
        None,
        true,
    );
    wait_for_status(&bootstrap_rpc, |status| status["tip_height"] == 2);
    let bootstrap_peer = peer_endpoint(&bootstrap, &bootstrap_p2p);
    let target_node = start_node_with_discovery(
        &target,
        &target_p2p,
        &target_rpc,
        &[&bootstrap_peer],
        None,
        true,
    );
    let deadline = Instant::now() + WAIT;
    loop {
        let log = fs::read_to_string(target.with_extension("litep2p.log")).unwrap_or_default();
        if log.contains(&format!("peer store saved endpoint={hostname_bootstrap}")) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "discovered source was not verified and saved: {log}"
        );
        thread::sleep(Duration::from_millis(50));
    }
    wait_for_status(&target_rpc, |status| status["tip_height"] == 2);
    drop(target_node);
    drop(bootstrap_node);
    drop(source_node);
    mine(&source, 1);
    source_node = start_node_with_discovery(&source, &source_p2p, &source_rpc, &[], None, true);
    let expected = wait_for_status(&source_rpc, |status| status["tip_height"] == 3);
    // No --peer arguments: the bootstrap is down and target loads the verified source.
    let target_node = start_node_with_discovery(&target, &target_p2p, &target_rpc, &[], None, true);
    wait_for_status(&target_rpc, |status| {
        status["tip_hash"] == expected["tip_hash"]
    });
    drop(target_node);
    drop(source_node);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn litep2p_rejects_bad_handshakes_and_recovers_after_pending_socket_exhaustion() {
    use futures::StreamExt;
    use litep2p::{
        Litep2p, Litep2pEvent,
        config::ConfigBuilder,
        protocol::notification::{
            ConfigBuilder as NotificationBuilder, NotificationEvent, ValidationResult,
        },
        transport::tcp::config::Config as TcpConfig,
        types::protocol::ProtocolName,
    };
    let root = temp_root("litep2p-handshake-admission");
    fs::create_dir_all(&root).unwrap();
    let database = root.join("server");
    let p2p = free_address();
    let rpc = free_address();
    let server = start_node(&database, &p2p, &rpc, &[], None);
    wait_for_status(&rpc, |_| true);

    // Silent clients consume transport negotiation slots, not established peers.
    let mut sockets: Vec<_> = (0..16).map(|_| TcpStream::connect(&p2p).unwrap()).collect();
    thread::sleep(Duration::from_millis(200));
    let mut rejected = 0;
    for socket in &mut sockets {
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        loop {
            let mut buffer = [0; 128];
            match socket.read(&mut buffer) {
                Ok(0) => {
                    rejected += 1;
                    break;
                }
                Ok(_) => continue,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                    ) =>
                {
                    rejected += 1;
                    break;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    break;
                }
                Err(error) => panic!("unexpected stalled socket error: {error}"),
            }
        }
    }
    assert!(
        rejected >= 8,
        "pending socket cap did not reject excess clients: {rejected}"
    );
    // Keep admitted clients open beyond the configured transport deadline.
    thread::sleep(Duration::from_secs(6));

    let endpoint: litep2p::types::multiaddr::Multiaddr = format!(
        "/ip4/127.0.0.1/tcp/{}/p2p/{}",
        p2p.split(':').next_back().unwrap(),
        peer_endpoint(&database, &p2p)
            .split('@')
            .next_back()
            .unwrap()
    )
    .parse()
    .unwrap();
    let mut identity = kernel::genesis::EXPECTED_GENESIS_HASH.0.to_vec();
    identity.extend_from_slice(&kernel::genesis::chain_spec_hash().unwrap().0);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        // Different chain, overlong frame, and unknown protocol must all fail.
        for (handshake, protocol, withhold_validation, expect_accept) in [
            (vec![0; 64], "/xparq/devnet/announce/2", false, false),
            (vec![0; 65], "/xparq/devnet/announce/2", false, false),
            (identity.clone(), "/xparq/devnet/announce/999", false, false),
            (identity.clone(), "/xparq/devnet/announce/2", true, false),
            (identity.clone(), "/xparq/devnet/announce/2", false, true),
        ] {
            let (config, mut notifications) = NotificationBuilder::new(ProtocolName::from(protocol))
                .with_max_size(2 * 1024 * 1024)
                .with_auto_accept_inbound(false)
                .with_handshake(handshake)
                .build();
            let mut network = Litep2p::new(ConfigBuilder::new()
                .with_tcp(TcpConfig { listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()], ..Default::default() })
                .with_notification_protocol(config).build()).unwrap();
            network.dial_address(endpoint.clone()).await.unwrap();
            let opened = tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    tokio::select! {
                        event = network.next_event() => match event {
                            Some(Litep2pEvent::ConnectionEstablished { peer, .. }) => { notifications.open_substream(peer).await.unwrap(); }
                            Some(Litep2pEvent::DialFailure { .. }) => return false,
                            None => panic!("transport event stream closed"),
                            _ => {}
                        },
                        event = notifications.next() => match event {
                            Some(NotificationEvent::ValidateSubstream { peer, .. }) => {
                                if !withhold_validation {
                                    notifications.send_validation_result(peer, ValidationResult::Accept);
                                }
                            },
                            Some(NotificationEvent::NotificationStreamOpened { .. }) => return true,
                            Some(NotificationEvent::NotificationStreamOpenFailure { .. }) => return false,
                            None => panic!("notification event stream closed"),
                            _ => {}
                        }
                    }
                }
            }).await.expect("handshake did not complete or reject before deadline");
            assert_eq!(opened, expect_accept, "unexpected handshake result for {protocol}");
        }
    });
    drop(sockets);
    drop(server);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn litep2p_healthy_peer_syncs_while_another_peer_floods_requests() {
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
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    };
    let root = temp_root("litep2p-fair-request-service");
    let source = root.join("source");
    let target = root.join("target");
    mine(&source, 2);
    let source_p2p = free_address();
    let source_rpc = free_address();
    let source_node = start_node(&source, &source_p2p, &source_rpc, &[], None);
    wait_for_status(&source_rpc, |status| status["tip_height"] == 2);
    let source_peer = peer_endpoint(&source, &source_p2p);
    let endpoint = format!(
        "/ip4/127.0.0.1/tcp/{}/p2p/{}",
        source_p2p.rsplit(':').next().unwrap(),
        source_peer.rsplit('@').next().unwrap()
    );
    let mut identity = kernel::genesis::EXPECTED_GENESIS_HASH.0.to_vec();
    identity.extend_from_slice(&kernel::genesis::chain_spec_hash().unwrap().0);
    let stop = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicUsize::new(0));
    let (ready_tx, ready_rx) = mpsc::channel();
    let flood_stop = stop.clone();
    let flood_attempts = attempts.clone();
    let flood = thread::spawn(move || {
        tokio::runtime::Runtime::new().unwrap().block_on(async move {
            let (notifications_config, mut notifications) = NotificationBuilder::new(ProtocolName::from("/xparq/devnet/announce/2"))
                .with_max_size(2 * 1024 * 1024).with_handshake(identity).build();
            let (request_config, mut requests) = RequestBuilder::new(ProtocolName::from("/xparq/devnet/blocks/2"))
                .with_max_size(2 * 1024 * 1024).with_timeout(Duration::from_secs(2)).build();
            let mut network = Litep2p::new(ConfigBuilder::new()
                .with_tcp(TcpConfig { listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()], ..Default::default() })
                .with_notification_protocol(notifications_config).with_request_response_protocol(request_config).build()).unwrap();
            network.dial_address(endpoint.parse().unwrap()).await.unwrap();
            let mut peer = None; let mut active = std::collections::HashSet::new();
            let mut ticker = tokio::time::interval(Duration::from_millis(10));
            let started = Instant::now();
            while !flood_stop.load(Ordering::Relaxed) && started.elapsed() < WAIT {
                tokio::select! {
                    event = network.next_event() => match event {
                        Some(Litep2pEvent::ConnectionEstablished { peer, .. }) => { notifications.open_substream(peer).await.unwrap(); }
                        None => break,
                        _ => {}
                    },
                    event = notifications.next() => match event {
                        Some(NotificationEvent::ValidateSubstream { peer, .. }) => notifications.send_validation_result(peer, ValidationResult::Accept),
                        Some(NotificationEvent::NotificationStreamOpened { peer: accepted, .. }) => { peer = Some(accepted); let _ = ready_tx.send(()); }
                        None => break,
                        _ => {}
                    },
                    event = requests.next() => match event {
                        Some(RequestResponseEvent::ResponseReceived { request_id, .. }) | Some(RequestResponseEvent::RequestFailed { request_id, .. }) => { active.remove(&request_id); }
                        Some(RequestResponseEvent::RequestReceived { request_id, .. }) => requests.reject_request(request_id),
                        None => break,
                    },
                    _ = ticker.tick() => {
                        if let Some(peer) = peer {
                            while active.len() < 8 {
                                let Ok(id) = requests.try_send_request(peer, vec![1], DialOptions::Reject) else { break; };
                                active.insert(id); flood_attempts.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
        });
    });
    ready_rx
        .recv_timeout(Duration::from_secs(15))
        .expect("flood peer handshake");
    let target_rpc = free_address();
    let target_node = start_node(&target, &free_address(), &target_rpc, &[&source_peer], None);
    wait_for_status(&target_rpc, |status| status["tip_height"] == 2);
    stop.store(true, Ordering::Relaxed);
    flood.join().unwrap();
    assert!(
        attempts.load(Ordering::Relaxed) >= 64,
        "flood did not exceed the per-peer request burst"
    );
    drop(target_node);
    drop(source_node);
    fs::remove_dir_all(root).unwrap();
}
