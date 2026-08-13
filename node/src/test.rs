use super::*;

fn mine_consensus_block(mut block: xparq::block::Block) -> xparq::block::Block {
    while xparq::consensus::Consensus::validate_proof_of_work_at_difficulty(
        &block,
        block.difficulty(),
    )
    .is_err()
    {
        block.header.nonce = xparq::block::Nonce(block.header.nonce.0.saturating_add(1));
    }
    block
}

fn next_empty_block(
    ledger: &xparq::ledger::Ledger,
    miner: Address,
    nonce: u64,
) -> xparq::block::Block {
    next_block(ledger, miner, nonce, Vec::new())
}

fn next_block(
    ledger: &xparq::ledger::Ledger,
    miner: Address,
    nonce: u64,
    transactions: Vec<xparq::transaction::SignedProtocolTransaction>,
) -> xparq::block::Block {
    let height = Height(ledger.tip_height().unwrap().0.saturating_add(1));
    let reward = ledger.mintable_subsidy(height).unwrap();
    let mut block = xparq::block::Block::from_protocol_transactions(
        height,
        ledger.tip_hash().unwrap(),
        ledger.expected_difficulty_after_tip().unwrap(),
        xparq::block::Nonce(nonce),
        Some(xparq::block::EmissionTransaction::new(miner, reward)),
        transactions,
    )
    .unwrap();
    let preview = ledger.preview_candidate_block(&block).unwrap();
    block.set_state_root(preview.state_root_after);
    mine_consensus_block(block)
}

#[test]
fn deeper_cumulative_work_branch_replaces_locally_finalized_display_chain() {
    let mut active = xparq::genesis::genesis_ledger().unwrap();
    let mut side = active.clone();
    let mut side_blocks = Vec::new();
    let active_miner = Address([0x71; xparq::crypto::ADDRESS_SIZE]);
    let winning_miner = Address([0x15; xparq::crypto::ADDRESS_SIZE]);

    for height in 1..=6 {
        let block = next_empty_block(&active, active_miner, height);
        active.apply_block(block).unwrap();
    }
    for height in 1..=7 {
        let block = next_empty_block(&side, winning_miner, 100 + height);
        side.apply_block(block.clone()).unwrap();
        side_blocks.push(block);
    }

    let expected_tip = side.tip_hash();
    let mut node =
        runtime::node::Node::temporary(active, xparq::consensus::Consensus::with_default_config())
            .unwrap();
    for block in side_blocks {
        node.apply_block(block).unwrap();
    }

    assert_eq!(node.tip_height(), Some(Height(7)));
    assert_eq!(node.tip_hash(), expected_tip);
}

#[test]
fn protocol_event_filter_accepts_current_emission_name() {
    assert!(rpc::api::is_protocol_event_kind("emission_distributed"));
    assert!(!rpc::api::is_protocol_event_kind("coinbase_paid"));
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn canonical_height_index_stores_only_the_block_hash() {
    let storage = runtime::storage::Storage::temporary().unwrap();
    let block = xparq::genesis::genesis_block().unwrap();
    let hash = block.hash().unwrap();

    storage.save_block(&block).unwrap();

    assert_eq!(
        storage.test_blocks_by_height_value_len(Height(0)).unwrap(),
        Some(xparq::crypto::HASH_SIZE)
    );
    assert_eq!(
        storage.load_block_by_height(Height(0)).unwrap(),
        Some(block)
    );
    assert!(storage.load_block_by_hash(&hash).unwrap().is_some());
}

#[test]
fn parse_address_accepts_wallet_address_string() {
    let address = Address([0xab; xparq::crypto::ADDRESS_SIZE]);
    let encoded = address_to_string(&address);
    assert_eq!(parse_address_string(&encoded), Ok(address));
}

#[test]
fn public_rpc_requires_tls_outside_loopback() {
    let mut config = RunConfig {
        rpc_addrs: vec!["0.0.0.0:6666".parse().unwrap()],
        ..RunConfig::default()
    };
    assert!(validate_rpc_security(&config).is_err());
    config.rpc_tls_cert = Some("server.crt".to_string());
    config.rpc_tls_key = Some("server.key".to_string());
    assert!(validate_rpc_security(&config).is_ok());
}

#[test]
fn admin_rpc_requires_a_strong_token() {
    let mut config = RunConfig {
        rpc_admin_addrs: vec!["127.0.0.1:6667".parse().unwrap()],
        ..RunConfig::default()
    };
    assert!(validate_rpc_security(&config).is_err());
    config.rpc_admin_token = Some(Zeroizing::new("short".to_string()));
    assert!(validate_rpc_security(&config).is_err());
    config.rpc_admin_token = Some(Zeroizing::new("a".repeat(32)));
    assert!(validate_rpc_security(&config).is_ok());
}

#[test]
fn mining_requires_an_explicit_reward_recipient() {
    let mut config = RunConfig {
        mine: true,
        ..RunConfig::default()
    };
    assert!(validate_mining_config(&config).is_err());

    config.miner_address = Some(Address([9; xparq::crypto::ADDRESS_SIZE]));
    assert!(validate_mining_config(&config).is_ok());
}

#[test]
fn mine_shortcut_reads_shared_config_without_a_wallet_argument() {
    assert_eq!(mine_config_args(&[]), Some(args(&["--mine"])));
    assert_eq!(
        mine_config_args(&args(&["--config", "miner.json"])),
        Some(args(&["--config", "miner.json", "--mine"]))
    );
    assert_eq!(mine_config_args(&args(&["wallet.json"])), None);
}

#[test]
fn parses_rpc_security_controls() {
    let config = parse_run_config(&args(&[
        "--rpc-admin-listen",
        "127.0.0.1:7777",
        "--rpc-admin-token",
        "0123456789abcdef0123456789abcdef",
        "--rpc-cors-origin",
        "https://wallet.example",
        "--rpc-max-body-bytes",
        "4096",
        "--rpc-timeout-secs",
        "9",
        "--rpc-max-connections",
        "12",
        "--rpc-max-concurrent-requests",
        "24",
        "--rpc-rate-limit-per-second",
        "10",
        "--rpc-rate-limit-burst",
        "20",
    ]))
    .unwrap();
    assert_eq!(
        config.rpc_admin_addrs,
        vec!["127.0.0.1:7777".parse().unwrap()]
    );
    assert_eq!(config.rpc_cors_origins, vec!["https://wallet.example"]);
    assert_eq!(config.rpc_max_body_bytes, 4096);
    assert_eq!(config.rpc_timeout, Duration::from_secs(9));
    assert_eq!(config.rpc_max_connections, 12);
    assert_eq!(config.rpc_max_concurrent_requests, 24);
    assert_eq!(config.rpc_rate_limit_per_second, 10);
    assert_eq!(config.rpc_rate_limit_burst, 20);
}

#[test]
#[cfg(feature = "mainnet")]
fn parse_run_config_accepts_operator_peer_without_defaults() {
    let config = parse_run_config(&args(&[
        "--config",
        "/tmp/xparq-missing-test-config.json",
        "--peer",
        "192.0.2.20:5555",
    ]))
    .unwrap();
    assert_eq!(config.peers, vec!["192.0.2.20:5555".parse().unwrap()]);
}

#[test]
#[cfg(feature = "mainnet")]
fn mainnet_defaults_to_local_rpc_without_peers() {
    let config = RunConfig::default();
    assert!(config.rpc_addrs.iter().all(|addr| addr.ip().is_loopback()));
    assert!(config.peers.is_empty());
}

#[test]
#[cfg(any(feature = "testnet", feature = "devnet"))]
fn non_mainnet_defaults_do_not_use_mainnet_peers() {
    let config = RunConfig::default();
    assert!(config.peers.is_empty());
}

#[test]
fn qcash_file_lookup_accepts_file_names_and_prefixes() {
    assert_eq!(
        rpc::api::qcash_file_lookup_prefix("100XPQ_E5D6217A7.QCash").unwrap(),
        "E5D6217A7"
    );
    assert_eq!(
        rpc::api::qcash_file_lookup_prefix(
            "e5d6217a74b06b8e000000000000000000000000000000000000000000000000"
        )
        .unwrap(),
        "E5D6217A74B06B8E000000000000000000000000000000000000000000000000"
    );
    assert!(rpc::api::qcash_file_lookup_prefix("100XPQ_not-hex.QCash").is_err());
    assert!(rpc::api::qcash_file_lookup_prefix("100XPQ_E5D6217A7.cash").is_err());
}

#[test]
fn qcash_utxo_explorer_reports_live_status_and_heights() {
    let coin = xparq::state::QCashUtxo {
        id: xparq::state::QCashCoinId([0xab; 32]),
        outpoint: xparq::state::QCashOutPoint {
            transaction_hash: TransactionHash([0xcd; 32]),
            output_index: 2,
        },
        withdrawer: Address([0xef; xparq::crypto::ADDRESS_SIZE]),
        amount: xparq::consensus::supply::Amount(5 * xparq::consensus::supply::XPQ),
        redeem_key_commitment: [0x12; 32],
        issued_height: Height(10),
    };
    let pending = rpc::api::qcash_utxo_value(&coin, Height(10));
    assert_eq!(pending["status"], "unredeemed");
    assert_eq!(pending["redeemability"], "pending");
    assert_eq!(pending["amount"], 5 * xparq::consensus::supply::XPQ);
    assert_eq!(pending["redeemable_height"], 11);
    assert_eq!(pending["remaining_redeem_delay_blocks"], 1);

    let redeemable = rpc::api::qcash_utxo_value(&coin, Height(11));
    assert_eq!(redeemable["status"], "unredeemed");
    assert_eq!(redeemable["redeemability"], "redeemable");
    assert_eq!(redeemable["remaining_redeem_delay_blocks"], 0);
}

#[test]
fn protocol_event_rpc_recognizes_every_persisted_kind() {
    for kind in [
        "transfer",
        "qcash_withdrawn",
        "qcash_redeemed",
        "qcash_split",
        "emission_distributed",
    ] {
        assert!(rpc::api::is_protocol_event_kind(kind), "missing {kind}");
    }
}
