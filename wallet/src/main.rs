use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, ExitCode};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::{OffsetDateTime, macros::format_description};
use xparq::{
    codec::{canonical_bytes, canonical_deserialize},
    consensus::supply::{Amount, DECIMALS, XPQ},
    crypto::{Address, SIGNATURE_SIZE, Signature, address_from_string, address_to_string},
    ledger::{
        BLOCK_REWARD_MATURITY, QCASH_REDEEM_DELAY, TrustedHeaderCheckpoint,
        advance_trusted_header_checkpoint, decode_account_non_membership_proof_bundle,
        decode_account_state_proof_bundle, decode_header_chain_chunk,
        decode_qcash_state_proof_bundle, trusted_header_checkpoint, verify_header_chain_extension,
    },
    qcash::{
        QCashCoinFile, QCashWithdrawalMetadata, decode_qcash_coin_file, encode_qcash_coin_file,
        qcash_redeem_key_commitment_from_secret,
    },
    state::{QCashCoinId, XpqCoinId},
    transaction::{
        OutputTarget, QCashTransaction, SignedProtocolTransaction, SignedQCashTransaction,
        SignedTransfer as SignedTransaction, Transfer as Transaction, TransferOutput,
    },
};
use zeroize::{Zeroize, Zeroizing};

const RPC_ADDR_ENV: &str = "XPARQ_RPC_ADDR";
const CONFIG_FILE_ENV: &str = "XPARQ_CONFIG";
#[cfg(feature = "mainnet")]
const DEFAULT_WALLET_RPC_ADDR: &str = "127.0.0.1:6666";
#[cfg(feature = "testnet")]
const DEFAULT_WALLET_RPC_ADDR: &str = "127.0.0.1:16666";
#[cfg(feature = "devnet")]
const DEFAULT_WALLET_RPC_ADDR: &str = "127.0.0.1:26666";
#[cfg(feature = "mainnet")]
const DEFAULT_SHARED_CONFIG_PATH: &str = "./data/mainnet/config.json";
#[cfg(feature = "testnet")]
const DEFAULT_SHARED_CONFIG_PATH: &str = "./data/testnet/config.json";
#[cfg(feature = "devnet")]
const DEFAULT_SHARED_CONFIG_PATH: &str = "./data/devnet/config.json";
#[cfg(feature = "mainnet")]
const WALLET_NETWORK: &str = "mainnet";
#[cfg(feature = "testnet")]
const WALLET_NETWORK: &str = "testnet";
#[cfg(feature = "devnet")]
const WALLET_NETWORK: &str = "devnet";

#[derive(Deserialize)]
struct SharedRpcConfig {
    network: String,
    rpc_addr_ipv4: Option<String>,
    rpc_addr_ipv6: Option<String>,
}

mod memory;

#[cfg(not(feature = "sqisign-blockchain-test"))]
const DEFAULT_WALLET_PATH: &str = "wallet.json";
#[cfg(feature = "sqisign-blockchain-test")]
const DEFAULT_WALLET_PATH: &str = "wallet-sqisign-level5-test.json";
#[cfg(not(feature = "sqisign-blockchain-test"))]
const DEFAULT_IMPORTED_WALLET_PATH: &str = "imported.json";
#[cfg(feature = "sqisign-blockchain-test")]
const DEFAULT_IMPORTED_WALLET_PATH: &str = "imported-sqisign-level5-test.json";
const DEFAULT_TRANSACTION_FEE_XPQ: &str = "auto";
const RPC_HTTP_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_HEADER_CHUNK_HTTP_RESPONSE_BYTES: usize = 3 * 1024 * 1024;

include!("wallet_file.rs");
include!("menu.rs");
include!("rpc_display.rs");
include!("commands.rs");

fn main() -> ExitCode {
    if let Err(error) = memory::harden_process_memory() {
        cli_log(
            "WARN",
            format_args!("process memory hardening is incomplete: {error}"),
        );
    }
    match run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            cli_log("ERROR", format_args!("{error}"));
            ExitCode::FAILURE
        }
    }
}

fn run(mut args: Vec<String>) -> Result<(), String> {
    let result = match args.first().map(String::as_str) {
        None | Some("menu") | Some("cli") => interactive_menu(),
        Some("-h") | Some("--help") | Some("help") => {
            print_help();
            Ok(())
        }
        Some("-V") | Some("--version") | Some("version") => {
            println!("wallet {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("new") => wallet_new(&args[1..]),
        Some("restore-mnemonic")
        | Some("mnemonic-restore")
        | Some("import")
        | Some("import-wallet") => wallet_restore_mnemonic(&args[1..]),
        Some("balance") => wallet_balance(&args[1..]),
        Some("stats") | Some("tracking") => wallet_global_stats(&args[1..]),
        Some("address-stats") | Some("address-tracking") => wallet_address_stats(&args[1..]),
        Some("hashrate") => wallet_hashrate(&args[1..]),
        Some("send") => wallet_send(&args[1..]),
        Some("cash") | Some("qcash") => wallet_cash(&args[1..]),
        Some("events") | Some("event") => wallet_events(&args[1..]),
        Some("proof") | Some("checkpoint") => wallet_proof(&args[1..]),
        Some(command) => Err(format!("unknown wallet command `{command}`. Try --help.")),
    };
    args.zeroize();
    result
}

fn cli_log(level: &str, message: std::fmt::Arguments<'_>) {
    let timestamp = OffsetDateTime::now_utc()
        .format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
        ))
        .unwrap_or_else(|_| "timestamp-unavailable".to_string());
    eprintln!("{timestamp} {level:<5} WALLET    {message}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_wallet_password_does_not_modify_wallet_file() {
        let mnemonic = xparq_wallet::generate_xparq_mnemonic(12).unwrap();
        let mut wallet =
            xparq_wallet::wallet_from_xparq_mnemonic(&mnemonic, "correct password").unwrap();
        wallet.mnemonic = Some(mnemonic.to_string());
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let wallet_path = std::env::temp_dir().join(format!(
            "wallet-wrong-auth-{}-{unique}.json",
            std::process::id()
        ));
        let wallet_path_string = wallet_path.to_string_lossy().into_owned();

        save_wallet(&wallet_path_string, &wallet).unwrap();
        let bytes_before = fs::read(&wallet_path).unwrap();
        let error = load_wallet_with_password(&wallet_path_string, "wrong password").unwrap_err();
        assert!(error.ends_with("wallet password does not match this wallet"));
        assert_eq!(fs::read(&wallet_path).unwrap(), bytes_before);
        fs::remove_file(wallet_path).unwrap();
    }

    #[test]
    fn formats_xpq_with_protocol_decimals() {
        assert_eq!(format_xpq(XPQ / 100), "0.010000 XPQ");
        assert_eq!(format_xpq(50 * XPQ + XPQ / 100), "50.010000 XPQ");
    }

    #[test]
    fn trusted_checkpoint_file_roundtrips_current_format() {
        let genesis = xparq::genesis::genesis_block().unwrap();
        let checkpoint = trusted_header_checkpoint(&[xparq::ledger::ChainHeader::new(
            genesis.height(),
            genesis.header,
        )])
        .unwrap();
        let wallet_path = std::env::temp_dir().join(format!(
            "wallet-checkpoint-{}-{}",
            std::process::id(),
            unix_timestamp().unwrap()
        ));
        let wallet_path = wallet_path.to_string_lossy().into_owned();

        save_wallet_checkpoint(&wallet_path, &checkpoint).unwrap();
        assert_eq!(
            load_wallet_checkpoint(&wallet_path).unwrap(),
            Some(checkpoint)
        );

        fs::remove_file(checkpoint_path(&wallet_path)).unwrap();
    }

    #[test]
    fn automatic_fee_uses_node_rate_and_payment_virtual_size() {
        assert_eq!(fee_for_rate(7, 250), Ok(Amount(1_750)));
        assert_eq!(fee_for_rate(1, 0), Ok(Amount(1)));
        assert!(fee_for_rate(u64::MAX, 2).is_err());
    }

    #[test]
    fn automatic_fee_requires_node_fee_status() {
        let current = serde_json::json!({
            "dynamic_market_fee_rate_per_byte": 7,
            "min_relay_fee_rate_per_byte": 3
        });
        assert_eq!(fee_rate_from_status(&current), Ok(7));
        let zero_policy = serde_json::json!({
            "dynamic_market_fee_rate_per_byte": 0,
            "min_relay_fee_rate_per_byte": 0
        });
        assert_eq!(fee_rate_from_status(&zero_policy), Ok(0));

        let incomplete = serde_json::json!({ "height": 10 });
        assert!(fee_rate_from_status(&incomplete).is_err());
    }

    #[test]
    fn shared_config_supplies_rpc_only_for_the_compiled_network() {
        let matching = serde_json::to_vec(&serde_json::json!({
            "network": WALLET_NETWORK,
            "rpc_addr_ipv4": "127.0.0.1:7777",
            "rpc_addr_ipv6": "[::1]:7777",
            "miner_secret_key": "ignored"
        }))
        .unwrap();
        assert_eq!(
            rpc_addr_from_shared_config_bytes(&matching),
            Some("127.0.0.1:7777".to_string())
        );

        let mismatched = br#"{"network":"another-network","rpc_addr_ipv4":"127.0.0.1:7777"}"#;
        assert_eq!(rpc_addr_from_shared_config_bytes(mismatched), None);
    }

    #[test]
    fn qcash_lookup_name_accepts_canonical_names_and_rejects_other_extensions() {
        assert_eq!(
            qcash_lookup_name("./cash/100XPQ_E5D6217A74B06B8E.QCash").unwrap(),
            "100XPQ_E5D6217A74B06B8E.QCash"
        );
        assert_eq!(
            qcash_lookup_name("E5D6217A74B06B8E").unwrap(),
            "E5D6217A74B06B8E"
        );
        assert!(qcash_lookup_name("100XPQ_E5D6217A74B06B8E.cash").is_err());
        assert!(qcash_lookup_name("bad/name?x=1").is_err());
    }

    #[test]
    fn qcash_status_label_formats_explorer_statuses() {
        assert_eq!(qcash_status_label("unredeemed"), "unredeemed");
        assert_eq!(qcash_status_label("redeemed"), "redeemed");
        assert_eq!(qcash_status_label("pending"), "invalid");
    }

    #[test]
    fn explicit_qcash_amounts_accept_fractional_xpq_and_must_match() {
        let amounts = parse_qcash_amounts("50, 20, 29.9").unwrap();
        let requested = parse_xpq_amount("99.9").unwrap();
        let (cash, remainder, outputs) = plan_exact_qcash_amounts(requested, amounts).unwrap();
        assert_eq!(cash, requested);
        assert_eq!(remainder, Amount(0));
        assert_eq!(outputs.len(), 3);
        assert_eq!(outputs[2], parse_xpq_amount("20").unwrap());

        let amounts = parse_qcash_amounts("5").unwrap();
        assert!(plan_exact_qcash_amounts(Amount(100 * XPQ), amounts).is_err());
        assert!(parse_qcash_amounts("0").is_err());
    }

    #[test]
    fn protocol_event_explorer_labels_every_core_event_kind() {
        let names = [
            "Transfer",
            "QCashWithdrawn",
            "QCashRedeemed",
            "QCashSplit",
            "EmissionDistributed",
        ];
        assert_eq!(names.len(), 5);
        assert!(
            names
                .iter()
                .all(|name| protocol_event_label(name) != "unknown")
        );
    }

    #[test]
    fn protocol_event_menu_maps_numbers_to_rpc_kind_names() {
        assert_eq!(event_kind_from_menu_selection("0"), Ok(None));
        assert_eq!(
            event_kind_from_menu_selection("1"),
            Ok(Some("transfer".to_string()))
        );
        assert_eq!(
            event_kind_from_menu_selection("5"),
            Ok(Some("emission_distributed".to_string()))
        );
        assert_eq!(
            event_kind_from_menu_selection("4"),
            Ok(Some("qcash_split".to_string()))
        );
        assert!(event_kind_from_menu_selection("6").is_err());
    }

    #[test]
    fn mnemonic_menu_maps_numbers_to_word_counts() {
        assert_eq!(mnemonic_words_from_menu_selection("1"), Ok(12));
        assert_eq!(mnemonic_words_from_menu_selection("2"), Ok(24));
        assert!(mnemonic_words_from_menu_selection("12").is_err());
    }

    #[test]
    fn qcash_amount_parser_orders_outputs_canonically() {
        assert_eq!(
            parse_qcash_amounts("0.1,29.9,1").unwrap(),
            vec![Amount(29_900_000), Amount(XPQ), Amount(100_000)]
        );
    }
}
