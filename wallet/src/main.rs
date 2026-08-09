use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, ExitCode};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use xparq::{
    codec::{canonical_bytes, canonical_deserialize, signed_protocol_transaction_bytes},
    consensus::supply::{Amount, DECIMALS, XPQ},
    crypto::{
        Address, PublicKey, SIGNATURE_SIZE, SecretKey, Signature, address_from_string,
        address_to_string, authorization_keypair_from_password, derive_public_key,
        dual_address_from_public_keys,
    },
    ledger::{
        BLOCK_REWARD_MATURITY, QCASH_REDEEM_DELAY, decode_account_non_membership_proof_bundle,
        decode_account_state_proof_bundle, decode_qcash_state_proof_bundle,
    },
    qcash::recovery::{
        RollbackProofBundle, TrustedHeaderCheckpoint, advance_trusted_header_checkpoint,
        decode_header_chain_chunk, trusted_header_checkpoint, verify_header_chain_extension,
    },
    qcash::{
        QCashCoinFile, QCashDenomination, QCashWithdrawalMetadata, decode_qcash_coin_file,
        encode_qcash_coin_file, qcash_redeem_key_commitment_from_secret,
    },
    state::{QCashCoinId, XpqCoinId},
    transaction::{
        OutputTarget, QCashTransaction, SignedProtocolTransaction, SignedQCashTransaction,
        SignedTransfer as SignedTransaction, Transfer as Transaction, TransferOutput,
    },
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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
    rpc_addr: String,
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
const WALLET_VERSION: u8 = 1;
const DEFAULT_TRANSACTION_FEE_XPQ: &str = "auto";
const RPC_HTTP_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_ROLLBACK_PROOF_BYTES: usize = 64 * 1024 * 1024;
const MAX_HEADER_CHUNK_HTTP_RESPONSE_BYTES: usize = 3 * 1024 * 1024;

include!("wallet_file.rs");
include!("menu.rs");
include!("rpc_display.rs");
include!("commands.rs");

fn main() -> ExitCode {
    if let Err(error) = memory::harden_process_memory() {
        eprintln!("warning: process memory hardening is incomplete: {error}");
    }
    match run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
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
        Some("new-mnemonic") | Some("mnemonic-new") => wallet_new_mnemonic(&args[1..]),
        Some("restore-mnemonic")
        | Some("mnemonic-restore")
        | Some("import")
        | Some("import-wallet") => wallet_restore_mnemonic(&args[1..]),
        Some("address") => wallet_address(&args[1..]),
        Some("balance") => wallet_balance(&args[1..]),
        Some("stats") | Some("tracking") => wallet_global_stats(&args[1..]),
        Some("address-stats") | Some("address-tracking") => wallet_address_stats(&args[1..]),
        Some("hashrate") => wallet_hashrate(&args[1..]),
        Some("pay") => wallet_pay(&args[1..]),
        Some("send") => wallet_send(&args[1..]),
        Some("pool-payout") => wallet_pool_payout(&args[1..]),
        Some("cash") | Some("qcash") => wallet_cash(&args[1..]),
        Some("events") | Some("event") => wallet_events(&args[1..]),
        Some("rollback") | Some("recovery") => wallet_rollback(&args[1..]),
        Some("proof") | Some("checkpoint") => wallet_proof(&args[1..]),
        Some(command) => Err(format!("unknown wallet command `{command}`. Try --help.")),
    };
    args.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_authorization_password_does_not_modify_wallet_file() {
        let owner = xparq::crypto::keypair_from_seed(&[0x51; 32]);
        let authorization =
            authorization_keypair_from_password(b"correct password", &owner.public_key).unwrap();
        let wallet = Wallet::from_keys_with_authorization(
            owner.public_key,
            owner.secret_key,
            authorization.public_key,
            None,
        );
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let wallet_path = std::env::temp_dir().join(format!(
            "xparq-wallet-wrong-auth-{}-{unique}.json",
            std::process::id()
        ));
        let wallet_path_string = wallet_path.to_string_lossy().into_owned();

        save_wallet(&wallet_path_string, &wallet).unwrap();
        let bytes_before = fs::read(&wallet_path).unwrap();
        let loaded = load_wallet(&wallet_path_string).unwrap();
        let error = resolve_authorization_for_wallet(
            &loaded,
            Some(AuthorizationInput::Password(Zeroizing::new(
                "wrong password".to_string(),
            ))),
        )
        .unwrap_err();

        assert_eq!(error, "authorization password does not match this wallet");
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
        let checkpoint = trusted_header_checkpoint(&[xparq::qcash::recovery::ChainHeader::new(
            genesis.height(),
            genesis.header,
        )])
        .unwrap();
        let wallet_path = std::env::temp_dir().join(format!(
            "xparq-wallet-checkpoint-{}-{}",
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

        let incomplete = serde_json::json!({ "height": 10 });
        assert!(fee_rate_from_status(&incomplete).is_err());
    }

    #[test]
    fn shared_config_supplies_rpc_only_for_the_compiled_network() {
        let matching = serde_json::to_vec(&serde_json::json!({
            "network": WALLET_NETWORK,
            "rpc_addr": "127.0.0.1:7777",
            "miner_secret_key": "ignored"
        }))
        .unwrap();
        assert_eq!(
            rpc_addr_from_shared_config_bytes(&matching),
            Some("127.0.0.1:7777".to_string())
        );

        let mismatched = br#"{"network":"another-network","rpc_addr":"127.0.0.1:7777"}"#;
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
    fn selected_qcash_denominations_are_allowed_types_not_single_outputs() {
        let allowed = parse_qcash_denominations("1, 2, 5").unwrap();
        let (cash, remainder, outputs) =
            plan_selected_qcash_denominations(Amount(100 * XPQ), &allowed).unwrap();

        assert_eq!(cash, Amount(100 * XPQ));
        assert_eq!(remainder, Amount(0));
        assert_eq!(outputs, vec![QCashDenomination::Five; 20]);
    }

    #[test]
    fn explicit_qcash_denomination_counts_must_match_requested_amount() {
        let selection = parse_qcash_denomination_selection("5x16,2x5,1x10").unwrap();
        let QCashDenominationSelection::Exact(outputs) = selection else {
            panic!("count syntax must produce exact outputs");
        };
        let (cash, remainder, outputs) =
            plan_exact_qcash_denominations(Amount(100 * XPQ), outputs).unwrap();
        assert_eq!(cash, Amount(100 * XPQ));
        assert_eq!(remainder, Amount(0));
        assert_eq!(outputs.len(), 31);

        let selection = parse_qcash_denomination_selection("5x1").unwrap();
        let QCashDenominationSelection::Exact(outputs) = selection else {
            panic!("count syntax must produce exact outputs");
        };
        assert!(plan_exact_qcash_denominations(Amount(100 * XPQ), outputs).is_err());

        let selection = parse_qcash_denomination_selection("1000000x1").unwrap();
        let QCashDenominationSelection::Exact(outputs) = selection else {
            panic!("large denomination must produce exact outputs");
        };
        let (cash, remainder, outputs) =
            plan_exact_qcash_denominations(Amount(1_000_000 * XPQ), outputs).unwrap();
        assert_eq!(cash, Amount(1_000_000 * XPQ));
        assert_eq!(remainder, Amount(0));
        assert_eq!(outputs, vec![QCashDenomination::OneMillion]);
    }

    #[test]
    fn protocol_event_explorer_labels_every_core_event_kind() {
        let names = [
            "Transfer",
            "QCashWithdrawn",
            "QCashRedeemed",
            "QCashRecoverRedeemed",
            "CoinbasePaid",
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
            event_kind_from_menu_selection("4"),
            Ok(Some("qcash_recover_redeemed".to_string()))
        );
        assert_eq!(
            event_kind_from_menu_selection("5"),
            Ok(Some("coinbase_paid".to_string()))
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
    fn qcash_denomination_menu_maps_numbers_from_smallest_to_largest() {
        assert_eq!(qcash_denomination_from_menu("1").unwrap().xpq(), 1);
        assert_eq!(qcash_denomination_from_menu("3").unwrap().xpq(), 5);
        assert_eq!(qcash_denomination_from_menu("15").unwrap().xpq(), 1_000_000);
        assert_eq!(
            qcash_allowed_denominations_from_menu("1, 3, 15"),
            Ok("1,5,1000000".to_string())
        );
        assert_eq!(
            qcash_exact_denominations_from_menu("3x2,1x5"),
            Ok("5x2,1x5".to_string())
        );
        assert!(qcash_denomination_from_menu("0").is_err());
        assert!(qcash_denomination_from_menu("16").is_err());
        assert!(qcash_exact_denominations_from_menu("1x0").is_err());
    }
}
