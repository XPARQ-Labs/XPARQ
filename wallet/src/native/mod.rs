use std::{
    fs,
    io::{self, Write},
    path::Path,
    str::FromStr,
    sync::OnceLock,
};

use kernel::monetary::coin::{CoinOutput, CoinShare, Zeno};
use kernel::{
    codec::canonical_bytes,
    consensus::{DECIMALS, StateTransitionWeight},
    crypto::{ProgramId, Signature, program_id_from_string},
    program::{AuthorizedProgramEnvelope, CoinCharges, CoinTransition},
};
use serde::Deserialize;
use wallet::{
    AccountWallet, account_wallet_file_bytes, account_wallet_for_legacy_transfer_from_file_bytes,
    account_wallet_from_bip39_mnemonic, account_wallet_from_file_bytes, generate_bip39_mnemonic,
    wallet_program_id_from_file_bytes,
};
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_WALLET_PATH: &str = "wallet.json";
const AUTOMATIC_FEE_ZENO_PER_BYTE: u64 = 8;
const MAX_FEE_CONVERGENCE_ROUNDS: usize = 8;
const DEFAULT_HISTORY_LIMIT: usize = 50;
const MAX_HISTORY_LIMIT: usize = 250;
const HISTORY_CURSOR_HEX_LEN: usize = 34;

struct LoadedWallet(AccountWallet);

impl LoadedWallet {
    fn program_id(&self) -> ProgramId {
        self.0.program_id
    }

    fn sign_onchain_spend(
        &self,
        intent: CoinTransition,
    ) -> Result<kernel::program::AuthorizedProgramInvocation, String> {
        self.0.sign_xpq_transfer(intent)
    }

    fn sign_legacy_onchain_spend(
        &self,
        salt: kernel::crypto::AuthorizationSalt,
        intent: CoinTransition,
    ) -> Result<kernel::program::AuthorizedProgramInvocation, String> {
        self.0.sign_xpq_transfer_with_legacy_salt(salt, intent)
    }
}
fn default_rpc_addr() -> &'static str {
    static RPC_ADDR: OnceLock<String> = OnceLock::new();
    RPC_ADDR
        .get_or_init(|| {
            std::env::var("XPARQ_RPC")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .or_else(|| {
                    std::env::var("RPC_ADDR")
                        .ok()
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty())
                })
                .unwrap_or_else(|| {
                    if cfg!(feature = "devnet") {
                        "127.0.0.1:26666".into()
                    } else if cfg!(feature = "testnet") {
                        "127.0.0.1:16666".into()
                    } else {
                        "127.0.0.1:6666".into()
                    }
                })
        })
        .as_str()
}

#[derive(Deserialize)]
struct AccountResponse {
    next_height: u64,
    #[serde(rename = "utxo_snapshot")]
    _utxo_snapshot: String,
    utxos: Vec<AccountUtxo>,
    next_utxo_offset: Option<usize>,
    next_utxo_cursor: Option<String>,
}

#[derive(Deserialize)]
struct BalanceResponse {
    total: u64,
    reserved: u64,
    utxo_count: usize,
    #[serde(default)]
    program_assets: Vec<AccountAssetBalance>,
}

#[derive(Deserialize)]
struct NodeBurnResponse {
    total_mined: u64,
    total_burned: u64,
    supply: u64,
}

#[derive(Deserialize)]
struct AccountAssetBalance {
    asset: String,
    name: String,
    #[serde(default)]
    balance: Option<String>,
    #[serde(default)]
    share_count: Option<usize>,
    #[serde(default)]
    shares: Vec<AccountAssetShare>,
}

#[derive(Deserialize)]
struct AccountAssetShare {
    amount: String,
}

#[derive(Deserialize)]
struct AccountUtxo {
    id: String,
    amount: u64,
    reserved: bool,
}

struct WalletAccountInputCandidates {
    salt: kernel::crypto::AccountSalt,
    program_id: ProgramId,
    utxos: Vec<AccountUtxo>,
}

#[derive(Deserialize)]
struct ProgramHistoryResponse {
    program_id: String,
    tip_height: u64,
    emission_count: usize,
    activities: Vec<ProgramActivity>,
    #[serde(default)]
    next_cursor: Option<String>,
}

#[derive(Deserialize)]
struct ProgramActivity {
    height: u64,
    block_hash: String,
    hash: Option<String>,
    #[serde(rename = "type")]
    activity_type: String,
    direction: String,
    amount: u64,
    size_bytes: Option<usize>,
    #[serde(default)]
    program: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct SubmitTransactionResponse {
    hash: String,
}

const MAX_CONSOLIDATION_INPUTS: usize = 1_000;

pub fn run(mut args: Vec<String>) -> Result<(), String> {
    let result = match args.first().map(String::as_str) {
        None | Some("menu") | Some("interactive") => interactive_menu(),
        Some("new") => create_wallet(&args[1..]),
        Some("restore") => restore_wallet(&args[1..]),
        Some(command @ ("accounts" | "account-add" | "account-use")) => {
            manage_accounts(command, &args[1..])
        }
        Some("program-id") => print_program_id(&args[1..]),
        Some("balance") => print_balance(&args[1..]),
        Some("history") => print_history(&args[1..]),
        Some("utxos") | Some("utxo-tracker") => print_utxo_tracker(&args[1..]),
        Some("sign-spend") => sign_spend(&args[1..]),
        Some("consolidate") => consolidate_coin_utxos(&args[1..]),

        Some(command) if command.starts_with("program-") => program::command(command, &args[1..]),

        Some("version") | Some("--version") | Some("-V") => {
            println!("wallet {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("help") | Some("--help") | Some("-h") => {
            print_help();
            Ok(())
        }
        Some(command) => Err(format!("unknown command `{command}`")),
    };
    args.zeroize();
    result
}

mod balance;
mod cli;
mod deploy;
mod history;
mod rpc;
mod transaction;
mod util;
mod utxo;
mod wallet_file;

use wallet_file::{load_wallet, load_wallet_for_legacy_transfer, write_account_wallet};

use cli::{create_wallet, interactive_menu, manage_accounts, print_program_id, restore_wallet};
use util::{format_amount, has_flag, option, parse_amount, print_help, repeated_options};

use balance::print_balance;
use history::print_history;
use rpc::{http_get_json, http_post_bytes};
use transaction::{
    consolidate_coin_utxos, prepare_legacy_migration, sign_spend, submit_or_print_transaction,
};
use utxo::print_utxo_tracker;

#[cfg(test)]
use history::{parse_history_limit, validate_history_cursor};

#[cfg(test)]
mod tests;

mod program;
