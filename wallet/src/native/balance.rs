use super::cli::format_asset_amount;
use super::*;
use extension::asset_program::asset::ASSET_DECIMALS;

pub(super) fn print_balance(args: &[String]) -> Result<(), String> {
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let bytes =
        Zeroizing::new(fs::read(path).map_err(|error| format!("failed to read {path}: {error}"))?);
    let wallet = account_wallet_from_file_bytes(&bytes)?;
    println!("Active Program ID: {}", wallet.program_id);
    println!("Accounts: {}", wallet.account_salts.len());
    let balances = fetch_wallet_balances(rpc, &wallet)?;
    drop(wallet);
    let mut failed = 0;
    for account in balances {
        println!();
        println!("Program ID: {}", account.program_id);
        println!("Active: {}", if account.active { "yes" } else { "no" });
        match account.balance {
            Ok(balance) => print_account_balance(&balance)?,
            Err(error) => {
                println!("Balance unavailable: {error}");
                failed += 1;
            }
        }
    }
    println!();
    println!("Network totals:");
    match http_get_json::<NodeBurnResponse>(rpc, "/status") {
        Ok(burn) => {
            println!("Total Mined: {}", format_amount(burn.total_mined));
            println!("Total Burned: {}", format_amount(burn.total_burned));
            println!("Supply: {}", format_amount(burn.supply));
        }
        Err(error) => println!("Network totals unavailable: {error}"),
    }
    if failed > 0 {
        return Err(format!(
            "balance unavailable for {failed} wallet account(s)"
        ));
    }
    Ok(())
}

struct WalletAccountBalance {
    program_id: String,
    active: bool,
    balance: Result<BalanceResponse, String>,
}

fn fetch_wallet_balances(
    rpc: &str,
    wallet: &AccountWallet,
) -> Result<Vec<WalletAccountBalance>, String> {
    wallet
        .account_salts
        .iter()
        .map(|salt| {
            let program_id =
                kernel::crypto::program_id_from_public_key_with_salt(&wallet.public_key, salt)
                    .map_err(|error| error.to_string())?
                    .to_string();
            let balance = http_get_json(rpc, &format!("/program/balance/{program_id}"));
            Ok(WalletAccountBalance {
                program_id,
                active: *salt == wallet.account_salt,
                balance,
            })
        })
        .collect()
}

fn print_account_balance(balance: &BalanceResponse) -> Result<(), String> {
    println!("Available: {}", format_amount(balance.total));
    println!("Reserved: {}", format_amount(balance.reserved));
    println!("UTXOs: {}", balance.utxo_count);
    println!("Program assets: {}", balance.program_assets.len());
    for asset in &balance.program_assets {
        let owned = asset.shares.iter().try_fold(0_u128, |sum, s| {
            let amount = s
                .amount
                .parse::<u128>()
                .map_err(|_| "invalid program amount")?;
            sum.checked_add(amount).ok_or("program balance overflow")
        })?;
        println!(
            "  {} ({}) — {}",
            asset.name,
            asset.asset,
            format_asset_amount(&owned.to_string(), ASSET_DECIMALS)?
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn balance_checks_all_recorded_accounts_even_after_rpc_failure() {
        let mnemonic = generate_bip39_mnemonic(12).unwrap();
        let mut wallet = account_wallet_from_bip39_mnemonic(&mnemonic, Signature::MlDsa44).unwrap();
        let first = wallet.program_id.to_string();
        let second = wallet.select_account([1; 32]).unwrap().to_string();
        let third = wallet.select_account([2; 32]).unwrap().to_string();
        wallet.select_account([1; 32]).unwrap();
        let expected = vec![first, second, third];
        let server_ids = expected.clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            for (index, id) in server_ids.iter().enumerate() {
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
                assert!(
                    String::from_utf8(request)
                        .unwrap()
                        .starts_with(&format!("GET /program/balance/{id} HTTP/1.1\r\n"))
                );
                let (status, body) = if index == 1 {
                    (
                        "500 Internal Server Error",
                        "{\"error\":\"account unavailable\"}".to_owned(),
                    )
                } else {
                    (
                        "200 OK",
                        serde_json::json!({"total":index as u64 * 100_000_000,
                        "reserved":73,"utxo_count":index,"program_assets":[]})
                        .to_string(),
                    )
                };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        let balances = fetch_wallet_balances(&address, &wallet).unwrap();
        server.join().unwrap();
        assert_eq!(balances.len(), 3);
        assert_eq!(
            balances
                .iter()
                .map(|b| b.program_id.clone())
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            balances.iter().map(|b| b.active).collect::<Vec<_>>(),
            vec![false, true, false]
        );
        assert_eq!(balances[0].balance.as_ref().unwrap().total, 0);
        assert!(
            balances[1]
                .balance
                .as_ref()
                .err()
                .unwrap()
                .contains("account unavailable")
        );
        assert_eq!(balances[2].balance.as_ref().unwrap().total, 200_000_000);
        assert_eq!(balances[2].balance.as_ref().unwrap().reserved, 73);
        assert_eq!(wallet.program_id.to_string(), expected[1]);
    }
}
