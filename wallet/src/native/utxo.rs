use super::rpc::fetch_account;
use super::*;

pub(super) fn print_utxo_tracker(args: &[String]) -> Result<(), String> {
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let bytes =
        Zeroizing::new(fs::read(path).map_err(|error| format!("failed to read {path}: {error}"))?);
    let address = kernel::crypto::address_to_string(&wallet_address_from_file_bytes(&bytes)?);
    let account = fetch_account(rpc, &address)?;

    println!("address: {address}");
    println!("next height: {}", account.next_height);
    println!("utxos: {}", account.utxos.len());
    let mut utxos = account.utxos.iter().collect::<Vec<_>>();
    utxos.sort_by(|left, right| left.id.cmp(&right.id));
    for utxo in utxos {
        println!("- utxo: {}  {}", utxo.id, format_amount(utxo.amount),);
    }
    Ok(())
}
