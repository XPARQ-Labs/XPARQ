use super::cli::format_asset_amount;
use super::*;
use kernel::native::asset::ASSET_DECIMALS;

pub(super) fn print_balance(args: &[String]) -> Result<(), String> {
    let path = option(args, "--wallet").unwrap_or(DEFAULT_WALLET_PATH);
    let rpc = option(args, "--rpc").unwrap_or(DEFAULT_RPC_ADDR);
    let bytes =
        Zeroizing::new(fs::read(path).map_err(|error| format!("failed to read {path}: {error}"))?);
    let address = kernel::crypto::address_to_string(&wallet_address_from_file_bytes(&bytes)?);
    let balance: BalanceResponse = http_get_json(rpc, &format!("/balance/{address}"))?;
    let burn: NodeBurnResponse = http_get_json(rpc, "/status")?;

    println!("Address: {address}");
    println!("Available: {}", format_amount(balance.total));
    println!("Reserved: {}", format_amount(balance.reserved));
    println!("UTXOs: {}", balance.utxo_count);
    println!("Total Mined: {}", format_amount(burn.total_mined));
    println!("Total Burned: {}", format_amount(burn.total_burned));
    println!("Supply: {}", format_amount(burn.supply));
    println!("Assets: {}", balance.assets.len());
    for (index, asset) in balance.assets.iter().enumerate() {
        let max_supply = format_asset_amount(&asset.max_supply, ASSET_DECIMALS)?;
        let mint = format_asset_amount(&asset.mint, ASSET_DECIMALS)?;

        println!();
        println!("Asset {}:", index + 1);
        println!("  Contract: {}", asset.asset);
        println!("  Name: {}", asset.name);
        println!("  Decimals: {}", ASSET_DECIMALS);
        println!("  Max Supply: {max_supply}");
        println!("  Mint: {mint}");
        println!("  Shares: {}", asset.shares.len());

        for (share_index, share) in asset.shares.iter().enumerate() {
            let amount = format_asset_amount(&share.amount, ASSET_DECIMALS)?;
            let owner = share
                .owner
                .get("address")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-");

            println!("    Share {}:", share_index + 1);
            println!("      ID: {}", share.share_id);
            println!("      Amount: {amount}");
            println!("      Owner: {owner}");
        }
    }
    Ok(())
}
