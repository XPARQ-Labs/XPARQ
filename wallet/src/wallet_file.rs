use xparq_wallet::{
    AuthorizationInput, AuthorizationKeys, XPARQ_MNEMONIC_DEFAULT_WORDS, Wallet,
    authorization_keys_from_password, generate_xparq_mnemonic, wallet_file_bytes,
    wallet_from_xparq_mnemonic,
};

fn wallet_address_string(wallet: &Wallet) -> String {
    address_to_string(&wallet.address)
}

fn save_wallet(path: &str, wallet: &Wallet) -> Result<(), String> {
    let bytes = wallet_file_bytes(wallet)?;
    write_new_synced_file(std::path::Path::new(path), &bytes)
}

fn create_mnemonic_wallet_file(
    path: &str,
    words: usize,
    auth_password: &str,
) -> Result<(Wallet, Zeroizing<String>), String> {
    let mnemonic = generate_xparq_mnemonic(words)?;
    let mut wallet = wallet_from_xparq_mnemonic(&mnemonic, auth_password)?;
    wallet.mnemonic = Some(mnemonic.to_string());
    save_wallet(path, &wallet)?;
    Ok((wallet, mnemonic))
}

fn restore_mnemonic_wallet_file(
    path: &str,
    mnemonic: &str,
    auth_password: &str,
) -> Result<Wallet, String> {
    let mut wallet = wallet_from_xparq_mnemonic(mnemonic, auth_password)?;
    wallet.mnemonic = Some(mnemonic.to_string());
    save_wallet(path, &wallet)?;
    Ok(wallet)
}
