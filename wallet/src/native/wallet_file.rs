use super::*;

pub(super) fn load_wallet(path: &str) -> Result<LoadedWallet, String> {
    let bytes =
        Zeroizing::new(fs::read(path).map_err(|error| format!("failed to read {path}: {error}"))?);
    account_wallet_from_file_bytes(&bytes).map(LoadedWallet)
}

pub(super) fn write_account_wallet(path: &str, wallet: &AccountWallet) -> Result<(), String> {
    let bytes = account_wallet_file_bytes(wallet)?;
    write_private_file_atomically(Path::new(path), &bytes)
}

pub(super) fn write_private_file_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if path.exists() {
        return Err(format!("wallet already exists: {}", path.display()));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("wallet path has no UTF-8 filename: {}", path.display()))?;
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| format!("secure temporary wallet name failed: {error}"))?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", hex::encode(random)));

    write_new_file(&temporary, bytes)?;
    if let Err(error) = fs::hard_link(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(format!(
            "failed to atomically install wallet {}: {error}",
            path.display()
        ));
    }
    fs::remove_file(&temporary)
        .map_err(|error| format!("failed to remove {}: {error}", temporary.display()))?;
    sync_directory(parent)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("failed to create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("failed to write and sync {}: {error}", path.display()))
}

fn sync_directory(directory: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        fs::File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("failed to sync {}: {error}", directory.display()))?;
    }
    Ok(())
}
