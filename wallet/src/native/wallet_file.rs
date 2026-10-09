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

/// Update an existing wallet only if it still matches the bytes that were loaded.
/// An exclusive marker serializes cooperating CLI writers; temp data is owner-only.
pub(super) fn update_account_wallet(
    path: &str,
    wallet: &AccountWallet,
    expected: &[u8],
) -> Result<(), String> {
    let path = fs::canonicalize(path).map_err(|error| format!("resolve wallet path: {error}"))?;
    let parent = path.parent().ok_or("wallet has no parent directory")?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("wallet has no UTF-8 filename")?;
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    let lock_path = parent.join(format!(".{filename}.account.lock"));
    let mut lock_options = fs::OpenOptions::new();
    lock_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        lock_options.mode(0o600);
    }
    let lock = lock_options.open(&lock_path).map_err(|error| {
        format!(
            "wallet account update lock {}: {error}",
            lock_path.display()
        )
    })?;
    let _lock_cleanup = Cleanup(lock_path);
    let _lock = lock;
    let current = Zeroizing::new(
        fs::read(&path).map_err(|error| format!("read wallet before update: {error}"))?,
    );
    if current.as_slice() != expected {
        return Err("wallet changed during account update; retry".into());
    }
    let bytes = account_wallet_file_bytes(wallet)?;
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|error| format!("temporary wallet name: {error}"))?;
    let temporary = parent.join(format!(".{filename}.{}.tmp", hex::encode(random)));
    let _temporary_cleanup = Cleanup(temporary.clone());
    write_new_file(&temporary, &bytes)?;
    // Recheck before installation to catch noncooperating edits while preparing data.
    let current = Zeroizing::new(
        fs::read(&path).map_err(|error| format!("read wallet before install: {error}"))?,
    );
    if current.as_slice() != expected {
        return Err("wallet changed during account update; retry".into());
    }
    fs::rename(&temporary, &path).map_err(|error| format!("install updated wallet: {error}"))?;
    sync_directory(parent)
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
