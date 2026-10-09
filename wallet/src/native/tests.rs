use super::wallet_file::write_private_file_atomically;
use super::*;
use std::io::Read;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_wallet_defaults_to_24_words_for_every_scheme_and_explicit_12_restores() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "xparq-wallet-words-{}-{unique}",
            std::process::id()
        ));
        for account in kernel::crypto::AccountSignatureScheme::ALL {
            let path = directory.join(format!("{}.json", account.id()));
            let args = vec![
                "--wallet".into(),
                path.to_str().unwrap().into(),
                "--account".into(),
                account.to_string(),
            ];
            super::super::cli::create_wallet(&args).unwrap();
            let loaded = super::super::wallet_file::load_wallet(path.to_str().unwrap()).unwrap();
            assert_eq!(
                loaded
                    .0
                    .mnemonic
                    .as_ref()
                    .unwrap()
                    .split_whitespace()
                    .count(),
                24
            );
        }
        let path = directory.join("explicit-12.json");
        super::super::cli::create_wallet(&[
            "--wallet".into(),
            path.to_str().unwrap().into(),
            "--words".into(),
            "12".into(),
        ])
        .unwrap();
        let loaded = super::super::wallet_file::load_wallet(path.to_str().unwrap()).unwrap();
        let phrase = loaded.0.mnemonic.as_ref().unwrap();
        assert_eq!(phrase.split_whitespace().count(), 12);
        let restored =
            wallet::account_wallet_from_bip39_mnemonic(phrase, loaded.0.public_key.scheme())
                .unwrap();
        assert_eq!(restored.program_id, loaded.0.program_id);
        fs::remove_dir_all(directory).unwrap();
    }

    fn utxo_status(utxo: &AccountUtxo) -> &'static str {
        if utxo.reserved {
            "reserved"
        } else {
            "available"
        }
    }

    #[test]
    fn transaction_submission_posts_canonical_bytes() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let program_id = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            while !request.ends_with(&[1, 2, 3, 4]) {
                let length = stream.read(&mut buffer).unwrap();
                assert!(length > 0 && request.len() + length <= 2048);
                request.extend_from_slice(&buffer[..length]);
            }
            assert!(request.starts_with(b"POST /transaction HTTP/1.1\r\n"));
            assert!(request.ends_with(&[1, 2, 3, 4]));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 85\r\nConnection: close\r\n\r\n{\"hash\":\"0000000000000000000000000000000000000000000000000000000000000000\"}",
                )
                .unwrap();
        });
        let response: SubmitTransactionResponse =
            http_post_bytes(&program_id.to_string(), "/transaction", &[1, 2, 3, 4]).unwrap();
        assert_eq!(response.hash, "0".repeat(64));
        server.join().unwrap();
    }

    #[test]
    fn wallet_file_is_atomically_created_as_owner_only() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "kernel-private-wallet-{}-{unique}",
            std::process::id()
        ));
        let path = directory.join("wallet.json");
        write_private_file_atomically(&path, b"secret mnemonic").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"secret mnemonic");
        assert!(write_private_file_atomically(&path, b"replace").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"secret mnemonic");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(fs::read_dir(&directory).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn history_limit_accepts_supported_range() {
        assert_eq!(parse_history_limit("1"), Ok(1));
        assert_eq!(parse_history_limit("50"), Ok(50));
        assert_eq!(parse_history_limit("250"), Ok(250));
        assert!(parse_history_limit("0").is_err());
        assert!(parse_history_limit("251").is_err());
        assert!(parse_history_limit("nope").is_err());
    }

    #[test]
    fn history_cursor_requires_complete_hex_suffix() {
        let valid = "00".repeat(HISTORY_CURSOR_HEX_LEN / 2);
        assert_eq!(validate_history_cursor(&valid), Ok(valid.as_str()));
        assert!(validate_history_cursor("00").is_err());
        assert!(validate_history_cursor(&"0".repeat(HISTORY_CURSOR_HEX_LEN)).is_ok());
        assert!(validate_history_cursor(&"g".repeat(HISTORY_CURSOR_HEX_LEN)).is_err());
    }

    #[test]
    fn utxo_status_and_amount_format_are_canonical() {
        let account = AccountResponse {
            next_height: 100,
            _utxo_snapshot: "test-snapshot".into(),
            next_utxo_offset: None,
            next_utxo_cursor: None,
            utxos: vec![
                AccountUtxo {
                    id: "available-one".into(),
                    amount: 2 * CoinShare::ZENO_PER_COIN,
                    reserved: false,
                },
                AccountUtxo {
                    id: "available-two".into(),
                    amount: 3 * CoinShare::ZENO_PER_COIN,
                    reserved: false,
                },
                AccountUtxo {
                    id: "reserved".into(),
                    amount: CoinShare::ZENO_PER_COIN,
                    reserved: true,
                },
            ],
        };

        assert_eq!(
            format_amount(2 * CoinShare::ZENO_PER_COIN + 1),
            "2.00000001 XPQ"
        );
        assert_eq!(utxo_status(&account.utxos[0]), "available");
        assert_eq!(utxo_status(&account.utxos[1]), "available");
        assert_eq!(utxo_status(&account.utxos[2]), "reserved");
    }
}
