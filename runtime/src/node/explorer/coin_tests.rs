use super::*;
use kernel::{
    ledger::{CoinRecord, LedgerState, utxo::CoinUtxo},
    monetary::{
        asset::{AssetContract, AssetRecord, AssetShare, Metadata, Share, Unit},
        coin::CoinShare,
    },
    program::ProgramRegistry,
};
use std::collections::BTreeMap;

#[test]
fn coin_pages_are_independent_of_large_asset_inventories() {
    let program = ProgramId([17; 32]);
    let owner = Owner::Program(program);
    let coins: BTreeMap<_, _> = (0..1001u64)
        .map(|i| {
            let mut id = [0; 32];
            id[..8].copy_from_slice(&i.to_be_bytes());
            (
                CoinShare::from_bytes(id),
                CoinUtxo {
                    amount: Zeno::ONE,
                    owner,
                },
            )
        })
        .collect();
    let mut records = BTreeMap::new();
    let mut shares = BTreeMap::new();
    for i in 0..7000u64 {
        let metadata =
            Metadata::new(format!("Asset {i}"), Unit::from_units(1), owner, owner).unwrap();
        let asset = AssetContract::derive(&metadata, i).unwrap();
        records.insert(
            asset,
            AssetRecord {
                metadata,
                supply: Unit::from_units(1),
                total_minted: Unit::from_units(1),
                total_burned: Unit::ZERO,
                mint_nonce: 0,
            },
        );
        let mut id = [0; 32];
        id[..8].copy_from_slice(&i.to_be_bytes());
        shares.insert(
            Share::from_bytes(id),
            AssetShare::new(asset, Unit::from_units(1), owner),
        );
    }
    // Decode detached state for a read-only response fixture; never install it
    // in a live ledger or bypass block admission.
    let decode = |records: &BTreeMap<AssetContract, AssetRecord>,
                  shares: &BTreeMap<Share, AssetShare>| {
        LedgerState::try_from_slice(
            &borsh::to_vec(&(
                (&coins, Zeno::from_zeno(1001)),
                CoinRecord {
                    total_mined: Zeno::from_zeno(1001),
                    total_burned: Zeno::ZERO,
                },
                ProgramRegistry::default(),
                (records, shares),
            ))
            .unwrap(),
        )
        .unwrap()
    };
    let state = decode(&records, &shares);
    let empty_assets = decode(&BTreeMap::new(), &BTreeMap::new());
    let inventory: Vec<_> = state.extensions().assets.shares_by_owner(owner)
        .map(|(id, share)| serde_json::json!({
            "id": id.to_string(), "asset": share.asset.to_string(), "amount": share.amount.to_string()
        })).collect();
    assert_eq!(inventory.len(), 7000);
    assert!(serde_json::to_vec(&inventory).unwrap().len() > 1024 * 1024);

    let page = coin_account_response(&state, Some(Height(10)), &[], program, 0, None).unwrap();
    assert_eq!(
        page,
        coin_account_response(&empty_assets, Some(Height(10)), &[], program, 0, None).unwrap()
    );
    assert!(page.get("asset_shares").is_none());
    assert!(page.get("program_assets").is_none());
    assert!(serde_json::to_vec(&page).unwrap().len() < 1024 * 1024 - 1024);
    assert_eq!(page["total"], 1001);
    assert_eq!(page["next_height"], 11);
    assert_eq!(page["utxos"].as_array().unwrap().len(), 1000);
    let cursor = page["next_utxo_cursor"].as_str().unwrap().parse().unwrap();
    let last =
        coin_account_response(&state, Some(Height(10)), &[], program, 0, Some(cursor)).unwrap();
    assert_eq!(last["utxos"].as_array().unwrap().len(), 1);
    assert_eq!(
        last["utxos"][0]["id"],
        coins.last_key_value().unwrap().0.to_string()
    );
    assert_eq!(last["utxo_snapshot"], page["utxo_snapshot"]);
    assert!(last["next_utxo_cursor"].is_null());
    assert_eq!(
        last,
        coin_account_response(&state, Some(Height(10)), &[], program, 1000, None).unwrap()
    );
}

#[test]
fn coin_rpc_routes_preserve_legacy_account_fields_and_validate_queries() {
    use super::super::rpc::handle_rpc_connection;
    let database = std::env::temp_dir().join(format!(
        "xparq-coin-rpc-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let program = ProgramId([17; 32]).to_string();
    let get = |route: String| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        write!(client, "GET {route} HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let result = handle_rpc_connection(&database, &mut server);
        drop(server);
        result?;
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).unwrap();
        let start = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        Ok::<serde_json::Value, String>(serde_json::from_slice(&bytes[start..]).unwrap())
    };
    let coin = get(format!("/program/coins/{program}")).unwrap();
    let mut legacy = get(format!("/program/account/{program}")).unwrap();
    assert!(
        legacy
            .as_object_mut()
            .unwrap()
            .remove("asset_shares")
            .unwrap()
            .is_array()
    );
    assert!(
        legacy
            .as_object_mut()
            .unwrap()
            .remove("program_assets")
            .unwrap()
            .is_array()
    );
    assert_eq!(coin, legacy);
    for query in [
        "utxo_offset=0".to_string(),
        format!("utxo_after={}", "0".repeat(64)),
    ] {
        assert_eq!(
            coin,
            get(format!("/program/coins/{program}?{query}")).unwrap()
        );
    }
    for route in [
        "/program/coins/bad".to_string(),
        format!("/program/coins/{program}?utxo_after=bad"),
        format!("/program/coins/{program}?utxo_offset=-1"),
        format!(
            "/program/coins/{program}?utxo_offset=0&utxo_after={}",
            "0".repeat(64)
        ),
    ] {
        assert!(get(route).is_err());
    }
    fs::remove_dir_all(database).unwrap();
}
