#![no_main]

use libfuzzer_sys::fuzz_target;
use xparq::crypto::{ADDRESS_SIZE, Address, address_from_string, address_to_string};

fuzz_target!(|data: &[u8]| {
    let mut bytes = [0_u8; ADDRESS_SIZE];
    let copied = data.len().min(ADDRESS_SIZE);
    bytes[..copied].copy_from_slice(&data[..copied]);
    let address = Address(bytes);
    let encoded = address_to_string(&address);

    assert_eq!(encoded.len(), 40);
    assert!(encoded.starts_with("x1"));
    assert_eq!(encoded, encoded.to_ascii_lowercase());
    assert_eq!(address_from_string(&encoded), Ok(address));

    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(decoded) = address_from_string(text) {
            assert_eq!(
                address_from_string(&address_to_string(&decoded)),
                Ok(decoded)
            );
        }
    }
});
