use super::*;

pub(super) fn parse_hash(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || value.contains(['/', '?', '#']) {
        return Err("Tx Hash must be 64 hexadecimal characters".into());
    }
    let bytes = hex::decode(value).map_err(|_| "Tx Hash is not valid hexadecimal")?;
    bytes
        .try_into()
        .map_err(|_| "Tx Hash must be 32 bytes".to_string())
}

pub(super) fn format_work(limbs: [u64; 8]) -> String {
    limbs
        .into_iter()
        .map(|limb| format!("{limb:016x}"))
        .collect()
}

pub(super) fn parse_address(value: &str) -> Result<Address, String> {
    address_from_string(value)
        .map_err(|_| "miner address must use canonical Qx hex with an kernel checksum".to_string())
}
