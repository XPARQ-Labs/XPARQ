use std::fmt;

use crate::AssetIdParseError;

pub(crate) const ASSET_ID_SIZE: usize = blake3::OUT_LEN;
pub(crate) const ASSET_ID_PREFIX: &str = "asset:";
const ASSET_ID_CONTEXT: &str = "xparq:asset-id";

/// Derives an asset identifier from unambiguous length-delimited fields.
pub(crate) fn derive(fields: &[&[u8]]) -> [u8; ASSET_ID_SIZE] {
    let mut hasher = blake3::Hasher::new_derive_key(ASSET_ID_CONTEXT);
    for field in fields {
        hasher.update(&(field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    *hasher.finalize().as_bytes()
}

pub(crate) fn fmt(bytes: &[u8; ASSET_ID_SIZE], formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(ASSET_ID_PREFIX)?;
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

pub(crate) fn parse(value: &str) -> Result<[u8; ASSET_ID_SIZE], AssetIdParseError> {
    let encoded = value
        .strip_prefix(ASSET_ID_PREFIX)
        .ok_or(AssetIdParseError)?;
    if encoded.len() != ASSET_ID_SIZE * 2
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(AssetIdParseError);
    }

    let mut bytes = [0; ASSET_ID_SIZE];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = (hex_nibble(encoded.as_bytes()[offset]).ok_or(AssetIdParseError)? << 4)
            | hex_nibble(encoded.as_bytes()[offset + 1]).ok_or(AssetIdParseError)?;
    }
    Ok(bytes)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_has_a_stable_test_vector() {
        assert_eq!(
            derive(&[b"field one", b"field two"]),
            [
                14, 233, 248, 156, 161, 240, 236, 75, 209, 13, 209, 115, 189, 81, 26, 129, 209,
                107, 222, 130, 28, 168, 168, 0, 49, 16, 97, 154, 110, 97, 0, 236,
            ]
        );
    }

    #[test]
    fn text_format_is_explicit_and_canonical() {
        let canonical = format!("{ASSET_ID_PREFIX}{}", "ab".repeat(ASSET_ID_SIZE));
        assert!(parse(&canonical).is_ok());
        assert!(parse(&"ab".repeat(ASSET_ID_SIZE)).is_err());
        assert!(parse(&format!("ASSET:{}", "ab".repeat(ASSET_ID_SIZE))).is_err());
        assert!(parse(&format!("{ASSET_ID_PREFIX}{}", "AB".repeat(ASSET_ID_SIZE))).is_err());
    }
}
