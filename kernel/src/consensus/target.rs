use crypto::{POW_HASH_SIZE, PoWHash};

const COMPACT_MANTISSA_MASK: u32 = 0x007f_ffff;
const COMPACT_SIGN_MASK: u32 = 0x0080_0000;

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct PoWTarget([u8; POW_HASH_SIZE]);

impl PoWTarget {
    pub const fn new(bytes: [u8; POW_HASH_SIZE]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; POW_HASH_SIZE] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }

    /// Returns true when the PoW hash is numerically less than or equal
    /// to this target.
    ///
    /// Both values use canonical big-endian byte ordering.
    pub fn meets(self, hash: &PoWHash) -> bool {
        hash.as_bytes() <= self.as_bytes()
    }

    /// Compatibility conversion for the old XPARQ leading-zero difficulty.
    ///
    /// difficulty 1 -> 0x7fff...
    /// difficulty 2 -> 0x3fff...
    /// difficulty 8 -> 0x00ff...
    ///
    /// Remove this after all legacy difficulty-based consensus code
    /// has been migrated to compact targets.
    pub fn from_leading_zero_bits(difficulty: u32) -> Option<Self> {
        let total_bits = (POW_HASH_SIZE * 8) as u32;

        if difficulty > total_bits {
            return None;
        }

        let mut bytes = [0xff_u8; POW_HASH_SIZE];

        let full_zero_bytes = (difficulty / 8) as usize;
        let remaining_zero_bits = (difficulty % 8) as u8;

        for byte in bytes.iter_mut().take(full_zero_bytes) {
            *byte = 0;
        }

        if remaining_zero_bits != 0 {
            let byte = bytes.get_mut(full_zero_bytes)?;
            *byte = 0xff >> remaining_zero_bits;
        }

        Some(Self(bytes))
    }

    /// Scales this 256-bit target by a small rational value.
    ///
    /// Examples:
    ///
    /// 95 / 100  -> smaller target -> harder PoW
    /// 105 / 100 -> larger target  -> easier PoW
    ///
    /// A 33-byte intermediate is used so multiplication can temporarily
    /// exceed 256 bits before division.
    pub fn scale_ratio(
        self,
        numerator: u32,
        denominator: u32,
    ) -> Option<Self> {
        if numerator == 0
            || denominator == 0
            || numerator > u8::MAX as u32
            || denominator > u8::MAX as u32
        {
            return None;
        }

        let mut wide = [0_u8; POW_HASH_SIZE + 1];
        let mut carry = 0_u32;

        // Multiply the 256-bit big-endian target by numerator.
        for index in (0..POW_HASH_SIZE).rev() {
            let product =
                u32::from(self.0[index]) * numerator + carry;

            wide[index + 1] = (product & 0xff) as u8;
            carry = product >> 8;
        }

        wide[0] = carry as u8;

        // Divide the 264-bit intermediate by denominator.
        let mut remainder = 0_u32;

        for byte in &mut wide {
            let value = (remainder << 8) | u32::from(*byte);

            *byte = (value / denominator) as u8;
            remainder = value % denominator;
        }

        // Final result must fit into 256 bits.
        if wide[0] != 0 {
            return None;
        }

        let mut bytes = [0_u8; POW_HASH_SIZE];
        bytes.copy_from_slice(&wide[1..]);

        // A zero target would make PoW impossible.
        // Clamp to the smallest non-zero target instead.
        if bytes.iter().all(|byte| *byte == 0) {
            bytes[POW_HASH_SIZE - 1] = 1;
        }

        Some(Self(bytes))
    }

    /// Decodes Bitcoin-style compact target representation.
    ///
    /// Layout:
    ///
    /// [ exponent: 8 bits ][ mantissa: 23 bits ]
    ///
    /// The compact sign bit is rejected because PoW targets are unsigned.
    pub fn from_compact(compact: u32) -> Option<Self> {
        let size = (compact >> 24) as usize;
        let mantissa = compact & COMPACT_MANTISSA_MASK;

        if compact & COMPACT_SIGN_MASK != 0 {
            return None;
        }

        if size == 0 || mantissa == 0 {
            return None;
        }

        // Bitcoin-style 256-bit overflow limits.
        let overflow = size > 34
            || (mantissa > 0xff && size > 33)
            || (mantissa > 0xffff && size > 32);

        if overflow {
            return None;
        }

        let mut bytes = [0_u8; POW_HASH_SIZE];

        if size <= 3 {
            let shift = 8 * (3 - size);
            let value = mantissa >> shift;

            for index in 0..size {
                let value_shift = 8 * (size - 1 - index);

                bytes[POW_HASH_SIZE - size + index] =
                    ((value >> value_shift) & 0xff) as u8;
            }
        } else {
            let mantissa_bytes = [
                ((mantissa >> 16) & 0xff) as u8,
                ((mantissa >> 8) & 0xff) as u8,
                (mantissa & 0xff) as u8,
            ];

            let base = POW_HASH_SIZE as isize - size as isize;

            for (offset, byte) in mantissa_bytes.into_iter().enumerate() {
                let index = base + offset as isize;

                if index < 0 {
                    // Compact values with exponent 33/34 may begin outside
                    // the 256-bit buffer, but those bytes must be zero.
                    if byte != 0 {
                        return None;
                    }

                    continue;
                }

                if index >= POW_HASH_SIZE as isize {
                    continue;
                }

                bytes[index as usize] = byte;
            }
        }

        let target = Self(bytes);

        if target.is_zero() {
            None
        } else {
            Some(target)
        }
    }

    /// Encodes this 256-bit target into Bitcoin-style compact form.
    ///
    /// Compact representation stores only the most significant 23 bits,
    /// so arbitrary targets may lose low-order precision.
    pub fn to_compact(self) -> u32 {
        let Some(first_nonzero) =
            self.0.iter().position(|byte| *byte != 0)
        else {
            return 0;
        };

        let mut size = (POW_HASH_SIZE - first_nonzero) as u32;

        let mut mantissa = if size <= 3 {
            let mut value = 0_u32;

            for byte in &self.0[first_nonzero..] {
                value = (value << 8) | u32::from(*byte);
            }

            value << (8 * (3 - size))
        } else {
            let first = u32::from(self.0[first_nonzero]);

            let second = self
                .0
                .get(first_nonzero + 1)
                .copied()
                .map(u32::from)
                .unwrap_or(0);

            let third = self
                .0
                .get(first_nonzero + 2)
                .copied()
                .map(u32::from)
                .unwrap_or(0);

            (first << 16) | (second << 8) | third
        };

        // Bit 23 is the compact sign bit.
        // Shift right one byte if the mantissa would set it.
        if mantissa & COMPACT_SIGN_MASK != 0 {
            mantissa >>= 8;
            size += 1;
        }

        (size << 24) | (mantissa & COMPACT_MANTISSA_MASK)
    }
}

pub fn hash_meets_target(
    hash: &PoWHash,
    target: PoWTarget,
) -> bool {
    target.meets(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitcoin_genesis_compact_target_roundtrip() {
        let bits = 0x1d00_ffff;

        let target =
            PoWTarget::from_compact(bits)
                .expect("valid compact target");

        assert_eq!(target.to_compact(), bits);

        assert_eq!(
            target.as_bytes(),
            &[
                0x00, 0x00, 0x00, 0x00,
                0xff, 0xff, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn xparq_pow_limit_roundtrip() {
        let bits = 0x207f_ffff;

        let target =
            PoWTarget::from_compact(bits)
                .expect("valid XPARQ PoW limit");

        assert_eq!(target.to_compact(), bits);
    }

    #[test]
    fn rejects_negative_compact_target() {
        assert!(
            PoWTarget::from_compact(0x1d80_ffff).is_none()
        );
    }

    #[test]
    fn rejects_zero_compact_target() {
        assert!(
            PoWTarget::from_compact(0).is_none()
        );
    }

    #[test]
    fn leading_zero_compatibility() {
        let target =
            PoWTarget::from_leading_zero_bits(8)
                .expect("valid difficulty");

        assert_eq!(target.as_bytes()[0], 0x00);

        assert!(
            target.as_bytes()[1..]
                .iter()
                .all(|byte| *byte == 0xff)
        );
    }

    #[test]
    fn target_scaling_harder_reduces_target() {
        let target =
            PoWTarget::from_compact(0x207f_ffff)
                .expect("valid target");

        let harder =
            target
                .scale_ratio(95, 100)
                .expect("target scaling succeeds");

        assert!(harder < target);
    }

    #[test]
    fn target_scaling_easier_increases_target() {
        let target =
            PoWTarget::from_compact(0x2007_ffff)
                .expect("valid target");

        let easier =
            target
                .scale_ratio(105, 100)
                .expect("target scaling succeeds");

        assert!(easier > target);
    }

    #[test]
    fn target_scaling_keep_preserves_target() {
        let target =
            PoWTarget::from_compact(0x2007_ffff)
                .expect("valid target");

        let same =
            target
                .scale_ratio(100, 100)
                .expect("target scaling succeeds");

        assert_eq!(same, target);
    }
}