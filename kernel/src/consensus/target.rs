use crypto::{POW_HASH_SIZE, PoWHash};

/// Bitcoin-style compact target uses 23 bits for the mantissa.
const COMPACT_MANTISSA_MASK: u32 = 0x007f_ffff;

/// Bit 23 is reserved as the sign bit.
///
/// XPARQ targets are unsigned, therefore this bit must always be zero.
const COMPACT_SIGN_MASK: u32 = 0x0080_0000;

/// Easiest PoW target permitted by XPARQ consensus.
///
/// 0x2000ffff corresponds to approximately 256 uniformly random
/// 256-bit hashes per valid PoW at the easiest permitted target.
///
/// Actual network difficulty may be substantially harder than this.
pub const POW_LIMIT_BITS: u32 = 0x201fffff;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PoWTarget([u8; POW_HASH_SIZE]);

impl PoWTarget {
    /// Constructs a target from its canonical 256-bit big-endian form.
    ///
    /// Zero is not a valid PoW target.
    pub fn from_bytes(bytes: [u8; POW_HASH_SIZE]) -> Option<Self> {
        let target = Self(bytes);

        if target.is_zero() { None } else { Some(target) }
    }

    /// Returns the target as a 256-bit big-endian integer.
    pub const fn as_bytes(&self) -> &[u8; POW_HASH_SIZE] {
        &self.0
    }

    fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }

    /// Returns true when `hash <= target`.
    ///
    /// Both `PoWHash` and `PoWTarget` must use the same big-endian
    /// numeric byte order.
    #[inline]
    pub fn meets(self, hash: &PoWHash) -> bool {
        hash.as_bytes() <= self.as_bytes()
    }

    /// Returns the maximum/easiest target permitted by XPARQ consensus.
    pub fn pow_limit() -> Self {
        Self::from_compact(POW_LIMIT_BITS).expect("POW_LIMIT_BITS must encode a valid PoW target")
    }

    /// Scales this 256-bit target by:
    ///
    /// ```text
    /// target * numerator / denominator
    /// ```
    ///
    /// This operation does not apply the XPARQ PoW limit.
    ///
    /// Use `scale_ratio_consensus()` when adjusting consensus difficulty.
    pub fn scale_ratio(self, numerator: u32, denominator: u32) -> Option<Self> {
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
            let product = u32::from(self.0[index])
                .checked_mul(numerator)?
                .checked_add(carry)?;

            wide[index + 1] = (product & 0xff) as u8;
            carry = product >> 8;
        }

        // numerator <= 255, therefore the remaining carry
        // always fits inside one byte.
        if carry > u8::MAX as u32 {
            return None;
        }

        wide[0] = carry as u8;

        // Divide the 264-bit intermediate by denominator.
        let mut remainder = 0_u32;

        for byte in &mut wide {
            let value = (remainder << 8) | u32::from(*byte);

            *byte = (value / denominator) as u8;
            remainder = value % denominator;
        }

        // Result must fit back into 256 bits.
        if wide[0] != 0 {
            return None;
        }

        let mut bytes = [0_u8; POW_HASH_SIZE];
        bytes.copy_from_slice(&wide[1..]);

        // Integer division may reduce the minimum target to zero.
        //
        // Consensus never permits a zero target, therefore saturate
        // at the smallest possible non-zero 256-bit target.
        if bytes.iter().all(|byte| *byte == 0) {
            bytes[POW_HASH_SIZE - 1] = 1;
        }

        Some(Self(bytes))
    }

    /// Scales a target for XPARQ consensus difficulty adjustment.
    ///
    /// The resulting target is always bounded by `POW_LIMIT_BITS`.
    ///
    /// This means difficulty adjustment can make mining easier,
    /// but never easier than the XPARQ consensus PoW limit.
    pub fn scale_ratio_consensus(self, numerator: u32, denominator: u32) -> Option<Self> {
        if numerator == 0
            || denominator == 0
            || numerator > u8::MAX as u32
            || denominator > u8::MAX as u32
        {
            return None;
        }

        let pow_limit = Self::pow_limit();

        match self.scale_ratio(numerator, denominator) {
            Some(target) => Some(target.min(pow_limit)),

            // A valid upward scaling may overflow 256 bits.
            //
            // Consensus interprets that as reaching the easiest
            // permitted target rather than accepting an invalid target.
            None if numerator > denominator => Some(pow_limit),

            None => None,
        }
    }

    /// Decodes Bitcoin-style compact target representation.
    ///
    /// Layout:
    ///
    /// ```text
    /// [ exponent: 8 bits ][ sign: 1 bit ][ mantissa: 23 bits ]
    /// ```
    ///
    /// This function only decodes the compact numeric representation.
    /// It does NOT enforce the XPARQ PoW limit or canonical encoding.
    ///
    /// Consensus code should use `from_consensus_compact()`.
    pub fn from_compact(compact: u32) -> Option<Self> {
        let size = (compact >> 24) as usize;
        let mantissa = compact & COMPACT_MANTISSA_MASK;

        // XPARQ PoW targets are unsigned.
        if compact & COMPACT_SIGN_MASK != 0 {
            return None;
        }

        // Zero exponent or zero mantissa cannot represent
        // a valid non-zero target.
        if size == 0 || mantissa == 0 {
            return None;
        }

        // Bitcoin-style 256-bit overflow limits.
        let overflow =
            size > 34 || (mantissa > 0xff && size > 33) || (mantissa > 0xffff && size > 32);

        if overflow {
            return None;
        }

        let mut bytes = [0_u8; POW_HASH_SIZE];

        if size <= 3 {
            let shift = 8 * (3 - size);
            let value = mantissa >> shift;

            for index in 0..size {
                let value_shift = 8 * (size - 1 - index);

                bytes[POW_HASH_SIZE - size + index] = ((value >> value_shift) & 0xff) as u8;
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

                // Exponent 33 or 34 can place leading mantissa bytes
                // outside the 256-bit target.
                //
                // Those bytes must be zero or the target overflows.
                if index < 0 {
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

        Self::from_bytes(bytes)
    }

    /// Decodes and validates an XPARQ consensus target.
    ///
    /// Consensus requires:
    ///
    /// - valid compact encoding
    /// - canonical compact encoding
    /// - unsigned target
    /// - non-zero target
    /// - target <= POW_LIMIT
    pub fn from_consensus_compact(compact: u32) -> Option<Self> {
        let target = Self::from_compact(compact)?;

        // A single numeric target must have exactly one representation
        // inside a block header.
        if target.to_compact() != compact {
            return None;
        }

        if target > Self::pow_limit() {
            return None;
        }

        Some(target)
    }

    /// Encodes this 256-bit target into Bitcoin-style compact form.
    ///
    /// Compact representation stores only the most significant 23 bits,
    /// therefore arbitrary raw targets may lose low-order precision.
    pub fn to_compact(self) -> u32 {
        let Some(first_nonzero) = self.0.iter().position(|byte| *byte != 0) else {
            // Normally unreachable because zero targets cannot be
            // constructed through public constructors.
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

        // Bit 23 is reserved for the compact sign bit.
        //
        // Shift right one byte if the highest mantissa bit would
        // otherwise be interpreted as a sign.
        if mantissa & COMPACT_SIGN_MASK != 0 {
            mantissa >>= 8;
            size += 1;
        }

        (size << 24) | (mantissa & COMPACT_MANTISSA_MASK)
    }
}

/// Returns true when `hash` satisfies `target`.
#[inline]
pub fn hash_meets_target(hash: &PoWHash, target: PoWTarget) -> bool {
    target.meets(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitcoin_genesis_compact_target_roundtrip() {
        let bits = 0x1d00_ffff;

        let target = PoWTarget::from_compact(bits).expect("valid compact target");

        assert_eq!(target.to_compact(), bits);

        assert_eq!(
            target.as_bytes(),
            &[
                0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn xparq_pow_limit_roundtrip() {
        let target = PoWTarget::from_compact(POW_LIMIT_BITS).expect("valid XPARQ PoW limit");

        assert_eq!(target.to_compact(), POW_LIMIT_BITS);
    }

    #[test]
    fn xparq_consensus_accepts_pow_limit() {
        let target = PoWTarget::from_consensus_compact(POW_LIMIT_BITS);

        assert!(target.is_some());
    }

    #[test]
    fn xparq_consensus_rejects_target_above_pow_limit() {
        // Easier than the current PoW limit.
        assert!(PoWTarget::from_consensus_compact(POW_LIMIT_BITS + 1).is_none());
    }

    #[test]
    fn rejects_negative_compact_target() {
        assert!(PoWTarget::from_compact(0x1d80_ffff).is_none());
    }

    #[test]
    fn rejects_zero_compact_target() {
        assert!(PoWTarget::from_compact(0).is_none());
    }

    #[test]
    fn rejects_zero_raw_target() {
        assert!(PoWTarget::from_bytes([0_u8; POW_HASH_SIZE]).is_none());
    }

    #[test]
    fn accepts_smallest_nonzero_raw_target() {
        let mut bytes = [0_u8; POW_HASH_SIZE];
        bytes[POW_HASH_SIZE - 1] = 1;

        assert!(PoWTarget::from_bytes(bytes).is_some());
    }

    #[test]
    fn target_scaling_harder_reduces_target() {
        let target = PoWTarget::from_compact(POW_LIMIT_BITS).expect("valid target");

        let harder = target
            .scale_ratio_consensus(95, 100)
            .expect("target scaling succeeds");

        assert!(harder < target);
    }

    #[test]
    fn target_scaling_easier_increases_target() {
        let target = PoWTarget::from_compact(0x2000_7fff).expect("valid target");

        let easier = target
            .scale_ratio_consensus(105, 100)
            .expect("target scaling succeeds");

        assert!(easier > target);
        assert!(easier <= PoWTarget::pow_limit());
    }

    #[test]
    fn easier_scaling_never_exceeds_pow_limit() {
        let target = PoWTarget::from_compact(POW_LIMIT_BITS).expect("valid target");

        let easier = target
            .scale_ratio_consensus(120, 100)
            .expect("target scaling succeeds");

        assert_eq!(easier, PoWTarget::pow_limit());
    }

    #[test]
    fn target_scaling_identity_preserves_target() {
        let target = PoWTarget::from_compact(0x2000_7fff).expect("valid target");

        let same = target
            .scale_ratio_consensus(100, 100)
            .expect("target scaling succeeds");

        assert_eq!(same, target);
    }

    #[test]
    fn target_scaling_rejects_large_ratio_values() {
        let target = PoWTarget::from_compact(0x2000_7fff).expect("valid target");

        assert!(target.scale_ratio(256, 100).is_none());
        assert!(target.scale_ratio(100, 256).is_none());

        assert!(target.scale_ratio_consensus(256, 100).is_none());

        assert!(target.scale_ratio_consensus(100, 256).is_none());
    }

    #[test]
    fn target_scaling_rejects_zero_ratio_values() {
        let target = PoWTarget::from_compact(0x2000_7fff).expect("valid target");

        assert!(target.scale_ratio(0, 100).is_none());
        assert!(target.scale_ratio(100, 0).is_none());
    }

    #[test]
    fn minimum_target_never_scales_to_zero() {
        let mut bytes = [0_u8; POW_HASH_SIZE];
        bytes[POW_HASH_SIZE - 1] = 1;

        let target = PoWTarget::from_bytes(bytes).expect("valid minimum target");

        let harder = target.scale_ratio(95, 100).expect("scaling succeeds");

        assert_eq!(harder, target);
    }

    #[test]
    fn rejects_noncanonical_consensus_compact() {
        // Both encode the same numeric target:
        //
        // non-canonical: 0x04001234
        // canonical:     0x03123400
        let target = PoWTarget::from_compact(0x0400_1234).expect("numeric target is valid");

        assert_eq!(target.to_compact(), 0x0312_3400);

        assert!(PoWTarget::from_consensus_compact(0x0400_1234).is_none());

        assert!(PoWTarget::from_consensus_compact(0x0312_3400).is_some());
    }

    #[test]
    fn canonical_compact_targets_roundtrip() {
        let targets = [0x1d00_ffff, POW_LIMIT_BITS, 0x1f7f_ff00, 0x1f12_3456];

        for bits in targets {
            let target = PoWTarget::from_compact(bits).expect("valid compact target");

            assert_eq!(
                target.to_compact(),
                bits,
                "compact target {bits:#010x} did not roundtrip"
            );
        }
    }
}
