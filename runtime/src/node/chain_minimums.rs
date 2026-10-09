//! Local admission policy for remote chain candidates. This is not consensus and
//! never substitutes advertised totals for verified PoW or execution validation.
use std::collections::BTreeMap;

use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ChainMinimums {
    pub work: Work,
    pub weight: u64,
}

impl ChainMinimums {
    pub fn allows(self, work: Work, weight: u64) -> bool {
        work >= self.work && weight >= self.weight
    }
}

static MINIMUMS: OnceLock<RwLock<BTreeMap<PathBuf, ChainMinimums>>> = OnceLock::new();

pub(super) fn configure(database: &Path, minimums: ChainMinimums) -> Result<(), String> {
    MINIMUMS
        .get_or_init(Default::default)
        .write()
        .map_err(|_| "chain minimums lock is poisoned")?
        .insert(database.to_path_buf(), minimums);
    Ok(())
}

pub(super) fn configured(database: &Path) -> Result<ChainMinimums, String> {
    Ok(MINIMUMS
        .get_or_init(Default::default)
        .read()
        .map_err(|_| "chain minimums lock is poisoned")?
        .get(database)
        .copied()
        .unwrap_or_default())
}

pub(super) fn allows(database: &Path, work: Work, weight: u64) -> Result<bool, String> {
    Ok(configured(database)?.allows(work, weight))
}

/// Work uses the same big-endian hexadecimal representation as /status; accept
/// abbreviated leading-zero forms without truncating any of its 512 bits.
pub(super) fn parse_work(value: &str) -> Result<Work, String> {
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if value.is_empty() || value.len() > 128 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(
            "--minimum-chain-work must contain 1–128 hexadecimal digits (optional 0x prefix)"
                .into(),
        );
    }
    let padded = format!("{value:0>128}");
    let mut limbs = [0; 8];
    for (limb, digits) in limbs.iter_mut().zip(padded.as_bytes().chunks_exact(16)) {
        *limb = u64::from_str_radix(std::str::from_utf8(digits).unwrap(), 16)
            .map_err(|_| "invalid --minimum-chain-work")?;
    }
    Ok(Work::from_be_limbs(limbs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floors_are_independent_inclusive_and_do_not_replace_work_first_fork_choice() {
        let minimums = ChainMinimums {
            work: Work::pow2(70),
            weight: 100,
        };
        assert!(minimums.allows(minimums.work, 100));
        assert!(!minimums.allows(Work::pow2(69), u64::MAX));
        assert!(!minimums.allows(Work::MAX, 99));
        assert!(ChainMinimums::default().allows(Work::ZERO, 0));
        assert!(minimums.allows(Work::pow2(72), 100));
        // A higher-work chain can still win with lower weight once both meet the floor.
        assert!(
            compare_chain_tips(
                Work::pow2(72),
                100,
                BlockHash([1; 32]),
                Work::pow2(71),
                1000,
                BlockHash([2; 32])
            )
            .is_gt()
        );
    }

    #[test]
    fn work_parser_preserves_all_512_bits_and_rejects_invalid_or_overflow_values() {
        for value in ["0", "0x0", "0X0000"] {
            assert_eq!(parse_work(value).unwrap(), Work::ZERO);
        }
        assert_eq!(parse_work("10000000000000000").unwrap(), Work::pow2(64));
        assert_eq!(parse_work(&"f".repeat(128)).unwrap(), Work::MAX);
        for value in ["", "0x", "-1", "+1", " 1", "1 ", "xyz", &"f".repeat(129)] {
            assert!(parse_work(value).is_err(), "{value}");
        }
        let work = Work::from_be_limbs([1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            parse_work(&super::super::util::format_work(work.to_be_limbs())).unwrap(),
            work
        );
    }
}
