//! SQIsign verifier transcript backend boundary.

pub(crate) use shake::{ExtendableOutput, Shake256, Update, XofReader};

#[cfg(test)]
mod tests {
    use super::{ExtendableOutput, Shake256, Update, XofReader};
    use alloc::{vec, vec::Vec};
    use sha3_legacy::digest::{
        ExtendableOutput as LegacyExtendableOutput, Update as LegacyUpdate,
        XofReader as LegacyXofReader,
    };
    use sha3_legacy::Shake256 as LegacyShake256;

    fn squeeze_local(parts: &[&[u8]], output: &mut [u8]) {
        let mut state = Shake256::default();
        for part in parts {
            state.update(part);
        }
        state.finalize_xof().read(output);
    }

    fn squeeze_legacy(parts: &[&[u8]], output: &mut [u8]) {
        let mut state = LegacyShake256::default();
        for part in parts {
            LegacyUpdate::update(&mut state, part);
        }
        let mut reader = LegacyExtendableOutput::finalize_xof(state);
        LegacyXofReader::read(&mut reader, output);
    }

    #[test]
    fn paqus_shake256_matches_legacy_transcript() {
        for input_len in [0, 1, 7, 135, 136, 137, 271, 272, 273] {
            let input: Vec<u8> = (0..input_len).map(|i| (i as u8).wrapping_mul(29)).collect();
            for output_len in [0, 1, 31, 32, 64, 135, 136, 137, 512] {
                let parts = [&input[..input_len / 2], &input[input_len / 2..]];
                let mut local = vec![0; output_len];
                let mut legacy = vec![0; output_len];
                squeeze_local(&parts, &mut local);
                squeeze_legacy(&parts, &mut legacy);
                assert_eq!(local, legacy);
            }
        }
    }
}
