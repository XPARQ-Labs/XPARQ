//! SQIsign transcript backend boundary.
//!
//! Keep all signing-side SHAKE usage behind this module so the backend can be
//! changed without mixing incompatible `digest` trait versions at call sites.

pub(crate) use shake::{ExtendableOutput, Shake256, Update, XofReader};

#[cfg(test)]
mod tests {
    use super::{ExtendableOutput, Shake256, Update, XofReader};
    use sha3_legacy::digest::{
        ExtendableOutput as LegacyExtendableOutput, Update as LegacyUpdate,
        XofReader as LegacyXofReader,
    };
    use sha3_legacy::Shake256 as LegacyShake256;

    fn local(parts: &[&[u8]], chunks: &[usize]) -> Vec<u8> {
        let mut state = Shake256::default();
        for part in parts {
            state.update(part);
        }
        let mut reader = state.finalize_xof();
        let mut output = Vec::new();
        for &len in chunks {
            let start = output.len();
            output.resize(start + len, 0);
            reader.read(&mut output[start..]);
        }
        output
    }

    fn legacy(parts: &[&[u8]], chunks: &[usize]) -> Vec<u8> {
        let mut state = LegacyShake256::default();
        for part in parts {
            LegacyUpdate::update(&mut state, part);
        }
        let mut reader = LegacyExtendableOutput::finalize_xof(state);
        let mut output = Vec::new();
        for &len in chunks {
            let start = output.len();
            output.resize(start + len, 0);
            LegacyXofReader::read(&mut reader, &mut output[start..]);
        }
        output
    }

    #[test]
    fn xparq_shake256_matches_legacy_transcript_stream() {
        let cases: &[(&[&[u8]], &[usize])] = &[
            (&[], &[0, 1, 31, 32, 136, 137]),
            (&[b"SQIsign"], &[64, 7, 257]),
            (
                &[b"domain", b"", b"context", &[0, 1, 2, 0xff]],
                &[1, 135, 1, 272],
            ),
        ];

        for &(parts, chunks) in cases {
            assert_eq!(local(parts, chunks), legacy(parts, chunks));
        }
    }
}
