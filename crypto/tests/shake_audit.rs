use shake::{
    ExtendableOutput, Update, XofReader,
    digest::{ExtendableOutputReset, Reset},
};

fn check<const RATE: usize>(message: &[u8], expected: &[u8]) {
    for chunk_size in [1, 7, 8, RATE - 1, RATE, RATE + 1, 4096] {
        let mut hasher = shake::Shake::<RATE>::default();
        for chunk in message.chunks(chunk_size) {
            hasher.update(&[]);
            hasher.update(chunk);
        }
        let mut cloned = hasher.clone();
        let mut reader = hasher.finalize_xof();
        let mut actual = vec![0; expected.len()];
        for chunk in actual.chunks_mut(chunk_size) {
            reader.read(&mut []);
            reader.read(chunk);
        }
        assert_eq!(actual, expected);
        let mut output = vec![0; expected.len()];
        cloned.finalize_xof_reset().read(&mut output);
        assert_eq!(output, expected);
        cloned.update(b"discarded input");
        cloned.reset();
        cloned.update(message);
        cloned.finalize_xof().read(&mut output);
        assert_eq!(output, expected);
    }
}

#[test]
fn shared_shake_matches_python_hashlib_at_rate_boundaries() {
    // hashlib.shake_128/256; input[i] = (17*i + 11) mod 256, output 513 bytes.
    for line in include_str!("vectors/shake-audit.txt").lines() {
        let mut fields = line.split_whitespace();
        let bits: usize = fields.next().unwrap().parse().unwrap();
        let length: usize = fields.next().unwrap().parse().unwrap();
        let expected = hex::decode(fields.next().unwrap()).unwrap();
        let message: Vec<u8> = (0..length).map(|i| (i * 17 + 11) as u8).collect();
        match bits {
            128 => check::<168>(&message, &expected),
            256 => check::<136>(&message, &expected),
            _ => panic!("unknown SHAKE variant"),
        }
    }
}
