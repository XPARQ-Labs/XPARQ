use rand::{rngs::StdRng, SeedableRng};
use sqisign_rs::{generate, Level1, Level3, Level5};
use std::{env, fs, path::Path};

macro_rules! write_level {
    ($directory:expr, $name:literal, $level:ty, $seed:expr) => {{
        let mut rng = StdRng::from_seed([$seed; 32]);
        let (public_key, signing_key) = generate::<$level>(&mut rng);
        let message = [b'P'; 64];
        let signature = signing_key
            .sign(&message, &mut rng)
            .map_err(|error| format!("{} signing failed: {error:?}", $name))?;

        let mut vector = Vec::new();
        vector.extend_from_slice(public_key.to_bytes().as_slice());
        vector.extend_from_slice(&(message.len() as u64).to_le_bytes());
        vector.extend_from_slice(signature.to_bytes().as_slice());
        vector.extend_from_slice(&message);
        fs::write($directory.join(concat!($name, "-valid.bin")), &vector)?;

        let signature_offset = public_key.to_bytes().len() + 8;
        vector[signature_offset + signature.to_bytes().len() / 2] ^= 0x80;
        fs::write($directory.join(concat!($name, "-invalid.bin")), &vector)?;
    }};
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = env::args()
        .nth(1)
        .ok_or("usage: c_interop_vectors OUTPUT_DIRECTORY")?;
    let output = Path::new(&output);
    fs::create_dir_all(output)?;

    write_level!(output, "lvl1", Level1, 0x11);
    write_level!(output, "lvl3", Level3, 0x33);
    write_level!(output, "lvl5", Level5, 0x55);
    Ok(())
}
