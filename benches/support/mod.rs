use std::{hint::black_box, time::Instant};

pub struct Config {
    pub samples: usize,
    pub verify_rounds: usize,
    pub signature_heavy: bool,
    pub blocks: usize,
    pub state_utxos: usize,
}

impl Config {
    pub fn from_args() -> Self {
        let mut config = Self {
            samples: 5,
            verify_rounds: 100,
            signature_heavy: false,
            blocks: 128,
            state_utxos: 50_000,
        };
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--bench" => {} // Cargo supplies this to harness=false targets.
                "--quick" => {
                    config.samples = 1;
                    config.verify_rounds = 10;
                    config.blocks = 8;
                    config.state_utxos = 1000;
                }
                "--signature-heavy" => config.signature_heavy = true,
                "--blocks" => {
                    config.blocks = args
                        .next()
                        .expect("--blocks value")
                        .parse()
                        .expect("invalid blocks")
                }
                "--state-utxos" => {
                    config.state_utxos = args
                        .next()
                        .expect("--state-utxos value")
                        .parse()
                        .expect("invalid UTXOs")
                }
                "--samples" => {
                    config.samples = args
                        .next()
                        .expect("--samples needs a value")
                        .parse()
                        .expect("invalid samples")
                }
                "--verify-rounds" => {
                    config.verify_rounds = args
                        .next()
                        .expect("--verify-rounds needs a value")
                        .parse()
                        .expect("invalid rounds")
                }
                _ => panic!(
                    "unknown argument {arg}; use --quick, --samples N, --verify-rounds N, --signature-heavy, --blocks N, --state-utxos N"
                ),
            }
        }
        assert!((1..=1000).contains(&config.samples));
        assert!((1..=10000).contains(&config.verify_rounds));
        assert!((1..=10_000).contains(&config.blocks));
        assert!((1..=200_000).contains(&config.state_utxos));
        println!(
            "# samples={}, warmup=1, verify_rounds={}, arch={}, os={}, threads={}",
            config.samples,
            config.verify_rounds,
            std::env::consts::ARCH,
            std::env::consts::OS,
            std::thread::available_parallelism().unwrap().get()
        );
        println!("case,operation,median_ms,min_ms,max_ms");
        config
    }
}

pub fn timed<T>(f: impl FnOnce() -> T) -> (T, f64) {
    let start = Instant::now();
    let result = black_box(f());
    (result, start.elapsed().as_secs_f64() * 1000.)
}

pub fn report(case: &str, operation: &str, values: &[f64]) {
    let mut values = values.to_vec();
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    let median = if values.len().is_multiple_of(2) {
        (values[middle - 1] + values[middle]) / 2.
    } else {
        values[middle]
    };
    println!(
        "{case},{operation},{median:.6},{:.6},{:.6}",
        values[0],
        values[values.len() - 1]
    );
}
