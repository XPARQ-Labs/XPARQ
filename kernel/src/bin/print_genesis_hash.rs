fn main() {
    let mut block = kernel::blockchain::Block::genesis().expect("construct genesis candidate");
    let nonce = std::env::args()
        .nth(1)
        .map(|value| value.parse().expect("genesis nonce must be a u64"))
        .unwrap_or(kernel::genesis::GENESIS_NONCE);
    block.header.nonce = kernel::common::Nonce(nonce);
    let hash = block.hash().expect("hash genesis candidate");
    for byte in hash.into_bytes() {
        print!("{byte:02x}");
    }
    println!();
}
