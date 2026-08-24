fn main() {
    let hash = xparq_genesis::genesis_hash().expect("construct frozen genesis");
    for byte in hash.0 {
        print!("{byte:02x}");
    }
    println!();
}
