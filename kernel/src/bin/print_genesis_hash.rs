fn main() {
    let hash = kernel::genesis::genesis_hash().expect("construct frozen genesis");
    for byte in hash.into_bytes() {
        print!("{byte:02x}");
    }
    println!();
}
