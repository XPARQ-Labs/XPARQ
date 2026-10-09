fn main() {
    for scheme in crypto::AccountSignatureScheme::ALL
        .into_iter()
        .filter(|s| s.is_slh_dsa())
    {
        let key = crypto::SigningSeed::new(scheme, Box::new([31; 32]));
        let public = key.public_key();
        let signature = key.sign(b"dependency-sharing-regression");
        println!(
            "{} {} {}",
            scheme,
            hex::encode(public.bytes),
            crypto::hash_bytes(&signature.bytes)
        );
    }
}
