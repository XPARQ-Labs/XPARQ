fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/xparq_node.proto");
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }
    tonic_prost_build::configure()
        .build_client(false)
        .compile_protos(&["proto/xparq_node.proto"], &["proto"])?;
    Ok(())
}
