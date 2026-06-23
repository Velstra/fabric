fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/raft.proto");
    println!("cargo:rerun-if-env-changed=PROTOC");
    // Vendor a protoc unless the caller set one (see velstra-proto/build.rs).
    // `set_var` is `unsafe` in edition 2024 — safe here: single-threaded build
    // script, set once before proto compilation.
    if std::env::var_os("PROTOC").is_none() {
        unsafe {
            std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
        }
    }
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&["proto/raft.proto"], &["proto"])?;
    Ok(())
}
