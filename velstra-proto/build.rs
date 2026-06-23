//! Compiles `proto/velstra.proto` into Rust client + server stubs via
//! `tonic-build`. A vendored `protoc` is used so neither this crate nor any
//! downstream consumer needs a system `protoc` installed.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/velstra.proto");
    // prost-build (under tonic-build) reads $PROTOC; point it at the vendored
    // binary. `set_var` is `unsafe` in edition 2024 — safe here: single-threaded
    // build script, set once before any proto compilation.
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }
    tonic_build::configure().compile_protos(&["proto/velstra.proto"], &["proto"])?;
    Ok(())
}
