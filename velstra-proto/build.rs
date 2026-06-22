//! Compiles `proto/velstra.proto` into Rust client + server stubs via
//! `tonic-build` (which shells out to the system `protoc`).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/velstra.proto");
    tonic_build::configure().compile_protos(&["proto/velstra.proto"], &["proto"])?;
    Ok(())
}
