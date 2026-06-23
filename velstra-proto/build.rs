//! Compiles `proto/velstra.proto` into Rust client + server stubs via
//! `tonic-build`. A vendored `protoc` is used by default so neither this crate
//! nor any downstream consumer needs a system `protoc` — but an externally set
//! `$PROTOC` wins, so sandboxed builders (Nix, Bazel) can supply their own.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/velstra.proto");
    println!("cargo:rerun-if-env-changed=PROTOC");
    // Only vendor when the caller hasn't already chosen a protoc. `set_var` is
    // `unsafe` in edition 2024 — safe here: single-threaded build script, set
    // once before any proto compilation.
    if std::env::var_os("PROTOC").is_none() {
        unsafe {
            std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
        }
    }
    tonic_build::configure().compile_protos(&["proto/velstra.proto"], &["proto"])?;
    Ok(())
}
