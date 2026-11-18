#[cfg(not(test))]
use which::which;

/// Intrinsics are deliberately unstable: the supported release compiler has
/// one operand type parameter, the CI compiler has two. Probe the actual
/// compiler instead of guessing from version strings or requiring a rolling
/// toolchain to keep an old signature forever. Only metadata is compiled;
/// nothing is linked or executed, and no target code is run by this probe.
fn atomic_or_signature() {
    println!("cargo:rustc-check-cfg=cfg(velstra_atomic_or_two_types)");
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("bpf") {
        return;
    }
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    let rustc = std::env::var_os("RUSTC").expect("RUSTC");
    let probe = out.join("atomic_or_probe.rs");
    let metadata = out.join("atomic_or_probe.rmeta");
    let mut errors = Vec::new();
    for types in ["u64", "u64, u64"] {
        std::fs::write(&probe, format!(
            "#![no_std]\n#![feature(core_intrinsics)]\n#![allow(internal_features)]\n\
             pub unsafe fn merge(p: *mut u64, v: u64) -> u64 {{ unsafe {{\n\
             core::intrinsics::atomic_or::<{types}, {{ core::intrinsics::AtomicOrdering::SeqCst }}>(p, v)\n\
             }} }}\n"
        )).expect("write atomic intrinsic probe");
        let result = std::process::Command::new(&rustc)
            .args([
                "--crate-name",
                "atomic_or_probe",
                "--crate-type",
                "lib",
                "--emit=metadata",
                "--edition=2021",
            ])
            .arg(&probe)
            .arg("-o")
            .arg(&metadata)
            .output()
            .expect("probe the actual Rust compiler");
        if result.status.success() {
            if types == "u64, u64" {
                println!("cargo:rustc-cfg=velstra_atomic_or_two_types");
            }
            return;
        }
        errors.push(String::from_utf8_lossy(&result.stderr).into_owned());
    }
    panic!(
        "compiler has no supported atomic OR intrinsic: {}",
        errors.join("\n")
    );
}

/// Building this crate has an undeclared dependency on the `bpf-linker` binary. This would be
/// better expressed by [artifact-dependencies][bindeps] but issues such as
/// https://github.com/rust-lang/cargo/issues/12385 make their use impractical for the time being.
///
/// This file implements an imperfect solution: it causes cargo to rebuild the crate whenever the
/// mtime of `which bpf-linker` changes. Note that possibility that a new bpf-linker is added to
/// $PATH ahead of the one used as the cache key still exists. Solving this in the general case
/// would require rebuild-if-changed-env=PATH *and* rebuild-if-changed={every-directory-in-PATH}
/// which would likely mean far too much cache invalidation.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies
#[cfg(not(test))]
fn main() {
    atomic_or_signature();
    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
}

#[cfg(test)]
mod tests {
    #[test]
    fn probe_actual_compiler_signature() {
        super::atomic_or_signature();
    }
}
