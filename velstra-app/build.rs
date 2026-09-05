use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "velstra-ebpf")
        .ok_or_else(|| anyhow!("velstra-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    // Which nightly compiles the data plane.
    //
    // `nightly` by default, so a workstation keeps working with whatever it
    // has. It is settable because the toolchain's LLVM is not a detail here:
    // bpf-linker has to be built against the same major version, and a
    // too-new one can emit a register the kernel verifier refuses outright
    // (`R11 is invalid`). When that happens the only way out is to name a
    // toolchain that does not.
    let pinned = std::env::var("VELSTRA_EBPF_TOOLCHAIN").unwrap_or_default();
    let toolchain = if pinned.is_empty() {
        Toolchain::default()
    } else {
        Toolchain::Custom(&pinned)
    };
    println!("cargo:rerun-if-env-changed=VELSTRA_EBPF_TOOLCHAIN");
    aya_build::build_ebpf([ebpf_package], toolchain)
}
