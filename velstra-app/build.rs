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
    // Keep the default aligned with CI's verified LLVM 22 toolchain. Rolling
    // nightly currently emits r11 in this program, which the kernel rejects.
    // An explicit override still supports controlled compiler upgrades.
    let pinned =
        std::env::var("VELSTRA_EBPF_TOOLCHAIN").unwrap_or_else(|_| "nightly-2026-08-01".to_owned());
    let toolchain = Toolchain::Custom(&pinned);
    println!("cargo:rerun-if-env-changed=VELSTRA_EBPF_TOOLCHAIN");
    aya_build::build_ebpf([ebpf_package], toolchain)
}
