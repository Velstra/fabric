//! Build the embedded datapath with the same atomic target used by the appliance.
use std::{env, io::Cursor, path::PathBuf, process::Command};

#[path = "build_support/embed.rs"]
mod object;

use anyhow::{Context, Result, anyhow, bail};
use cargo_metadata::Message;
// Cargo must also track changes in the datapath's transitive dependencies.
use velstra_ebpf as _;

fn main() -> Result<()> {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR")?);
    let workspace = manifest.parent().context("agent manifest has no parent")?;
    let out = PathBuf::from(env::var_os("OUT_DIR").context("OUT_DIR")?);
    let endian = env::var("CARGO_CFG_TARGET_ENDIAN").context("target endianness")?;
    let name = match endian.as_str() {
        "little" => "bpfel-atomic",
        "big" => "bpfeb-atomic",
        _ => bail!("unsupported target endianness: {endian}"),
    };
    let target = workspace
        .join("velstra-ebpf/targets")
        .join(format!("{name}.json"));
    for path in [
        workspace.join("velstra-ebpf"),
        workspace.join("velstra-common"),
        workspace.join("Cargo.toml"),
        workspace.join("Cargo.lock"),
    ] {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!("cargo:rerun-if-env-changed=VELSTRA_EBPF_TOOLCHAIN");
    println!("cargo:rerun-if-env-changed=VELSTRA_EBPF_OBJ");
    if let Some(object) = env::var_os("VELSTRA_EBPF_OBJ") {
        println!(
            "cargo:rerun-if-changed={}",
            PathBuf::from(&object).display()
        );
        object::embed(&PathBuf::from(object), &out.join("velstra"))
            .context("copying the supplied BPF object")?;
        return Ok(());
    }
    let toolchain =
        env::var("VELSTRA_EBPF_TOOLCHAIN").unwrap_or_else(|_| "nightly-2026-08-01".into());
    let mut command = match Command::new("rustup").arg("--version").output() {
        Ok(version) if version.status.success() => {
            let mut command = Command::new("rustup");
            command.args(["run", &toolchain, "cargo"]);
            command
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Nix provides the pinned cargo/rustc directly, without rustup.
            Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        }
        Ok(version) => bail!(
            "rustup is present but failed: {}",
            String::from_utf8_lossy(&version.stderr)
        ),
        Err(error) => return Err(error).context("checking rustup"),
    };
    let mut arch = env::var("CARGO_CFG_TARGET_ARCH").context("target architecture")?;
    if arch.starts_with("riscv64") {
        arch = "riscv64".into();
    }
    let prefix = if endian == "big" { "BPFEB" } else { "BPFEL" };
    let atomic_linker = format!("CARGO_TARGET_{prefix}_ATOMIC_LINKER");
    let legacy_linker = format!("CARGO_TARGET_{prefix}_UNKNOWN_NONE_LINKER");
    println!("cargo:rerun-if-env-changed={atomic_linker}");
    println!("cargo:rerun-if-env-changed={legacy_linker}");
    let linker = env::var_os(&atomic_linker)
        .or_else(|| env::var_os(&legacy_linker))
        .unwrap_or_else(|| "bpf-linker".into())
        .into_string()
        .map_err(|_| anyhow!("BPF linker path must be UTF-8"))?;
    let flags = [
        format!("--cfg=bpf_target_arch=\"{arch}\""),
        "-Cdebuginfo=2".into(),
        format!("-Clinker={linker}"),
        "-Clink-arg=--btf".into(),
        "-Dwarnings".into(),
        "-Dlinker-messages".into(),
    ]
    .join("\x1f");
    let output = command
        .current_dir(workspace)
        .args([
            "build",
            "--package",
            "velstra-ebpf",
            "--bin",
            "velstra",
            "--release",
            "--locked",
            "--message-format=json",
            "-Z",
            "json-target-spec",
            "-Z",
            "build-std=core",
            "--target",
        ])
        .arg(&target)
        // Keep nested Cargo away from the host target lock and output file.
        .arg("--target-dir")
        .arg(out.join("atomic-bpf-target"))
        .env("CARGO_ENCODED_RUSTFLAGS", flags)
        .env_remove("RUSTFLAGS")
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .output()
        .context("building the atomic BPF datapath")?;
    for line in String::from_utf8_lossy(&output.stderr).lines() {
        eprintln!("{line}");
    }
    let mut binary = None;
    for message in Message::parse_stream(Cursor::new(&output.stdout)) {
        match message.context("reading BPF Cargo diagnostics")? {
            Message::CompilerArtifact(artifact) if artifact.target.name == "velstra" => {
                if let Some(path) = artifact.executable {
                    binary = Some(path.into_std_path_buf());
                }
            }
            Message::CompilerMessage(message) => {
                if let Some(rendered) = message.message.rendered {
                    for line in rendered.lines() {
                        eprintln!("{line}");
                    }
                }
            }
            Message::TextLine(line) => eprintln!("{line}"),
            _ => {}
        }
    }
    if !output.status.success() {
        bail!("atomic BPF compilation failed: {}", output.status);
    }
    let binary =
        binary.ok_or_else(|| anyhow!("BPF Cargo did not report the velstra executable"))?;
    object::embed(&binary, &out.join("velstra")).context("embedding the atomic BPF datapath")?;
    Ok(())
}
