# Development

Run commands from the repository root. Linux is required for dataplane tests.
The host-only libraries need Rust but not root or the BPF toolchain.

## Toolchain

Install Rust through Rustup. The agent's build script pins the BPF compiler to
`nightly-2026-08-01`; do not replace it with rolling nightly without kernel
verification. `bpf-linker` must use the same LLVM major as that compiler.

```sh
rustup toolchain install stable --component rustfmt --component clippy
rustup toolchain install nightly-2026-08-01 --component rust-src
rustup run nightly-2026-08-01 rustc --version --verbose
```

The pinned compiler uses LLVM 22. On a Debian/Ubuntu build host whose package
repositories provide LLVM 22:

```sh
sudo apt-get install llvm-22-dev libpolly-22-dev
export PATH=/usr/lib/llvm-22/bin:$PATH
cargo install bpf-linker --locked --no-default-features --features llvm-22
bpf-linker --version
```

If those packages are unavailable, the reviewed
[CI toolchain action](../.github/actions/bpf-linker/action.yml) shows the
LLVM repository/key setup. On macOS, see [Brewfile](../Brewfile); live dataplane
tests still need Linux. These are build-host dependencies, not appliance updates.

## Build

```sh
cargo build --release --locked
./target/release/velstra validate examples/rules.toml
```

The build embeds the BPF object in the agent. The protobuf crate uses vendored
`protoc` unless an explicit `PROTOC` is supplied.

## Tests

Host-only control-plane tests, without compiling the BPF program:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --exclude velstra --exclude velstra-ebpf --all-targets --locked -- -D warnings
cargo test --workspace --exclude velstra --exclude velstra-ebpf --locked
```

After the full toolchain is installed, include the agent:

```sh
cargo clippy -p velstra --all-targets --locked -- -D warnings
cargo test --workspace --exclude velstra-ebpf --locked
```

The BPF-only crate cannot be tested as a normal host executable. Load and traffic
tests require a Linux kernel with XDP/TC support, root and `iproute2`:

```sh
sudo ./tests/e2e/loadcheck.sh
sudo ./tests/e2e/run.sh
```

Install `arping` for the ARP-suppression scenario. A skipped case is not a pass.
See [E2E usage](../tests/e2e/README.md) and the [manual traffic lab](TESTING.md)
for scenario scope and round-trip assertions. CI lanes are defined in
[ci.yml](../.github/workflows/ci.yml); a source build alone does not prove kernel
acceptance or traffic behavior.
