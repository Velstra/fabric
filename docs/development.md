# Development environment

Choose the lightweight host build for controller and model work. Install the BPF toolchain when you need the host agent or want to exercise the Linux dataplane. Run commands from the repository root.

## Toolchain

The agent embeds a BPF object built with `nightly-2026-08-01` and an LLVM 22-compatible `bpf-linker`. Use Rustup for both the host compiler and this BPF compiler:

```sh
rustup toolchain install stable --component rustfmt --component clippy
rustup toolchain install nightly-2026-08-01 --component rust-src
rustup run nightly-2026-08-01 rustc --version --verbose
```

Check the reported LLVM major before building the linker. On Debian/Ubuntu with the matching LLVM packages available:

```sh
sudo apt-get install llvm-22-dev libpolly-22-dev
export PATH="/usr/lib/llvm-22/bin:$PATH"
cargo install bpf-linker --locked --no-default-features --features llvm-22
bpf-linker --version
```

The repository’s [CI setup](https://github.com/Velstra/fabric/blob/main/.github/actions/bpf-linker/action.yml) documents its LLVM package source. The protobuf build uses vendored protoc unless an explicit `PROTOC` is supplied.

## Build

```sh
cargo build --release --locked
./target/release/velstra validate examples/rules.toml
```

The second command prints the parsed policy without loading any programs. For a controller-only binary, follow the [local quickstart](quickstart.md).

## Tests

```sh
cargo fmt --all -- --check
cargo test --workspace --exclude velstra --exclude velstra-ebpf --locked
```

These tests cover host logic. The release binary and a Linux host with root/XDP/TC support are required for [packet tests](TESTING.md). See [CI](https://github.com/Velstra/fabric/blob/main/.github/workflows/ci.yml) for clippy, BPF build and release gates.

## Build this handbook

Use mdBook 0.4.52:

```sh
mdbook build
```

Open `book/index.html` locally. The documentation workflow builds pull requests and deploys the built book on pushes to main. GitHub Pages must use **GitHub Actions** as the publishing source.
