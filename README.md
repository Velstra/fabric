# Velstra Fabric

Rust networking stack: an eBPF/XDP firewall and NAT dataplane, a per-host agent,
a controller and a Kubernetes CNI plugin.
For the complete firewall appliance, use [Sentinel](https://github.com/Velstra/sentinel).

## Start with the host tests

Install Rust through Rustup, then:

```sh
git clone https://github.com/Velstra/fabric.git
cd fabric
cargo test -p velstra-common --locked
cargo test --workspace --exclude velstra --exclude velstra-ebpf --locked
```

These tests need neither root nor the eBPF compiler. The protobuf compiler is
vendored; an explicit `PROTOC` overrides it.

## Build and run the agent

The full build needs the pinned nightly toolchain and a matching
`bpf-linker`/LLVM installation. Follow [toolchain setup](docs/development.md#toolchain),
then:

```sh
cargo build --release --locked
./target/release/velstra validate examples/rules.toml
```

To attach the firewall, replace `eth0` with an isolated lab interface.
This changes real packet handling; do not use your only management link.

```sh
sudo ./target/release/velstra run --iface eth0 --config examples/rules.toml
```

Stop with Ctrl-C. Start with the [sample policies](examples/) before writing
your own.

## Test the dataplane

Linux, root and XDP/TC kernel support are required:

```sh
sudo ./target/release/velstra verify-ebpf
sudo ./tests/e2e/run.sh
```

[Development checks](docs/development.md#tests) ·
[E2E scenarios](tests/e2e/README.md) ·
[Manual traffic lab](docs/TESTING.md)

## Documentation

[Agent operation](docs/agent.md) ·
[Configuration/API](docs/CONFIGURATION.md) ·
[Architecture](docs/ARCHITECTURE.md) ·
[HA replication](docs/ha-state-replication.md) ·
[Kubernetes](deploy/k8s/README.md) ·
[Release policy](docs/RELEASE-POLICY.md)

## License

Agent/control plane: AGPL-3.0-or-later. Shared ABI/protobuf libraries:
MIT OR Apache-2.0. eBPF: GPL-2.0-or-later OR MIT.
See [LICENSING.md](LICENSING.md) for commercial terms and the component split.
