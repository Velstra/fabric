# Velstra Fabric

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/brand/logo-on-dark.svg">
  <img src=".github/brand/logo.svg" alt="Velstra Fabric" height="72">
</picture>

An eBPF/XDP dataplane, per-host agent, topology controller and Kubernetes CNI for tenant networks on Linux. Use it to answer neighbor requests on the host, carry tenant Ethernet over SRv6, or apply per-port policy. For a complete firewall appliance, see [Velstra Sentinel](https://github.com/Velstra/sentinel).

## Try it

Build the controller and inspect a two-host topology without root, virtual machines or an eBPF toolchain. The [local fabric quickstart](https://velstra.github.io/fabric/quickstart.html) includes the expected result.

```sh
git clone https://github.com/Velstra/fabric.git
cd fabric
cargo test -p velstra-common --locked
cargo build -p velstra-controller --locked
```

## Operator handbook

- [Start a local fabric](docs/quickstart.md)
- [Verify local neighbor discovery and Ethernet over SRv6](docs/overlay.md)
- [Configure and operate the agent](docs/agent.md)
- [Manage topology and workload ports](docs/CONFIGURATION.md)
- [Deploy the Kubernetes CNI](docs/kubernetes.md)
- [Build the agent](docs/development.md) and [verify the dataplane](docs/TESTING.md)

[Browse the GitHub Pages handbook](https://velstra.github.io/fabric/) · [Source examples](examples/) · [Release qualification](docs/RELEASE-POLICY.md)

## License

Agent/control plane: AGPL-3.0-or-later. Shared ABI/protobuf libraries:
MIT OR Apache-2.0. eBPF: GPL-2.0-or-later OR MIT.
See [LICENSING.md](LICENSING.md) for commercial terms and the component split.
