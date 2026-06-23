# velstra-orchestrator

The fabric model for [Velstra](https://github.com/Velstra/fabric), an eBPF/XDP
software-defined networking stack written in Rust.

This is the leap from "configure each host" to "declare the fabric". You declare
**networks** (tenant L2 segments / VNIs), **hosts** (VTEPs), and **ports**
(workload vNICs), and the orchestrator **derives** each host's complete data-plane
config — allocating an IP (IPAM) and MAC per port, and emitting, for every other
host with a port on the same network, the tunnel + ARP entries needed to reach
it. `migrate_port` moves a port to another host keeping its IP/MAC, re-pointing
every peer's tunnel.

It emits the exact [`velstra-config`] a host already consumes, so the data plane
and agent are untouched. The whole crate is pure and unit-tested.

[`velstra-config`]: https://crates.io/crates/velstra-config

## License

AGPL-3.0-or-later — see the [workspace](https://github.com/Velstra/fabric).
