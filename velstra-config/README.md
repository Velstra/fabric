# velstra-config

The configuration model for [Velstra](https://github.com/Velstra/fabric), an
eBPF/XDP software-defined networking stack written in Rust.

It parses and validates a node's TOML config — firewall policies, blocklists,
per-port rules, routes, load-balancer services, and the VXLAN/Geneve overlay
(interfaces, tunnels, neighbours) — and **resolves** it into the flat,
map-ready representation the data plane consumes (via [`velstra-common`]). It
also converts to/from the gRPC wire types ([`velstra-proto`]) the controller
pushes.

This is the bridge between human-authored intent and the bytes that go into the
BPF maps; it is pure and unit-tested, with no I/O of its own.

[`velstra-common`]: https://crates.io/crates/velstra-common
[`velstra-proto`]: https://crates.io/crates/velstra-proto

## License

AGPL-3.0-or-later — see the [workspace](https://github.com/Velstra/fabric).
