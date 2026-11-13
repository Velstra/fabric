# Licensing

Velstra uses a **Proxmox/VyOS-style** model: the whole product is open source,
with the runtime under a strong copyleft (AGPL-3.0) so it stays open even when
offered as a service, while the shared libraries stay permissive for reuse and
kernel compatibility. The authoritative license for each crate is the `license`
field in its `Cargo.toml`; this document summarises the structure.

Copyright © 2026 Maximilian Brandt and contributors.

## Per-component licenses

| Component | Crate(s) | License | Why |
|---|---|---|---|
| **Control plane & agent** (the product) | `velstra-app`, `velstra-controller`, `velstra-orchestrator`, `velstra-raft`, `velstra-config`, `velstra-cni` | **AGPL-3.0-or-later** | The copyleft moat — modifications, including those offered over a network (SaaS), must be shared back. |
| **Shared ABI / wire contract** | `velstra-common`, `velstra-proto` | **MIT OR Apache-2.0** | Linked into *both* the GPL eBPF object and the AGPL control plane, and meant to be reusable; must be compatible with both. |
| **eBPF data plane** | `velstra-ebpf` | **GPL-2.0-or-later OR MIT** | Compiles to the in-kernel object, which must be GPL-compatible to call GPL-only BPF helpers. The object carries a `Dual MIT/GPL` license marker. |

Full texts: [`LICENSE`](LICENSE) (AGPL-3.0), [`LICENSE-MIT`](LICENSE-MIT),
[`LICENSE-APACHE`](LICENSE-APACHE), [`LICENSE-GPL2`](LICENSE-GPL2).

## Commercial / dual licensing

Contact the maintainer to discuss commercial terms. Availability depends on the
rights held for the relevant code and bundled dependencies. No project CLA is
currently administered; do not assume that contributors have granted additional
commercial relicensing rights. The licenses listed above remain authoritative.

## Contributions

Contributions use their component's license. See
[`CONTRIBUTING.md`](CONTRIBUTING.md); a documentation statement is not a signed CLA.
