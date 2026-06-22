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

The AGPL is deliberate: it keeps the project open and discourages closed forks
and unshared SaaS. Organisations that cannot accept the AGPL's obligations (for
example, embedding Velstra in a closed-source appliance) can obtain a separate
**commercial license** — this is possible because contributors sign a CLA (see
[`CONTRIBUTING.md`](CONTRIBUTING.md)) granting the maintainer the right to
relicense. Contact the maintainer for commercial terms.

## Contributions

By contributing you agree to the Contributor License Agreement, which keeps
dual-licensing possible. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
