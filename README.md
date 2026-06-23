# Velstra — a next-gen, eBPF/XDP software-defined network stack

Velstra is a modern, cloud-native **Software-Defined Networking (SDN)** stack
written in 100% Rust. It aims to be an architecturally superior, memory-safe
replacement for the aging Open vSwitch (OVS) / OVN family by strictly separating
**network intelligence** (the control plane) from **packet processing** (the
data plane).

* **Data plane (the muscle):** Rust compiled to **eBPF**, attached via **XDP**
  (eXpress Data Path) at the earliest point in the NIC driver — *before* the
  kernel allocates an `sk_buff`. Built on [Aya](https://aya-rs.dev).
* **Control plane (the brain):** a pure-Rust user-space daemon that computes
  policy and pushes it into the kernel through eBPF maps.

> **Status:** Phases 1–4 are implemented, tested and documented — a dual-stack
> (IPv4/IPv6) firewall / DDoS filter (Phase 1), L2/L3 switching & routing via
> `XDP_REDIRECT` (Phase 2), a **stateful** L4 load balancer with connection
> tracking and reverse NAT (Phase 3), and a **VXLAN/Geneve overlay** for
> multi-host tenants (Phase 4). A **gRPC controller** distributes config to a
> fleet of nodes with live updates. A Kubernetes CNI is on the [roadmap](#roadmap).

## Why?

* **Performance.** XDP bypasses the entire `iptables`/`netfilter` path, so
  unwanted traffic is dropped at the driver and millions of packets per second
  can be filtered without saturating the CPU.
* **Safety.** Rust eliminates whole bug classes (use-after-free, data races,
  buffer overflows) that have plagued C-based network daemons for years.
* **Zero legacy.** No 15 years of unused protocol baggage — lean, modern,
  cloud-native.

Targets: cloud/hosting providers wanting a lightweight OVN alternative,
Kubernetes operators (a future CNI, à la Cilium), and edge/home-lab nodes where
every CPU cycle counts (Raspberry Pi, edge gateways).

## Architecture

```
            ┌──────────────────────────────────────────┐
 rules.toml │  velstra (user space, control plane)      │
   ───────► │  parse → validate → program maps → attach  │
            └───────────────┬──────────────────────────-─┘
                            │ eBPF maps (CONFIG / BLOCKLIST / PORT_RULES / STATS)
                            ▼
            ┌──────────────────────────────────────────┐
   NIC ───► │  velstra (kernel space, XDP data plane)   │ ─► XDP_PASS ─► kernel
   packets  │  parse → lookup maps → decide() → verdict  │ ─► XDP_DROP ─► dropped
            └──────────────────────────────────────────┘
```

The crates:

| Crate                | Space        | Responsibility                                       |
|----------------------|--------------|------------------------------------------------------|
| `velstra-common`    | shared       | Map ABI types, the pure `decide()`/`plan_*()` policy, a reference parser — all unit tested. |
| `velstra-ebpf`      | kernel       | The XDP program: parse, look up maps, apply the policy. |
| `velstra-config`    | shared       | TOML schema, validation, and proto ⇄ config conversion. |
| `velstra-proto`     | shared       | The gRPC `.proto` and generated client/server stubs. |
| `velstra-app`       | user (`velstra`) | The agent: CLI, map programming, stats, controller client. |
| `velstra-controller`| user (`velstra-controller`) | The central gRPC controller. |
| `velstra-cni`       | user (`velstra-cni`) | A Kubernetes CNI plugin: pod veth + IPAM. |

The firewall **policy lives once**, in `velstra-common::decide`, so the kernel
and the test suite run identical logic and can never drift apart. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design.

## Quick start

### Prerequisites

```shell
rustup toolchain install stable
rustup toolchain install nightly --component rust-src   # required to build eBPF
cargo install bpf-linker                                # the eBPF linker
# macOS only: `brew bundle` (uses the Brewfile) for an LLVM that supports BPF.
```

### Build, test, validate

```shell
cargo test -p velstra-common   # fast: pure logic, no root, no eBPF toolchain
cargo build --release           # builds the eBPF object + the daemon

# Check a policy without touching the kernel:
./target/release/velstra validate examples/rules.toml
```

### Run (requires root)

```shell
sudo -E ./target/release/velstra run --iface eth0 --config examples/rules.toml
```

Useful flags:

| Flag               | Meaning                                                       |
|--------------------|---------------------------------------------------------------|
| `--iface <name>`   | Interface to attach to (default `eth0`).                      |
| `--config <path>`  | TOML policy file. Omitted ⇒ fail-open (pass everything).      |
| `--xdp-mode <m>`   | `auto` (default), `driver`, `skb`, or `hw`. `auto` tries native driver mode then falls back to generic SKB. |
| `--stats-interval` | Seconds between live stats dumps (`0` to disable).            |

Verify it works (in another shell, after attaching with `drop_icmp = true`):

```shell
ping -c3 <host>     # 100% packet loss — dropped at the NIC by XDP
```

## Configuration

See [`examples/rules.toml`](examples/rules.toml) for a fully-commented policy.
In short:

```toml
default_action = "pass"          # or "drop" for an allow-list firewall
drop_icmp      = true
log            = false           # log every drop/forward/NAT via aya-log (debug)
blocklist      = ["203.0.113.0/24", "198.51.100.13", "2001:db8::/32"]

[[port_rule]]
proto  = "tcp"
port   = 22
action = "drop"
```

**Precedence** (highest first): blocklist → ICMP filter → port rule → default.

### Dual-stack (IPv6)

The firewall is **dual-stack**. IPv6 frames take a parallel, stateless path that
reuses the same `decide()` logic: the source is matched against an IPv6 blocklist
trie (`BLOCKLIST6`), ICMPv6 is covered by `drop_icmp`, and `[[port_rule]]` /
`default_action` apply to both families. Just put IPv6 CIDRs in the **same**
`blocklist` list — any entry containing a `:` is parsed as IPv6 (a bare address
is a `/128`). Switching/routing and load balancing remain IPv4-only for now, so
allowed IPv6 traffic is passed to the kernel stack.

### Stateful firewall

Set `stateful = true` on a policy to track TCP/UDP connections and allow
**established flows in either direction** — replies are permitted even under a
deny-by-default policy (the blocklist still wins). This is the classic stateful
*gateway* firewall: attach to both zones (e.g. LAN and WAN), a connection
allowed out from the LAN is recorded, and the matching reply ingressing the WAN
is allowed automatically. Counter: `established_allowed`.

> Because XDP runs on **ingress**, this covers *forwarded* traffic (a firewall
> appliance between zones). Replies to connections the host itself originates are
> covered by the egress hook below.

### Egress firewall (TC)

Pass `--egress` to also attach a TC `clsact` hook at **egress** on each
`--iface`. XDP only sees traffic *arriving*; the egress hook filters traffic
*leaving* — host-originated packets, and the receive side of a tenant tap. It
reuses the same `decide()` and per-policy maps (selected by the **egress**
interface), but matches the blocklist and port rules on the **destination**
("don't talk to these") rather than the source. On a `stateful` policy it records
each allowed flow so the **reply** (arriving at the XDP ingress hook) is
permitted — closing the host-originated-connection gap. Counters: `tx_packets`,
`egress_dropped`.

```shell
sudo -E ./target/release/velstra run --iface eth0 --egress --config rules.toml
```

It's opt-in because an egress filter can drop traffic the ingress side never
sees. *(IPv4 only for now; IPv6 and overlay-aware egress are on the roadmap.)*

### Multi-tenant policy (per interface)

One agent can enforce a **different firewall per interface** — the ingress
interface selects which policy a packet is evaluated against. This is the
foundation for VM "security groups" and multi-firewall hosts: each VM tap (or
NIC) gets its own tenant policy, all in one XDP program. The top-level config is
policy `0` (the default for unassigned interfaces); `[[policy]]` blocks add
tenants, and `[[interface]]` maps interfaces to them (see
[`examples/multitenant.toml`](examples/multitenant.toml)):

```toml
default_action = "pass"          # policy 0 (default)

[[policy]]
id = 1
default_action = "drop"          # tenant 1: deny-by-default
[[policy.port_rule]]
proto = "tcp"
port  = 443
action = "pass"

[[interface]]
name   = "tap-a"
policy = 1                        # tap-a's traffic uses tenant 1's rules
```

The firewall maps (`CONFIG`, `BLOCKLIST`, `PORT_RULES`) are keyed by policy id;
an `IFACE_POLICY` map (ingress ifindex → policy) does the per-packet selection.
Routing and load balancing are currently global (shared across policies).

Tenant policies and interface assignments are part of the gRPC wire format too,
so the [controller](#distributed-mode-a-controller-for-the-fleet) distributes a
node's full multi-tenant config — not just a single policy.

### Forwarding (Phase 2)

Packets that *pass* the firewall can then be **forwarded** out of another
interface — Velstra as a software router/switch. Add `[[route]]` blocks
(see [`examples/router.toml`](examples/router.toml)):

```toml
[[route]]
dest      = "10.20.0.0/16"        # longest-prefix match on the destination IP
out_iface = "eth1"                 # redirect out of this interface (XDP_REDIRECT)
via_mac   = "02:00:00:00:00:01"    # next-hop MAC
mode      = "route"                # "route" = L3 (decrement TTL + fix checksum)
                                   # "switch" = L2 (re-address only)
# src_mac defaults to the egress interface's own MAC
```

Routing is **opt-in**: with no routes, Velstra is a pure firewall. A routed
packet whose TTL would reach zero is dropped (counter `forward_ttl_exceeded`);
the IPv4 header checksum is repaired incrementally (RFC 1624).

> Note: `XDP_REDIRECT` to another device works out of the box in generic/SKB
> mode; native driver mode additionally requires the **egress** NIC's driver to
> support `ndo_xdp_xmit`. veth pairs and most modern NICs do.

### Load balancing & NAT (Phase 3)

A `[[service]]` turns Velstra into a stateless **L4 load balancer**: traffic to
a virtual IP is DNAT-rewritten to one of several backends
(see [`examples/loadbalancer.toml`](examples/loadbalancer.toml)):

```toml
[[service]]
vip   = "10.0.0.100"   # clients connect here
port  = 80
proto = "tcp"          # tcp or udp
backends = [
  { ip = "10.0.0.7", port = 8080 },
  { ip = "10.0.0.8", port = 8080 },
  { ip = "10.0.0.9" },             # port omitted -> keep the original
]
```

Each new flow's *source* is hashed to a backend ([FNV-1a]) and recorded in a
`CONNTRACK` LRU map. The destination IP/port are DNAT-rewritten and the IPv4
**and** TCP/UDP checksums (incl. the pseudo-header) are repaired incrementally
(RFC 1624); the packet is `XDP_PASS`ed for the kernel to deliver to the backend.

**Stateful (reverse NAT).** Because the flow is tracked, replies on the way back
(backend→client) are recognised and **SNAT**-ed: the source is rewritten back to
the VIP so the client's connection completes end-to-end. For Velstra to see
both directions, attach it to **both** the client-facing and backend-facing
interfaces — they share the same maps:

```shell
sudo -E ./target/release/velstra run \
    --iface eth-client --iface eth-backend --config rules.toml
```

Counters: `load_balanced` (new), `lb_established` (tracked DNAT), `lb_reverse`
(SNAT reply). A UDP datagram with a disabled (zero) checksum is left untouched;
the NAT fast path requires a 20-byte IPv4 header (no options).

[FNV-1a]: https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function

### Multi-host tenants — VXLAN/Geneve overlay (Phase 4)

A tenant can span **many hosts**: VMs on different physical machines share one
virtual L2 segment even though the underlay between them only routes IP. Velstra
encapsulates the tenant frame in a VXLAN (UDP/4789) or Geneve (UDP/6081) tunnel
between the hosts' tunnel endpoints (VTEPs).

The **overlay segment (VNI) is decoupled from the firewall policy** — a port's
virtual *network* and its *ruleset* (security group) are separate concerns: many
ports can share one policy on different VNIs, or one VNI can host ports with
different policies. `vni` defaults to `policy` if omitted (the single-tenant
convenience), so the simple case stays a single number.

```toml
[overlay]                          # this host's VTEP
local_vtep     = "10.10.0.1"
underlay_iface = "eth0"            # its MAC = the outer source MAC
encap          = "vxlan"           # or "geneve"

[[interface]]                      # firewall policy 7, overlay segment 5000
name = "tapA"
policy = 7
vni    = 5000                      # omit -> defaults to `policy`

[[tunnel]]                         # where remote tenant addresses live
vni         = 5000
inner_dst   = "192.168.100.0/24"   # a CIDR: a whole remote subnet = one entry
remote_vtep = "10.10.0.2"          # that host's VTEP
via_mac     = "02:00:00:00:00:02"
out_iface   = "eth0"

[[neighbor]]                       # ARP suppression: a remote tenant IP -> MAC
vni = 5000
ip  = "192.168.100.2"
mac = "02:00:00:00:0b:02"
```

**ARP suppression** makes VM-to-VM actually work without flooding: when a local
VM ARPs for a peer on another host, Velstra answers from `ARP_TABLE` (the
controller-pushed `[[neighbor]]` IP→MAC entries) and bounces the reply with
`XDP_TX` — the broadcast never leaves the host. An **MTU guard** drops a frame
that would exceed `underlay_mtu - 36` (counter `overlay_too_big`) instead of
emitting one the underlay silently black-holes, so size tenant MTUs to ≤ 1464
(at the default 1500 underlay) or enable jumbo frames. *(IPv6 ND suppression and
MSS-clamp/PMTU are on the roadmap.)*

On egress from a tenant tap, a longest-prefix hit in the `OVERLAY_FDB` trie on
`(vni, inner dst)` **encapsulates** (prepend a 50-byte outer
Ethernet/IPv4/UDP/VXLAN stack, with the outer IPv4 checksum and an
entropy-bearing UDP source port for underlay ECMP) and `XDP_REDIRECT`s onto the
underlay. Because the FDB is an **LPM trie**, one entry covers a whole remote
subnet (`/24`) instead of one per host — the difference between thousands and
millions of entries at scale. A miss means the destination is local — normal
switching takes over. Inbound UDP to the tunnel port is **decapsulated**
(`XDP_PASS` to the host bridge). All header construction is a pure, unit-tested
function ([`build_encap`]); the kernel only `bpf_xdp_adjust_head()`s and copies
the bytes. The controller distributes the overlay over gRPC, so a central brain
pushes each host just the endpoints it needs (the Andromeda model — no flooding,
no message queue). Attach to both the tenant tap and the underlay NIC; one process
shares the maps. Counters: `overlay_encap`, `overlay_decap`. See
[`examples/overlay.toml`](examples/overlay.toml).

[`build_encap`]: velstra-common/src/overlay.rs

## Distributed mode (a controller for the fleet)

Instead of editing TOML on every box, run a central **controller** that serves
each node its config over gRPC and pushes live updates:

```shell
# Controller: one <node_id>.toml per node in a directory
velstra-controller serve --config-dir /etc/velstra/nodes

# Agent: fetch config from the controller instead of a local file
sudo -E velstra run --iface eth0 --controller http://10.0.0.1:50051 --node-id web-1
```

The agent fetches its config on start, applies it to the maps, then **watches**
for changes: edit `web-1.toml` on the controller and the agent re-programs the
maps in place — no restart, no detach, existing connections (the `CONNTRACK`
map) preserved. Agents also report their counters back, which the controller
logs. The wire schema mirrors the TOML one-to-one (`velstra-config` converts
between them), so `velstra validate` still checks a node file before you ship
it. See [`examples/controller/`](examples/controller) for sample node configs.

**Admin API.** Push config at runtime (overriding a node's file until deleted),
over a separate, localhost-by-default admin channel:

```shell
velstra-controller admin set    --node web-1 --file web-1.toml
velstra-controller admin list
velstra-controller admin delete --node web-1   # revert to the file
```

**mTLS.** Secure the agent channel with mutual TLS (`scripts/gen-certs.sh`
generates a test PKI):

```shell
velstra-controller serve --config-dir nodes \
    --tls-cert server.pem --tls-key server.key --client-ca ca.pem
sudo -E velstra run --iface eth0 --node-id web-1 \
    --controller https://controller.local:50051 \
    --tls-ca ca.pem --tls-cert client.pem --tls-key client.key \
    --tls-domain controller.local
```

### Declarative fabric (orchestration)

Per-node TOML is the low level. Above it, the controller can take a **single
declarative topology** — hosts (VTEPs), networks (tenants), and ports (VM NICs) —
and *derive* each host's config itself: which tap rides which VNI/policy, and the
tunnel + ARP entry every *other* host needs to reach each port. You declare
intent once; the controller computes and pushes the per-host reality (the
Andromeda model). The data plane and agent are unchanged — it emits the same
`NodeConfig`.

```shell
velstra-controller serve --topology examples/topology.toml
velstra-controller admin list      # node  version  source(=derived)
```

```toml
# examples/topology.toml (excerpt) — one tenant spanning two hosts
[[host]]
id = "host-1"
vtep = "10.10.0.1"
underlay_iface = "eth0"
underlay_mac = "02:00:00:00:00:11"

[[network]]
vni = 5000
name = "blue"
subnet = "192.168.100.0/24"

[[port]]
network = 5000
host = "host-1"
tap = "tap-blue-1"        # ip/mac auto-allocated if omitted
```

IPs and MACs are auto-allocated (IPAM) when a port omits them. The topology file
**seeds** the fabric; at runtime you mutate it over the admin gRPC API and every
affected host's config is re-derived and pushed immediately:

```shell
velstra-controller orch add-network --vni 6000 --name green --subnet 192.168.200.0/24
velstra-controller orch create-port --network 6000 --host host-1 --tap tap-green-1
# -> created port port-6000-192.168.200.1 : 192.168.200.1 (02:00:c0:a8:c8:01) on host-1
velstra-controller orch list-ports
```

The `--topology` file is the **persistent store**: the controller loads it at
startup (if it exists) and atomically writes it back after every mutation, so
runtime changes survive a restart — an empty appliance just creates it on the
first `create-port`. Admin overrides still win, then derived configs, then static
files. `velstra-orchestrator` holds the pure model + deriver (IPAM, tunnel/ARP
derivation); the controller wraps it with the `VelstraOrchestrator` gRPC service
and the `orch` CLI. `examples/topology.toml` is a worked seed.

### High availability (controller cluster)

Run several controllers as a **Raft cluster** so there's no single point of
failure — no external datastore, no message queue, just embedded consensus
([`velstra-raft`] over [openraft]). The fabric is the replicated state machine:
the **leader** accepts orchestration writes and replicates them; **followers**
apply the same log (so IPAM is deterministic) and each serves agents the derived
config independently. If the leader dies, the cluster re-elects one.

```shell
# Three controllers; bootstrap once on node 1. --raft-dir persists snapshots so
# the fabric survives a full-cluster restart (reloaded as the committed state).
velstra-controller serve --node-id 1 --raft-listen 10.0.0.1:50053 --raft-dir /var/lib/velstra \
    --bootstrap --peer 1=10.0.0.1:50053 --peer 2=10.0.0.2:50053 --peer 3=10.0.0.3:50053
velstra-controller serve --node-id 2 --raft-listen 10.0.0.2:50053 --raft-dir /var/lib/velstra  # host 2
velstra-controller serve --node-id 3 --raft-listen 10.0.0.3:50053 --raft-dir /var/lib/velstra  # host 3
```

`orch`/`admin` writes must go to the leader — a follower refuses with *"not the
leader; current leader is node N"*. Reads (`list-ports`, the agent config stream)
work on any node. Single-controller mode (the file-backed `--topology` store) stays
the default when `--node-id` is omitted.

Point each agent at **every** controller — `--controller` is repeatable. The agent
streams its config from the first one that answers and, if that controller goes
down, transparently fails over to the next (config reads are served by any cluster
member). Its data plane keeps running on the last-applied config the whole time:

```shell
sudo -E velstra run --iface eth0 --node-id web-1 \
    --controller https://10.0.0.1:50051 \
    --controller https://10.0.0.2:50051 \
    --controller https://10.0.0.3:50051
```

[`velstra-raft`]: velstra-raft/
[openraft]: https://github.com/datafuselabs/openraft

## Statistics

The data plane keeps lock-free **per-CPU counters**; the daemon sums and prints
them periodically and on exit:

```
  counter                       value
  -------------------- --------------
  rx_packets                  1048576
  rx_bytes                  150994944
  passed_default               900123
  dropped_blocklist            120000
  dropped_icmp                  28453
  ...
  -------------------- --------------
  drop rate                    14.16%
```

## Testing

```shell
cargo test -p velstra-common   # policy, parser, CIDR, map ABI (no root)
make test                       # whole workspace incl. config + control plane
cargo clippy --workspace
cargo fmt --all -- --check
```

The kernel program cannot be unit tested directly, so its parsing and policy are
mirrored by `velstra-common`'s slice-based reference parser and the shared
`decide()` / `plan_forward()` / `plan_dnat()` functions, all exhaustively tested.

**End-to-end (root).** A suite under [`tests/e2e/`](tests/e2e) loads the *real*
XDP + TC programs onto throwaway veth/netns topologies and asserts on live
behaviour — firewall (v4/v6/ICMP/port), egress, and overlay (ARP suppression,
encap, MTU guard):

```shell
make e2e                        # or: sudo ./tests/e2e/run.sh [scenario...]
```

For a guided manual walkthrough of all three phases (incl. routing & LB), follow
[`docs/TESTING.md`](docs/TESTING.md).

## Roadmap

* **Phase 1 — Firewall & filter (done):** stateless `XDP_DROP` filtering,
  CIDR blocklist, per-port rules, ICMP filter, per-CPU stats.
* **Phase 2 — Routing & switching (done):** L2/L3 forwarding via `XDP_REDIRECT`
  with a longest-prefix-match FIB, MAC rewrite, TTL decrement + incremental
  checksum, and an L2 switch mode.
* **Phase 3 — Load balancing & NAT (done):** stateful L4 load balancing with
  source-hash backend selection, connection tracking (LRU `CONNTRACK`), DNAT +
  reverse SNAT, and incremental IPv4 + TCP/UDP checksum repair.
* **Phase 4 — VXLAN/Geneve overlay (done):** multi-host tenants over a routed
  underlay. `build_encap()` builds the outer stack (pure, unit-tested); the data
  plane `bpf_xdp_adjust_head()`s to encap onto the underlay and decap inbound
  tunnel packets. Overlay segment (VNI) decoupled from firewall policy; FDB is an
  LPM trie (subnet per entry); controller pushes it over gRPC.
* **Dual-stack (done):** the firewall (blocklist, ICMPv6, port rules, default)
  is IPv4 + IPv6; routing/LB/overlay underlay stay IPv4.
* **Egress firewall (done):** opt-in TC `clsact` hook (`--egress`) filters
  leaving traffic by destination and records stateful flows for the return path,
  covering host-originated connections and the receive side of tenant taps.
* **Orchestration (done):** a declarative fabric topology (hosts/networks/ports)
  the controller turns into per-host config — IPAM, automatic tunnel + ARP
  derivation, push (`velstra-orchestrator` + `--topology`). The leap from
  hand-written per-host TOML to declared intent.
* **Controller HA (done):** controllers form an embedded **Raft** cluster
  (`velstra-raft` over openraft) — the fabric is the replicated state machine,
  the leader serves writes, followers replicate + serve reads, automatic
  re-election. Snapshots persist to `--raft-dir` (survives a full-cluster
  restart); agents take a repeatable `--controller` list and fail over to any
  reachable member. No external datastore, no message queue.
* **Distribution (done):** a central **gRPC** (`tonic`) controller serves and
  live-updates per-node config across a fleet (file + runtime admin overrides),
  secured with **mTLS**; agents report stats back.
* **Kubernetes CNI (in progress):** `velstra-cni` implements the CNI protocol
  with pod veth/netns setup (see [`docs/TESTING.md`](docs/TESTING.md) §7). Two
  modes: **standalone** (host-local IPAM) and **controller-integrated**, where
  ADD calls the controller's `CreatePort` (Raft-replicated IP/MAC allocation) and
  the node's agent — on the pushed config — attaches the XDP firewall/LB to the
  new pod veth. Next: the agent DaemonSet + manifests, and attaching to a
  configured veth as it appears.

## License

Open source, **Proxmox/VyOS-style**: the product is copyleft, the shared
libraries are permissive.

- **Control plane & agent** — **AGPL-3.0-or-later** (`velstra-app`,
  `-controller`, `-orchestrator`, `-raft`, `-config`, `-cni`).
- **Shared ABI / wire libraries** — **MIT OR Apache-2.0** (`velstra-common`,
  `-proto`).
- **eBPF data plane** — **GPL-2.0-or-later OR MIT** (`velstra-ebpf`; the kernel
  object is marked `Dual MIT/GPL`).

A **commercial license** is available for organisations that cannot use the AGPL
(dual licensing, enabled by the contributor CLA). See [`LICENSING.md`](LICENSING.md)
and [`CONTRIBUTING.md`](CONTRIBUTING.md). Full texts: [`LICENSE`](LICENSE) (AGPL),
`LICENSE-MIT`, `LICENSE-APACHE`, `LICENSE-GPL2`.
