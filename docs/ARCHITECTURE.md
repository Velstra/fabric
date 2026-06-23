# Velstra architecture

This document explains *how* Velstra is built and *why* it is split the way it
is. For usage, see the [README](../README.md).

## Design goals

1. **One policy, two homes.** The packet verdict logic must run identically in
   the kernel (for speed) and on the host (for testing). We never want two
   implementations that can drift apart.
2. **Fail open, never black-hole.** A firewall that crashes or mis-parses must
   *pass* traffic, not silently drop it. Every error path is explicit and
   counted.
3. **Lock-free hot path.** The data plane touches only per-CPU state and a few
   map lookups — no locks, no allocations, no syscalls per packet.
4. **A typed, validated control surface.** Operators edit a small TOML file;
   everything is validated before a single byte reaches the kernel.

## Crate layout

```
velstra-common  (no_std, shared ABI + logic)  ──┐
                                                  ├─ linked into ──► velstra-ebpf (kernel, XDP)
                                                  └─ linked into ──► velstra-app  (user, daemon/CLI)
```

### `velstra-common`

The contract between kernel and user space. It is `#![no_std]` for normal builds
(so it links into the eBPF object) but compiles with `std` under `cfg(test)` so
the logic runs in the ordinary test harness. It has **no external dependencies**
in its default configuration; the optional `user` feature only pulls in `aya` to
provide the [`aya::Pod`] marker impls the user-space map API needs.

| Module    | Contents                                                              |
|-----------|-----------------------------------------------------------------------|
| `policy`  | `Action`, `Counter`, and the pure `decide()` verdict function.        |
| `config`  | `GlobalConfig` + `ConfigFlags` — the single `CONFIG` map entry.       |
| `packet`  | Wire constants, `PortKey`, `PacketMeta`, the `lpm_key_addr` helper.   |
| `parse`   | A safe, slice-based **reference parser** mirroring the kernel parser. |
| `forward` | Phase 2: `RouteEntry`, `plan_forward()`, RFC 1624 checksum fixup.     |
| `lb`      | Phase 3: `ServiceKey`/`Backend`, `plan_dnat()`, source hashing.       |
| `cidr`    | Dependency-free IPv4 CIDR parsing and masking.                        |
| `mac`     | Dependency-free `aa:bb:..`-style MAC address parsing.                 |

### `velstra-ebpf`

A single XDP program. It parses each frame on raw, bounds-checked packet
pointers (the verifier forbids slices), looks the packet up against the maps,
and calls the shared `decide()`. It is built **only** for the BPF target, by the
control plane's build script via `aya-build`; it is never compiled for the host.

### `velstra-app`

The `velstra` binary: CLI, TOML config loading/validation, map programming, XDP
attach (with mode fallback), and per-CPU statistics reporting.

## The map ABI (kernel ⇄ user)

| Map           | Kind          | Key → Value                          | Written by | Read by |
|---------------|---------------|--------------------------------------|-----------|---------|
| `IFACE_POLICY`| `HashMap`     | `ifindex` → `policy_id` (firewall ruleset) | user | kernel  |
| `IFACE_VNI`   | `HashMap`     | `ifindex` → `vni` (overlay segment)   | user      | kernel  |
| `CONFIG`      | `HashMap`     | `policy_id` → `GlobalConfig`          | user      | kernel  |
| `BLOCKLIST`   | `LpmTrie`     | `ScopedAddr` (policy + src IPv4 CIDR) → `u32` | user | kernel |
| `BLOCKLIST6`  | `LpmTrie`     | `ScopedAddr6` (policy + src IPv6 CIDR) → `u32` | user | kernel |
| `PORT_RULES`  | `HashMap`     | `ScopedPortKey` (policy + proto/port) → `Action` | user | kernel |
| `ROUTES`     | `LpmTrie`     | `Key<u32>` (dst CIDR) → `RouteEntry`  | user      | kernel  |
| `TX_PORTS`   | `DevMap`      | `ifindex` → `ifindex`                 | user      | kernel  |
| `SERVICES`   | `HashMap`     | `ServiceKey` → `ServiceValue`         | user      | kernel  |
| `BACKENDS`   | `Array`       | `index` → `Backend`                   | user      | kernel  |
| `CONNTRACK`  | `LruHashMap`  | `FlowKey` (5-tuple) → `FlowState`     | kernel    | kernel  |
| `OVERLAY_CONFIG`| `Array`    | `0` → `OverlayConfig` (this host's VTEP) | user   | kernel  |
| `OVERLAY_FDB`| `LpmTrie`     | `TunnelKey` (vni + inner-dst prefix) → `TunnelEndpoint` | user | kernel |
| `ARP_TABLE`  | `HashMap`     | `ArpKey` (vni + tenant IP) → `ArpEntry` (MAC) | user | kernel |
| `STATS`      | `PerCpuArray` | `Counter index` → `u64`              | kernel    | user    |

`ROUTES` and `TX_PORTS` are the Phase 2 forwarding plane: the FIB (longest-prefix
match on the *destination* address) and the redirect device map that
`bpf_redirect_map` requires. `SERVICES` and `BACKENDS` are the Phase 3 load
balancer: a service maps `(VIP, port, proto)` to a `[start, count)` window into
the flat backend pool. `CONNTRACK` is written **and** read by the data plane
itself: on a new flow it records a forward (DNAT) and a reverse (SNAT) entry, so
replies can be un-NAT-ed. It is the only map the control plane never touches.

Both sides import the **same** key/value types from `velstra-common`, so the
binary layout cannot disagree. Two subtleties are worth calling out:

* **`PortKey` has an explicit padding byte.** BPF hash-map lookups compare the
  *entire* key including padding, so the padding must be deterministically zero
  on both sides. We make it a named, always-zero field rather than relying on
  the compiler.
* **`lpm_key_addr` encodes IPs for the LPM trie.** The kernel LPM trie walks the
  key's raw bytes from the most-significant network octet. The key must be a
  `u32` whose in-memory bytes equal the network-order octets; on little-endian
  hosts that is `u32::from_le_bytes`. The data plane reads the packet's source
  address and calls the *same* function, so inserts and lookups always agree.

## The packet path

```
        ┌── IPv6 ─► stateless firewall (BLOCKLIST6 + ICMPv6 + PORT_RULES + default) ─► XDP_PASS/DROP
        │
        ├── ARP on a tenant port? ─► answer from ARP_TABLE, XDP_TX (suppression)  ◄── Phase 4
        ├── XDP_PASS (other / malformed) ──► kernel stack
frame ──┤
        └── IPv4: parse eth → IPv4 → L4 ports
                 │
                 ├── UDP to our tunnel port? ─► decap (adjust_head +50), XDP_PASS  ◄── Phase 4
                 ▼
        decide(meta, cfg, blocklisted, rule)        ◄── Phase 1, shared with tests
                 │
        ┌────────┴─────────┐
     DROP                 PASS
   XDP_DROP                │
                          ├── OVERLAY_FDB hit (vni,dst)? ─► encap (adjust_head −50), XDP_REDIRECT  ◄── Phase 4
                          ▼
              SERVICES lookup (VIP, dport, proto)
                          │
              plan_dnat(...) ── backend by source hash  ◄── Phase 3, shared with tests
                          │
        ┌─────────────────┴───────────────┐
   no service                    rewrite dst IP/port + IPv4/L4 csum
        │                              XDP_PASS (kernel routes to backend)
        ▼
              ROUTES lookup (dst longest-prefix)
                          │
              plan_forward(ttl, csum, proto, route)  ◄── Phase 2, shared with tests
                          │
        ┌─────────────────┼──────────────────┐
   no route           TtlExceeded          Redirect(rewrite)
        │              XDP_DROP        rewrite MACs (+TTL/csum), XDP_REDIRECT
        ▼
   XDP_PASS  (+ bump the firewall's pass counter)
```

Precedence inside `decide()` (Phase 1), highest first:

1. **Blocklist** (source CIDR) — the DDoS/abuse lever, beats everything.
2. **ICMP filter** (`drop_icmp`).
3. **Port rule** — explicit `(proto, dport)` allow or deny.
4. **Default policy** — `default_action`.

**IPv6 / dual-stack.** IPv6 frames take a separate, **stateless** firewall path
that reuses the very same `decide()` with the IPv6 source matched against
`BLOCKLIST6`, ICMPv6 (next-header 58) folded into the `drop_icmp` filter, and the
**shared** `PORT_RULES` / `CONFIG` (one policy, both families — a `:` in a
`blocklist` entry routes it to the v6 trie). Routing and load balancing stay
IPv4-only for now, so an allowed IPv6 packet is simply `XDP_PASS`ed to the kernel
stack; IPv6 extension headers are not walked (next-header must be TCP/UDP for a
port rule to match). Note `decide()` reads only `proto`/`dport` plus the
pre-computed blocklist/rule inputs, never the IPv4 address fields, which is why
it serves both families unchanged.

Then, for (IPv4) packets that passed, `plan_forward()` (Phase 2):

1. **No matching route** → `XDP_PASS` (hand to the kernel — forwarding is purely
   additive).
2. **Route, router mode** → if TTL would expire, drop; else decrement TTL,
   repair the checksum incrementally (RFC 1624), rewrite L2, `XDP_REDIRECT`.
3. **Route, switch mode** → rewrite L2 only, `XDP_REDIRECT`.

## Why the data plane can't be unit tested (and what we do instead)

eBPF code runs under the kernel verifier and a restricted instruction set; it
can't be executed by `cargo test`. Velstra handles this by pushing all the
*logic* out of the kernel program:

* the **verdict** is `velstra_common::decide`, tested directly;
* the **wire format** is captured by `velstra_common::parse::parse_frame`, a
  safe slice parser tested against truncated frames, IP options, non-IPv4, and
  port-less protocols.

The kernel program is then a thin, mechanical translation of those two onto raw
pointers. This keeps the untestable surface as small as possible.

## Testing strategy

| Layer                         | How it's covered                                  |
|-------------------------------|---------------------------------------------------|
| Policy precedence             | `policy::tests` via `decide()`                    |
| Wire parsing & edge cases     | `parse::tests` via `parse_frame()`                |
| Forwarding & TTL/checksum     | `forward::tests` via `plan_forward()` (RFC 1624)  |
| DNAT/SNAT & IPv4/L4 checksums | `lb::tests` via `plan_nat()` (full recompute, both directions; SNAT inverts DNAT) |
| Backend hashing & spread      | `lb::tests` via `session_hash`/`select_backend`   |
| Map ABI (sizes, padding)      | `packet`/`config`/`forward`/`lb` layout tests     |
| CIDR & MAC parsing            | `cidr::tests`, `mac::tests`                        |
| Config parse/validate         | `velstra-app` `config::tests`                    |
| Stats aggregation & rendering | `velstra-app` `firewall::tests`                  |
| End-to-end build + load       | `cargo build --release` + `velstra validate` (CI)|

For a hands-on walkthrough of running and observing all three phases on a pair
of network namespaces, see [TESTING.md](TESTING.md).

## Roadmap notes

* **Phase 2 (switching/routing)** — *done.* `ROUTES` (FIB) + `TX_PORTS` (devmap),
  `plan_forward()` returns drop / pass / redirect, with MAC rewrite and an
  RFC 1624 TTL/checksum fixup.
* **Phase 3 (LB & NAT)** — *done.* `SERVICES` + `BACKENDS` + a `CONNTRACK` LRU
  map; `plan_nat()` does source-hash backend selection and incremental IPv4 +
  TCP/UDP (pseudo-header) checksum repair for **both** directions (DNAT in, SNAT
  out). Stateful: a flow is pinned to its backend and replies are un-NAT-ed. To
  see both directions, attach the program to the client- and backend-facing NICs
  (one process ⇒ shared maps). The NAT fast path assumes a 20-byte IPv4 header.
* **Phase 4 (overlay)** — *done.* `OVERLAY_CONFIG` (this host's VTEP) +
  `OVERLAY_FDB` (an **LPM trie**: `vni` exact + inner-dst **prefix** → remote
  endpoint, so one entry covers a whole remote subnet). `build_encap()` builds the
  whole 50-byte VXLAN/Geneve outer stack (outer Ethernet/IPv4/UDP/shim, IPv4
  checksum, entropy-bearing UDP source port) as a pure, unit-tested function. The
  data plane only `bpf_xdp_adjust_head()`s and copies the bytes: encap (−50,
  redirect onto the underlay) when an inner destination resolves to a remote
  VTEP, decap (+50, `XDP_PASS`) for inbound tunnel packets. The **overlay segment
  (VNI) is decoupled from the firewall policy** — `IFACE_VNI` maps a port to its
  virtual network, `IFACE_POLICY` to its ruleset (security group); `vni` defaults
  to `policy` for the single-tenant convenience case. Decap is stateless and hands
  the inner frame to the kernel bridge; routing/LB stay IPv4 underlay-only. The
  controller distributes the overlay over gRPC (`Overlay` + `Tunnel` proto
  messages) — the Andromeda "push the topology" model. **ARP suppression**:
  requests on a tenant port are answered locally from `ARP_TABLE` (controller-
  pushed IP→MAC) and bounced with `XDP_TX`, so the broadcast never floods the
  overlay — the same `[[neighbor]]` data the controller already holds. **MTU
  guard**: an inner frame that would exceed `underlay_mtu - 36` is dropped with a
  counter (`overlay_too_big`) rather than silently black-holed; size tenant MTUs
  accordingly or use jumbo underlay frames. *Follow-ups:* IPv6 Neighbor Discovery
  suppression (the ND analogue of ARP); MSS-clamp / ICMP-PMTU instead of dropping
  oversized; on-demand FDB population from dataplane misses; re-run the inner
  firewall (by decoded VNI) after decap — best paired with the TC egress hook;
  Geneve TLV options to carry the source security context (OVN-style).
* **Phase B (egress firewall)** — *done.* A second eBPF program — a TC `clsact`
  classifier `velstra_egress` — shares the maps and `decide()` with the XDP hook
  but runs at **egress** (`--egress`). It filters leaving traffic by destination
  (blocklist + port rules + ICMP + default, scoped by egress ifindex) and, on a
  stateful policy, records the flow so the reply is allowed at ingress — covering
  host-originated connections and the receive side of a tenant tap (the inner
  firewall after overlay decap). IPv4 only; IPv6/overlay-aware egress are
  follow-ups. Counters `tx_packets` / `egress_dropped`.
* **Orchestration (Track C)** — *done.* `velstra-orchestrator` is a pure model
  of the virtual fabric (hosts/networks/ports) with IPAM and a **deriver**: given
  the topology it computes each host's `FileConfig` — local tap bindings plus a
  tunnel + ARP entry for every remote port on a network the host participates in.
  The controller loads a declarative `--topology` file into a third config layer
  (`derived`, between `files` and admin `overrides`) and serves it like any other
  `NodeConfig`, so the data plane and agent are untouched. This is the leap from
  "configure each host" to "declare the fabric". A `VelstraOrchestrator` gRPC
  service (on the admin channel) exposes the model at **runtime** —
  `AddHost`/`AddNetwork`/`CreatePort`/`RemovePort`/`MigratePort`/`ListPorts` (with
  the `orch` CLI) — mutating a live `Topology` in the controller; each mutation
  re-derives and re-serves, so a `create-port` propagates to the affected hosts
  immediately. `migrate-port` moves a port to another host while keeping its
  id/IP/MAC, so a live-migrated workload stays reachable and every peer's
  tunnel/ARP entry re-points at the new VTEP. The `--topology` file is the
  **durable store**: loaded at startup and written back atomically (temp +
  rename) after every mutation, with ports pinning their allocated IP so a reload
  reproduces the same ids/MACs — the appliance survives a restart. The
  orchestrator channel can require **mTLS** (`--tls-cert/--client-ca`), so the
  earlier follow-ups — port migration and a secured orchestration channel — are
  both done.
* **Controller HA (Track D)** — *done.* `velstra-raft` wraps **openraft**: the
  replicated state machine **is** the orchestrator `Topology`, so a committed
  `TopoRequest` is applied in log order on every controller (deterministic IPAM).
  Peers talk over a tiny gRPC transport. The controller's **cluster mode**
  (`--node-id`/`--raft-listen`/`--peer`/`--bootstrap`) holds a `RaftNode`: the
  leader serves orchestration writes (`raft.propose`), followers redirect writes
  and re-derive from the replicated topology on each apply (so any node serves
  agents). Snapshots persist to `--raft-dir` and are reloaded on boot, so the
  fabric survives a full-cluster restart instead of coming up empty. Agents take a
  repeatable `--controller` list and fail over to any reachable controller (config
  reads are served by every member), re-applying the first config after each
  reconnect since per-controller versions aren't comparable across a failover.
  Single-controller mode (file-backed) stays the default. No external datastore, no
  message queue — the Andromeda "central, consistent brain" without the OpenStack
  baggage. *Follow-ups:* log-index-based global-monotonic config versioning.
* **Distribution** introduces a gRPC (`tonic`) control channel so multiple
  data planes share one brain, and a Kubernetes CNI front-end.
