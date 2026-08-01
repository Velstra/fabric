# Changelog

## [Unreleased]

## [0.4.0] — 2026-08-01

### Added

- **A port opened on request, with a deadline (C18).** A host on the inside asks
  for an inbound port and gets it for a while; nothing is opened permanently and
  nothing is opened by a third party for somebody else.
- **Captive-portal admission (C20).** A zone holds every device until it is
  admitted, keyed by MAC so both address families are covered by one decision.
- **IPFIX export (C12).** The flow table is exported as RFC 7011 records —
  **deltas, not totals**, because a collector sums what it receives; the template
  is re-sent with every message so a collector that starts late still parses.
- **SYN proxy (C15).** The datapath completes the handshake with a SYN cookie and
  splices the sequence numbers, so a flood never reaches the server behind it.
- **Per-flow accounting.** Every flow carries packet and byte counters, which is
  what lets "top talkers" rank by volume rather than by connection count. The
  counters are deliberately **not** synced to an HA peer: they are local
  observations, not shared state.
- **Source validation (uRPF, BCP 38)** per zone, in XDP, via a reversed
  `bpf_fib_lookup`, with the exemptions a real link needs (DHCP, link-local).
- **A run-time blocklist with a deadline**, and one operation to lift every
  block. Sized for whole-country blocking (8192 → 262144 entries) so GeoIP
  expands to ordinary CIDRs rather than needing a datapath of its own.
- **Deterministic CGNAT port blocks.** A fixed block of WAN ports per internal
  address gives attribution without keeping a translation log.
- **Per-rule rate limiting** (token bucket in XDP) and **destination-address
  matching**, which is what unblocks GeoIP and FlowSpec rules that name a
  destination.
- **A read-only agent query socket** for flows and counters, so diagnostics do
  not have to be re-implemented anywhere else. The conntrack handle became a
  shared `Arc` for it — single ownership had quietly broken diagnostics under HA.
- **Change events**, two ways: a `/v1/events` stream and webhook delivery.
- **Tenant IP-VRFs and EVPN inter-subnet routing (B7).** Type-5 IP Prefix routes
  are parsed and held, symmetric-IRB routes are derived from them, and the XDP
  anycast gateway routes between subnets of a tenant — L3 tenant routing with no
  MPLS anywhere.
- **IP-VRFs and load balancers driven through the API**, with a configuration
  and API reference to go with it.
- **A host-wide fail-closed switch** for packets the datapath cannot parse.
- **IPv6 extension-header classification and sizing** in `velstra-common`.
- **SRv6 `End.DT2U` decap authenticated against a trusted-peer set** — the C2
  analogue of `VTEP_PEERS`, and the follow-on the SRv6 decap entry below called
  for.
- **The Raft peer transport is restricted to an allowlist of controller CNs**, so
  a certificate from the same CA is not by itself a licence to join the cluster.
- **SRv6 L2 decap data plane (B9, part 3) — endpoint `End.DT2U`.** The symmetric
  counterpart of the headend encap: the XDP datapath now *terminates* SRv6, so two
  fabric hosts bridge an L2 tenant over SRv6 end to end. `[[srv6_local_sid]]`
  declares the service SIDs this node instantiates (`sid`, `vni`, `behavior`);
  `try_srv6_decap` — first thing on the IPv6 path, before the firewall — strips
  the outer Ethernet + IPv6 of a packet whose destination is one of our SIDs and
  hands the inner Ethernet frame to the kernel bridge (delivered by inner MAC). It
  is gated to non-tenant (underlay) ingress so a tenant tap can't forge an
  encapsulated frame and inject its inner frame past isolation (full `SRV6_PEERS`
  trusted-source auth — the C2 analogue of `VTEP_PEERS` — is a follow-on, as is
  `End.DT2M` BUM flood). New map `SRV6_LOCAL_SIDS`, agent programming in
  `program_srv6`, `srv6_decap` counter. Unit-tested (config resolve incl. the
  behaviour keyword, `velstra validate`); a two-agent netns e2e scenario
  (`srv6_roundtrip`: A encaps → B decaps, both counters) exercises the full loaded
  datapath. **eBPF object changed → sentinel `ebpfHash` bump on repin.**
- **SRv6 L2 encap data plane (B9, part 2) — headend `End.DT2U`.** The XDP
  datapath now speaks SRv6 as an alternative overlay wire format to VXLAN/Geneve.
  `[srv6]` sets this host's tunnel-source identity (a 128-bit source address out
  of its locator) and `[[srv6_route]]` maps a tenant `(vni, dst-MAC)` to a remote
  `End.DT2U` service SID. On egress, `try_srv6_encap` wraps the tenant frame in
  outer Ethernet + IPv6 (reduced encap — the single SID rides in the IPv6
  destination, no SRH) and redirects it onto the underlay, mirroring the VXLAN
  MAC-FDB path but with no UDP/shim/checksum (IPv6 has no header checksum). New
  BPF maps `SRV6_CONFIG` + `SRV6_FDB`, agent `program_srv6`, `srv6_encap` counter.
  SRv6 and VXLAN are mutually exclusive per host (validated). Unit-tested end to
  end (codec bytes, config resolve, `velstra validate`); a netns e2e scenario
  (`srv6_encap`) exercises the loaded datapath. **eBPF object changed → sentinel
  `ebpfHash` bump on repin.** Decap (`End.DT2U`/`DT2M`, part 3) follows.
- **SRv6 L2 codec (B9, part 1) — `velstra-common::srv6`.** The pure, `no_std`,
  unit-tested contract for an SRv6 (RFC 8986) overlay data plane, ahead of wiring
  it into the XDP datapath. `build_srv6_encap` produces the outer Ethernet + IPv6
  stack for reduced encapsulation (H.Encaps.Red — a single service SID in the IPv6
  destination, no Segment Routing Header), the `End.DT2*` L2 case; `build_service_sid`
  / `decode_service_sid` compose and read wren's locator-derived SID layout
  (`[locator][disc][vni]`, RFC 9252) so both sides agree on a SID's tenant and
  behaviour. New `#[repr(C)]` map types `Srv6Endpoint`, `Srv6SidKey`, `Srv6LocalSid`
  (padding-free, `aya::Pod` under the `user` feature) and the `behavior` /
  `sid_disc` code-point modules. Pure contract only — no eBPF object change, so no
  `ebpfHash` bump; the encap/decap datapath (parts 2–3) follows.
- **Stateful-HA conntrack sync (C9)** — a *pfsync*-analog for the eBPF `CONNTRACK`
  map. When `[conntrack_sync]` is set, the agent binds a UDP socket, pushes its live
  conntrack entries to each `peer` every interval, and applies the entries a peer
  pushes — so established NAT'd flows survive a VRRP failover onto the backup. The
  `peer` list is repeatable, so a three-or-more-node cluster forms a full mesh. The
  wire framing is explicit little-endian records and untrusted input is bounded and
  dropped on any malformation; the stream is unauthenticated, so it belongs on a
  trusted/dedicated sync link. File-config-only (an HA-appliance concern) and no
  eBPF change — the `CONNTRACK` map already existed, so no `ebpfHash` bump.

### Fixed

- **Masquerade uses a per-flow WAN source port (NAPT).** Without it two inside
  hosts using the same source port collide on the way out, and the reply goes to
  whichever of them the table happened to hold.
- **The Raft log is persisted**, so writes that were acknowledged survive a
  full-cluster crash instead of being acknowledged and then forgotten.
- **Overlay decap enforces the inner VNI** and no longer admits a frame into a
  segment that has been removed — both are tenant isolation, and both were
  places where a tenant could reach a neighbour's segment.
- **A learned tenant MAC is bound to the port that claimed it**, so one tenant
  cannot steal another's MAC by announcing it.
- **IPv6 extension headers are walked before a packet is classified**, so a rule
  cannot be bypassed by putting the transport header behind one.
- **`FW_FLOWS` is replicated in conntrack sync**, not only `CONNTRACK` — a
  failover was restoring half the state it needs.
- **A load-balanced reply that returns through another zone is un-NAT'd**, and a
  NAT'd reply is admitted through a deny-by-default zone. Both were policy-scoped
  conntrack misses: the reply crossed a zone boundary the forward path never did.
- **A protocol port saturates rather than truncating to `u16`.**
- **SRv6 decap validates the outer next-header** and stops double-counting
  transmitted packets.
- **Agent config reads are scoped to the reading CN**, IPAM allocations are
  deduplicated, `derive` is guarded, and the conntrack token is checked.

### Documentation

- A configuration and API reference.

## [0.3.0] — 2026-07-11

NAT completeness in the eBPF/XDP data plane, plus two datapath correctness fixes.

### Added
- **Hairpin NAT (NAT reflection).** A dual-translation datapath so an internal
  client can reach a port-forwarded service via its public IP: the packet is
  DNAT'd to the internal host and source-NAT'd to the box's address on the
  client's segment, so the reply routes back through the firewall.
- **NPTv6 / NAT66 (RFC 6296).** Stateless, checksum-neutral IPv6 prefix
  translation between an internal ULA prefix and a delegated external prefix, on
  both the TC-egress and XDP-ingress datapaths.

### Fixed
- **Port-forward DNAT reply crossing zones.** The reply to a router-DNAT
  (port-forward) connection is now keyed in conntrack policy-independently, so it
  is matched even though the forward and reply packets enter through different
  zones.
- **eBPF verifier: `Option<PortFwd>` across the forward path.** The main program
  no longer keeps a map-value-pointer niche live across the tail-call split
  (which the verifier rejected as an uninitialised read); it carries a plain
  bool and re-looks-up the target downstream.

## [0.2.0] — 2026-07-07

Extends the fabric orchestration model and adds an HTTP northbound.

### Added
- **Subnets + IPAM (D2)** — first-class subnets with deterministic address
  management in the orchestrator model.
- **Floating IPs / secondary addresses (B6)** — first-class floating IPs and
  additional addresses on ports.
- **REST/JSON northbound gateway (D1)** — a versioned HTTP gateway on the
  controller that exposes the fabric API alongside gRPC (axum, sharing the
  existing tonic hyper/http stack — no duplicate HTTP runtime).
- **gRPC + Raft CRUD** for subnets/IPAM, floating IPs, and security-group
  topology (B5/D2/B6) — mutations replicate through the controller's Raft
  state machine.

## [0.1.0] — 2026-07-05

First tagged release of the fabric eBPF/XDP network core.

### Included
- L2/L3 overlay (VXLAN/Geneve) with per-MAC learning FDB, BUM head-end
  replication, ARP/IPv6-ND suppression, and EVPN↔fabric bridge (B1–B4).
- Firewall (v4+v6, per-policy posture, reject, per-rule log, source-CIDR),
  NAT (masquerade + DNAT), XDP L4 load balancer, tenant scoping.
- gRPC controller with mTLS + per-CN authz, Raft-HA (TLS peer transport,
  on-disk snapshots), orchestrator model (hosts/networks/ports, IPAM,
  live migration), CNI with fail-closed XDP attach.
- **Security groups (B5)** — named rule sets → deterministic per-port
  policy_id, gRPC + Raft CRUD.

### Not yet included
- SRv6 eBPF data plane (B9), inter-network IRB, per-port stats/QoS/mirroring,
  overlay MTU, event streaming.

[0.2.0]: https://github.com/Velstra/fabric/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Velstra/fabric/releases/tag/v0.1.0
