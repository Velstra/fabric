# Changelog

## [Unreleased]

### Added

- **Wren's forwarding table into `ROUTES`, FPM-style.** `--wren-routes` (with
  `--wren-socket`) subscribes the agent to Wren's `monitor routes` feed and
  programs what it hears: each learned route's next hop is resolved to a MAC
  through the kernel's ARP table (an unresolved gateway is nudged and retried
  on the next pass), written under `--wren-routes-policy`, and removed on
  withdrawal; `--wren-routes-table` picks the VRF. A static route wins over a
  learned one for the same destination, on-link routes stay the kernel's,
  IPv6 prefixes are skipped and said so, and a Wren restart leaves the trie in
  force until the feed is back. Best-effort like the EVPN advertiser: nothing
  here can kill the agent.

- **A learned type-5 `End.DT4`/`End.DT6` SID is now refused *visibly*, not
  silently.** The datapath terminates only the L2 SRv6 behaviours
  (`End.DT2U`/`End.DT2M`); an RFC 9252 §6 type-5 route advertises an L3 SID whose
  payload is a bare IP packet, which this single-shared-bridge host model has no way
  to route into the right tenant VRF. The controller therefore keeps deriving the
  L3-VNI `End.DT2U` SID for symmetric IRB (the path B9 shipped) and now surfaces the
  refused L3 SID: `srv6_irb_gated_sids` reports each learned `End.DT4`/`End.DT6` SID
  the datapath cannot honour and which derived DT2U SID was programmed in its place,
  exposed at `GET /v1/srv6/irb-gated` (monotonic `total` + live `current`, the
  sample-not-state contract the SID-divergence surface already uses) and logged once
  per SID. This is the honest half of the Stage-3 gate (EVPN-over-SRv6 convergence
  plan, gap G3): standing up L3 interop with a third-party PE no longer falls back to
  the derived SID with no indication the advertised one was dropped. True
  `End.DT4`/`End.DT6` decap + L3 encap in XDP — which needs a per-tenant L3
  delivery path this host model does not yet have — remains the named follow-up.
- **SRv6 is a complete overlay, not a unicast-only one.** `End.DT2M` frames are
  decapsulated (they were refused outright, so every ARP, ND and DHCP frame on an
  SRv6 segment died), BUM traffic is head-end replicated over SRv6 at the TC layer
  (`SRV6_FLOOD_LIST`, mirroring the VXLAN `FLOOD_LIST` path), and symmetric IRB
  routes over SRv6 (`SRV6_IRB_ROUTES`).
- **SRv6 reaches the wire protocol.** `NodeConfig` carries five new messages —
  `Srv6`, `Srv6Route`, `Srv6LocalSid`, `Srv6Flood`, `Srv6IrbRoute` — and
  `HostSpec` carries an `srv6_locator`. `Encap` gains `ENCAP_SRV6`. Until now the
  agent's config conversion hardcoded `srv6: None` on the way back in, so a
  controller could not have served an SRv6 config even if one had been asked for.
- **The orchestrator derives the whole SRv6 table set** from the same topology
  that drives VXLAN: this host's endpoint, both service SIDs of every segment it
  serves, a unicast entry toward each remote workload, a flood target per remote
  host, and the trusted decap peers.

  Every SID is *derived* — `locator ++ discriminator(1) ++ vni(3)`, the layout
  wren already uses — so nothing is allocated, stored or replicated, and a
  controller failover cannot renumber a running tenant. A peer is addressable the
  moment it exists in the topology, before BGP has converged.
- `--encap srv6 --srv6-locator <prefix/len>` on `velstra-controller orch
  add-host`, `"encap": "srv6"` + `"srv6_locator"` over REST, and a new
  `srv6_bum_replicated` counter.
- **An external (non-topology) EVPN peer is trusted for decap from its learned
  SID alone.** A federated SRv6 speaker that is not a configured fabric host has
  no topology entry to borrow a next-hop MAC from, so this fabric still cannot
  *encapsulate toward* it — but it can now **accept** its frames: the new
  `locator_src_from_service_sid` recovers the peer's zero-filled locator (the
  `SRV6_PEERS` decap-auth key) from a learned `End.DT2U`/`End.DT2M` SID *without*
  its locator length, by locating the standard `disc ++ vni` function window. It
  is conservative — a foreign-layout SID (a PE allocating from its own pool with a
  different structure) recovers nothing and stays untrusted rather than guessed
  at, so the source-auth boundary is no looser than the topology-derived path.
  Until now such a peer's BUM and return traffic was dropped fail-closed. This is
  the decap half of external-peer support; encapsulating toward one still needs
  underlay next-hop resolution EVPN does not carry, and a truly foreign-layout
  peer needs the SID structure on the `monitor evpn` wire — both later chunks.

### Fixed

- **An SRv6 EVPN fabric learned nothing.** wren emits
  `+ evpn vni V mac M vtep VT srv6 SID` once an `srv6-locator` is configured —
  ten tokens, the same count as the `... ip IP vtep VT` form. The monitor parser
  matched on token *count* and required `t[6] == "ip"`, so every type-2 MAC route
  was discarded with no log line and no counter: the MAC-FDB simply never filled.
  The bridging lines now read their tail as keyword/value pairs, which is what the
  type-5 lines two functions below already did.
- **A type-5 route's SRv6 SID was parsed and thrown away**, on the grounds that
  the datapath was VXLAN-only. It no longer is.
- **`add_ip_vrf`-style validation for hosts.** A host whose encapsulation and SRv6
  locator disagree is refused in both directions, rather than silently coming up
  as VXLAN — an operator who believes they enabled SRv6 and did not is the failure
  this prevents.
- **The BUM classifier is attached on an SRv6 host.** `attach_bum_ingress` was
  gated on a VXLAN `[overlay]` being configured, so an SRv6 box had its flood set
  programmed, its counters present, and no classifier — nothing was ever
  replicated. Both halves of the flood path were dead independently, which is why
  neither looked half-working.
- **A VNI's 24-bit ceiling is checked for SRv6 hosts too.** It was gated on
  `[overlay]`, and on SRv6 the VNI goes into a service SID's 3-byte function
  field — the same width — so an over-wide VNI would have been silently truncated
  by `build_service_sid`, putting two segments on one SID.
- **ARP and IPv6 ND suppression no longer require an `[overlay]` section.** They
  are keyed by `(vni, ip)` and answered before any encapsulation, so an `[srv6]`
  host satisfies them too; requiring VXLAN specifically made an SRv6 host's
  derived config fail to resolve.

### Notes

The eBPF object changed (two new maps and three new datapath branches), so an
appliance pinning it needs an `ebpfHash` bump.

Verified by `checks.srv6` in the sentinel repository: two VMs, a real IPv6
underlay, a real eBPF load and real frames, asserting the End.DT2U round-trip,
head-end replication *and* acceptance of an End.DT2M flood copy, symmetric IRB
over SRv6, the gateway-MAC gate, and decap source authentication. Two new
scenarios (`srv6_flood`, `srv6_irb`) cover the same ground in `tests/e2e/run.sh`
for a root shell without Nix.

RFC 9252 §6 specifies `End.DT4`/`End.DT6` for type-5 routes and this deliberately
deviates: that payload is a bare IP packet, which has to be delivered into the
tenant's own L3 device to be routed in the right VRF, and this host model has a
single shared kernel bridge. Symmetric IRB therefore rides an `End.DT2U` SID on
the L3 VNI — exactly what the VXLAN path does — and the controller derives that
SID rather than using the advertised `End.DT4` one. Interop with a third-party PE
needs the L3 behaviours, and those need per-tenant L3 devices first.

## [0.4.1] — 2026-08-01

A build fix. 0.4.0 is sound, but its CI lane was red — and had been since
2026-07-30, which is the part worth saying out loud: three lints were failing
`-D warnings` and nobody was looking.

### Fixed

- **`velstra-controller`: the command enum is boxed.** `clippy::large_enum_variant`
  on a 464-byte `Command`. It is parsed once at start-up, so the size costs
  nothing in practice — but a lint that fails the build is a lint that has to be
  answered, and `Box<ServeArgs>` is what clippy itself suggests. `clap`'s derive
  takes it without complaint and `--help` is unchanged.
- **`velstra-app`: the run-time port-mapping table has named types.**
  `BTreeMap<(PolicyId, u8, u16), ([u8; 4], u16, Instant)>` says nothing about
  what is a key and what is a deadline; `MappingKey` and `MappingValue` do.
- **`velstra-app`: a test no longer assigns a flow state it immediately
  discards.** The value from `flow()` was overwritten before it was read.

Nothing about the data plane, the API or the wire format changes — the eBPF
object is untouched, so an appliance pinning it needs no `ebpfHash` bump.

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
