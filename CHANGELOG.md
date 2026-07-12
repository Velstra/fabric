# Changelog

## [Unreleased]

### Added
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
