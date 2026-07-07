# Changelog

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
