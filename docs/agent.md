# Agent operation

The agent reads a node policy from TOML or receives one from the controller.
The controller's topology file is a different input; see
[Configuration](CONFIGURATION.md). Use a lab interface for attachment tests.

## Local policy

```sh
./target/release/velstra validate examples/rules.toml
sudo ./target/release/velstra run --iface eth0 --config examples/rules.toml
```

Replace `eth0` with the intended interface. `--iface` is repeatable. The default
XDP mode tries the native driver and falls back to generic/SKB; use
`--xdp-mode skb` for namespace/veth labs. Ctrl-C detaches the agent.

Policies are demonstrated in [rules.toml](../examples/rules.toml) and
[multitenant.toml](../examples/multitenant.toml). Blocklist and ICMP checks take
precedence over port rules and the default action. Named interface policies
select the relevant map entries; unassigned interfaces use policy 0.

`stateful = true` admits tracked replies, while blocklists still take precedence.
Attach to both sides to observe forwarded connections. Add `--egress` for the
IPv4 TC egress hook and host-originated state tracking. It is opt-in and can
block the host's own traffic. Routed IPv6 and the IPv4 XDP FIB/load-balancer
paths have different capabilities; do not infer IPv6 fast-path routing from
dual-stack firewall support.

## Live updates

The agent closes a packet gate while replacing policy maps and draining kernel
readers. A failed apply restores previous configuration and temporary mappings;
failed restoration keeps traffic blocked and retries reconciliation. Query
status reports the failure rather than claiming a healthy policy.

The barrier needs Linux `MEMBARRIER_CMD_GLOBAL` support and no `nohz_full`.
This protects updates inside the running agent; it is not persistent firewall
attachment after agent termination.

## Routing, NAT and overlays

- [router.toml](../examples/router.toml): IPv4 longest-prefix forwarding,
  next-hop MAC rewriting and L3 TTL/checksum handling. Native redirects also
  require support in the egress NIC driver.
- `--wren-socket PATH --wren-routes`: consume Wren's route stream. Static
  routes take precedence, unresolved gateways are retried, and route-feed or
  neighbor-read failures do not mean an empty routing table. IPv6 and on-link
  learned routes remain kernel-delegated. The default policy is 0 and table
  254; select others with `--wren-routes-policy`/`--wren-routes-table`.
- [loadbalancer.toml](../examples/loadbalancer.toml): IPv4 VIP DNAT with
  conntrack/reverse SNAT. Attach on client and backend sides. A backend marked
  `draining = true` receives no new flows but keeps existing ones;
  `client_affinity = true` chooses by client address, reducing distribution
  when many clients share one source NAT address.
- [overlay.toml](../examples/overlay.toml): VXLAN/Geneve, VNI-scoped neighbor
  suppression and tunnel lookup. VNI and firewall policy are separate identities.
  Size tenant MTUs for the underlay/encapsulation; the guard drops oversized
  packets and does not implement full ICMP packet-too-big discovery. The agent
  derives MSS limits for configured tunnels.

Counters describe the observed packet path, not proof that a remote application
completed a request. Use [traffic tests](TESTING.md) for end-to-end behavior.

## Controller connection

For an isolated plaintext lab, start the controller on loopback:

```sh
./target/release/velstra-controller serve --config-dir examples/controller
```

For remote deployments, configure mutual TLS on the controller and agent using
`--tls-cert`, `--tls-key` and their CA options; do not expose the lab's plaintext
channels. Agent `--controller` endpoints are repeatable for failover. The agent
keeps its last-applied policy during a controller outage.

The controller's `admin`/`orch` commands, topology persistence, REST access and
load-balancer management are covered in [Configuration](CONFIGURATION.md).
Controller Raft replication is distinct from Sentinel appliance HA/conntrack
failover; see [architecture](ARCHITECTURE.md),
[Kubernetes](kubernetes.md) and [state replication](ha-state-replication.md).
