# Configuration reference

Velstra has **two** configuration surfaces, and it matters which one you are
looking at:

| Surface | Written by | Contents |
|---|---|---|
| **Topology file** (`--topology`) | you | the fabric's *intent* — hosts, networks, ports, tenants, services |
| **Node config** (`--config`, or served by the controller) | the controller | one host's derived *reality* — policies, tunnels, FDB entries, VIPs |

You declare the first. The controller computes the second, per host, and pushes
it. Writing node configs by hand is supported (a standalone agent needs no
controller — see [`examples/rules.toml`](../examples/rules.toml) and friends), but
in a fabric they are an **output**: anything you hand-write there is replaced on
the next derive.

The same entities the topology file declares are also drivable at runtime over
the northbound API — gRPC, the `orch` CLI, and REST. See
[Northbound API](#northbound-api) below.

---

## Topology file

One TOML file describes the whole virtual fabric. Blocks may appear in any order;
the loader resolves them in dependency order (hosts → networks → subnets →
security groups → IP-VRFs → ports → load balancers) and rejects a reference to
something that does not exist.

A worked seed lives in [`examples/topology.toml`](../examples/topology.toml).

### `[[host]]` — a physical node (VTEP)

```toml
[[host]]
id             = "host-1"
vtep           = "10.10.0.1"          # underlay VTEP address (IPv4)
underlay_iface = "eth0"
underlay_mac   = "02:00:00:00:00:11"
encap          = "vxlan"              # or "geneve"; default vxlan
udp_port       = 4789                 # default per encap (4789 / 6081)
underlay_mtu   = 1500                 # sizes the overlay MTU guard
```

The `underlay_mac` is what peers address encapsulated frames to. A wrong one is
not a validation error — it is a black hole — so it is worth checking against
`ip link` on the node.

### `[[network]]` — a tenant L2 segment

```toml
[[network]]
vni            = 5000
name           = "blue"
subnet         = "192.168.100.0/24"   # IPAM allocates port addresses from here
default_action = "pass"               # pass (default) | drop | reject
drop_icmp      = false
```

The VNI doubles as the segment's default firewall **policy id**, which is why a
port with no security group is filtered by its network's `default_action` /
`drop_icmp`.

### `[[subnet]]` — first-class addressing (optional, dual-stack)

A network may carry several subnets — typically one IPv4 and one IPv6. Use these
instead of `[[network]].subnet` when you need a gateway, a bounded pool, or v6.

```toml
[[subnet]]
id          = "blue-v4"
vni         = 5000
cidr        = "192.168.100.0/24"
gateway     = "192.168.100.1"
pool_start  = "192.168.100.10"        # bounds what IPAM hands out
pool_end    = "192.168.100.200"
enable_dhcp = true
```

The gateway and both pool bounds must lie inside the CIDR. Runtime IPAM
allocations and port↔subnet bindings are **not** persisted here — in cluster mode
they live in the Raft snapshot; this file holds declarations only.

### `[[security_group]]` — a reusable rule set

```toml
[[security_group]]
name           = "web"
default_action = "drop"
stateful       = true                 # reply traffic of tracked flows is allowed
drop_icmp      = false
blocklist      = ["198.51.100.0/24"]  # source CIDRs dropped outright

[[security_group.rule]]
proto  = "tcp"
port   = 443
action = "pass"                       # default: drop
log    = false
src    = "10.0.0.0/8"                 # optional; absent = from any source
```

Each group gets a deterministic policy id, so its rules survive restarts and
re-derives. A rule with a source constraint wins over a `from any` rule on the
same port. Ports bind a group by name (see `[[port]]`).

### `[[ip_vrf]]` — a tenant's routed context (B7, symmetric IRB)

Groups several L2 segments into one routed context, so traffic *between* them is
routed rather than bridged, behind one anycast gateway.

```toml
[[ip_vrf]]
l3_vni      = 50100
name        = "tenant-a"
gateway_mac = "02:00:5e:00:00:aa"     # identical on every host of this tenant
networks    = [5000, 5001]
```

Deliberately the same shape as wren's `[[bgp.evpn.ip-vrf]]` — one operator
configures both sides of the same tenant.

- The **gateway MAC must be unicast and non-zero**: it becomes the inner *source*
  MAC of a routed frame, and a multicast one is unroutable. Keeping it identical
  fabric-wide is what lets a migrated workload keep its default-gateway ARP entry.
- A network belongs to **at most one** IP-VRF. Two would make a packet's tenant
  ambiguous, and the datapath would resolve it by map-insertion order.
- Every listed network must exist, and a network cannot be removed while a VRF
  still routes it.
- The L3 VNI has its own 24-bit number space: an L3 VNI numerically equal to some
  L2 VNI is a different context, not the same one.

The remote prefixes themselves are **learned**, not configured — they arrive as
BGP EVPN type-5 routes over wren's `monitor evpn` stream and become `[[irb_route]]`
entries in the derived node config.

### `[[port]]` — a VM/workload NIC

```toml
[[port]]
network        = 5000
host           = "host-1"
tap            = "tap-blue-1"
ip             = "192.168.100.10"     # omit to auto-allocate
security_group = "web"                # binds the group by name
# policy       = 7                    # raw policy id; `security_group` wins
```

The port's id is derived as `port-<vni>-<ip>` and is what the API and pool
members refer to.

### `[[load_balancer]]` — a virtual service (LBaaS)

A VIP fronting a pool of fabric ports, DNAT-rewritten in XDP at the ingress host.

```toml
[[load_balancer]]
id    = "web-vip"
vni   = 5000
vip   = "192.168.100.200"
port  = 80
proto = "tcp"                         # tcp (default) or udp

[[load_balancer.member]]
host = "host-1"
tap  = "tap-blue-1"
port = 8080                           # omit to keep the client's original port
```

A member names its port the way this file names ports — by `host` + `tap` — not
by the generated port id, which you cannot know when the address is
auto-allocated. Over the API a member names the port id directly.

Rejected, because the datapath would accept each of these and then misbehave:

- a second load balancer on the same `(vni, vip, port, proto)` — it would
  *overwrite* the first in the service map rather than collide;
- a VIP equal to a port's own address — that port's traffic would be DNAT'd away
  from it;
- a member on another network — load balancing across a tenant boundary;
- a protocol other than TCP/UDP, or service port `0`.

An **empty pool is legal**: a drained service passes traffic through and counts
`lb_no_backend`. Removing a member's port drains it from the pool automatically.

---

## Northbound API

Every entity above is also drivable at runtime. All three front-ends propose the
same replicated mutations, so they agree in single-controller and Raft-cluster
mode alike.

### CLI

```shell
velstra-controller orch [--endpoint http://127.0.0.1:50052] <verb> [flags]
```

| Entity | Verbs |
|---|---|
| hosts | `add-host` |
| networks | `add-network` |
| ports | `create-port`, `remove-port`, `migrate-port`, `list-ports` |
| security groups | `add-security-group`, `remove-security-group`, `list-security-groups`, `bind-port` |
| subnets / IPAM | `add-subnet`, `remove-subnet`, `list-subnets`, `bind-subnet`, `unbind-addr`, `alloc-addr`, `release-addr` |
| floating IPs | `alloc-floating-ip`, `associate-floating-ip`, `disassociate-floating-ip`, `release-floating-ip`, `list-floating-ips` |
| IP-VRFs | `add-ip-vrf`, `remove-ip-vrf`, `list-ip-vrfs` |
| load balancers | `add-load-balancer`, `remove-load-balancer`, `list-load-balancers` |

Host and network *removal* are gRPC/REST-only today — the CLI has no
`remove-host` / `remove-network` verb.

```shell
velstra-controller orch add-ip-vrf --l3-vni 50100 --name tenant-a \
    --gateway-mac 02:00:5e:00:00:aa --network 5000 --network 5001

velstra-controller orch add-load-balancer --id web-vip --vni 5000 \
    --vip 192.168.100.200 --port 80 --member port-5000-192.168.100.10:8080
```

### REST

Started only when `--rest-listen <addr>` is given (there is no default port).
Bearer tokens map to caller identities with `--rest-token <cn>=<secret>`; with no
tokens configured the gateway is open, mirroring the admin channel's default.

Fabric resources live under `/v1`; `/healthz` and `/version` are unversioned
probes.

| Path | Methods |
|---|---|
| `/v1/hosts`, `/v1/hosts/<id>` | `GET` `POST` / `GET` `DELETE` |
| `/v1/networks`, `/v1/networks/<vni>` | `GET` `POST` / `GET` `DELETE` |
| `/v1/ports`, `/v1/ports/<id>` | `GET` `POST` / `GET` `DELETE` |
| `/v1/subnets`, `/v1/subnets/<id>` | `GET` `POST` / `GET` `DELETE` |
| `/v1/security-groups`, `/v1/security-groups/<name>` | `GET` `POST` / `GET` `DELETE` |
| `/v1/ip-vrfs`, `/v1/ip-vrfs/<l3_vni>` | `GET` `POST` / `GET` `DELETE` |
| `/v1/load-balancers`, `/v1/load-balancers/<id>` | `GET` `POST` / `GET` `DELETE` |
| `/v1/floating-ips`, `/v1/floating-ips/<id>` | `GET` `POST` / `GET` `DELETE` |
| `/v1/floating-ips/<id>/associate`, `/v1/floating-ips/<id>/disassociate` | `POST` |
| `/v1/audit` | `GET` |
| `/v1/events` | `GET` (SSE) |
| `/healthz`, `/version` | `GET` |

Reads are open; **mutations are admin-only** (a node token may only register its
own host and create ports on it) and every one of them — allowed or denied — is
recorded in the audit log.

```shell
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
     -X POST http://127.0.0.1:9500/v1/load-balancers \
     -d '{"id":"web-vip","vni":5000,"vip":"192.168.100.200","port":80,
          "members":[{"port_id":"port-5000-192.168.100.10","port":8080}]}'
```

#### Change events

`GET /v1/events` is a Server-Sent Events stream of the same records the audit log
keeps — which operation touched which target, by whom, and whether it succeeded.
That is enough for a consuming product to react by re-reading the affected
resource, instead of polling the whole fabric.

```
event: audit
id: 9
data: {"seq":9,"ts_millis":1785014747925,"actor":"ops-admin",
       "operation":"network.create","target":"vni=101","result":"ok"}
```

Only records emitted *after* subscribing are delivered; `GET /v1/audit` serves
the backlog, so a consumer that wants both reads the backlog first and
de-duplicates on `seq`. A subscriber that cannot keep up is **lagged**, not
blocked — it gets an `event: lagged` naming how many records it missed and the
stream continues. Back-pressure is deliberately not an option here: a slow
consumer must never stall the fabric's mutations.

Errors use one envelope throughout:

```json
{ "status": 400, "message": "load balancer \"web\": 10.0.0.5:80 is already fronted by \"other\" on this network" }
```

### gRPC

`VelstraOrchestrator` on the admin port, defined in
[`velstra-proto/proto/velstra.proto`](../velstra-proto/proto/velstra.proto) —
the authority for field numbers and message shapes. The CLI is a thin client over
it.

---

## Derived node config

What the controller pushes to each agent. You do not write this, but knowing its
shape is the fastest way to read what your intent actually produced:

| Block | Meaning |
|---|---|
| `[[policy]]` | one per participating network and per bound security group |
| `[[interface]]` | a local tap, bound to its policy + VNI |
| `[[tunnel]]` | a remote tenant address → the VTEP hosting it |
| `[[mac_route]]` | EVPN-learned MAC → VTEP (L2 bridging) |
| `[[neighbor]]` / `[[nd_neighbor]]` | ARP / IPv6 ND suppression entries |
| `[[flood_vtep]]` | the BUM head-end replication set for a VNI |
| `[[irb_route]]` | a learned remote prefix, routed via the anycast gateway |
| `[[service]]` | a load-balanced VIP, once per policy id on the segment |
| `[overlay]` | this host's VTEP identity and encapsulation |

A load balancer appears once per policy id in play on its segment, not once per
network: the datapath looks a service up under the **ingress port's** policy id,
which equals the VNI only for ports with no security group.

---

## See also

- [ARCHITECTURE.md](ARCHITECTURE.md) — how the pieces fit together
- [TESTING.md](TESTING.md) — running the datapath against real traffic
- [`examples/`](../examples/) — worked configs for each surface
