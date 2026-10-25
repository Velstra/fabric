# HA state replication

Configure both nodes with the same strong random credential and explicit peers:

```toml
[conntrack_sync]
listen = "10.3.0.1:5429"
peer = ["10.3.0.2:5429"]
secret = "replace-with-at-least-32-random-bytes"
interval_ms = 50
```

Reverse the endpoints on the other member. `secret` selects TCP, with fresh
mutual challenges and HMAC-SHA256 authenticated, sequenced frames. There is no
automatic downgrade to UDP. Authentication does not encrypt flow metadata; use
WireGuard or a private HA network for confidentiality. Without `secret`, existing
configurations retain the original unauthenticated UDP protocol and second-based
`interval_secs`. Do not expose that listener to an untrusted network.

The producer uses `BPF_MAP_LOOKUP_BATCH` on the NAT and dual-stack firewall LRU
maps. A new TCP connection sends a full snapshot; subsequent frames carry changed
records and deletions. Interrupted streams reconnect with a fresh session and
snapshot. Relative idle ages cross the wire; a peer's monotonic clock and traffic
counters never replace local clock values or accounting. Locally advanced state
takes precedence over queued peer updates and deletions. Unchanged imported
entries are not sent back to their source. A completed replacement snapshot
removes stale imports belonging to that peer.

Each frame names a SHA-256 fingerprint of shared filtering, NAT, policy IDs,
interface bindings and state lifetimes. Applying a frame holds the same lock as
live policy reconciliation. An incomplete/failed apply or a different fingerprint
rejects the stream; reconnect retries after both nodes converge. Node-local
routes, link addresses and sync endpoints are not part of the fingerprint.

Replication is asynchronous: a failure before a new flow reaches the standby can
lose that flow. Keep the default 50ms interval for fast failover. Larger explicit
intervals increase the potential state loss window. Conntrack replication does
not elect or fence a master. VIP election, NAT to a shared address, and protection
against two simultaneously forwarding masters must be configured separately.

The Sentinel `ha-kernel` NixOS check exercises actual LRU maps, authenticated TCP,
deltas, deletion, local ownership and rejection of obsolete policy state. The
`ha-failover` check uses four VMs and an established TCP socket through shared
SNAT while terminating the active VM without a graceful VRRP withdrawal.
