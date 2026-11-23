# Connection-state reclamation and capacity

## Background reclamation

The datapath treats an expired connection entry as absent but never deletes
it. The agent therefore runs a background collector over `FW_FLOWS` and
`CONNTRACK`: every second it walks a bounded slice (65,536 entries) of each
table, resuming where the previous tick stopped, and deletes entries that are
expired by the applied `[conntrack]` timeouts. While the SYN-proxy splice sweep
runs (below) the slice of these two tables grows to a fifth of the table, so a
walk takes at most five ticks however large the tables are sized.

The collector **never closes the datapath gate**. Deleting an entry the
datapath already ignores changes no verdict, so there is no pause and no
failure mode that blocks traffic. Each candidate is re-read immediately before
its delete, so an entry refreshed since the walk is kept. What remains is a
window of microseconds in which a new connection that reuses an expired tuple
could lose its first entry; it recovers with one retransmission.

`SYN_FLOWS` carries no timestamp. Its records (one per SYN-proxied
connection, the sequence offset the proxy translates by) are ended by the
**splice sweep** the same walk drives: every live `FW_FLOWS` and `CONNTRACK`
entry claims the splice of its connection, and a record no live entry claims
for two complete rounds of both tables, and for at least 2 s (or ten
conntrack-sync intervals), is removed. A proxied connection therefore lives
exactly as long as its connection state. The sweep runs only while some port
is SYN-proxied and only on a node that owns its state (always without leased
HA, otherwise the lease owner). Without leased HA it never judges a record
conntrack sync holds as imported from a peer; a leased owner owns everything
it holds and judges all of it. Removals are counted as the `SYN_FLOWS` table's
`reclaimed_expired`. A round reads all of `SYN_FLOWS` once (about 36 bytes of
transient memory per record, some 150 MB at the 2M-connection ceiling) and
walks `FW_FLOWS` and `CONNTRACK` in five ticks each; its CPU cost at the
largest sizes has not been measured.

## On demand

The privileged local query socket also accepts:

```text
expire-state firewall 65536
expire-state nat 65536
```

The second argument is the maximum entries examined (1–65,536). The call runs
one immediate pass of the same collector on its own map handles and reports
`examined`, `removed`, `scan_complete` and `elapsed_ns` as JSON. `pause_ns` is
always 0: nothing is paused. Do not grant untrusted processes access to this
socket.

## Capacity

The state maps are sized when the agent loads, from `[state] connections`, or
from the host's memory when that is absent (about a twelfth of RAM; never
fewer than 16,384 connections). One connection is budgeted six `FW_FLOWS`
entries and two `CONNTRACK` entries, which covers a port-forward.

```toml
[state]
connections = 262144   # optional; default derived from RAM
persist = true         # keep hooks and state across an agent restart
```

`capacity` on the query socket reports each table's size and its occupancy
from the collector's last complete walk, and a table at or above 80 % is
`warning`; the agent also logs a warning when a table crosses that mark. A
table not walked within two minutes is `unknown`, never healthy.

Changing `[state]` requires an agent restart (`reload` answers
`restart-required`).

## Persistence

With `persist = true` the agent pins its XDP and TC egress attachments and the
connection-state maps under `/sys/fs/bpf/velstra`. A crashed or stopped agent
leaves the last policy enforcing; the next agent swaps its programs into the
pinned attachments atomically and adopts the established connections, if the
state layout, the table sizes and the interface-to-policy assignment are
unchanged. Otherwise it starts with empty tables and logs why.

`velstra release-datapath` detaches everything a persisting agent left pinned.
Run it only with the agent stopped. Starting an agent with `persist = false`
does the same.
