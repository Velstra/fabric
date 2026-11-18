# Compact firewall state

`FirewallSessionKey` and `FirewallSession` define a **storage contract**, not
the current `FW_FLOWS` datapath. The production map and HA wire protocol are
unchanged. Passing these tests does not pass the stateful traffic pressure gate.

## Representation

One canonical key holds both directional values. TCP/UDP endpoints sort by
address then port; ICMP echo uses the request as its canonical direction.
Policy, address family, protocol, ports and echo identifiers remain part of
identity. Opposite echo requests remain separate sessions. Unsupported keys,
nonzero padding, noncanonical IPv4 address tails and symmetric TCP/UDP tuples
are rejected instead of aliasing permissions.

Both directions retain their own phase, initiator/responder bit, local activity
and imported age. Packing never selects the freshest direction or completes a
handshake. Existing complete pairs round-trip without changing either value;
incomplete or conflicting pairs are rejected. Reclamation requires **both**
directions expired and still requires an external writer fence.

| Logical storage | Directional format | Compact format |
| --- | ---: | ---: |
| One policy, both directions | 2 entries, 136 payload bytes | 1 entry, 92 payload bytes |
| Two policies, one NAT flow | 4 entries, 272 payload bytes | 2 entries, 184 payload bytes |
| 20,000 such flows | 80,000 entries | 40,000 entries |

These are key/value payload sizes, not measured kernel allocation. The proposed
value is **48 bytes instead of 24**. At a fixed 65,536-entry limit, preallocated
key/value payload would increase from 4.25 MiB to 5.75 MiB, even though payload
per complete flow falls. Kernel bookkeeping, alignment and allocator overhead
need separate measurement before production adoption. No production map was
enlarged or replaced by this change.

## Tests

- Common unit tests cover canonical identity, import-order independence,
  rejection of invalid pairs, lossless directional expiry, and every 8-bit
  control value across supported protocols, phases, directions and age cases.
- `velstra-app/tests/firewall_session.rs` creates disposable, unpinned kernel
  HASH maps. It checks all four logical roles at each load step through 20,000
  flows, then fills 65,536 physical entries with 32,768 two-policy flows.
  These are synthetic state records: **no TCP connection is created** by this
  test. Traffic-level retention is still a separate failed acceptance gate.
- Overflow and duplicate `NOEXIST` writes must preserve all retained values;
  `EXIST` updates at capacity must not create missing sessions.
- Four workers rendezvous before and after each of 2,048 claims. Exactly one
  complete value may win each key. A separate test checks concurrent syscall
  whole-value replacement and lookup for mixed directional values.

The kernel test is ignored by ordinary unprivileged Cargo runs. The dedicated
Nix VM fixture explicitly executes it and requires its structured receipt.
It never opens or mutates an appliance's existing map.

## Integration gates still open

This is not a drop-in map type change. Before enabling it:

1. Serialize packet read/modify/write transitions. Atomic whole-value syscall
   replacement does not prove in-place eBPF writes or prevent lost updates.
2. Admit complete multi-policy/NAT flows without evicting existing owners or
   exposing a partially admitted connection. One canonical pair is not an
   atomic transaction across two policies and NAT state.
3. Adapt every writer, reader, diagnostic, FlowSpec purge, expiry operation and
   replication import/export. Do not import a partial legacy pair as complete.
4. Define HA mixed-version compatibility and fenced migration/restart. Keep
   independent imported ages and reject conflicting directional identities.
5. Load the actual new packet object on supported kernels, rerun packet/HA
   regressions, then run the unchanged 20,000-connection traffic gate. Measure
   full-table rejection, bounded reclamation, memory and packet interruption.

Until these gates pass, the existing production pressure failure remains open.

### Consumer checklist for the format switch

| Consumer | Required invariant |
| --- | --- |
| `velstra-ebpf/src/conntrack.rs` | Classification chooses the original direction; updates and reset/expiry handling cannot overwrite another writer's progress. |
| `velstra-ebpf/src/icmp_related.rs` | Quoted-flow permission checks select the correct directional state, including NAT normalization. |
| `velstra-app/src/firewall.rs` | FlowSpec purges, policy resets, diagnostic rows and duplicated map handles understand the actual map ABI. |
| `velstra-app/src/expiry.rs` | Reclaim only a completely expired session behind the existing writer fence. |
| `velstra-app/src/conntrack_sync/secure.rs` | Snapshot/import preserves both directions, clocks, authority, generation and full-state bounds. |
| `velstra-app/src/capacity.rs` | Report physical occupancy separately from logical directional/session counts. |
| `sentinel/nix/nat-capacity-pressure-probe.py` | Decode the new ABI into the same four logical roles; do not weaken socket, timing or ownership assertions. |

A legacy peer with 65,536 directional slots **cannot hold 80,000 directional
rows** exported from 20,000 complete two-policy flows. Merely expanding the new
format back into old wire rows therefore does not establish mixed-version HA
compatibility. Require explicit peer capacity/format agreement or refuse that
migration; never truncate a snapshot and declare the standby ready.
