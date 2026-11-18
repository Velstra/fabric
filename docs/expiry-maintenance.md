# Explicit expiry maintenance

The privileged local query socket accepts:

```text
expire-state firewall 1024
expire-state nat 1024
```

The second argument is the maximum entries examined (1–65,536), not a deletion
count. There is no timer. Do not grant untrusted processes access to this socket.

Maintenance requires a ready standalone agent with current applied intent and
no HA or conntrack replication. It holds the firewall writer lock, closes
`APPLY_STATE`, drains existing kernel packet readers and samples monotonic time.
Candidates are collected before deletion and individually rechecked against the
applied timeouts. An expired direction does not authorize removing its reverse.
NAT maintenance also excludes other users of the shared NAT handle.

The JSON result reports `examined`, `removed`, `scan_complete`,
`budget_exhausted`, `pause_ns` and the completed configuration `generation`.
Scanning/deletion stops at a 250-ms work budget; kernel calls and the preceding
reader drain can overrun it. `pause_ns` reports actual elapsed time, not an SLA.

`scan_complete=false` is a partial prefix of the hash-map walk. There is no
persistent scan cursor: repeated bounded calls are not guaranteed to cover the
whole table. This command is not a background collector or zero-loss operation;
traffic arriving while the gate is closed is rejected.

Any failure after attempting closure tries to leave the datapath failed and
reports the error. If the failed-state write also fails, status explicitly
reports uncertain forwarding, not healthy success. Another maintenance call
cannot clear this condition; successful configuration reconciliation is needed.
Precondition failures do not reopen an existing failed transaction.

This does **not** prevent LRU eviction, admit more live flows, reclaim SYN-proxy
state, provide atomic pair publication or support HA. The 20,000-flow release
gate remains failed. Qualification evidence for this new operation must be
recorded separately from the previously qualified packet-object baseline.
