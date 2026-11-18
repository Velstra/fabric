# Firewall-state publication fault test

Run the fixture checks without kernel privileges:

```sh
cargo test -p velstra --test firewall_publication
```

The ignored test needs a disposable privileged Linux VM and a **source-derived
instrumented object**. In the frozen candidate's `velstra-ebpf/src/main.rs`,
replace exactly this single declaration:

```rust
static FW_FLOWS: LruHashMap<FirewallKey, FirewallState> = LruHashMap::with_max_entries(65536, 0);
```

with:

```rust
static FW_FLOWS: HashMap<FirewallKey, FirewallState> = HashMap::with_max_entries(4, 0);
```

Reject a missing or non-unique source match. Make no other product-source
changes. Build with the candidate's pinned toolchain/dependencies and retain
the source manifest, transformation and original/instrumented object hashes.
The ordinary preallocated HASH cannot evict entries; capacity four makes actual
kernel map-insert failure deterministic. Production LRU overflow does not.

```sh
VELSTRA_FW_PUBLICATION_OBJECT=/absolute/path/instrumented-ebpf.o \
VELSTRA_FW_PUBLICATION_RECEIPT=/run/firewall-publication.json \
  cargo test -p velstra --test firewall_publication \
  kernel_publication_failures -- --ignored --exact --nocapture
```

Use the compiled test executable directly in a VM without Cargo. The companion
Sentinel Nix fixture accepts that executable package and the instrumented object.
No programs are attached, no maps are pinned, and no network packets are emitted.
Every case gets fresh maps; programs run with `BPF_PROG_TEST_RUN`, repeat one.
Before every packet, the harness checks the private scratch-map ABI, fills all
possible CPU slots with `0xa5` and verifies readback. Exact IPv4 key comparisons
therefore detect stale address tails rather than relying on zeroed fresh maps.

## Assertions

XDP IPv4 ingress, plain TC IPv4 egress, TCP masquerade and ICMP echo masquerade
each run with two, three and four unrelated entries preloaded:

| Preloaded | Required result |
| --- | --- |
| 2 | Pass, both directional state entries published |
| 3 | Drop, exactly the first directional entry retained |
| 4 | Drop, neither directional entry published |

The test checks the kernel map type/capacity/layout/flags, exact packet action,
both directional keys and reply roles, IPv4 and transport checksums, unchanged
unrelated keys and values, and exact failure/aggregate-drop/NAT-success counter
deltas. Partial paired publication is intentionally visible, not rolled back.
TCP masquerade seeds reverse first; the other paths record forward first.

Additional ingress/egress controls prove that stateless SYNs and untracked ACKs
do not manufacture publication failures, and a real SYN/SYN-ACK/ACK sequence
updates both existing directions when the map is full. Successful completion
writes 18 case receipts with the exact instrumented object SHA-256.

## Limits

This tests real candidate writers under deliberate map-capacity faults, **not
the exact production object**, wire delivery, successful LRU-eviction retention,
atomic paired publication, concurrent admission or expiry/HA fencing. A rewritten
packet returned by a dropped TC test-run is diagnostic data, not an emitted
packet. IPv6, router-NAT, load-balancer and SYN-cookie writer branches require
separate packet fixtures; these 18 cases do not claim their coverage. Repeat
normal packet and verifier gates against the unchanged release object.
