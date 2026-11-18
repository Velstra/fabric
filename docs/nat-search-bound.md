# NAT discovery bound

The standalone TCP/UDP allocator previously scanned all 32,768 permitted ports
before every new default-layout allocation. A separate eight-byte array now
summarizes the largest displacement it may have published. This changes search
cost, not port selection, ownership checks, map capacity or timeout policy.

## Safety invariant

- Before inserting candidate index `i`, the allocator atomically ORs `i` into
  the shared summary. The OR is at least every index that contributed to it.
- Search visits indices `0..=summary`, capped to the domain. An empty map's
  initial zero therefore searches index zero, not an empty range.
- The summary never decreases, including after failed claims, deletion, expiry
  maintenance and configuration reset. It cannot be evicted.
- Generic NAT, legacy allocation and ICMP allocation permanently set the
  summary to 65,535 **before** writing. These paths then require full discovery.
- Non-default layouts always search their full domain and invalidate the
  summary before allocation. Layout changes cannot reinterpret a narrow bound.
- A changed summary after a missed search triggers one complete-domain search.
  Missing metadata also forces full search; inability to mark prevents writing.
- Replication retains the existing legacy mode. Changing between standalone
  and replicated configuration requires the existing service-restart contract,
  which creates fresh, unpinned maps together. This is not a replicated index.

All dataplane accesses to the summary are atomic. The pinned BPF Rust target
requires a compiler intrinsic for atomic OR; the object must pass the supported
kernel verifier matrix before packet qualification. The build script probes
the actual compiler's intrinsic signature using metadata-only compilation;
unsupported signatures stop the build. The compiler contract exercises both
supported signatures, host-target bypass and compiler failure.
External privileged writes
to NAT maps are not a supported insertion path: diagnostic seeders must first
invalidate the summary or use the normal guarded writer.

This does not make NAT allocation linearizable. Existing publication, LRU
eviction, failed-rewrite cleanup and same-flow concurrency limitations remain.
A concurrent writer within the already covered range has the same race as a
full scan. The summary can grow conservatively to full discovery, permanently
losing the speedup until service restart; it never trades coverage for speed.

The 20,000-flow retention failure is separate: four directional firewall
records per connection still exceed the existing 65,536-entry firewall map.
