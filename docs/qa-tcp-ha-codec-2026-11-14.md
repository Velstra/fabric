# TCP HA codec primitives — not runtime-qualified

This tranche implements and host-tests a portable codec. It does **not** switch
the running VCS2 receiver, install a TCP map, or fix the observed wrong-sequence
RST dataplane failure. The module is compiled only by the host-test target until
runtime integration is approved; no dead-code lint waiver is used. Old and new
runtime schemas must not be mixed.

## Exact portable contract

`velstra-app/src/conntrack_sync/tcp.rs` uses the common canonical
`TcpSessionKey` and the complete validated `TcpSnapshot`:

| Record | Explicit little-endian layout | Bytes |
| --- | --- | ---: |
| Schema descriptor | `VTSC`, version1, reserved0, key44, snapshot120, state ABI1 | 16 |
| Upsert | `VTC1`, version1, kind1, key44, initiator-side4, snapshot120 | 176 |
| Qualified deletion | `VTC1`, version1, kind2, key44, initiator-side4, incarnation8, admission-domain8 | 72 |

The key sorts endpoints by address bytes and then **numeric** port. IPv4 tails
must be zero; family must be4/6. Port0 is representable. Identical endpoints
are explicitly rejected because packet direction would be ambiguous. The
initiator side is immutable session orientation, not current packet direction.

No spinlock, local config epoch, absolute monotonic clock or local revision is
serialized. Every snapshot field is encoded explicitly, not by struct memcpy.
Unknown versions, kinds, ABI/flags, reserved values, inconsistent snapshots,
truncation, trailing bytes and noncanonical keys are refused. Legacy flags-only
`VCS1` TCP records cannot be promoted by this decoder. The existing active
legacy decoder is unchanged and this module is **not** its runtime replacement.
`GC_PENDING` remains a local retirement-in-progress state, not an authoritative
portable Upsert; that phase is rejected even when structurally valid. A qualified
deletion can carry its identity without promoting it as ready session state.

Each record has a two-byte length prefix. Batches are bounded by both256 records
and32768 **payload** bytes (the VCS2 authenticated outer envelope adds77 bytes).
Thus184 upserts fit32752 bytes;185 require a second frame. An independent mixed
case fills exactly32768 bytes. Duplicate keys are rejected, and the whole frame
is decoded before any caller could apply its records. Empty input produces no
frames; an empty record frame is rejected.

Qualified deletion equality checks canonical key, initiator side, incarnation
and shared policy admission domain. It is necessary protection against deleting
a newer connection using the same tuple, not authority or an ordering protocol.

## Runtime migration still required

1. Authenticate an exact schema descriptor in BEGIN before HA authority,
   snapshot installation or readiness. Reject older peers explicitly; never
   fabricate TCP sequence/window state from old flags-only records. Planned
   draining/reconnect may be needed across this incompatible upgrade.
2. Create the agreed canonical HASH authority with a BTF-recognized top-level
   spinlock and explicit initiator/local-epoch/session fields. Export a coherent
   per-value snapshot while kernel writers use that same lock.
3. Use lock-aware map access. Linux documents `BPF_F_LOCK` for spinlocked value
   lookup/update; an ordinary `elem_flags=0` batch is not the new coherence
   contract. A lock-aware copy is not an atomic compare-and-swap of incarnation
   and revision. Live replacement/import and deletion still need a proven owner
   protocol, fencing and kernel lifecycle, not a stale lookup followed by a
   blind update.
4. Preserve node-local revision monotonicity for in-place changes. The pure
   `TcpSession::import` constructor is only for a fresh fenced object; repeatedly
   resetting a live same-incarnation object to revision1 creates an ABA hazard.
   Allocate nonreused incarnations and retain sufficient terminal/order evidence
   across reconnects. Authenticate and order every deletion as well as upsert.
5. Integrate NAT/physical-policy aliases, SYN-proxy sequence spaces, timeouts,
   GC/capacity and ownership without creating a second TCP authority. Prove
   concurrent insertion, export, import, tuple reuse, failover and recovery in
   real kernel/packet tests before enabling this format.

The current snapshot ABI has no TCP-MD5/TCP-AO session-authentication requirement.
An option-free reset can still be rejected by an authenticated endpoint; this
codec does not invent authentication capability. TCP timestamp/PAWS and complete
packet observation also remain separate integration proof obligations. Parser
syntax/checksum flags alone cannot establish those session-level facts.

Primary interfaces: [Linux BPF UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/bpf.h),
[HASH map concurrency](https://docs.kernel.org/bpf/map_hash.html),
[Aya HashMap implementation](https://github.com/aya-rs/aya/tree/main/aya/src/maps/hash_map).

## Host verification scope

Ten dedicated tests cover independent literal golden vectors, all directional
metadata, schema/reserved failures, every truncation, malformed state, qualified
deletion, IPv6/numeric ports, byte/record limits, duplicate/partial batches and
10000 deterministic malformed mutations. These are codec/model tests, not HA
runtime or verifier acceptance. Full userland/Clippy receipts are recorded in
the private audit work directory; the parent release ledger owns final status.

Actual commands, from `fabric`:

```sh
AYA_BUILD_SKIP=1 CARGO_BUILD_JOBS=2 VELSTRA_EBPF_TOOLCHAIN=nightly-2026-08-01 \
  cargo test -p velstra --target x86_64-unknown-linux-gnu
AYA_BUILD_SKIP=1 CARGO_BUILD_JOBS=2 VELSTRA_EBPF_TOOLCHAIN=nightly-2026-08-01 \
  cargo clippy -p velstra --target x86_64-unknown-linux-gnu --all-targets -- -D warnings
rustfmt --edition 2024 --check velstra-app/src/conntrack_sync/tcp.rs
```

The final host run passes165 tests in5.00s, with7 existing privileged kernel
tests explicitly ignored (CAP_BPF/CAP_SYS_ADMIN VM coverage is separate).
Clippy and scoped rustfmt pass. `AYA_BUILD_SKIP` reuses the already-built real
embedded ELF, SHA256
`3792780bf341c438b91efcfd12916cd605f959968d1b1a7ba5a4c9a7e884d2a0`;
it does not substitute a fabricated object or qualify a new BPF build.

Codec source SHA256:
`8af53353f221b3cf4034cec577a706a17009f1621d2dc4564cdf3f07fba0f282`.
Receipts under private `work/audit-fixes-20261113.O9Vnp70C/`:
`tcp-ha-codec-app-host-v3.log` and `tcp-ha-codec-app-clippy-v4.log`.
The final run includes GC-pending Upsert refusal and qualified deletion control;
earlier host/Clippy receipts are retained as v2/v3.
Earlier Clippy failures remain disclosed: a concurrent parser MSRV issue, then
unwired production dead-code and a test-helper lint. The codec is now explicitly
test-only rather than enabled prematurely or covered by a blanket lint waiver.
