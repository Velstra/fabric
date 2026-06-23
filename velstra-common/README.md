# velstra-common

The shared ABI / wire types for [Velstra](https://github.com/Velstra/fabric), an
eBPF/XDP software-defined networking stack written in Rust.

These are the `#[repr(C)]` structs the data plane and the user-space agent both
use — BPF map keys/values (policy config, conntrack, services, FIB routes,
overlay FDB/ARP) and packet/overlay header helpers. Defining them once here is
what lets the kernel program and the controlling agent agree on a layout, and
lets the *same* logic be unit-tested in user space and compiled into the kernel.

The crate is `no_std`-compatible (it compiles into the BPF object). The optional
**`user`** feature pulls in [`aya`](https://github.com/aya-rs/aya) to mark the
types `aya::Pod` for user-space map access.

## License

MIT OR Apache-2.0 — a permissive ABI library. The Velstra product is
AGPL-3.0-or-later.
