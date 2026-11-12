# Rustix extended-attribute dependency correction

The locked `rustix 1.1.4` is covered by
[RUSTSEC-2026-0486](https://rustsec.org/advisories/RUSTSEC-2026-0486.html),
issued November 11, 2026. The upstream correction is
[`8e6aaa6`](https://github.com/bytecodealliance/rustix/commit/8e6aaa6713d2bb64b1fdd8c472e3a32a10a76d70).
The lock now selects patched `1.1.6`, registry checksum
`e5e76742e5294153d4dde1207dbec5bdd81eef6fabdc0d2118babadabfd858aa`.
The unaffected `0.38.44` entry and all other package versions remain unchanged.

In Fabric's resolved graph, the affected 1.x entry comes through
`tempfile -> prost-build -> tonic-build` during protocol code generation.
The source dependency is corrected rather than exempted. A locked version alone
does not prove that an attacker can reach the affected functions in Fabric.

Qualification includes formatting, strict host/agent Clippy, the full applicable
host/agent tests and real BPF compilation. Seven privileged agent tests ignored
on the ordinary workstation are not claimed as passes; their actual kernel VM
execution remains separate.

An independent real-filesystem probe requires successful nonempty user-xattr
roundtrips and tests all six affected get/list functions with initialized
zero-length slices. It does not skip unsupported filesystems or execute the
unsafe Vec variant. The original 1.1.4 reports unwritten byte counts; patched
1.1.6 returns zero for all six. The same normal roundtrip passes both versions,
and the empty-buffer assertion fails only on the original. The local bounded
proof has SHA-256 `a2ef44bbda199d8bb6a5bacf6663213117dd2c2eef4efecfc17ba4c776c5462c`.

No dataplane source, map ABI, HA protocol or publication rule changed. Sentinel
must deliberately advance its current Fabric input to include this fix; the
historical old-allocator test input must remain separate. This source correction
is not a final-image CVE clearance or a production release certificate.
