# Rustix dependency correction

The November 2026 build dependency update moved the locked `rustix` 1.x dependency from 1.1.4 to 1.1.6 for the extended-attribute correction. It entered the build graph through protobuf code generation. A separate 0.38.x entry used by other dependencies was outside the change.

To inspect the dependency chain at the revision you intend to build:

```sh
cargo tree --locked -i rustix@1.1.6
```

This command addresses the recorded lockfile version; use the current locked version for later revisions. Consumers that pin Fabric must advance their own input and qualify the resulting build.

[Upstream correction](https://github.com/bytecodealliance/rustix/commit/8e6aaa6713d2bb64b1fdd8c472e3a32a10a76d70) · [Advisory](https://rustsec.org/advisories/RUSTSEC-2026-0486.html) · [Release qualification](RELEASE-POLICY.md)
