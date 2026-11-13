# Contributing

Contributions are welcome — bug reports, fixes, features, docs.

## License

Velstra is **AGPL-3.0-or-later** (the shared ABI libraries are MIT/Apache and
the eBPF object is GPL/MIT — see [`LICENSING.md`](LICENSING.md)).

Contributions use the license of the component they modify. There is currently
no administered Contributor License Agreement (CLA) or configured CLA-enforcement
process. A pull request is not evidence of consent to additional commercial
relicensing rights. Any future CLA requires a separate, explicit process and
review of existing contributions.

## Development

```sh
make test          # whole workspace (no root)
make e2e           # end-to-end on dummy interfaces (root) — see tests/e2e/
cargo clippy --workspace --exclude velstra-ebpf
cargo fmt --all
```

The eBPF data plane cannot be unit-tested (it needs the kernel verifier at load
time); its logic is mirrored by pure, tested functions in `velstra-common`. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/TESTING.md`](docs/TESTING.md).

## Sign-off

Please write clear commit messages and keep changes focused. New public APIs and
non-obvious behaviour should come with tests and doc comments, matching the
surrounding code.
