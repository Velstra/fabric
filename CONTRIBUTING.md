# Contributing

Contributions are welcome — bug reports, fixes, features, docs.

## License & CLA

Velstra is **AGPL-3.0-or-later** (the shared ABI libraries are MIT/Apache and
the eBPF object is GPL/MIT — see [`LICENSING.md`](LICENSING.md)).

To keep **dual-licensing** possible (so the project can fund itself by offering a
commercial license to organisations that cannot use the AGPL), contributors must
agree to a **Contributor License Agreement (CLA)** before their first
contribution is merged. The CLA:

- lets you keep the copyright to your contribution, **and**
- grants the maintainer the right to license your contribution under the AGPL
  *and* under separate commercial terms.

Without this, the project could never be relicensed (it would need every past
contributor's permission), and the open-core/commercial model would be
impossible. This is the same approach used by Qt, Grafana, and many others.

> The CLA is enforced via [CLA Assistant](https://github.com/cla-assistant/cla-assistant)
> on pull requests. (Set this up on the GitHub repo before accepting external PRs.)

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
