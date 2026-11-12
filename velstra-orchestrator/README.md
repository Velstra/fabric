# velstra-orchestrator

Derives per-host configuration from hosts, networks and workload ports.
Includes IP/MAC allocation, tunnel and neighbor derivation, and port migration.

From the workspace root:

```sh
cargo test -p velstra-orchestrator --locked
```

[Topology/API reference](../docs/CONFIGURATION.md) ·
[Example topology](../examples/topology.toml)

License: AGPL-3.0-or-later.
