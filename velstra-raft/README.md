# velstra-raft

Embedded Raft replication for the controller's fabric topology, using OpenRaft.
The leader accepts writes; replicas apply committed changes and serve reads.

From the workspace root:

```sh
cargo test -p velstra-raft --locked
```

[Architecture](../docs/ARCHITECTURE.md) ·
[Controller configuration](../docs/CONFIGURATION.md)

License: AGPL-3.0-or-later.
