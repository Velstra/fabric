# velstra-raft

Embedded [Raft](https://raft.github.io/) consensus for the
[Velstra](https://github.com/Velstra/fabric) controllers, built on
[openraft](https://github.com/datafuselabs/openraft).

The replicated state machine **is** the [`velstra-orchestrator`] fabric topology:
a committed mutation (add host/network, create/remove/migrate port) is applied,
in log order, on every controller — so they all hold one consistent fabric with
**no external datastore and no message queue**. The leader accepts writes;
followers replicate, apply, and serve reads. Peers talk over a small gRPC
transport, and snapshots persist to disk so the cluster survives a full restart.

This is what makes a Velstra controller cluster highly available without bolting
on etcd or a broker.

[`velstra-orchestrator`]: https://crates.io/crates/velstra-orchestrator

## License

AGPL-3.0-or-later — see the [workspace](https://github.com/Velstra/fabric).
