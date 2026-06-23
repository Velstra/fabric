# velstra-proto

gRPC wire types and [tonic](https://github.com/hyperium/tonic) client/server
stubs for the [Velstra](https://github.com/Velstra/fabric) control plane — an
eBPF/XDP software-defined networking stack written in Rust.

This crate is the shared definition of the Velstra control-plane API: the
messages and services the controller serves and the agent / CNI / tooling
consume, so every component agrees on one wire format.

## Services

- **`VelstraControl`** — the agent-facing channel: fetch a node's config, watch
  for live updates, report statistics.
- **`VelstraAdmin`** — push per-node config overrides at runtime.
- **`VelstraOrchestrator`** — declare the fabric (hosts, networks, ports) and let
  the controller derive and push each host's config: `AddHost`, `AddNetwork`,
  `CreatePort`, `RemovePort`, `MigratePort`, `ListPorts`.

## Usage

```toml
[dependencies]
velstra-proto = "0.1"
```

```rust
use velstra_proto::velstra_orchestrator_client::VelstraOrchestratorClient;
use velstra_proto::CreatePortRequest;

let mut client = VelstraOrchestratorClient::connect("http://10.0.0.1:50052").await?;
let port = client
    .create_port(CreatePortRequest {
        network: 5000,
        host: "node-a".into(),
        tap: "vel0a1b".into(),
        ip: String::new(), // auto-allocate
    })
    .await?
    .into_inner();
```

The `.proto` is compiled at build time with a **vendored `protoc`**, so no system
`protoc` install is required.

## License

MIT OR Apache-2.0 (a permissive ABI/wire library, so anything can speak the
protocol). The Velstra product itself is AGPL-3.0-or-later — see the
[workspace](https://github.com/Velstra/fabric).
