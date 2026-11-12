# velstra-proto

Protobuf definitions and generated Rust clients/servers for the agent,
admin and orchestrator services. The contract is
[proto/velstra.proto](proto/velstra.proto).

From the workspace root:

```sh
cargo check -p velstra-proto --locked
```

The build uses vendored `protoc` unless `PROTOC` is explicitly set.
See the [API reference](../docs/CONFIGURATION.md#northbound-api).

License: MIT OR Apache-2.0; see [LICENSING.md](../LICENSING.md).
