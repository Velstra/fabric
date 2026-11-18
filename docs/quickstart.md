# Start a local fabric

Inspect a tenant topology with the same controller and CLI that serve a deployed fabric. This exercise opens loopback listeners, uses a temporary copy of the example and requires neither root nor an eBPF-capable kernel.

## Build the controller

Install a current stable Rust toolchain and a native linker. Run these commands on a Linux host:

```sh
git clone https://github.com/Velstra/fabric.git
cd fabric
cargo build --locked -p velstra-controller
```

## Start the example

From the repository root:

```sh
lab_dir=$(mktemp -d)
cp examples/topology.toml "$lab_dir/topology.toml"
./target/debug/velstra-controller serve \
  --topology "$lab_dir/topology.toml" \
  --listen 127.0.0.1:50051 --admin-listen 127.0.0.1:50052
```

Leave the controller running. In another terminal, from the same checkout:

```sh
./target/debug/velstra-controller orch list-ports
./target/debug/velstra-controller orch list-load-balancers
```

Look for `192.168.100.10` on `host-1`, `192.168.100.20` on `host-2`, and the `web-vip` load balancer. The hosts and ports are model objects here. Packet forwarding requires agents and actual interfaces.

## Finish

Stop the controller with Ctrl-C. The temporary directory contains only the exercise's topology. Continue with [local neighbor discovery](overlay.md#local-neighbor-discovery) to test a packet path on Linux.
