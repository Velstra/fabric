# Run the host agent

Choose a local node policy for one machine or a controller endpoint for a managed fabric. A controller topology file and an agent policy have different schemas.

## Local policy

After [building the agent](development.md#build), inspect a sample without changing packet handling:

```sh
./target/release/velstra validate examples/rules.toml
./target/release/velstra validate examples/overlay.toml
```

Each command prints the path and resolved rules. To exercise actual packets, use the [isolated namespace test](TESTING.md#run-a-focused-dataplane-check). To attach manually, substitute an isolated lab interface that you own for `lab0`:

```sh
sudo ./target/release/velstra run --iface lab0 --xdp-mode skb \
  --config examples/rules.toml --stats-interval 5
```

The agent reports its attachment and counters. Ctrl-C detaches it. Use `--iface` more than once when forward and return traffic enter different interfaces. Enable `--egress` only when outbound policy is intended for that host.

## Live updates

During a full policy replacement, the agent closes the packet gate and drains existing kernel readers before changing maps. Arriving packets are dropped, not buffered. If applying a replacement fails, it attempts to restore the previous state. A failed restoration keeps the gate closed. The update barrier requires Linux global membarrier support and a kernel without `nohz_full` isolation. This mechanism applies while the agent runs.

## Routing, NAT and overlays

| Example | Use it to inspect |
|---|---|
| [router.toml](https://github.com/Velstra/fabric/blob/main/examples/router.toml) | IPv4 longest-prefix forwarding and next-hop rewriting. |
| [loadbalancer.toml](https://github.com/Velstra/fabric/blob/main/examples/loadbalancer.toml) | Service VIP, backend selection and reply translation. Draining a backend leaves existing flows pinned. |
| [overlay.toml](https://github.com/Velstra/fabric/blob/main/examples/overlay.toml) | Tunnel endpoint, interface VNI and tenant neighbor entries. Size tenant MTUs for the encapsulation overhead. |

To import Wren routes, configure `--wren-socket PATH --wren-routes`. Static routes take precedence. Unresolved gateways are retried; on-link and IPv6 learned routes use the kernel.

## Controller connection

Repeat `--controller` for failover. For a remote deployment, use HTTPS endpoints and configure `--tls-ca`, `--tls-cert` and `--tls-key`. The agent retains the last-applied config while reconnecting.

[Controller setup](quickstart.md) · [Mutual TLS in Kubernetes](kubernetes.md#mtls)
