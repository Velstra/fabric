# Dataplane tests

Loads the actual XDP/TC programs in disposable Linux namespaces and sends
traffic through veth links. Requires root, XDP/TC kernel support and `iproute2`.
Install `arping` and `ndisc6` to exercise both neighbor-discovery scenarios.

From the repository root, after [toolchain setup](../../docs/development.md):

```sh
cargo build --release --locked
sudo ./tests/e2e/loadcheck.sh
sudo ./tests/e2e/run.sh
```

Run selected scenarios:

```sh
sudo ./tests/e2e/run.sh fw_icmp overlay_arp
```

The suite covers firewall rules, egress filtering, routing, load balancing and
overlay behavior. Routing/LB counter assertions do not prove a complete
round trip; verify the backend application and the return path separately. See [packet verification](../../docs/TESTING.md).

Override the agent with `VELSTRA_BIN`. To add a case, add a
`scenario_<name>` function and its name to `ALL` in [run.sh](run.sh).
