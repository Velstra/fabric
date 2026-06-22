# Velstra end-to-end tests

These tests load the **real** XDP and TC programs into the kernel and exercise
each phase against a throwaway topology of network namespaces and veth pairs.
Unlike the unit tests (`cargo test`, no root), they verify the data plane the way
it actually runs — the eBPF verifier, map programming, attach, and live traffic.

## Running

```sh
cargo build --release          # build the agent (embeds the eBPF object)
sudo ./tests/e2e/run.sh        # all scenarios
sudo ./tests/e2e/run.sh fw_icmp overlay_arp   # selected scenarios
# or:
make e2e
```

Requirements: **root** (CAP_BPF/CAP_NET_ADMIN), a recent kernel with XDP +
`clsact` support, `iproute2`. Optional: `ethtool` (offload toggling), `arping`
(the ARP-suppression test skips without it). Override the binary with
`VELSTRA_BIN=/path/to/velstra`.

Each scenario builds its own uniquely-named namespaces and tears them down via an
EXIT trap, so a failure never leaves stray state. The harness runs the agent in
generic XDP mode (`--xdp-mode skb`) so it works on veth without driver support.

## What's covered

| Scenario | Phase | Asserts |
|----------|-------|---------|
| `fw_pass`          | 1  | default-pass lets ICMP through (`passed_default`) |
| `fw_default_drop`  | 1  | default-drop blocks unmatched traffic (`dropped_default`) |
| `fw_blocklist_v4`  | 1  | IPv4 source blocklist (`dropped_blocklist`) |
| `fw_icmp`          | 1  | ICMP filter (`dropped_icmp`) |
| `fw_port`          | 1  | per-port rule drops a TCP SYN (`dropped_rule`) |
| `fw_blocklist_v6`  | 1  | IPv6 source blocklist (dual-stack) |
| `egress_blocklist` | B  | egress firewall drops by destination (`egress_dropped`) |
| `routing`          | 2  | a matching route redirects the packet (`forwarded`) |
| `lb`               | 3  | a SYN to the VIP is DNAT-rewritten to a backend (`load_balanced`) |
| `overlay_arp`      | 4  | ARP suppression answers locally (`arp_suppressed`) |
| `overlay_encap`    | 4  | tenant frame to a remote subnet is encapsulated (`overlay_encap`) and an oversized frame is dropped by the MTU guard (`overlay_too_big`) |

Assertions read the agent's per-CPU statistics, which it prints every second. The
`routing`/`lb` scenarios assert that the redirect/DNAT *fired* (its counter), not
a completed round-trip — that needs the host prep in `docs/TESTING.md` §4
(checksum offload off, conntrack notrack, forwarding, …).

## Adding a scenario

Add a `scenario_<name>()` function to `run.sh`, append `<name>` to the `ALL`
array, and use the `lib.sh` helpers (`ns_add`, `veth_pair`, `agent_start`,
`assert_ge`, `assert_cmd`, `assert_fail`).
