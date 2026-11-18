# Verify packet handling

Choose the check that answers your question. Use a disposable Linux host for privileged tests; the harness creates networking fixtures and attaches actual kernel programs. Build the [release binaries](development.md#build) first.

| Question | Check | Observable result |
|---|---|---|
| Does the node config parse? | `./target/release/velstra validate examples/rules.toml` | Resolved policy printed, exit 0; no interfaces touched. |
| Will this kernel accept the object? | `sudo ./tests/e2e/loadcheck.sh` | The real eBPF verifier accepts the programs. |
| Does a policy affect traffic? | `sudo ./tests/e2e/run.sh fw_pass fw_icmp` | The namespace cases compare allowed traffic and the expected ICMP drop. |
| Did both overlay endpoints process a frame? | `sudo ./tests/e2e/run.sh srv6_roundtrip` | Sender encapsulation and receiver decapsulation counters advance. |
| Does the CNI create a controller-managed port? | `sudo ./tests/e2e/cni-controller.sh` | CNI, the controller and the node agent agree on the allocated port and interface. |

## Run a focused dataplane check

```sh
sudo ./tests/e2e/run.sh fw_pass fw_icmp
```

The test uses interfaces joined by veth pairs so packets cross the XDP receive hook. Traffic to a local dummy address can travel through loopback and miss that hook entirely. Read the assertion next to each case; a green routing or load-balancing counter alone cannot demonstrate a full application round trip.

## Troubleshoot an unexpected result

| Symptom | Check next |
|---|---|
| Agent binary missing | Run the release build, or set `VELSTRA_BIN` to the intended binary before starting the harness. |
| Load check fails | Read the verifier output and confirm that this Linux kernel supports eBPF, XDP and TC. |
| ARP or ND case skips | Install `arping` or `ndisc6`, respectively, then rerun [the two cases](overlay.md#local-neighbor-discovery). |
| A VIP rewrites requests but replies fail | Check return routing, backend reachability, and that the agent sees both directions with shared NAT maps. |

[Scenario definitions and assertions](https://github.com/Velstra/fabric/blob/main/tests/e2e/run.sh) · [CNI fixture](https://github.com/Velstra/fabric/blob/main/tests/e2e/cni-controller.sh) · [Kubernetes lab](kubernetes.md)

## Scenario inventory

The runnable names below come from [the scenario registry](https://github.com/Velstra/fabric/blob/main/tests/e2e/run.sh). Append one or more names to `sudo ./tests/e2e/run.sh` to select them.

| Area | Cases |
|---|---|
| Ingress policy | `fw_pass`, `fw_default_drop`, `fw_icmp`, `fw_port`, `fw_blocklist_v4`, `fw_blocklist_v6` |
| Egress, forwarding and NAT | `egress_blocklist`, `routing`, `lb` |
| Tenant Ethernet | `overlay_arp`, `overlay_nd`, `overlay_encap`, `overlay_mac_fdb`, `local_mac_learn` |
| SRv6 | `srv6_encap`, `srv6_roundtrip`, `srv6_flood`, `srv6_irb` |

Other integration fixtures target different layers:

- [Controller-driven CNI](https://github.com/Velstra/fabric/blob/main/tests/e2e/cni-controller.sh) exercises allocation and attachment in a disposable namespace. The [Kubernetes guide](kubernetes.md) covers a cluster deployment.
- [Live reconciliation](https://github.com/Velstra/fabric/blob/main/tests/e2e/reconcile.sh) exercises a policy update pushed by the controller to a running agent; install `bpftool` for its map checks.
- [Controller-driven SRv6](https://github.com/Velstra/fabric/blob/main/tests/e2e/srv6-controller.sh) starts from self-registration and follows generated state through to the node agent.

For the original multi-terminal IPv4 NAT lab, see the [versioned walkthrough](https://github.com/Velstra/fabric/blob/a3c27e2ff45e08b0789c7f23459118081f724c13/docs/TESTING.md#4-load-balancer--nat-phase-3). It describes checksum offload, host forwarding and return-path assumptions specific to that topology.
