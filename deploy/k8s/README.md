# Velstra on Kubernetes

A deployment skeleton for running Velstra as a cluster's CNI: an HA controller
(embedded Raft) plus a per-node agent that installs the CNI plugin and attaches
the XDP firewall/LB to each pod.

```
Pod ADD
  → velstra-cni: controller.CreatePort(vni, host=node, tap=veth)   (admin :50052)
  → Raft replicate → derive → push NodeConfig                       (agent :50051)
  → agent attaches XDP(policy=vni, vni) to the pod veth as it appears
```

## Layout

| File | What |
|---|---|
| `00-namespace.yaml` | namespace + service accounts |
| `10-controller.yaml` | 3-node Raft controller `StatefulSet` + headless `Service` |
| `20-agent.yaml` | agent `DaemonSet` + CNI install init container |

## 1. Build and publish the images

The manifests reference `ghcr.io/velstra/{controller,agent,cni}:latest`. Build
and push them (or `kind load docker-image` for a local Kind cluster). The images
must contain the binaries on `PATH`: `velstra-controller`, `velstra` (agent),
and `velstra-cni` at `/usr/local/bin/velstra-cni`.

## 2. Apply

```shell
kubectl apply -f deploy/k8s/
kubectl -n velstra-system rollout status statefulset/velstra-controller
kubectl -n velstra-system rollout status daemonset/velstra-agent
```

The agents self-register their nodes as VTEP hosts on startup — no manual
`AddHost`. Confirm the cluster has a leader and the hosts registered:

```shell
kubectl -n velstra-system logs velstra-controller-0 | grep -i "leader\|AddHost"
```

## 3. Bootstrap the network

Ports can only be created on a network the controller knows. Define the example
network the agent's conflist references (`vni 5000`, `192.168.100.0/24`). Writes
go to the **leader** — target each controller until one accepts (a follower
answers *"not the leader; current leader is node N"*):

```shell
kubectl -n velstra-system exec velstra-controller-0 -- \
  velstra-controller orch --endpoint http://127.0.0.1:50052 \
  add-network --vni 5000 --name blue --subnet 192.168.100.0/24 --drop-icmp false
```

Now pods scheduled onto the cluster get a `192.168.100.0/24` address, their veth
attached to the XDP data plane, and overlay reachability to pods on other nodes.

```shell
kubectl -n velstra-system exec velstra-controller-0 -- \
  velstra-controller orch --endpoint http://127.0.0.1:50052 list-ports
```

## Configure for your cluster

- **Underlay interface** — `UNDERLAY_IFACE` env in `20-agent.yaml` (default
  `eth0`); the VTEP IP is taken from the node's `status.hostIP`.
- **Network** — change `vni`/`subnet` in the conflist (`20-agent.yaml`) and the
  matching `add-network`. Multiple networks = multiple conflists.

## Production hardening (not in this skeleton)

- **mTLS.** The control channels run plaintext here. Both the agent
  (`--tls-ca/--tls-cert/--tls-key`) and the CNI (`tlsCA`/`tlsCert`/`tlsKey` in
  the conflist) support TLS; mount a cert Secret and switch the endpoints to
  `https://`. Generate PKI with `scripts/gen-certs.sh`.
- **Lock down the orchestrator channel.** `:50052` can mutate the fabric. Add a
  `NetworkPolicy` so only agents/CNI reach it, on top of mTLS client auth.
- **Resource requests/limits** and `PodDisruptionBudget` for the controller.

## End-to-end test

The full path needs a real kernel (loading eBPF requires root), so it is not part
of the host-only `make test`. See [`../../docs/TESTING.md`](../../docs/TESTING.md)
§7 for the Kind-based walk-through; run it on a machine where you can load XDP.
