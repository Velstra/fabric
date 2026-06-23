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

The manifests reference `ghcr.io/velstra/{controller,agent,cni}:latest`. CI
builds and pushes these on every push to the default branch (tagged `latest` +
the commit SHA) and on `v*` tags (tagged with the version) — so on a published
cluster you can just pull them.

To build locally instead: `make docker-build` (or `make kind-load` for a local
Kind cluster). The images package the host-built binaries (`velstra-controller`,
`velstra`, `velstra-cni`); the eBPF object is embedded in the agent binary, so no
eBPF toolchain is needed at image-build time.

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

## mTLS

The base manifests run plaintext for clarity. Both control channels — the agent
channel (`:50051`) **and** the fabric-mutating admin/orchestrator channel
(`:50052`) — support TLS with client-cert verification. Turn it on:

**1. Generate the PKI and Secrets** (CA, a multi-SAN server cert, agent + cni
client certs):

```shell
./deploy/k8s/tls/gen-pki.sh velstra-system
```

**2. Controller** (`10-controller.yaml`) — mount the server Secret and pass the
TLS flags (they cover both channels):

```yaml
        # container:
          # ... existing args, plus:
          #   --tls-cert /etc/velstra/tls/tls.crt
          #   --tls-key  /etc/velstra/tls/tls.key
          #   --client-ca /etc/velstra/tls/ca.pem
          volumeMounts:
            - { name: tls, mountPath: /etc/velstra/tls, readOnly: true }
      volumes:
        - name: tls
          secret: { secretName: velstra-controller-tls }
```

**3. Agent** (`20-agent.yaml`) — mount the agent + cni Secrets, switch the
endpoints to `https://`, and add the client TLS flags
(`--tls-ca /etc/velstra/tls/ca.pem --tls-cert /etc/velstra/tls/tls.crt
--tls-key /etc/velstra/tls/tls.key`). The init container also copies the **cni**
cert + CA to a host path the on-host plugin can read, and the conflist gains
`tlsCA`/`tlsCert`/`tlsKey` (host paths) with `https://` controllers:

```sh
# in the init container, after installing the binary:
install -m 0644 /cni-tls/ca.pem  /host/etc/velstra/pki/ca.pem
install -m 0644 /cni-tls/tls.crt /host/etc/velstra/pki/cni.crt
install -m 0600 /cni-tls/tls.key /host/etc/velstra/pki/cni.key
# conflist: "controllers": ["https://…:50052"], plus
#   "tlsCA": "/etc/velstra/pki/ca.pem",
#   "tlsCert": "/etc/velstra/pki/cni.crt",
#   "tlsKey": "/etc/velstra/pki/cni.key"
```

Don't set `--tls-domain` on the agent: each controller endpoint has its own pod
DNS name, all covered by the server cert's SANs, so default hostname
verification works.

**4. Bootstrap over TLS** — the `orch`/`admin` CLIs take the same flags:

```shell
kubectl -n velstra-system exec velstra-controller-0 -- \
  velstra-controller orch --endpoint https://127.0.0.1:50052 \
  --tls-ca /etc/velstra/tls/ca.pem \
  --tls-cert /etc/velstra/tls/tls.crt --tls-key /etc/velstra/tls/tls.key \
  add-network --vni 5000 --name blue --subnet 192.168.100.0/24 --drop-icmp false
```

## Other hardening

- **Resource requests/limits** are set on both workloads, and a
  `PodDisruptionBudget` (`minAvailable: 2`) keeps a Raft quorum during drains and
  rollouts — both in the base manifests.
- **Lock down the orchestrator channel.** A plain pod-selector `NetworkPolicy`
  on `:50052`/`:50053` does **not** work here: the agents run with
  `hostNetwork`, so their traffic appears to originate from the node IP, not a
  pod. Restrict by node CIDR (an `ipBlock` peer) instead, on top of the mTLS
  client-cert auth — which is the real access control.

## End-to-end test

The full path needs a real kernel (loading eBPF requires root), so it is not part
of the host-only `make test`. See [`../../docs/TESTING.md`](../../docs/TESTING.md)
§7 for the Kind-based walk-through; run it on a machine where you can load XDP.
