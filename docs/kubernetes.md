# Deploy the Kubernetes CNI

The sample manifests run three Raft controllers and one agent per node. On pod creation the CNI allocates a port from the controller; the node's agent attaches the derived policy to the pod veth.

Use a disposable Linux cluster configured for an external CNI. The base manifests install a host CNI and start plaintext listeners. Build [Fabric's binaries](development.md#build) and have Docker, Kind and kubectl available. In Kind, use `disableDefaultCNI: true` in the cluster configuration.

## Deploy the lab

The examples assume the default Kind cluster name and a kubectl context pointing to that cluster. Start from the repository root:

```sh
make kind-load
kubectl apply -f deploy/k8s/
kubectl -n velstra-system rollout status statefulset/velstra-controller
kubectl -n velstra-system rollout status daemonset/velstra-agent
```

The manifests use the images built locally and loaded into the Kind nodes. For a versioned deployment, use the [qualified tag](RELEASE-POLICY.md). The controller needs persistent storage for its per-replica snapshots. Set the underlay interface in the [agent manifest](https://github.com/Velstra/fabric/blob/main/deploy/k8s/20-agent.yaml) to the interface actually used by the nodes.

## Bootstrap the network

Create the same VNI/subnet that the installed CNI configuration references. In this example ordinal 0 is the initial bootstrap node; use the current leader if it has changed.

```sh
kubectl -n velstra-system exec velstra-controller-0 -- \
  velstra-controller orch --endpoint http://127.0.0.1:50052 \
  add-network --vni 5000 --name blue --subnet 192.168.100.0/24 --drop-icmp false
```

Schedule a test pod, then compare its assigned IP with the controller's port list:

```sh
kubectl get pods -o wide
kubectl -n velstra-system exec velstra-controller-0 -- \
  velstra-controller orch --endpoint http://127.0.0.1:50052 list-ports
```

If creation fails, check that the controller knows the network, that the agent registered the host, and that CNI and controller use matching credentials.

## mTLS

For a deployment outside the plaintext lab, supply client and server identities for the agent, admin and Raft channels. A privileged admin identity is distinct from a node identity.

| Component | Required configuration |
|---|---|
| Controller | Mount server key/cert and client CA. Set `--tls-cert`, `--tls-key` and `--client-ca`. Configure allowed admin and Raft peer CNs. |
| Node agent | Use HTTPS endpoints and `--tls-ca`, `--tls-cert`, `--tls-key`. The agent's certificate CN must match its host ID for host-scoped writes. |
| CNI binary | Install its credentials at paths available on the host. Set `controllers` to HTTPS URLs and configure `tlsCA`, `tlsCert` and `tlsKey` in the conflist. |
| CLI | Use a separate operator client certificate authorized by the controller to change fabric-wide topology. |

The [lab PKI helper](https://github.com/Velstra/fabric/blob/main/deploy/k8s/tls/gen-pki.sh) generates example secrets; adapt its shared sample identities to your actual authorization model. Restrict listeners to known node/control networks, since host-networked agents can appear to originate at node addresses.

[Manifests](https://github.com/Velstra/fabric/tree/main/deploy/k8s) · [CNI integration test](TESTING.md)
