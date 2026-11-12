# Kubernetes lab deployment

Example Raft controllers, per-node agents and CNI installation.
The base manifests use plaintext control channels and privileged host networking:
use only in an isolated lab until [mTLS and access controls](../../docs/kubernetes.md#mtls)
are configured.

Requires a disposable Kind cluster, Docker, kubectl and the
[Fabric build toolchain](../../docs/development.md). From the repository root:

```sh
make kind-load
kubectl apply -f deploy/k8s/
kubectl -n velstra-system rollout status statefulset/velstra-controller
kubectl -n velstra-system rollout status daemonset/velstra-agent
```

The manifests use local `:latest` images with `IfNotPresent`.
Main-branch pushes do not publish images; releases require version tags.

Set the underlay interface and network in [20-agent.yaml](20-agent.yaml),
then [bootstrap the network](../../docs/kubernetes.md#3-bootstrap-the-network)
through the elected controller leader.

[Deployment and TLS guide](../../docs/kubernetes.md) ·
[Kind traffic walkthrough](../../docs/TESTING.md)
