#!/usr/bin/env bash
# Velstra controller-integrated CNI end-to-end test.
#
# Validates the whole control path on a single host, in one throwaway netns:
#   CNI ADD -> controller.CreatePort -> Raft -> derived config pushed
#           -> agent attaches the XDP firewall to the pod veth.
#
#   sudo ./tests/e2e/cni-controller.sh
#
# Needs root (loads eBPF), iproute2, and the release binaries:
#   cargo build --release
#
# It reuses the output/assert/topology/cleanup helpers from lib.sh and adds the
# controller + cni process management this scenario needs.

cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=lib.sh
source ./lib.sh

CTL="${VELSTRA_CTL:-$(cd ../.. && pwd)/target/release/velstra-controller}"
CNI="${VELSTRA_CNI:-$(cd ../.. && pwd)/target/release/velstra-cni}"

VNI=5000
SUBNET="192.168.100.0/24"
ADMIN="http://127.0.0.1:50052"

require_ctl_cni() {
  local b
  for b in "$CTL" "$CNI"; do
    if [ ! -x "$b" ]; then
      echo "error: missing $b — build first: cargo build --release" >&2
      exit 1
    fi
  done
}

# Run the orchestrator CLI against the controller in namespace $1.
ctl_orch() { # ns args...
  local ns=$1
  shift
  nse "$ns" "$CTL" orch --endpoint "$ADMIN" "$@"
}

# Start a single-node controller cluster in namespace $1 and wait until its
# admin API answers. Its PID joins _AGENTS so the cleanup trap reaps it.
controller_start() { # ns
  local ns=$1 log="$WORKDIR/controller.log" i
  nse "$ns" "$CTL" serve --node-id 1 --bootstrap \
    --listen 127.0.0.1:50051 --admin-listen 127.0.0.1:50052 --raft-listen 127.0.0.1:50053 \
    >"$log" 2>&1 &
  _AGENTS+=("$!")
  for i in $(seq 1 100); do
    ctl_orch "$ns" list-ports >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  echo "  controller did not come up; log:" >&2
  sed 's/^/    /' "$log" >&2
  return 1
}

# Wait until the agent log records a successful host self-registration.
wait_host_registered() { # log
  local i
  for i in $(seq 1 60); do
    grep -q "registered host" "$1" 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}

scenario_cni_controller() {
  section "Kubernetes CNI — controller-integrated ADD/attach/DEL"
  ns_add host # the "node": controller + agent + cni live here
  ns_add pod  # the workload sandbox the CNI wires up

  # A dummy underlay so the agent can read a VTEP MAC for self-registration
  # (the firewall attaches to the pod veth, not this device).
  nse host ip link add dummy0 type dummy
  nse host ip addr add 10.20.0.1/24 dev dummy0
  nse host ip link set dummy0 up

  controller_start host || { bad "controller start"; return; }
  ok "controller up (single-node Raft leader)"

  # Retry: a freshly-bootstrapped single node may not have won its election yet,
  # so the first write can hit "not the leader".
  local i defined=
  for i in $(seq 1 30); do
    if ctl_orch host add-network --vni "$VNI" --name blue --subnet "$SUBNET" \
         --drop-icmp false >/dev/null 2>&1; then
      defined=1
      break
    fi
    sleep 0.2
  done
  if [ -n "$defined" ]; then
    ok "network $VNI defined"
  else
    bad "add-network failed"
    note "last add-network error:"
    ctl_orch host add-network --vni "$VNI" --name blue --subnet "$SUBNET" \
      --drop-icmp false 2>&1 | sed 's/^/      /' >&2
    note "controller log:"
    sed 's/^/      /' "$WORKDIR/controller.log" >&2
    return
  fi

  # The agent: no --iface (config-driven attach), self-registers host "node-a".
  agent_start host -- --underlay-iface dummy0 --node-id node-a --vtep-ip 10.20.0.1 \
    --controller http://127.0.0.1:50051 --orchestrator "$ADMIN" \
    || { bad "agent start"; return; }
  if wait_host_registered "$LAST_LOG"; then
    ok "agent self-registered node-a as a VTEP host"
  else
    bad "agent never registered its host"
    return
  fi

  # Drive the CNI in controller mode for a pod.
  local conf out
  conf="{\"cniVersion\":\"1.0.0\",\"name\":\"blue\",\"type\":\"velstra-cni\",\"vni\":$VNI,\"subnet\":\"$SUBNET\",\"node\":\"node-a\",\"controllers\":[\"$ADMIN\"]}"
  out="$(nse host env CNI_COMMAND=ADD CNI_CONTAINERID=pod1 \
           CNI_NETNS=/var/run/netns/pod CNI_IFNAME=eth0 \
           "$CNI" <<<"$conf" 2>"$WORKDIR/cni-add.err")"
  if printf '%s' "$out" | grep -q '192\.168\.100\.'; then
    ok "CNI ADD got a controller-allocated IP [$(printf '%s' "$out" | grep -oE '192\.168\.100\.[0-9]+/[0-9]+' | head -1)]"
  else
    bad "CNI ADD did not return an allocated IP"
    note "stdout: $out"
    sed 's/^/    /' "$WORKDIR/cni-add.err" >&2
    return
  fi

  # The controller knows the port, on node-a.
  if ctl_orch host list-ports 2>/dev/null | grep -q "node-a"; then
    ok "controller list-ports shows the port on node-a"
  else
    bad "port not visible in the controller"
  fi

  # The pod got the address inside its sandbox. (`ip netns exec` directly — the
  # `nse` helper is a shell function, unavailable inside a `bash -c` subshell.)
  if nse pod ip -4 addr show eth0 2>/dev/null | grep -q '192\.168\.100\.'; then
    ok "pod eth0 has a 192.168.100.x address"
  else
    bad "pod eth0 has no tenant address"
  fi

  # Within a couple of config-attach ticks, the agent attaches XDP to the veth.
  local veth attached=
  veth="$(nse host ip -o link show type veth 2>/dev/null | grep -oE 'vel[0-9a-f]+' | head -1)"
  if [ -z "$veth" ]; then
    bad "no vel* host veth was created"
    return
  fi
  for i in $(seq 1 40); do
    if nse host ip link show "$veth" 2>/dev/null | grep -qi xdp; then attached=1; break; fi
    sleep 0.1
  done
  if [ -n "$attached" ]; then
    ok "agent attached XDP to the pod veth $veth"
  else
    bad "XDP never attached to $veth"
    nse host ip link show "$veth" 2>&1 | sed 's/^/    /' >&2
  fi

  # DEL tears the port down and calls RemovePort.
  nse host env CNI_COMMAND=DEL CNI_CONTAINERID=pod1 \
    CNI_NETNS=/var/run/netns/pod CNI_IFNAME=eth0 "$CNI" <<<"$conf" >/dev/null 2>&1
  settle 1
  if ctl_orch host list-ports 2>/dev/null | grep -q "node-a"; then
    bad "port still present after CNI DEL"
  else
    ok "CNI DEL removed the port from the controller"
  fi

  agent_stop
}

main() {
  require_root
  require_bin
  require_ctl_cni
  scenario_cni_controller
  summary
}

main "$@"
