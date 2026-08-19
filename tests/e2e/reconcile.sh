#!/usr/bin/env bash
# Velstra controller-driven port security and live-reconfigure end-to-end test.
#
#   sudo ./tests/e2e/reconcile.sh
#
# Needs root (loads eBPF), iproute2, bpftool, and the release binaries:
#   cargo build --release
#
# WHY THIS TEST EXISTS
#
# The appliance and the controller reach the data plane by different roads, and
# only one of them was ever driven. `sentinel commit` writes the node's TOML and
# runs `systemctl reload-or-restart velstra` — and velstra.service has no
# ExecReload, so every appliance change *restarts* the agent and every eBPF map
# starts empty. The VM checks all take that road.
#
# A controller pushes configuration down a gRPC stream instead, and the agent
# calls `Firewall::reconfigure` — the same process, the same maps, live. Two
# defects lived in that gap on 2026-08-18 and neither was visible from the
# appliance:
#
#   1. `InterfaceAssignment` carried {name, policy, vni} while `InterfaceFile`
#      has ten fields, so `bind_mac` and `bind_addresses` never crossed the wire.
#      The orchestrator turns port security on for *every* tenant tap by default
#      ("not a knob" — it allocated the MAC and the address itself), so the
#      protection every cloud NIC was supposed to have was off.
#
#   2. The writers only ever inserted. Removing a port left its binding in the
#      maps, because a restart — the appliance's road — is what used to clear
#      them.
#
# So the test asserts both ends of the same road: the binding *arrives*, and it
# *leaves*.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=lib.sh
source ./lib.sh

CTL="${VELSTRA_CTL:-$(cd ../.. && pwd)/target/release/velstra-controller}"
VNI=5100
SUBNET="192.168.110.0/24"
ADMIN="http://127.0.0.1:50062"
TAP=veltap0

require_ctl() {
  [ -x "$CTL" ] || {
    echo "error: missing $CTL — build first: cargo build --release" >&2
    exit 1
  }
}

ctl_orch() { # ns args...
  local ns=$1
  shift
  nse "$ns" "$CTL" orch --endpoint "$ADMIN" "$@"
}

controller_start() { # ns
  local ns=$1 log="$WORKDIR/controller.log" i
  nse "$ns" "$CTL" serve --node-id 1 --bootstrap \
    --listen 127.0.0.1:50061 --admin-listen 127.0.0.1:50062 --raft-listen 127.0.0.1:50063 \
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

# How many entries a map holds right now.
#
# `bpftool map dump` prints one JSON array; an absent map is 0 rather than an
# error, which would otherwise read as "empty" and pass this test for the wrong
# reason — so the caller checks for a non-zero count first.
map_entries() { # name
  bpftool -j map dump name "$1" 2>/dev/null | python3 -c \
    'import json,sys
try:
    print(len(json.load(sys.stdin)))
except Exception:
    print(0)'
}

# Wait until a map reaches at least `n` entries, or give up.
wait_map_at_least() { # name n
  local i
  for i in $(seq 1 60); do
    [ "$(map_entries "$1")" -ge "$2" ] && return 0
    sleep 0.2
  done
  return 1
}

wait_map_empty() { # name
  local i
  for i in $(seq 1 60); do
    [ "$(map_entries "$1")" -eq 0 ] && return 0
    sleep 0.2
  done
  return 1
}

wait_host_registered() { # log
  local i
  for i in $(seq 1 60); do
    grep -q "registered host" "$1" 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}

scenario_reconcile() {
  section "Controller-driven port security, arriving and leaving"
  ns_add host

  nse host ip link add dummy0 type dummy
  nse host ip addr add 10.30.0.1/24 dev dummy0
  nse host ip link set dummy0 up

  # The tenant NIC. A tap rather than a veth: it is what a VM gets, and the
  # agent attaches its firewall to whatever the config names.
  nse host ip tuntap add dev "$TAP" mode tap
  nse host ip link set "$TAP" up

  controller_start host || { bad "controller start"; return; }
  ok "controller up"

  local i defined=
  for i in $(seq 1 30); do
    if ctl_orch host add-network --vni "$VNI" --name green --subnet "$SUBNET" \
         --drop-icmp false >/dev/null 2>&1; then
      defined=1
      break
    fi
    sleep 0.2
  done
  [ -n "$defined" ] || { bad "add-network failed"; return; }
  ok "network $VNI defined"

  agent_start host -- --underlay-iface dummy0 --node-id node-r --vtep-ip 10.30.0.1 \
    --controller http://127.0.0.1:50061 --orchestrator "$ADMIN" \
    || { bad "agent start"; return; }
  wait_host_registered "$LAST_LOG" || { bad "agent never registered its host"; return; }
  ok "agent registered node-r"

  # --- the binding arrives -------------------------------------------------
  #
  # Nothing here asks for port security. The orchestrator turns it on because it
  # allocated the address and the MAC itself, which is exactly why its absence
  # was invisible: no operator ever typed it, so nobody missed it.
  if ! ctl_orch host create-port --network "$VNI" --host node-r --tap "$TAP" \
         --ip 192.168.110.10 --mac 02:00:00:aa:bb:cc >/dev/null 2>&1; then
    bad "create-port failed"
    ctl_orch host create-port --network "$VNI" --host node-r --tap "$TAP" \
      --ip 192.168.110.11 --mac 02:00:00:aa:bb:cd 2>&1 | sed 's/^/      /' >&2
    return
  fi
  ok "port created on node-r"

  if wait_map_at_least PORT_BINDINGS 1; then
    ok "the port's MAC binding reached the data plane [PORT_BINDINGS=$(map_entries PORT_BINDINGS)]"
  else
    bad "PORT_BINDINGS is empty — port security never crossed the wire"
    note "this is the defect the wire fix closed: InterfaceAssignment dropped bind_mac"
  fi

  if wait_map_at_least PORT_ADDRS_V4 1; then
    ok "the port's permitted source address reached the data plane [PORT_ADDRS_V4=$(map_entries PORT_ADDRS_V4)]"
  else
    bad "PORT_ADDRS_V4 is empty — the guest may claim any address"
  fi

  # --- and it leaves -------------------------------------------------------
  #
  # Live, with no restart. A restart would clear the maps whatever the code did,
  # which is how this stayed hidden: every appliance commit restarts the agent.
  local pid_before
  pid_before="$LAST_PID"

  # `list-ports` prints a header row and then one row per port, id first. Read
  # the column rather than matching a shape: an id format nobody promised is not
  # something to build a test on.
  local port_id
  port_id="$(ctl_orch host list-ports 2>/dev/null | awk 'NR==2 {print $1}')"
  if [ -z "$port_id" ]; then
    bad "could not read the port id back from the controller"
    ctl_orch host list-ports 2>&1 | sed 's/^/      /' >&2
    return
  fi

  ctl_orch host remove-port --id "$port_id" >/dev/null 2>&1 \
    || { bad "remove-port failed"; return; }
  ok "port removed [$port_id]"

  if wait_map_empty PORT_BINDINGS; then
    ok "the binding left the data plane with the port"
  else
    bad "PORT_BINDINGS still holds $(map_entries PORT_BINDINGS) entry/entries after the port was removed"
    note "a stale binding polices a port nobody owns any more"
  fi

  if wait_map_empty PORT_ADDRS_V4; then
    ok "the permitted address left with the port"
  else
    bad "PORT_ADDRS_V4 still holds $(map_entries PORT_ADDRS_V4) entry/entries"
  fi

  # The whole point is that this happened without a restart. If the agent died
  # and came back, the maps would be empty for a reason that proves nothing.
  if kill -0 "$pid_before" 2>/dev/null; then
    ok "the agent never restarted — this was a live reconfigure"
  else
    bad "the agent is gone; the empty maps prove nothing"
  fi

  agent_stop
}

main() {
  require_root
  require_bin
  require_ctl
  command -v bpftool >/dev/null 2>&1 || { echo "error: bpftool not found" >&2; exit 1; }
  scenario_reconcile
  summary
}

main "$@"
