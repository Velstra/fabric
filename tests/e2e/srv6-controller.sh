#!/usr/bin/env bash
# Velstra controller-driven SRv6 end-to-end test.
#
# The whole cloud path, with nothing hand-written:
#
#   agent self-registers (encap srv6 + locator)  ->  controller stores it
#   -> orchestrator derives an SRv6 NodeConfig   ->  agent applies it
#   -> a tenant frame crosses the underlay as SRv6 and is decapsulated
#
# This is deliberately NOT the same test as `run.sh srv6_roundtrip`, which hands
# each agent a TOML somebody wrote. Everything asserted here — every service SID,
# every next hop, every trusted peer — was *derived* by the control plane from
# two locators and a port table. A fabric can pass the TOML test and still be
# unusable from a controller, which is exactly the state this repository was in.
#
#   sudo ./tests/e2e/srv6-controller.sh
#
# Needs root (loads eBPF), iproute2, and the release binaries:
#   cargo build --release

cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=lib.sh
source ./lib.sh

CTL="${VELSTRA_CTL:-$(cd ../.. && pwd)/target/release/velstra-controller}"

VNI=5000
SUBNET="192.168.100.0/24"
# The control plane lives on the underlay link, so both namespaces can reach it.
CTL_ADDR="10.99.0.1"
CONTROL="http://$CTL_ADDR:50051"
ADMIN="http://$CTL_ADDR:50052"
# Two locators, one per host. Never routed: the outer destination MAC delivers
# the frame, exactly as a VTEP address would. Their only job is to be the thing
# every SID is derived from.
LOC1="fc00:0:1::/64"
LOC2="fc00:0:2::/64"

require_ctl() {
  if [ ! -x "$CTL" ]; then
    echo "error: missing $CTL — build first: cargo build --release" >&2
    exit 1
  fi
}

orch() { nse h1 "$CTL" orch --endpoint "$ADMIN" "$@"; }

controller_start() {
  local log="$WORKDIR/controller.log" i
  nse h1 "$CTL" serve --node-id 1 --bootstrap \
    --listen "$CTL_ADDR:50051" --admin-listen "$CTL_ADDR:50052" \
    --raft-listen "$CTL_ADDR:50053" >"$log" 2>&1 &
  _AGENTS+=("$!")
  for i in $(seq 1 100); do
    orch list-ports >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  echo "  controller did not come up; log:" >&2
  sed 's/^/    /' "$log" >&2
  return 1
}

# Block until an agent has registered its own host. Read from the agent's log
# rather than the controller's, because that is the side that knows whether the
# call was *accepted* — a locator the topology refuses fails here, on the node,
# which is where an operator would look.
wait_host_registered() { # log
  local i
  for i in $(seq 1 150); do
    grep -q "registered host" "$1" 2>/dev/null && return 0
    sleep 0.2
  done
  return 1
}

# Block until an agent's log shows it applied a config carrying an SRv6 endpoint.
wait_srv6_applied() { # log
  local i
  for i in $(seq 1 150); do
    grep -qiE "srv6" "$1" 2>/dev/null && return 0
    sleep 0.2
  done
  return 1
}

main() {
  require_root
  require_bin
  require_ctl

  section "B9 — SRv6 driven by the controller, end to end"

  # h1 holds the control plane, a tenant tap and the underlay; h2 is the far
  # side. `vm` is the workload behind h1's tap.
  ns_add h1
  ns_add h2
  ns_add vm
  # The underlay link carries both the control plane (v4) and the tunnels.
  veth_pair h1 uplink0 "$CTL_ADDR/24" h2 under0 "10.99.0.2/24"
  veth_pair h1 tap0 - vm tap0c -
  nse vm ip addr add 192.168.100.10/24 dev tap0c

  controller_start || { bad "controller start"; return; }

  # Each agent registers ITSELF, the way a cloud node agent does: the wire
  # family follows the locator, and the underlay MAC is read from the interface
  # rather than repeated by hand.
  agent_start h2 -- --iface under0 --node-id n2 \
    --underlay-iface under0 --vtep-ip 10.99.0.2 \
    --encap srv6 --srv6-locator "$LOC2" \
    --controller "$CONTROL" --orchestrator "$ADMIN" \
    || { bad "agent h2 start"; return; }
  local log2="$LAST_LOG" pid2="$LAST_PID"

  agent_start h1 -- --iface tap0 --iface uplink0 --node-id n1 \
    --underlay-iface uplink0 --vtep-ip "$CTL_ADDR" \
    --encap srv6 --srv6-locator "$LOC1" \
    --controller "$CONTROL" --orchestrator "$ADMIN" \
    || { bad "agent h1 start"; kill -TERM "$pid2" 2>/dev/null; return; }
  local log1="$LAST_LOG"

  if wait_host_registered "$log1" && wait_host_registered "$log2"; then
    ok "both agents registered themselves as SRv6 hosts"
  else
    bad "an agent never registered"
    note "h1 log tail:"; tail -20 "$log1" | sed 's/^/       /'
    note "h2 log tail:"; tail -20 "$log2" | sed 's/^/       /'
    return
  fi

  orch add-network --vni "$VNI" --name blue --subnet "$SUBNET" >/dev/null \
    || { bad "add-network"; return; }
  # The local workload...
  orch create-port --network "$VNI" --host n1 --tap tap0 \
    --ip 192.168.100.10 --mac "$(nse vm cat /sys/class/net/tap0c/address)" >/dev/null \
    || { bad "create-port n1"; return; }
  # ...and a remote one, which is what gives n1 something to encapsulate toward.
  local remote_mac="02:ab:cd:ef:00:0b"
  orch create-port --network "$VNI" --host n2 --tap tap0 \
    --ip 192.168.100.11 --mac "$remote_mac" >/dev/null \
    || { bad "create-port n2"; return; }

  if wait_srv6_applied "$log1" && wait_srv6_applied "$log2"; then
    ok "both agents applied a controller-derived SRv6 config"
  else
    bad "an agent never applied an SRv6 config"
    note "h1 log tail:"; tail -20 "$log1" | sed 's/^/       /'
    note "h2 log tail:"; tail -20 "$log2" | sed 's/^/       /'
    return
  fi

  # Give the derived config a moment to reach the maps after it is applied.
  settle 3

  section "  unicast — the derived End.DT2U SID"
  # The workload addresses the remote port's MAC at L2 without ARPing for it, so
  # the SRv6 FDB is the only thing that can resolve the destination. That entry
  # was written by the controller, from n2's locator.
  nse vm ip neigh replace 192.168.100.11 lladdr "$remote_mac" dev tap0c
  nse vm ping -c3 -W1 192.168.100.11 >/dev/null 2>&1 || true
  settle 3
  assert_ge "$log1" srv6_encap 1 "n1 encapsulated toward the derived SID"
  assert_ge "$log2" srv6_decap 1 "n2 decapsulated it — the two ends agree"

  section "  broadcast — the derived End.DT2M SID"
  # No FDB entry can consume a broadcast, so the TC classifier is the only thing
  # left. Its flood target is a *different* SID from the unicast one above, also
  # derived, and n2 instantiates it because it serves the segment.
  local decap_before
  decap_before="$(counter "$log2" srv6_decap)"
  nse vm ping -c3 -W1 192.168.100.99 >/dev/null 2>&1 || true
  settle 4
  assert_ge "$log1" srv6_bum_replicated 1 "n1 head-end replicated the broadcast"
  assert_ge "$log2" srv6_decap "$((decap_before + 1))" \
    "n2 accepted the flood copy (End.DT2M, not just End.DT2U)"

  # When that last one fails, the useful question is *why* the copy was not
  # taken, and the answer is in n2's neighbouring counters rather than the one
  # that was asserted. `srv6_drop_untrusted` moving means the frame arrived and
  # the peer set refused it; staying at zero means it never arrived at all, or
  # arrived addressed to a SID this host does not instantiate — two very
  # different bugs that the assertion alone cannot tell apart.
  if [ "$(counter "$log2" srv6_decap)" -le "$decap_before" ]; then
    dump_matching "$log2" 'srv6_[a-z_]+' "n2 SRv6 counters (did the copy arrive?)"
    dump_matching "$log1" 'srv6_[a-z_]+' "n1 SRv6 counters"
    if have bpftool; then
      # The kernel truncates a map name to 15 characters, so ask by prefix and
      # let bpftool pick — hard-coding the full name is how a dump silently
      # returns nothing and the diagnostic looks like an empty map.
      _mapdump() { # ns name-prefix label
        note "$3:"
        # BPF maps are not netns-scoped, so any namespace can see them; the id
        # list is filtered by name because both agents are loaded at once.
        local ids
        ids=$(nse "$1" bpftool map show 2>/dev/null | grep -oE "^[0-9]+: .*name $2[a-zA-Z_]*" | cut -d: -f1)
        if [ -z "$ids" ]; then note "  (no map matching $2)"; return; fi
        for id in $ids; do
          nse "$1" bpftool map dump id "$id" 2>&1 | sed 's/^/       /' >&2
        done
      }
      _mapdump h2 SRV6_LOCAL_SID "n2's instantiated SIDs"
      _mapdump h1 SRV6_FLOOD_LIS "n1's flood targets"
      _mapdump h2 SRV6_PEERS "n2's trusted peers"
    else
      note "install bpftool for a map-level answer"
    fi
  fi

  section "  nothing fell back to VXLAN"
  # The failure this rules out is the quiet one: a fabric that looks configured
  # because the VXLAN path picked up the traffic instead.
  assert_zero "$log1" overlay_encap "no frame left over VXLAN"
  assert_zero "$log2" overlay_decap "no frame arrived over VXLAN"

  kill -TERM "$pid2" 2>/dev/null || true
  summary
}

main "$@"
