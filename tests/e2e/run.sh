#!/usr/bin/env bash
# Velstra end-to-end suite. Loads the real eBPF programs and exercises every
# phase against a throwaway netns/veth topology.
#
#   sudo ./tests/e2e/run.sh            # run all scenarios
#   sudo ./tests/e2e/run.sh fw_icmp    # run one scenario by name
#
# Needs root, a recent kernel, iproute2, and (optionally) ethtool / arping.
# Build the agent first: cargo build --release
#
# Each scenario builds its own uniquely-named topology so they never collide;
# the EXIT trap in lib.sh tears everything down.

cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=lib.sh
source ./lib.sh

# A TCP connect attempt using bash's /dev/tcp (no `nc` dependency). Succeeds if
# the SYN gets through and is accepted/refused; fails (times out) if dropped.
tcp_connect() { # ns host port
  nse "$1" timeout 2 bash -c "exec 3<>/dev/tcp/$2/$3" 2>/dev/null
}

# ---------------------------------------------------------------------------
scenario_fw_pass() {
  section "Phase 1 — default pass lets traffic through"
  ns_add fpa; ns_add fpb
  veth_pair fpa va 10.10.1.1/24 fpb vb 10.10.1.2/24
  printf 'default_action = "pass"\n' >"$WORKDIR/pass.toml"
  agent_start fpb -- --iface vb --config "$WORKDIR/pass.toml" || { bad "agent start"; return; }
  nse fpa ping -c2 -W1 10.10.1.2 >/dev/null 2>&1 || true
  settle
  assert_ge   "$LAST_LOG" rx_packets     1 "agent saw ingress traffic"
  assert_ge   "$LAST_LOG" passed_default 1 "ICMP passed by default"
  assert_cmd  "ping succeeds under default-pass" -- nse fpa ping -c1 -W1 10.10.1.2
  agent_stop
}

scenario_fw_default_drop() {
  section "Phase 1 — default drop blocks unmatched traffic"
  ns_add fda; ns_add fdb
  veth_pair fda va 10.10.2.1/24 fdb vb 10.10.2.2/24
  printf 'default_action = "drop"\n' >"$WORKDIR/drop.toml"
  agent_start fdb -- --iface vb --config "$WORKDIR/drop.toml" || { bad "agent start"; return; }
  nse fda ping -c2 -W1 10.10.2.2 >/dev/null 2>&1 || true
  settle
  assert_ge   "$LAST_LOG" dropped_default 1 "ICMP dropped by default-drop"
  assert_fail "ping fails under default-drop" -- nse fda ping -c1 -W1 10.10.2.2
  agent_stop
}

scenario_fw_blocklist_v4() {
  section "Phase 1 — IPv4 source blocklist"
  ns_add fba; ns_add fbb
  veth_pair fba va 10.10.3.1/24 fbb vb 10.10.3.2/24
  cat >"$WORKDIR/bl4.toml" <<-EOF
	default_action = "pass"
	blocklist = ["10.10.3.1/32"]
	EOF
  agent_start fbb -- --iface vb --config "$WORKDIR/bl4.toml" || { bad "agent start"; return; }
  nse fba ping -c2 -W1 10.10.3.2 >/dev/null 2>&1 || true
  settle
  assert_ge   "$LAST_LOG" dropped_blocklist 1 "blocklisted source dropped"
  assert_fail "ping from blocklisted source fails" -- nse fba ping -c1 -W1 10.10.3.2
  agent_stop
}

scenario_fw_icmp() {
  section "Phase 1 — ICMP filter"
  ns_add fia; ns_add fib
  veth_pair fia va 10.10.4.1/24 fib vb 10.10.4.2/24
  cat >"$WORKDIR/icmp.toml" <<-EOF
	default_action = "pass"
	drop_icmp = true
	EOF
  agent_start fib -- --iface vb --config "$WORKDIR/icmp.toml" || { bad "agent start"; return; }
  nse fia ping -c2 -W1 10.10.4.2 >/dev/null 2>&1 || true
  settle
  assert_ge   "$LAST_LOG" dropped_icmp 1 "ICMP dropped by the filter"
  assert_fail "ping fails with drop_icmp" -- nse fia ping -c1 -W1 10.10.4.2
  agent_stop
}

scenario_fw_port() {
  section "Phase 1 — per-port rule (tcp/9999 drop)"
  ns_add fpoa; ns_add fpob
  veth_pair fpoa va 10.10.5.1/24 fpob vb 10.10.5.2/24
  cat >"$WORKDIR/port.toml" <<-EOF
	default_action = "pass"
	[[port_rule]]
	proto = "tcp"
	port = 9999
	action = "drop"
	EOF
  agent_start fpob -- --iface vb --config "$WORKDIR/port.toml" || { bad "agent start"; return; }
  tcp_connect fpoa 10.10.5.2 9999 || true
  settle
  assert_ge   "$LAST_LOG" dropped_rule 1 "SYN to tcp/9999 dropped by rule"
  assert_fail "connect to blocked port fails" -- tcp_connect fpoa 10.10.5.2 9999
  agent_stop
}

scenario_fw_blocklist_v6() {
  section "Phase 1 — IPv6 source blocklist (dual-stack)"
  if ! ping -6 -c0 ::1 >/dev/null 2>&1 && ! ping6 -c0 ::1 >/dev/null 2>&1; then
    skip "no working IPv6 ping; skipping"
    return
  fi
  ns_add f6a; ns_add f6b
  veth_pair f6a va 10.10.6.1/24 f6b vb 10.10.6.2/24
  add6 f6a va fd00:6::1/64
  add6 f6b vb fd00:6::2/64
  sleep 1 # DAD settle
  cat >"$WORKDIR/bl6.toml" <<-EOF
	default_action = "pass"
	blocklist = ["fd00:6::1"]
	EOF
  agent_start f6b -- --iface vb --config "$WORKDIR/bl6.toml" || { bad "agent start"; return; }
  nse f6a ping -6 -c2 -W1 fd00:6::2 >/dev/null 2>&1 || nse f6a ping6 -c2 -W1 fd00:6::2 >/dev/null 2>&1 || true
  settle
  assert_ge "$LAST_LOG" dropped_blocklist 1 "blocklisted IPv6 source dropped"
  agent_stop
}

scenario_egress_blocklist() {
  section "Phase B — egress firewall (destination blocklist)"
  ns_add ega; ns_add egb
  veth_pair ega va 10.10.7.1/24 egb vb 10.10.7.2/24
  cat >"$WORKDIR/egress.toml" <<-EOF
	default_action = "pass"
	blocklist = ["10.10.7.1/32"]
	EOF
  # Agent on vb with --egress; traffic LEAVING vb toward 10.10.7.1 is filtered.
  agent_start egb -- --iface vb --egress --config "$WORKDIR/egress.toml" || { bad "agent start"; return; }
  nse egb ping -c2 -W1 10.10.7.1 >/dev/null 2>&1 || true
  settle
  assert_ge   "$LAST_LOG" tx_packets     1 "egress hook saw outgoing traffic"
  assert_ge   "$LAST_LOG" egress_dropped 1 "egress to blocklisted dst dropped"
  assert_fail "egress ping to blocklisted dst fails" -- nse egb ping -c1 -W1 10.10.7.1
  agent_stop
}

scenario_overlay_arp() {
  section "Phase 4 — overlay ARP suppression"
  if ! have arping; then skip "arping not installed; skipping"; return; fi
  ns_add oah  # host (VTEP)
  ns_add oac  # tenant VM
  veth_pair oah tap0 - oac tap0c 192.168.100.1/24
  # A dummy underlay device so the overlay's local_vtep MAC resolves.
  nse oah ip link add uplink0 type dummy
  nse oah ip addr add 10.20.0.1/24 dev uplink0
  nse oah ip link set uplink0 up
  cat >"$WORKDIR/arp.toml" <<-EOF
	default_action = "pass"
	[overlay]
	local_vtep = "10.20.0.1"
	underlay_iface = "uplink0"
	[[interface]]
	name = "tap0"
	policy = 0
	vni = 5000
	[[neighbor]]
	vni = 5000
	ip = "192.168.100.2"
	mac = "02:00:00:00:0b:02"
	EOF
  agent_start oah -- --iface tap0 --config "$WORKDIR/arp.toml" || { bad "agent start"; return; }
  # The VM ARPs for a peer that lives "on another host"; the agent answers.
  nse oac arping -c2 -w2 -I tap0c 192.168.100.2 >/dev/null 2>&1 || true
  settle
  assert_ge  "$LAST_LOG" arp_suppressed 1 "ARP answered locally from the table"
  assert_cmd "arping gets a (synthetic) reply" -- nse oac arping -c1 -w2 -I tap0c 192.168.100.2
  agent_stop
}

# B3 — IPv6 Neighbor-Discovery suppression. The IPv6 mirror of overlay_arp: a
# tenant VM sends an ICMPv6 Neighbor Solicitation for a peer that lives "on
# another host"; the agent answers it locally from ND_TABLE (a `[[nd_neighbor]]`)
# with a synthesised Neighbor Advertisement, so the solicitation never floods
# the overlay. Asserts the nd_suppressed counter fires.
scenario_overlay_nd() {
  section "B3 — overlay IPv6 ND suppression"
  if ! have ndisc6; then skip "ndisc6 not installed; skipping"; return; fi
  ns_add onh  # host (VTEP)
  ns_add onc  # tenant VM
  veth_pair onh tap0 - onc tap0c fd00:100::1/64
  # A dummy underlay device so the overlay's local_vtep MAC resolves.
  nse onh ip link add uplink0 type dummy
  nse onh ip addr add 10.20.0.1/24 dev uplink0
  nse onh ip link set uplink0 up
  cat >"$WORKDIR/nd.toml" <<-EOF
	default_action = "pass"
	[overlay]
	local_vtep = "10.20.0.1"
	underlay_iface = "uplink0"
	[[interface]]
	name = "tap0"
	policy = 0
	vni = 5000
	[[nd_neighbor]]
	vni = 5000
	ip = "fd00:100::2"
	mac = "02:00:00:00:0b:02"
	EOF
  agent_start onh -- --iface tap0 --config "$WORKDIR/nd.toml" || { bad "agent start"; return; }
  # The VM solicits a peer that lives "on another host"; the agent answers. A
  # real solicited NS carries the SLLA option (≥ 32-byte ICMPv6 body), which is
  # what the in-place NA write requires.
  nse onc ndisc6 -1 -w 2000 fd00:100::2 tap0c >/dev/null 2>&1 || true
  settle
  assert_ge "$LAST_LOG" nd_suppressed 1 "NS answered locally from the ND table"
  agent_stop
}

scenario_overlay_encap() {
  section "Phase 4 — overlay encap + MTU guard"
  ns_add oeh  # host (VTEP)
  ns_add oec  # tenant VM
  ns_add oeu  # remote underlay peer
  veth_pair oeh tap0 - oec tap0c 192.168.100.1/24
  veth_pair oeh uplink0 10.20.0.1/24 oeu under0 10.20.0.2/24
  local umac
  umac="$(nse oeu cat /sys/class/net/under0/address)"
  cat >"$WORKDIR/encap.toml" <<-EOF
	default_action = "pass"
	[overlay]
	local_vtep = "10.20.0.1"
	underlay_iface = "uplink0"
	underlay_mtu = 1500
	[[interface]]
	name = "tap0"
	policy = 0
	vni = 5000
	[[tunnel]]
	vni = 5000
	inner_dst = "192.168.100.0/24"
	remote_vtep = "10.20.0.2"
	via_mac = "$umac"
	out_iface = "uplink0"
	EOF
  agent_start oeh -- --iface tap0 --iface uplink0 --config "$WORKDIR/encap.toml" \
    || { bad "agent start"; return; }
  # Pre-seed the VM's neighbour so it emits an IP frame (no ARP) into tap0.
  nse oec ip neigh replace 192.168.100.2 lladdr 02:00:00:00:0b:02 dev tap0c
  nse oec ping -c2 -W1 192.168.100.2 >/dev/null 2>&1 || true
  settle
  assert_ge "$LAST_LOG" overlay_encap 1 "tenant frame to remote subnet encapsulated"
  # Oversized frame must be dropped by the MTU guard, not silently black-holed.
  nse oec ping -c1 -W1 -s 1600 192.168.100.2 >/dev/null 2>&1 || true
  settle
  assert_ge "$LAST_LOG" overlay_too_big 1 "oversized inner frame dropped by MTU guard"
  agent_stop
}

# B1 — per-MAC MAC-FDB forwarding. Programs a `[[mac_route]]` (and NO `[[tunnel]]`)
# so the ONLY way a tenant frame can be encapsulated is by matching its inner
# destination MAC in MAC_FDB. The inner dst IP is deliberately left out of any
# OVERLAY_FDB entry, so a hit here proves the L2 MAC path resolves independently
# of the L3 (inner-IP) FDB.
scenario_overlay_mac_fdb() {
  section "B1 — overlay per-MAC MAC-FDB encap"
  ns_add omh  # host (VTEP)
  ns_add omc  # tenant VM
  ns_add omu  # remote underlay peer
  veth_pair omh tap0 - omc tap0c 192.168.100.1/24
  veth_pair omh uplink0 10.20.0.1/24 omu under0 10.20.0.2/24
  local umac
  umac="$(nse omu cat /sys/class/net/under0/address)"
  # The tenant peer's MAC — the frame's inner dst MAC, and the MAC-FDB key.
  local peer_mac="02:00:00:00:0b:02"
  cat >"$WORKDIR/mac.toml" <<-EOF
	default_action = "pass"
	[overlay]
	local_vtep = "10.20.0.1"
	underlay_iface = "uplink0"
	underlay_mtu = 1500
	[[interface]]
	name = "tap0"
	policy = 0
	vni = 5000
	[[mac_route]]
	vni = 5000
	mac = "$peer_mac"
	remote_vtep = "10.20.0.2"
	via_mac = "$umac"
	out_iface = "uplink0"
	EOF
  agent_start omh -- --iface tap0 --iface uplink0 --config "$WORKDIR/mac.toml" \
    || { bad "agent start"; return; }
  # Pre-seed the VM's neighbour so it emits an IP frame addressed to peer_mac at
  # L2 (no ARP). There is NO tunnel for 192.168.100.2, so only the MAC-FDB can
  # resolve it — the encap counter firing proves the L2 path works standalone.
  nse omc ip neigh replace 192.168.100.2 lladdr "$peer_mac" dev tap0c
  nse omc ping -c2 -W1 192.168.100.2 >/dev/null 2>&1 || true
  settle
  assert_ge "$LAST_LOG" overlay_encap 1 "tenant frame encapsulated via MAC-FDB (no L3 FDB entry)"
  agent_stop
}

# B9 — SRv6 per-MAC End.DT2U encap. The SRv6 analogue of `overlay_mac_fdb`:
# programs an `[srv6]` endpoint + a `[[srv6_route]]` (and NO `[overlay]`), so the
# ONLY way a tenant frame leaves is by matching its inner destination MAC in
# SRV6_FDB and being wrapped in outer Ethernet+IPv6 (reduced encap, a single
# End.DT2U service SID). The `srv6_encap` counter firing proves the L2-over-SRv6
# headend path resolves and redirects; the exact outer-header bytes are covered
# by the `build_srv6_encap` unit test in velstra-common.
scenario_srv6_encap() {
  section "B9 — SRv6 per-MAC End.DT2U encap"
  ns_add s6h  # host (SRv6 source)
  ns_add s6c  # tenant VM
  ns_add s6u  # remote underlay peer
  veth_pair s6h tap0 - s6c tap0c 192.168.100.1/24
  veth_pair s6h uplink0 fc00:0:1::1/64 s6u under0 fc00:0:1::2/64
  local umac
  umac="$(nse s6u cat /sys/class/net/under0/address)"
  # The tenant peer's MAC — the frame's inner dst MAC, and the SRV6_FDB key.
  local peer_mac="02:00:00:00:0b:02"
  cat >"$WORKDIR/srv6.toml" <<-EOF
	default_action = "pass"
	[srv6]
	local_src = "fc00:0:1::1"
	underlay_iface = "uplink0"
	underlay_mtu = 1500
	[[interface]]
	name = "tap0"
	policy = 0
	vni = 10000
	[[srv6_route]]
	vni = 10000
	mac = "$peer_mac"
	remote_sid = "fc00:0:2:2710::"
	via_mac = "$umac"
	out_iface = "uplink0"
	EOF
  agent_start s6h -- --iface tap0 --iface uplink0 --config "$WORKDIR/srv6.toml" \
    || { bad "agent start"; return; }
  # Pre-seed the VM's neighbour so it emits an IP frame addressed to peer_mac at
  # L2 (no ARP). There is NO tunnel/overlay for 192.168.100.2, so only SRV6_FDB
  # can resolve it — the srv6_encap counter firing proves the SRv6 path standalone.
  nse s6c ip neigh replace 192.168.100.2 lladdr "$peer_mac" dev tap0c
  nse s6c ping -c2 -W1 192.168.100.2 >/dev/null 2>&1 || true
  settle
  assert_ge "$LAST_LOG" srv6_encap 1 "tenant frame encapsulated via SRv6 End.DT2U (SRV6_FDB)"
  agent_stop
}

# B9 — SRv6 End.DT2U encap↔decap round-trip across TWO agents. Host A encaps a
# tenant frame toward host B's service SID; host B, whose SID this is, decaps it.
# Asserts both halves: A's `srv6_encap` and B's `srv6_decap` counters. This is the
# true L2-over-SRv6 datapath, end to end, with no packet crafting — just the two
# real agents and a ping from the tenant.
scenario_srv6_roundtrip() {
  section "B9 — SRv6 End.DT2U encap↔decap round-trip"
  ns_add s6a   # host A: SRv6 source (encap)
  ns_add s6ac  # tenant VM behind A
  ns_add s6b   # host B: SRv6 endpoint (decap)
  veth_pair s6a tap0 - s6ac tap0c 192.168.100.1/24
  veth_pair s6a uplink0 fc00:0:1::1/64 s6b under0 fc00:0:1::2/64
  local bmac sid peer_mac
  bmac="$(nse s6b cat /sys/class/net/under0/address)"
  sid="fc00:0:2:2710::"
  peer_mac="02:00:00:00:0b:02"
  # Host A: encap tenant (vni 10000) frames whose inner dst MAC = peer_mac toward
  # host B's service SID.
  cat >"$WORKDIR/srv6-a.toml" <<-EOF
	default_action = "pass"
	[srv6]
	local_src = "fc00:0:1::1"
	underlay_iface = "uplink0"
	[[interface]]
	name = "tap0"
	policy = 0
	vni = 10000
	[[srv6_route]]
	vni = 10000
	mac = "$peer_mac"
	remote_sid = "$sid"
	via_mac = "$bmac"
	out_iface = "uplink0"
	EOF
  # Host B: instantiate that SID and decapsulate End.DT2U into vni 10000.
  cat >"$WORKDIR/srv6-b.toml" <<-EOF
	default_action = "pass"
	[srv6]
	local_src = "fc00:0:2::1"
	underlay_iface = "under0"
	[[srv6_local_sid]]
	sid = "$sid"
	vni = 10000
	behavior = "end.dt2u"
	EOF
  agent_start s6b -- --iface under0 --config "$WORKDIR/srv6-b.toml" \
    || { bad "agent B start"; return; }
  local logb="$LAST_LOG" pidb="$LAST_PID"
  agent_start s6a -- --iface tap0 --iface uplink0 --config "$WORKDIR/srv6-a.toml" \
    || { bad "agent A start"; kill -TERM "$pidb" 2>/dev/null; return; }
  local loga="$LAST_LOG"
  # Tenant emits an IP frame addressed to peer_mac at L2 (no ARP), which A encaps
  # toward the SID and B (owning the SID) decaps.
  nse s6ac ip neigh replace 192.168.100.2 lladdr "$peer_mac" dev tap0c
  nse s6ac ping -c3 -W1 192.168.100.2 >/dev/null 2>&1 || true
  settle
  assert_ge "$loga" srv6_encap 1 "host A encapsulated the tenant frame (End.DT2U)"
  assert_ge "$logb" srv6_decap 1 "host B decapsulated it into the tenant (End.DT2U)"
  agent_stop                              # stops A (LAST_PID)
  kill -TERM "$pidb" 2>/dev/null || true  # stop B (the EXIT trap also reaps it)
}

# B4b — local MAC learning. A tenant frame ingressing a tenant port (`vni != 0`)
# is learned into the `LOCAL_MACS` map on the firewall-allowed path, so the agent
# can advertise it to a co-located Wren daemon (EVPN type-2). This asserts the
# datapath half — the map gets populated — which happens regardless of
# `--wren-socket`; the advertise half needs a running Wren and is covered by unit
# tests. BPF maps are not netns-scoped, so `bpftool` in the root netns can dump
# the agent's map; the scenario skips cleanly when bpftool is unavailable.
scenario_local_mac_learn() {
  section "B4b — local MAC learning into LOCAL_MACS"
  if ! command -v bpftool >/dev/null 2>&1; then
    skip "local MAC learning (bpftool not available to dump LOCAL_MACS)"
    return
  fi
  ns_add lmh  # host (VTEP)
  ns_add lmc  # tenant VM
  veth_pair lmh tap0 192.168.100.1/24 lmc tap0c 192.168.100.2/24
  cat >"$WORKDIR/learn.toml" <<-EOF
	default_action = "pass"
	[[interface]]
	name = "tap0"
	policy = 0
	vni = 6000
	EOF
  agent_start lmh -- --iface tap0 --config "$WORKDIR/learn.toml" \
    || { bad "agent start"; return; }
  # Pre-seed the host neighbour so the tenant emits an IP frame (no ARP) straight
  # into tap0, where the XDP program learns its source MAC/IP.
  local hmac
  hmac="$(nse lmh cat /sys/class/net/tap0/address)"
  nse lmc ip neigh replace 192.168.100.1 lladdr "$hmac" dev tap0c
  nse lmc ping -c2 -W1 192.168.100.1 >/dev/null 2>&1 || true
  settle
  # A populated LOCAL_MACS (≥1 key) proves the tenant's src MAC/IP was learned.
  local keys
  keys="$(bpftool map dump name LOCAL_MACS 2>/dev/null | grep -c 'key')"
  if [ "${keys:-0}" -ge 1 ] 2>/dev/null; then
    ok "tenant src MAC/IP learned into LOCAL_MACS [keys=$keys ≥ 1]"
  else
    bad "LOCAL_MACS empty after tenant frame [keys=$keys, expected ≥ 1]"
  fi
  agent_stop
}

scenario_routing() {
  section "Phase 2 — routing redirect"
  ns_add rtc; ns_add rtr; ns_add rtb
  veth_pair rtc vc 10.20.0.1/24 rtr vrc 10.20.0.254/24    # client ── router
  veth_pair rtr vrb 10.30.0.254/24 rtb vb 10.30.0.2/24    # router ── backend
  nse rtc ip route add 10.30.0.0/24 via 10.20.0.254       # client → backend via router
  local bmac
  bmac="$(nse rtb cat /sys/class/net/vb/address)"
  cat >"$WORKDIR/route.toml" <<-EOF
	default_action = "pass"
	[[route]]
	dest = "10.30.0.0/24"
	out_iface = "vrb"
	via_mac = "$bmac"
	mode = "switch"
	EOF
  # Attach on the router; the packet ingresses vrc and is redirected out vrb.
  agent_start rtr -- --iface vrc --iface vrb --config "$WORKDIR/route.toml" \
    || { bad "agent start"; return; }
  nse rtc ping -c2 -W1 10.30.0.2 >/dev/null 2>&1 || true
  settle
  # `forwarded` is bumped when a route matches and the packet is redirected
  # (asserting the counter, not a full round-trip, which needs reverse routing).
  assert_ge "$LAST_LOG" forwarded 1 "packet redirected by a matching route"
  agent_stop
}

scenario_lb() {
  section "Phase 3 — load balancer DNAT"
  ns_add lbc; ns_add lbh
  veth_pair lbc vc 10.40.0.1/24 lbh vh 10.40.0.254/24
  nse lbc ip route add 10.40.99.0/24 via 10.40.0.254      # client → VIP via lb host
  cat >"$WORKDIR/lb.toml" <<-EOF
	default_action = "pass"
	[[service]]
	vip = "10.40.99.10"
	port = 80
	proto = "tcp"
	backends = [{ ip = "10.40.0.5", port = 8080 }]
	EOF
  agent_start lbh -- --iface vh --config "$WORKDIR/lb.toml" || { bad "agent start"; return; }
  tcp_connect lbc 10.40.99.10 80 || true
  settle
  # The SYN to the VIP is DNAT-rewritten to the backend (counter fires before the
  # rewritten packet is passed on; a completed round-trip needs host prep — see
  # docs/TESTING.md §4).
  assert_ge "$LAST_LOG" load_balanced 1 "SYN to the VIP DNAT-rewritten to a backend"
  agent_stop
}

# ---------------------------------------------------------------------------
ALL=(
  fw_pass fw_default_drop fw_blocklist_v4 fw_icmp fw_port fw_blocklist_v6
  egress_blocklist routing lb overlay_arp overlay_nd overlay_encap overlay_mac_fdb
  srv6_encap srv6_roundtrip local_mac_learn
)

main() {
  require_root
  require_bin
  local sel=("$@")
  [ "${#sel[@]}" -eq 0 ] && sel=("${ALL[@]}")
  for s in "${sel[@]}"; do
    if declare -F "scenario_$s" >/dev/null; then
      "scenario_$s"
    else
      echo "unknown scenario: $s (have: ${ALL[*]})" >&2
      FAIL=$((FAIL + 1))
    fi
  done
  summary
}

main "$@"
