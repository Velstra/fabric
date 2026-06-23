# Testing Velstra on your machine

This is a hands-on, copy-paste walkthrough for running Velstra against real
traffic on a single Linux box — no extra hardware — and **watching what it
does** in the logs and the live statistics.

> **Why not a `dummy` interface?** XDP runs on an interface's **receive** path.
> Traffic you send *to* a local `dummy` IP never traverses that NIC's RX queue
> (it shortcuts through loopback), so an XDP program attached to a `dummy` device
> sees nothing. The right tool is a **veth pair across network namespaces**: one
> end lives in a "client" namespace and the other in your host, and packets the
> client sends genuinely arrive on the host end's RX path where XDP can act on
> them. That is what we use below.

All commands need root (`sudo`). Build first:

```shell
cargo build --release
```

## 1. Create the test network

A client namespace connected to your host by a veth pair:

```shell
sudo ip netns add client
sudo ip link add veth-host type veth peer name veth-cl
sudo ip link set veth-cl netns client

# Host side
sudo ip addr add 10.0.0.1/24 dev veth-host
sudo ip link set veth-host up

# Client side
sudo ip netns exec client ip addr add 10.0.0.2/24 dev veth-cl
sudo ip netns exec client ip link set veth-cl up
sudo ip netns exec client ip link set lo up
```

Confirm it works *before* attaching Velstra:

```shell
sudo ip netns exec client ping -c2 10.0.0.1   # should reply
```

## 2. Run the firewall and watch it

Write a policy that drops ICMP and logs every action:

```shell
cat > /tmp/fw.toml <<'EOF'
default_action = "pass"
drop_icmp      = true
log            = true
blocklist      = ["10.0.0.0/8"]   # comment out to test ICMP-only first
[[port_rule]]
proto  = "tcp"
port   = 8000
action = "drop"
EOF
```

Start the daemon. `RUST_LOG=info` turns on the live log; `--xdp-mode skb` uses
generic XDP, which always works on veth:

```shell
sudo -E RUST_LOG=info ./target/release/velstra \
    run --iface veth-host --xdp-mode skb --config /tmp/fw.toml --stats-interval 5
```

You'll see it attach:

```
[INFO  velstra::firewall] policy: default=Pass, 1 blocklist entr(y/ies), 1 port rule(s), 0 route(s), 0 service(s)
[INFO  velstra::firewall] attached to veth-host in Skb mode — Velstra is live
Velstra is running. Press Ctrl-C to detach.
```

In a **second terminal**, generate traffic from the client:

```shell
sudo ip netns exec client ping -c3 10.0.0.1
```

Back in the daemon terminal you'll see per-packet drop lines (from the eBPF
program itself, via `aya-log`) and, every 5 s, the counters:

```
[INFO  velstra-ebpf] DROP 10.0.0.2 proto=1 dport=0 reason=dropped_blocklist

Live statistics:
  counter                       value
  -------------------- --------------
  rx_packets                        3
  dropped_blocklist                 3
  ...
  -------------------- --------------
  drop rate                   100.00%
```

Things to try:

| Change | What you should observe |
|---|---|
| Remove `blocklist`, keep `drop_icmp` | `ping` still 100% loss, reason `dropped_icmp` |
| `python3 -m http.server 8000 --bind 10.0.0.1` then `sudo ip netns exec client curl -m3 10.0.0.1:8000` | hangs/fails, counter `dropped_rule` (remove the `[[port_rule]]` and it succeeds, counter `passed_default`) |
| `default_action = "drop"` with no rules | everything from the client is dropped (`dropped_default`) |

Press **Ctrl-C**; the daemon prints final statistics and detaches the program.

## 3. Routing / switching (Phase 2)

Add a second namespace to act as the next hop, and a second veth:

```shell
sudo ip netns add nexthop
sudo ip link add veth-nh type veth peer name veth-nhp
sudo ip link set veth-nhp netns nexthop
sudo ip addr add 10.0.9.1/24 dev veth-nh
sudo ip link set veth-nh up
sudo ip netns exec nexthop ip addr add 10.0.9.2/24 dev veth-nhp
sudo ip netns exec nexthop ip link set veth-nhp up
```

Find the next hop's MAC (you'll put it in the route):

```shell
sudo ip netns exec nexthop cat /sys/class/net/veth-nhp/address   # e.g. 02:..:..
```

```shell
cat > /tmp/route.toml <<'EOF'
default_action = "pass"
log = true
[[route]]
dest      = "10.0.9.0/24"
out_iface = "veth-nh"
via_mac   = "PASTE_THE_NEXTHOP_MAC_HERE"
mode      = "route"
EOF

sudo -E RUST_LOG=info ./target/release/velstra \
    run --iface veth-host --xdp-mode skb --config /tmp/route.toml
```

Watch the egress while sending a packet whose destination is `10.0.9.x`:

```shell
# terminal 2: sniff what arrives at the next hop
sudo ip netns exec nexthop tcpdump -ni veth-nhp

# terminal 3: send from the client toward 10.0.9.5
sudo ip netns exec client ping -c2 10.0.9.5
```

You'll see `FWD -> ifindex N` in the daemon log and the **redirected** frames
appear on `veth-nhp` (re-addressed to the next-hop MAC, TTL decremented). This
proves the `XDP_REDIRECT` path end-to-end.

## 4. Load balancer / NAT (Phase 3)

This is the most involved test: a full, stateful L4 round-trip needs the host to
**forward** between two subnets *and* it fights several Linux defaults that are
specific to a single-host veth lab. None of these are Velstra bugs — on a real
NIC, with traffic arriving from the network, they don't apply. But on a veth lab
you must prepare the host. Read the **"Host prep"** box below carefully; missing
any one item shows up as a `curl` timeout.

Add a backend namespace and a web server:

```shell
sudo ip netns add backend
sudo ip link add veth-be type veth peer name veth-bep
sudo ip link set veth-bep netns backend
sudo ip addr add 10.0.1.1/24 dev veth-be
sudo ip link set veth-be up
sudo ip netns exec backend ip addr add 10.0.1.2/24 dev veth-bep
sudo ip netns exec backend ip link set veth-bep up
sudo ip netns exec backend ip route add default via 10.0.1.1

# terminal 2: a real listener bound to the backend
sudo ip netns exec backend python3 -m http.server 8080 --bind 10.0.1.2
```

> ### Host prep for stateful NAT on veth (do all five)
>
> ```shell
> # 1. Enable IP forwarding (the host routes client <-> backend).
> sudo sysctl -w net.ipv4.ip_forward=1
>
> # 2. Disable veth checksum offload. Locally-generated packets carry only a
> #    partial (pseudo-header) L4 checksum; XDP must see/patch a *complete* one.
> for d in veth-host veth-be; do sudo ethtool -K $d tx off rx off; done
> sudo ip netns exec client  ethtool -K veth-cl  tx off rx off
> sudo ip netns exec backend ethtool -K veth-bep tx off rx off
>
> # 3. Allow forwarding between our veths. If Docker/firewalld is installed the
> #    FORWARD chain defaults to DROP — insert ACCEPTs at the top.
> sudo iptables -I FORWARD -i veth-host -o veth-be -j ACCEPT
> sudo iptables -I FORWARD -i veth-be -o veth-host -j ACCEPT
>
> # 4. Stop netfilter conntrack from tagging XDP-NAT'd replies as "invalid"
> #    (XDP rewrites the packet *before* netfilter sees it).
> sudo iptables -t raw -I PREROUTING -i veth-host -j CT --notrack
> sudo iptables -t raw -I PREROUTING -i veth-be   -j CT --notrack
>
> # 5. Turn off reverse-path filtering (the SNAT'd reply's source is the VIP,
> #    which lives on the *other* interface).
> for k in all veth-host veth-be; do sudo sysctl -w net.ipv4.conf.$k.rp_filter=0; done
> ```
>
> **Do not** add the VIP as a local alias (`ip addr add 10.0.0.100/32 ...`). If
> the VIP is a local host IP, the SNAT'd reply (source = VIP) arriving back on
> the host is dropped as a *martian source*. Instead, point the client at the
> VIP with a static ARP entry so the host never owns the address:
>
> ```shell
> HOSTMAC=$(cat /sys/class/net/veth-host/address)
> sudo ip netns exec client ip neigh replace 10.0.0.100 lladdr "$HOSTMAC" dev veth-cl
> ```

```shell
cat > /tmp/lb.toml <<'EOF'
default_action = "pass"
log = true
[[service]]
vip   = "10.0.0.100"
port  = 80
proto = "tcp"
backends = [
  { ip = "10.0.1.2", port = 8080 },
]
EOF
```

Velstra does **stateful** NAT: it DNATs requests on the way in *and* SNATs the
backend's replies back to the VIP. For it to see both directions, attach it to
**both** the client-facing and backend-facing interfaces — one process, so the
`CONNTRACK` map is shared:

```shell
# terminal 1
sudo -E RUST_LOG=info ./target/release/velstra run \
    --iface veth-host --iface veth-be --xdp-mode skb --config /tmp/lb.toml
```

Now hit the VIP from the client — the round-trip completes:

```shell
# terminal 3
sudo ip netns exec client curl -m3 http://10.0.0.100/
```

`curl` gets the directory listing back (the client only ever talks to
`10.0.0.100:80` — it never sees the backend). The daemon log shows both
directions:

```
[INFO  velstra-ebpf] DNAT 10.0.0.100:80 -> 10.0.1.2:8080      # request (new flow)
[INFO  velstra-ebpf] NAT(ct) reverse=1 -> 10.0.0.100:80       # reply, SNAT'd back
```

The counters tell the story: `load_balanced` (first packet of a flow),
`lb_established` (later request packets, DNAT'd via conntrack), and `lb_reverse`
(reply packets, SNAT'd). Watch with `tcpdump -ni veth-bep` that the backend sees
the request DNAT'd to `10.0.1.2:8080`.

> **Topology note.** Reverse NAT only works because the program is attached to
> the interface where replies arrive (`veth-be`). With a single `--iface` it
> still DNATs (you can observe it with tcpdump), but the reply isn't un-NAT-ed
> and `curl` won't complete. The NAT fast path also requires a 20-byte IPv4
> header (no IP options) — option-bearing packets fall through to routing.

## 5. Reading the output

* **Per-packet logs** (`DROP …`, `FWD …`, `DNAT …`) come from the eBPF program
  via `aya-log` and only appear when `log = true` and you run with
  `RUST_LOG=info`. They are great for debugging but add hot-path cost — turn them
  off for benchmarking.
* **Counters** are summed across CPUs and printed every `--stats-interval`
  seconds and once on exit. `drop rate` is `(all drop counters) / rx_packets`.
* No traffic showing up? Check you attached to the **host** end (`veth-host`),
  that the client interface is `up`, and that plain connectivity worked in step 1.

## 6. Clean up

```shell
sudo ip netns del client   2>/dev/null
sudo ip netns del nexthop  2>/dev/null
sudo ip netns del backend  2>/dev/null
sudo ip link del veth-host 2>/dev/null
sudo ip link del veth-nh   2>/dev/null
sudo ip link del veth-be   2>/dev/null

# Remove the host-prep rules from the Phase 3 test (ignore "not found").
sudo iptables -D FORWARD -i veth-host -o veth-be -j ACCEPT       2>/dev/null
sudo iptables -D FORWARD -i veth-be -o veth-host -j ACCEPT       2>/dev/null
sudo iptables -t raw -D PREROUTING -i veth-host -j CT --notrack  2>/dev/null
sudo iptables -t raw -D PREROUTING -i veth-be   -j CT --notrack  2>/dev/null
```

(The veth peers in the namespaces disappear automatically with their namespace.
The `rp_filter`/`ip_forward` sysctls and offload settings are per-boot and reset
on reboot, or restore them by hand if you like.)

## 7. CNI plugin (manual test, no Kubernetes)

`velstra-cni` speaks the CNI protocol, so you can drive it by hand exactly as a
container runtime would — with environment variables and a JSON config on stdin
— against a network namespace you create yourself.

```shell
cargo build --release
sudo ip netns add testpod

CONF='{"cniVersion":"1.0.0","name":"velstra","type":"velstra-cni","subnet":"10.244.0.0/24"}'

# ADD: allocate an IP and wire eth0 into the pod netns.
echo "$CONF" | sudo CNI_COMMAND=ADD CNI_CONTAINERID=test1 \
    CNI_NETNS=/var/run/netns/testpod CNI_IFNAME=eth0 \
    ./target/release/velstra-cni
#  -> {"cniVersion":"1.0.0","interfaces":[...],"ips":[{"address":"10.244.0.2/24",...}],...}

sudo ip netns exec testpod ip addr show eth0   # has 10.244.0.2/24
sudo ip netns exec testpod ip route            # default via 10.244.0.1
ip link show type veth | grep vel              # the host-side veth

# DEL: tear it down (idempotent).
echo "$CONF" | sudo CNI_COMMAND=DEL CNI_CONTAINERID=test1 \
    CNI_NETNS=/var/run/netns/testpod CNI_IFNAME=eth0 \
    ./target/release/velstra-cni

sudo ip netns del testpod
```

In a real cluster, install the binary to `/opt/cni/bin/velstra-cni` and the
[`examples/cni/10-velstra.conflist`](../examples/cni/10-velstra.conflist) to
`/etc/cni/net.d/`. The Velstra agent, run as a DaemonSet, then attaches the XDP
firewall/LB to the `vel*` host veths this plugin creates — that agent-side
integration is the next step on the roadmap.
