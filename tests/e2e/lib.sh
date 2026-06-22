#!/usr/bin/env bash
# Shared helpers for the Velstra end-to-end test harness.
#
# These tests load the *real* XDP/TC programs into the kernel, so they need root
# (CAP_NET_ADMIN + CAP_BPF) and a recent kernel. They build a throwaway topology
# out of network namespaces and veth pairs, run the agent inside a namespace,
# generate traffic, and assert on the per-CPU statistics the agent prints.
#
# Everything created is tracked and torn down by an EXIT trap, so a failed test
# never leaves stray namespaces or qdiscs behind.

set -uo pipefail

# The agent binary. Override with VELSTRA_BIN=...
BIN="${VELSTRA_BIN:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/target/release/velstra}"

WORKDIR="$(mktemp -d /tmp/velstra-e2e.XXXXXX)"
declare -a _NETNS=() _AGENTS=()
PASS=0
FAIL=0
SKIP=0

# --- output -----------------------------------------------------------------
_c() { printf '\033[%sm' "$1"; }
section() { printf '\n%s=== %s ===%s\n' "$(_c '1;36')" "$*" "$(_c 0)"; }
note()    { printf '       %s\n' "$*"; }
ok()      { PASS=$((PASS + 1)); printf '  %sPASS%s %s\n' "$(_c '32')" "$(_c 0)" "$*"; }
bad()     { FAIL=$((FAIL + 1)); printf '  %sFAIL%s %s\n' "$(_c '31')" "$(_c 0)" "$*"; }
skip()    { SKIP=$((SKIP + 1)); printf '  %sSKIP%s %s\n' "$(_c '33')" "$(_c 0)" "$*"; }

# --- preconditions ----------------------------------------------------------
require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "error: the e2e suite must run as root (loads eBPF). Try: sudo $0" >&2
    exit 1
  fi
}

require_bin() {
  if [ ! -x "$BIN" ]; then
    echo "error: agent binary not found at $BIN" >&2
    echo "       build it first: cargo build --release" >&2
    exit 1
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# Run a command in a namespace.
nse() { ip netns exec "$@"; }

# --- topology ---------------------------------------------------------------
ns_add() {
  ip netns add "$1"
  _NETNS+=("$1")
  nse "$1" ip link set lo up
}

# Best-effort: turn off veth checksum offload so the kernel doesn't leave
# packets with bad/partial checksums that confuse our parsing or the peer.
_no_offload() {
  local ns=$1 dev=$2
  have ethtool && nse "$ns" ethtool -K "$dev" tx off rx off >/dev/null 2>&1 || true
}

# Create a veth pair with one end in each of two namespaces and assign IPv4s.
# Pass "-" as a cidr to leave that end address-less (e.g. a bridge-side tap).
#   veth_pair ns1 dev1 cidr1  ns2 dev2 cidr2
veth_pair() {
  local ns1=$1 dev1=$2 ip1=$3 ns2=$4 dev2=$5 ip2=$6
  ip link add "$dev1" netns "$ns1" type veth peer name "$dev2" netns "$ns2"
  [ "$ip1" != "-" ] && nse "$ns1" ip addr add "$ip1" dev "$dev1"
  [ "$ip2" != "-" ] && nse "$ns2" ip addr add "$ip2" dev "$dev2"
  nse "$ns1" ip link set "$dev1" up
  nse "$ns2" ip link set "$dev2" up
  _no_offload "$ns1" "$dev1"
  _no_offload "$ns2" "$dev2"
}

# Add an IPv6 address to a device in a namespace.
add6() { nse "$1" ip -6 addr add "$3" dev "$2" nodad; }

# --- agent ------------------------------------------------------------------
# Start the agent inside a namespace. Sets LAST_LOG / LAST_PID.
#   agent_start <ns> -- <agent args...>
agent_start() {
  local ns=$1
  shift
  [ "$1" = "--" ] && shift
  local log="$WORKDIR/agent-${ns}-$RANDOM.log"
  nse "$ns" "$BIN" run --xdp-mode skb --stats-interval 1 "$@" >"$log" 2>&1 &
  local pid=$!
  _AGENTS+=("$pid")
  LAST_LOG="$log"
  LAST_PID="$pid"
  # Wait until it reports live (or died).
  local i
  for i in $(seq 1 100); do
    if grep -q "Velstra is live" "$log" 2>/dev/null; then return 0; fi
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "  agent died on startup; log:" >&2
      sed 's/^/    /' "$log" >&2
      return 1
    fi
    sleep 0.1
  done
  echo "  agent did not become live in time; log:" >&2
  sed 's/^/    /' "$log" >&2
  return 1
}

# Stop the most-recently-started agent. We use SIGTERM, not SIGINT: a
# non-interactive shell sets background jobs to *ignore* SIGINT (POSIX), so
# `kill -INT` would be swallowed and `wait` would block forever. SIGTERM is not
# masked and terminates the agent promptly; the XDP/TC links drop when its fds
# close. Assertions have already read the periodic stats, so this is harmless.
# Poll briefly, then SIGKILL as a last resort, so the suite never hangs.
agent_stop() {
  [ -n "${LAST_PID:-}" ] || return 0
  kill -TERM "$LAST_PID" 2>/dev/null || true
  local i
  for i in $(seq 1 20); do
    kill -0 "$LAST_PID" 2>/dev/null || { wait "$LAST_PID" 2>/dev/null; return 0; }
    sleep 0.1
  done
  kill -KILL "$LAST_PID" 2>/dev/null || true
  wait "$LAST_PID" 2>/dev/null || true
}

# --- assertions -------------------------------------------------------------
# Read the latest value of a named counter from an agent log (0 if absent).
counter() {
  local log=$1 name=$2 val
  val="$(grep -E "^[[:space:]]*${name}[[:space:]]" "$log" 2>/dev/null | tail -1 | awk '{print $NF}')"
  echo "${val:-0}"
}

# Give the periodic stats dump time to land in the log.
settle() { sleep "${1:-2}"; }

assert_ge() { # log name min msg
  local v
  v="$(counter "$1" "$2")"
  if [ "${v:-0}" -ge "$3" ] 2>/dev/null; then ok "$4 [$2=$v ≥ $3]"; else
    bad "$4 [$2=$v, expected ≥ $3]"
    _dump "$1"
  fi
}

assert_zero() { # log name msg
  local v
  v="$(counter "$1" "$2")"
  if [ "${v:-0}" -eq 0 ] 2>/dev/null; then ok "$3 [$2=0]"; else
    bad "$3 [$2=$v, expected 0]"
    _dump "$1"
  fi
}

assert_cmd() { # msg -- cmd...   (passes if cmd succeeds)
  local msg=$1
  shift
  [ "$1" = "--" ] && shift
  if "$@" >/dev/null 2>&1; then ok "$msg"; else bad "$msg [cmd failed: $*]"; fi
}

assert_fail() { # msg -- cmd...  (passes if cmd FAILS, e.g. traffic was dropped)
  local msg=$1
  shift
  [ "$1" = "--" ] && shift
  if "$@" >/dev/null 2>&1; then bad "$msg [cmd unexpectedly succeeded: $*]"; else ok "$msg"; fi
}

_dump() {
  echo "       --- last stats table ---" >&2
  grep -E '^[[:space:]]*(counter|[a-z_]+ +[0-9]+|drop rate)' "$1" 2>/dev/null | tail -30 | sed 's/^/       /' >&2
}

# --- cleanup ----------------------------------------------------------------
cleanup() {
  local p ns
  for p in "${_AGENTS[@]:-}"; do kill -TERM "$p" 2>/dev/null || true; done
  sleep 0.3
  for p in "${_AGENTS[@]:-}"; do kill -KILL "$p" 2>/dev/null || true; done
  for ns in "${_NETNS[@]:-}"; do ip netns del "$ns" 2>/dev/null || true; done
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

summary() {
  printf '\n%s──────── %d passed, %d failed, %d skipped ────────%s\n' \
    "$(_c '1')" "$PASS" "$FAIL" "$SKIP" "$(_c 0)"
  [ "$FAIL" -eq 0 ]
}
