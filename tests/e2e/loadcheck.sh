#!/usr/bin/env bash
# Does the data plane load at all? Nothing else -- no topology, no traffic.
# Answers in two seconds what the e2e suite answers in a minute, and it is the
# question that was actually failing.
set -uo pipefail
# Repo root: derived from this script's location (tests/e2e/ -> ../..) so it runs
# from a CI checkout or any clone, not just a developer's home. Override with
# VELSTRA_ROOT=... if the tree lives somewhere the derivation can't reach.
R="${VELSTRA_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
cat > "$W/min.toml" <<'TOML'
default_action = "pass"
source_validation = "strict"
TOML
ip link add loadcheck0 type dummy 2>/dev/null
ip link set loadcheck0 up
timeout 20 "$R/target/release/velstra" run --iface loadcheck0 --config "$W/min.toml" \
  --stats-interval 0 > "$W/out.log" 2>&1 &
PID=$!
for _ in $(seq 60); do
  grep -q "Velstra is live" "$W/out.log" 2>/dev/null && break
  kill -0 "$PID" 2>/dev/null || break
  sleep 0.25
done
if grep -q "Velstra is live" "$W/out.log"; then
  echo "LOADS: the verifier accepted the datapath"
  RC=0
else
  echo "REFUSED:"
  sed 's/^/  /' "$W/out.log"
  RC=1
fi
kill -TERM "$PID" 2>/dev/null
wait "$PID" 2>/dev/null
ip link del loadcheck0 2>/dev/null
exit $RC
