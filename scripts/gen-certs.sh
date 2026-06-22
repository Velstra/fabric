#!/usr/bin/env bash
# Generate a tiny PKI for testing Velstra's controller mTLS: a CA, a server
# certificate (for the controller), and a client certificate (for an agent).
#
#   ./scripts/gen-certs.sh [out-dir] [server-dns-name]
#
# Then:
#   velstra-controller serve --config-dir nodes \
#       --tls-cert certs/server.pem --tls-key certs/server.key --client-ca certs/ca.pem
#   sudo -E velstra run --iface eth0 \
#       --controller https://CONTROLLER:50051 --node-id web-1 \
#       --tls-ca certs/ca.pem --tls-cert certs/client.pem --tls-key certs/client.key \
#       --tls-domain controller.local
set -euo pipefail

OUT="${1:-certs}"
DNS="${2:-controller.local}"
mkdir -p "$OUT"
cd "$OUT"

# CA
openssl genrsa -out ca.key 4096 2>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
    -subj "/CN=Velstra Test CA" -out ca.pem 2>/dev/null

gen() { # name CN [extra-san]
    local name="$1" cn="$2" san="${3:-}"
    openssl genrsa -out "$name.key" 4096 2>/dev/null
    openssl req -new -key "$name.key" -subj "/CN=$cn" -out "$name.csr" 2>/dev/null
    local ext="subjectAltName=DNS:$cn"
    [ -n "$san" ] && ext="$ext,$san"
    openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -CAcreateserial \
        -days 825 -sha256 -extfile <(printf '%s\n' "$ext") -out "$name.pem" 2>/dev/null
    rm -f "$name.csr"
}

# Server cert: SANs cover the chosen DNS name plus localhost for local testing.
gen server "$DNS" "DNS:localhost,IP:127.0.0.1"
# Client cert (the agent's identity).
gen client velstra-agent

rm -f ca.srl
echo "wrote CA + server + client certs to $OUT/ (server DNS: $DNS)"
ls -1 "$PWD"
