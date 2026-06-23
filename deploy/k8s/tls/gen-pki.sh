#!/usr/bin/env bash
# Generate a PKI for Velstra-on-Kubernetes mTLS and create the K8s Secrets:
#   * a CA,
#   * a controller SERVER cert whose SANs cover every controller endpoint (the
#     service, each replica's stable pod DNS, and localhost for the in-pod CLI),
#   * client certs identifying the agent and the CNI.
#
#   ./deploy/k8s/tls/gen-pki.sh [namespace] [out-dir]
#
# Secrets created (each holds tls.crt, tls.key, ca.pem):
#   velstra-controller-tls   (server identity + client CA)
#   velstra-agent-tls        (agent client identity)
#   velstra-cni-tls          (cni client identity)
#
# See ../README.md "mTLS" for the matching manifest changes.
set -euo pipefail

NS="${1:-velstra-system}"
OUT="${2:-pki}"
SVC="velstra-controller"
DOMAIN="${SVC}.${NS}.svc.cluster.local"

mkdir -p "$OUT"
cd "$OUT"

# --- CA ---------------------------------------------------------------------
openssl genrsa -out ca.key 4096 2>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
    -subj "/CN=Velstra CA" -out ca.pem 2>/dev/null

# --- Server cert (the controller) -------------------------------------------
# SANs: the headless service, each replica's stable pod DNS, and localhost (the
# `orch`/`admin` CLI run via `kubectl exec` connects to 127.0.0.1).
SAN="DNS:${SVC},DNS:${SVC}.${NS},DNS:${SVC}.${NS}.svc,DNS:${DOMAIN}"
SAN="${SAN},DNS:${SVC}-0.${DOMAIN},DNS:${SVC}-1.${DOMAIN},DNS:${SVC}-2.${DOMAIN}"
SAN="${SAN},DNS:localhost,IP:127.0.0.1"
openssl genrsa -out server.key 4096 2>/dev/null
openssl req -new -key server.key -subj "/CN=${DOMAIN}" -out server.csr 2>/dev/null
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -days 825 -sha256 -extfile <(printf 'subjectAltName=%s\n' "$SAN") \
    -out server.pem 2>/dev/null

# --- Client certs (mTLS identities) -----------------------------------------
for who in agent cni; do
    openssl genrsa -out "$who.key" 4096 2>/dev/null
    openssl req -new -key "$who.key" -subj "/CN=velstra-$who" -out "$who.csr" 2>/dev/null
    openssl x509 -req -in "$who.csr" -CA ca.pem -CAkey ca.key -CAcreateserial \
        -days 825 -sha256 -extfile <(printf 'subjectAltName=DNS:velstra-%s\n' "$who") \
        -out "$who.pem" 2>/dev/null
done
rm -f ./*.csr ca.srl

# --- K8s Secrets ------------------------------------------------------------
mk_secret() { # secret-name cert key
    kubectl -n "$NS" create secret generic "$1" \
        --from-file=tls.crt="$2" --from-file=tls.key="$3" --from-file=ca.pem=ca.pem \
        --dry-run=client -o yaml | kubectl apply -f -
}
mk_secret velstra-controller-tls server.pem server.key
mk_secret velstra-agent-tls agent.pem agent.key
mk_secret velstra-cni-tls cni.pem cni.key

echo "PKI written to $OUT/ and Secrets created in namespace $NS."
