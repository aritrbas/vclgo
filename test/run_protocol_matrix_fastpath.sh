#!/bin/bash
# Complete routed protocol/error acceptance matrix. The caller must provide
# SERVER_VCL_CONFIG and CLIENT_VCL_CONFIG for two VPP instances whose IPv6
# interfaces can reach each other (documented defaults are 10.77.0.0/24
# and 2001:db8:77::/64). IPv6 carries the data-plane cases; the strict
# ICMP-port-unreachable gate uses IPv4 because this VPP version has no
# IPv6 branch in udp_connection_handle_icmp().

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${SERVER_VCL_CONFIG:?set SERVER_VCL_CONFIG for VPP A}"
: "${CLIENT_VCL_CONFIG:?set CLIENT_VCL_CONFIG for VPP B}"

IPV6_SERVER="${IPV6_SERVER:-2001:db8:77::1}"
IPV6_CLIENT="${IPV6_CLIENT:-2001:db8:77::2}"
IPV4_SERVER="${IPV4_SERVER:-10.77.0.1}"
BASE_LOG_DIR="${BASE_LOG_DIR:-/tmp/vclgo-protocol-matrix-fastpath}"
MATRIX_CONC="${MATRIX_CONC:-100}"
MATRIX_REQS="${MATRIX_REQS:-32}"
mkdir -p "$BASE_LOG_DIR"

echo "[protocol-matrix] IPv6 TCP + refused/reset/half-close"
TCP_NETWORK=tcp6 \
SERVER_ADDR="[$IPV6_SERVER]:9876" \
CLIENT_ADDR="[$IPV6_SERVER]:9876" \
REFUSED_ADDR="[$IPV6_SERVER]:19876" \
RESET_SERVER_ADDR="[$IPV6_SERVER]:19878" \
RESET_CLIENT_ADDR="[$IPV6_SERVER]:19878" \
RESET_PROBE=1 TCP_CONC="$MATRIX_CONC" \
LOG_DIR="$BASE_LOG_DIR/tcp6" \
bash "$SCRIPT_DIR/run_smoke_fastpath.sh"

echo "[protocol-matrix] IPv6 connected/wildcard-unconnected UDP + IPv4 ICMP error"
UDP_NETWORK=udp6 \
SERVER_ADDR="[$IPV6_SERVER]:9877" \
CLIENT_LOCAL_ADDR='[::]:0' \
ICMP_ERROR_NETWORK=udp4 \
ICMP_ERROR_ADDR="$IPV4_SERVER:19877" \
UDP_CONC="$MATRIX_CONC" UDP_MSGS=8 \
LOG_DIR="$BASE_LOG_DIR/udp6" \
bash "$SCRIPT_DIR/run_smoke_udp_fastpath.sh"

run_http_case() {
    local label=$1
    local port=$2
    local path=$3
    local server_extra=$4
    local client_extra=$5
    echo "[protocol-matrix] $label"
    HTTP_NETWORK=tcp6 \
    SERVER_ADDR="[$IPV6_SERVER]:$port" \
    CLIENT_URL="https://[$IPV6_SERVER]:$port$path" \
    HTTP_SERVER_EXTRA="$server_extra" \
    HTTP_CLIENT_EXTRA="$client_extra -max-retries 0" \
    NO_PROXY='*' no_proxy='*' \
    ROUNDS=1 CONC="$MATRIX_CONC" REQS="$MATRIX_REQS" WARMUP_REQS=0 \
    LOG_DIR="$BASE_LOG_DIR/$label" \
    bash "$SCRIPT_DIR/run_http_soak_fastpath.sh"
}

run_http_case tls-http1 8443 / \
    '-tls' '-insecure -http2=false -require-proto HTTP/1.1'
run_http_case tls-http2 8444 / \
    '-tls' '-insecure -http2=true -require-proto HTTP/2.0'

echo "[protocol-matrix] HTTP/2 request cancellation"
HTTP_NETWORK=tcp6 \
SERVER_ADDR="[$IPV6_SERVER]:8445" \
CLIENT_URL="https://[$IPV6_SERVER]:8445/delay" \
HTTP_SERVER_EXTRA='-tls -delay 2s' \
HTTP_CLIENT_EXTRA='-insecure -http2=true -require-proto HTTP/2.0 -cancel-after 100ms -max-retries 0' \
NO_PROXY='*' no_proxy='*' \
ROUNDS=1 CONC="$MATRIX_CONC" REQS=1 WARMUP_REQS=0 \
LOG_DIR="$BASE_LOG_DIR/http2-cancel" \
bash "$SCRIPT_DIR/run_http_soak_fastpath.sh"

echo "[protocol-matrix] IPv6 gRPC over HTTP/2"
GRPC_NETWORK=tcp6 \
SERVER_ADDR="[$IPV6_SERVER]:50051" \
CLIENT_ADDR="[$IPV6_SERVER]:50051" \
GRPC_CONC="$MATRIX_CONC" GRPC_REQS="$MATRIX_REQS" \
LOG_DIR="$BASE_LOG_DIR/grpc6" \
bash "$SCRIPT_DIR/run_grpc_fastpath.sh"

echo "[protocol-matrix] OK"
