#!/bin/bash
# Extract per-packet fields from a pcap into CSV using tshark.
# Usage: ./extract_fields.sh <input.pcap> <output.csv>

set -euo pipefail

IN="$1"
OUT="$2"

tshark -r "$IN" \
    -T fields \
    -E separator=, -E quote=d -E header=y \
    -e frame.number \
    -e frame.time_epoch \
    -e eth.src \
    -e eth.dst \
    -e ip.src \
    -e ip.dst \
    -e ip.proto \
    -e tcp.srcport \
    -e tcp.dstport \
    -e udp.srcport \
    -e udp.dstport \
    -e frame.len \
    -e dns.qry.name \
    -e tls.handshake.extensions_server_name \
    -e http.host \
    -e http.request.uri \
    > "$OUT"

echo "Wrote $(wc -l < "$OUT") rows to $OUT"
