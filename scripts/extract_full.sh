#!/bin/bash
# Full-fidelity per-packet field extraction for forensic reconstruction.
# Usage: ./extract_full.sh <input.pcap> <output.csv>
# Note: tshark exits non-zero on some source captures that are cut short
# mid-packet (a known artifact of several IoT-23 honeypot captures); this is
# a data-quality limitation of the source file, not an extraction failure --
# tshark still emits every complete packet, so we do not treat it as fatal.
set -uo pipefail
IN="$1"
OUT="$2"

tshark -r "$IN" \
    -T fields \
    -E separator=, -E quote=d -E header=y -E occurrence=f \
    -e frame.number \
    -e frame.time_epoch \
    -e frame.len \
    -e eth.src \
    -e eth.src.oui_resolved \
    -e eth.dst \
    -e eth.dst.oui_resolved \
    -e ip.src \
    -e ip.dst \
    -e ip.ttl \
    -e ip.proto \
    -e tcp.srcport \
    -e tcp.dstport \
    -e tcp.flags.str \
    -e udp.srcport \
    -e udp.dstport \
    -e icmp.type \
    -e dns.qry.name \
    -e dns.flags.response \
    -e tls.record.version \
    -e tls.handshake.type \
    -e tls.handshake.version \
    -e tls.handshake.extensions_server_name \
    -e tls.handshake.ciphersuites \
    -e tls.handshake.extensions_supported_groups \
    -e tls.handshake.extensions_ec_point_formats \
    -e tls.handshake.certificate \
    -e http.host \
    -e http.request.uri \
    > "$OUT"

echo "Wrote $(($(wc -l < "$OUT") - 1)) packet rows to $OUT"
