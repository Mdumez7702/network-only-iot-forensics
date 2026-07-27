#!/bin/bash
# Run the complete network-only forensic reconstruction pipeline end to end
# for every device pcap found in pcaps/, then run the cross-device
# comparison stage once at the end.
#
# Usage: ./scripts/run_all.sh
# Expects pcaps/<device>_<capture-name>.pcap for hue, echo and somfy
# (see README.md "Obtaining the Dataset" for how to download these --
# they are not included in this repository).
set -uo pipefail  # not -e: tshark returns non-zero on the known-truncated
                   # Echo capture without this being a pipeline failure;
                   # see README.md "Known Data Quality Note".

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PCAPS="$ROOT/pcaps"
RESULTS="$ROOT/Results"
FIGURES="$ROOT/Figures"
TABLES="$ROOT/Tables"
SCREENSHOTS="$ROOT/Screenshots"
SCRIPTS="$ROOT/scripts"

mkdir -p "$RESULTS" "$FIGURES" "$TABLES" "$SCREENSHOTS"

declare -A DEVICES=(
    [hue]="$PCAPS/hue_2018-10-25.pcap"
    [echo]="$PCAPS/echo_2018-09-21.pcap"
    [somfy]="$PCAPS/somfy_2019-07-03.pcap"
)

for device in "${!DEVICES[@]}"; do
    pcap="${DEVICES[$device]}"
    if [ ! -f "$pcap" ]; then
        echo "Skipping $device: $pcap not found (see README.md to obtain it)"
        continue
    fi
    echo "=== $device ($pcap) ==="
    full_csv="$RESULTS/${device}_full.csv"

    "$SCRIPTS/extract_full.sh" "$pcap" "$full_csv"
    python3 "$SCRIPTS/device_id.py" "$device" "$full_csv" "$TABLES"
    python3 "$SCRIPTS/traffic_stats.py" "$device" "$full_csv" "$FIGURES" "$TABLES"
    python3 "$SCRIPTS/dns_analysis.py" "$device" "$full_csv" "$FIGURES" "$TABLES"
    python3 "$SCRIPTS/tls_analysis.py" "$device" "$pcap" "$full_csv" "$FIGURES" "$TABLES"
    python3 "$SCRIPTS/flow_periodicity.py" "$device" "$full_csv" "$FIGURES" "$TABLES"
    python3 "$SCRIPTS/activity_engine.py" "$device" "$TABLES" "$RESULTS" "$full_csv"
    python3 "$SCRIPTS/stats_exports.py" "$device" "$pcap" "$SCREENSHOTS"
    python3 "$SCRIPTS/export_timeline_formats.py" "$device" "$RESULTS"
    echo
done

echo "=== Cross-device comparison ==="
python3 "$SCRIPTS/comparison.py" "$TABLES" "$RESULTS" "$FIGURES"

echo
echo "Pipeline complete. See Results/, Tables/, Figures/ and Screenshots/."
