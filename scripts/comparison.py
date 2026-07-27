#!/usr/bin/env python3
"""
Part 10 - Cross-device comparison: Echo vs. Hue vs. Somfy.

Reads each device's Tables/ and Results/ outputs and produces comparison
tables + charts covering protocol mix, traffic volume, cloud behaviour,
communication frequency, burst behaviour, periodic behaviour and
background traffic share.

Usage: python3 comparison.py <tables_dir> <results_dir> <figures_dir>
"""
import sys
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

DEVICES = ["echo", "hue", "somfy"]


def safe_read(path, **kwargs):
    try:
        return pd.read_csv(path, **kwargs)
    except (FileNotFoundError, pd.errors.EmptyDataError):
        return pd.DataFrame()


def main():
    tab_dir, res_dir, fig_dir = sys.argv[1:4]
    rows = []
    proto_rows = {}

    for d in DEVICES:
        proto = safe_read(f"{tab_dir}/{d}_protocol_distribution.csv", index_col=0)
        proto_rows[d] = proto.iloc[:, 0] if not proto.empty else pd.Series(dtype=float)

        seg = safe_read(f"{tab_dir}/{d}_traffic_state_segmentation.csv")
        burst_bins = int((seg["state"] == "burst").sum()) if not seg.empty else 0
        idle_bins = int((seg["state"] == "idle").sum()) if not seg.empty else 0
        total_bins = len(seg) if not seg.empty else 0

        sess = safe_read(f"{tab_dir}/{d}_session_periodicity.csv")
        n_heartbeat = int((sess["classification"] == "heartbeat/periodic (session-level)").sum()) if not sess.empty else 0

        dns_class = safe_read(f"{tab_dir}/{d}_dns_cloud_classification.csv", index_col=0)
        n_cloud_categories = int((dns_class.index != "Unclassified / other").sum()) if not dns_class.empty else 0

        ja3 = safe_read(f"{tab_dir}/{d}_ja3_fingerprints.csv")
        n_ja3 = ja3["ja3_hash"].nunique() if not ja3.empty else 0

        timeline = safe_read(f"{res_dir}/{d}_forensic_timeline.csv")
        total_events = len(timeline)
        high_conf = int((timeline["confidence"] == "High").sum()) if not timeline.empty else 0

        rows.append({
            "device": d,
            "total_packets": int(proto.iloc[:, 0].sum()) if not proto.empty else 0,
            "dominant_protocol": proto.iloc[:, 0].idxmax() if not proto.empty else "n/a",
            "burst_bin_pct": round(100 * burst_bins / total_bins, 1) if total_bins else 0,
            "idle_bin_pct": round(100 * idle_bins / total_bins, 1) if total_bins else 0,
            "session_heartbeat_endpoints": n_heartbeat,
            "distinct_cloud_categories": n_cloud_categories,
            "distinct_ja3_fingerprints": n_ja3,
            "reconstructed_events": total_events,
            "high_confidence_events": high_conf,
        })

    comparison = pd.DataFrame(rows)
    comparison.to_csv(f"{tab_dir}/comparison_device_summary.csv", index=False)
    print(comparison.to_string(index=False))

    # Protocol mix comparison (stacked bar, share of packets)
    proto_df = pd.DataFrame(proto_rows).fillna(0)
    proto_share = proto_df.div(proto_df.sum(axis=0), axis=1) * 100
    proto_share.to_csv(f"{tab_dir}/comparison_protocol_share.csv")

    fig, ax = plt.subplots(figsize=(7, 5))
    proto_share.T.plot(kind="bar", stacked=True, ax=ax,
                        color=["#4C72B0", "#55A868", "#C44E52", "#8172B2", "#CCB974"])
    ax.set_title("Protocol Mix Comparison: Echo vs. Hue vs. Somfy")
    ax.set_ylabel("Share of packets (%)")
    ax.set_xlabel("Device")
    plt.xticks(rotation=0)
    ax.legend(title="Protocol", bbox_to_anchor=(1.02, 1), loc="upper left")
    fig.savefig(f"{fig_dir}/comparison_protocol_mix.png", dpi=300, bbox_inches="tight")
    fig.savefig(f"{fig_dir}/comparison_protocol_mix.svg", bbox_inches="tight")
    plt.close(fig)

    # Burst vs idle vs heartbeat comparison
    fig, ax = plt.subplots(figsize=(7, 5))
    x = range(len(DEVICES))
    ax.bar(x, comparison["burst_bin_pct"], width=0.25, label="Burst bins (%)", color="#C44E52")
    ax.bar([i + 0.25 for i in x], comparison["idle_bin_pct"], width=0.25, label="Idle bins (%)", color="#8C8C8C")
    ax.bar([i + 0.5 for i in x], comparison["session_heartbeat_endpoints"], width=0.25,
           label="Heartbeat endpoints (count)", color="#4C72B0")
    ax.set_xticks([i + 0.25 for i in x])
    ax.set_xticklabels(comparison["device"])
    ax.set_title("Behavioural Comparison: Burst / Idle / Heartbeat")
    ax.legend()
    fig.savefig(f"{fig_dir}/comparison_behaviour.png", dpi=300, bbox_inches="tight")
    fig.savefig(f"{fig_dir}/comparison_behaviour.svg", bbox_inches="tight")
    plt.close(fig)

    # Cloud/CDN category comparison
    all_cats = set()
    cat_data = {}
    for d in DEVICES:
        dc = safe_read(f"{tab_dir}/{d}_dns_cloud_classification.csv", index_col=0)
        cat_data[d] = dc.iloc[:, 0] if not dc.empty else pd.Series(dtype=float)
        all_cats |= set(cat_data[d].index)
    cat_df = pd.DataFrame(cat_data).reindex(sorted(all_cats)).fillna(0)
    cat_df.to_csv(f"{tab_dir}/comparison_cloud_categories.csv")

    fig, ax = plt.subplots(figsize=(9, 5))
    cat_df.plot(kind="bar", ax=ax, color=["#DD8452", "#4C72B0", "#55A868"])
    ax.set_title("Cloud/CDN Contact Categories by Device")
    ax.set_ylabel("DNS/SNI record count")
    plt.xticks(rotation=40, ha="right")
    fig.savefig(f"{fig_dir}/comparison_cloud_categories.png", dpi=300, bbox_inches="tight")
    fig.savefig(f"{fig_dir}/comparison_cloud_categories.svg", bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    main()
