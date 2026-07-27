#!/usr/bin/env python3
"""
Part 6 - Flow/session analysis: idle vs. burst vs. heartbeat segmentation.

For the dominant flows in a capture, examines inter-arrival time
regularity to distinguish:
  - heartbeat/periodic traffic: low coefficient of variation in
    inter-arrival times (device checking in at a roughly fixed interval)
  - burst traffic: short windows of high packet-rate activity that stand
    out sharply (z-score > threshold) from the capture's baseline rate
  - idle traffic: baseline low-rate background communication

Usage: python3 flow_periodicity.py <device> <full.csv> <figures_dir> <tables_dir>
"""
import sys
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

PROTO_MAP = {"1": "ICMP", "6": "TCP", "17": "UDP"}


def flow_key(row):
    proto = PROTO_MAP.get(str(row["ip.proto"]), str(row["ip.proto"]))
    sport = row.get("tcp.srcport") if pd.notna(row.get("tcp.srcport")) else row.get("udp.srcport")
    dport = row.get("tcp.dstport") if pd.notna(row.get("tcp.dstport")) else row.get("udp.dstport")
    a, b = str(row["ip.src"]), str(row["ip.dst"])
    pa, pb = str(sport), str(dport)
    if (a, pa) > (b, pb):
        a, b, pa, pb = b, a, pb, pa
    return f"{proto}|{a}:{pa}<->{b}:{pb}"


def main():
    device, csv_path, fig_dir, tab_dir = sys.argv[1:5]
    df = pd.read_csv(csv_path, dtype=str)
    df["frame.time_epoch"] = pd.to_numeric(df["frame.time_epoch"], errors="coerce")
    df = df.dropna(subset=["frame.time_epoch", "ip.src", "ip.dst"]).sort_values("frame.time_epoch")
    df["flow"] = df.apply(flow_key, axis=1)

    results = []
    for flow, g in df.groupby("flow"):
        if len(g) < 6:
            continue
        times = g["frame.time_epoch"].sort_values().values
        iat = np.diff(times)
        if iat.mean() == 0:
            continue
        cv = iat.std() / iat.mean()  # coefficient of variation
        classification = "heartbeat/periodic" if cv < 0.5 and iat.mean() > 1 else \
                          "bursty/irregular" if cv >= 0.5 else "continuous/high-rate"
        results.append({
            "flow": flow, "packets": len(g),
            "mean_interval_s": round(iat.mean(), 3), "cv": round(cv, 3),
            "duration_s": round(times[-1] - times[0], 1),
            "classification": classification,
        })

    periodicity = pd.DataFrame(results).sort_values("packets", ascending=False)
    periodicity.to_csv(f"{tab_dir}/{device}_flow_periodicity.csv", index=False)

    # Session-level (connection-event) periodicity: individual TCP/UDP flows are
    # often too short-lived to show intra-flow periodicity, so the real heartbeat
    # signal is in how often *new* connections open to the same remote endpoint.
    flow_starts = df.groupby("flow").agg(
        start=("frame.time_epoch", "min"),
        remote_ip=("ip.dst", "first"),
        proto=("ip.proto", lambda s: PROTO_MAP.get(str(s.iloc[0]), str(s.iloc[0]))),
    )
    session_results = []
    for remote_ip, g in flow_starts.groupby("remote_ip"):
        starts = np.sort(g["start"].values)
        if len(starts) < 4:
            continue
        iat = np.diff(starts)
        if iat.mean() == 0:
            continue
        cv = iat.std() / iat.mean()
        classification = "heartbeat/periodic (session-level)" if cv < 0.5 else "irregular connection pattern"
        session_results.append({
            "remote_endpoint": remote_ip, "num_connections": len(starts),
            "mean_interval_s": round(iat.mean(), 2), "cv": round(cv, 3),
            "classification": classification,
        })
    session_periodicity = pd.DataFrame(session_results)
    if not session_periodicity.empty:
        session_periodicity = session_periodicity.sort_values("num_connections", ascending=False)
    session_periodicity.to_csv(f"{tab_dir}/{device}_session_periodicity.csv", index=False)

    # Overall packet-rate baseline + burst/idle/heartbeat segmentation (10s bins)
    t0 = df["frame.time_epoch"].min()
    df["bin"] = ((df["frame.time_epoch"] - t0) // 10) * 10
    rate = df.groupby("bin").size()
    mean, std = rate.mean(), rate.std()
    if std == 0 or pd.isna(std):
        std = 1
    z = (rate - mean) / std
    state = pd.cut(z, bins=[-np.inf, -0.5, 1.5, np.inf], labels=["idle", "baseline", "burst"])
    segmentation = pd.DataFrame({"packets": rate, "z_score": z, "state": state})
    segmentation.to_csv(f"{tab_dir}/{device}_traffic_state_segmentation.csv")

    fig, ax = plt.subplots(figsize=(10, 4))
    colors = segmentation["state"].map({"idle": "#8C8C8C", "baseline": "#4C72B0", "burst": "#C44E52"})
    ax.bar(segmentation.index, segmentation["packets"], color=colors, width=9)
    ax.set_title(f"{device.capitalize()}: Traffic State Segmentation (idle / baseline / burst)")
    ax.set_xlabel("Seconds since capture start")
    ax.set_ylabel("Packets per 10s bin")
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=c, label=l) for l, c in
                        [("idle", "#8C8C8C"), ("baseline", "#4C72B0"), ("burst", "#C44E52")]])
    fig.savefig(f"{fig_dir}/{device}_traffic_state_segmentation.png", dpi=300, bbox_inches="tight")
    fig.savefig(f"{fig_dir}/{device}_traffic_state_segmentation.svg", bbox_inches="tight")
    plt.close(fig)

    n_heartbeat = (periodicity["classification"] == "heartbeat/periodic").sum() if len(periodicity) else 0
    n_session_heartbeat = (session_periodicity["classification"] == "heartbeat/periodic (session-level)").sum() \
        if len(session_periodicity) else 0
    n_burst_bins = int((segmentation["state"] == "burst").sum())
    print(f"[{device}] {len(periodicity)} flows analysed ({n_heartbeat} intra-flow periodic); "
          f"{len(session_periodicity)} remote endpoints with >=4 connections "
          f"({n_session_heartbeat} session-level heartbeat); "
          f"{n_burst_bins} burst bins / {len(segmentation)} total bins")


if __name__ == "__main__":
    main()
