#!/usr/bin/env python3
"""
Network-only IoT activity reconstruction — first-pass analysis.

For a given extracted-fields CSV (see extract_fields.sh), this produces:
  - protocol distribution table + chart
  - top talkers / endpoint conversation table
  - DNS / TLS-SNI query list (identifies cloud services contacted)
  - traffic-volume-over-time chart (used to spot activity bursts)
  - a simple burst-detection pass as a first attempt at activity timeline
    reconstruction (periods of elevated traffic vs. idle/heartbeat baseline)

Usage:
    python3 analyze.py <device_name> <fields.csv> <results_dir> <figures_dir>

Example:
    python3 analyze.py hue results/hue_fields.csv results figures
"""
import sys
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

PROTO_MAP = {"1": "ICMP", "6": "TCP", "17": "UDP"}


def load(csv_path):
    df = pd.read_csv(csv_path, dtype=str)
    df["frame.time_epoch"] = pd.to_numeric(df["frame.time_epoch"], errors="coerce")
    df["frame.len"] = pd.to_numeric(df["frame.len"], errors="coerce")
    df["ip.proto"] = df["ip.proto"].map(lambda x: PROTO_MAP.get(str(x), str(x)))
    df["time"] = pd.to_datetime(df["frame.time_epoch"], unit="s")
    return df.dropna(subset=["frame.time_epoch"])


def protocol_distribution(df, device, results_dir, figures_dir):
    counts = df["ip.proto"].value_counts()
    counts.to_csv(f"{results_dir}/{device}_protocol_distribution.csv", header=["packet_count"])

    plt.figure(figsize=(6, 4))
    counts.plot(kind="bar", color="#4C72B0")
    plt.title(f"{device}: Protocol Distribution")
    plt.ylabel("Packet count")
    plt.tight_layout()
    plt.savefig(f"{figures_dir}/{device}_protocol_distribution.png", dpi=150)
    plt.close()
    return counts


def top_talkers(df, device, results_dir, n=15):
    convo = (
        df.groupby(["ip.src", "ip.dst"])
        .agg(packets=("frame.len", "count"), bytes=("frame.len", "sum"))
        .sort_values("bytes", ascending=False)
        .head(n)
    )
    convo.to_csv(f"{results_dir}/{device}_top_conversations.csv")
    return convo


def dns_tls_queries(df, device, results_dir):
    dns = df["dns.qry.name"].dropna().value_counts()
    sni = df["tls.handshake.extensions_server_name"].dropna().value_counts()
    combined = pd.concat([dns, sni]).groupby(level=0).sum().sort_values(ascending=False)
    combined.to_csv(f"{results_dir}/{device}_dns_sni_hosts.csv", header=["query_count"])
    return combined


def traffic_timeline(df, device, results_dir, figures_dir, bin_seconds=10):
    t0 = df["frame.time_epoch"].min()
    df = df.copy()
    df["bin"] = ((df["frame.time_epoch"] - t0) // bin_seconds) * bin_seconds
    ts = df.groupby("bin").agg(packets=("frame.len", "count"), bytes=("frame.len", "sum"))
    ts.to_csv(f"{results_dir}/{device}_traffic_timeline.csv")

    plt.figure(figsize=(10, 4))
    plt.plot(ts.index, ts["packets"], color="#DD8452")
    plt.title(f"{device}: Packets per {bin_seconds}s bin (activity bursts)")
    plt.xlabel("Seconds since capture start")
    plt.ylabel("Packet count")
    plt.tight_layout()
    plt.savefig(f"{figures_dir}/{device}_traffic_timeline.png", dpi=150)
    plt.close()
    return ts


def detect_bursts(ts, device, results_dir, z_thresh=2.0):
    mean, std = ts["packets"].mean(), ts["packets"].std()
    if std == 0 or pd.isna(std):
        bursts = ts.iloc[0:0]
    else:
        bursts = ts[(ts["packets"] - mean) / std > z_thresh]
    bursts.to_csv(f"{results_dir}/{device}_candidate_activity_bursts.csv")
    return bursts


def main():
    if len(sys.argv) != 5:
        print(__doc__)
        sys.exit(1)
    device, csv_path, results_dir, figures_dir = sys.argv[1:5]

    df = load(csv_path)
    print(f"[{device}] Loaded {len(df)} packets, "
          f"span {df['frame.time_epoch'].max() - df['frame.time_epoch'].min():.1f}s")

    proto = protocol_distribution(df, device, results_dir, figures_dir)
    print(f"[{device}] Protocols:\n{proto}")

    convo = top_talkers(df, device, results_dir)
    print(f"[{device}] Top conversation bytes: {convo['bytes'].iloc[0] if len(convo) else 'n/a'}")

    hosts = dns_tls_queries(df, device, results_dir)
    print(f"[{device}] Distinct DNS/SNI hosts contacted: {len(hosts)}")

    ts = traffic_timeline(df, device, results_dir, figures_dir)
    bursts = detect_bursts(ts, device, results_dir)
    print(f"[{device}] Candidate activity bursts (z>2): {len(bursts)}")

    print(f"[{device}] Done. Results in {results_dir}/, figures in {figures_dir}/")


if __name__ == "__main__":
    main()
