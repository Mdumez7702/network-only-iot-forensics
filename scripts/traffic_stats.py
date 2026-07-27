#!/usr/bin/env python3
"""
Part 3 - Traffic analysis: full graph/table set.

Usage: python3 traffic_stats.py <device> <full.csv> <figures_dir> <tables_dir>

Produces (all PNG @300dpi + SVG, all with title/axis labels):
  protocol_distribution, packet_size_histogram, packets_per_second,
  packets_per_minute, traffic_volume_over_time, flow_duration_histogram,
  tcp_flags_distribution, udp_port_distribution, top_destination_ports,
  top_source_ports, inter_arrival_times, conversation_heatmap,
  top_endpoints, top_conversations, internal_vs_external_traffic

Tables (CSV):
  top_endpoints, top_conversations, top_talkers, flow_summary,
  internal_external_split
"""
import sys
import ipaddress
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

PROTO_MAP = {"1": "ICMP", "6": "TCP", "17": "UDP", "2": "IGMP"}
plt.rcParams.update({"figure.dpi": 150, "savefig.dpi": 300, "font.size": 10})


def save(fig, figures_dir, name):
    fig.savefig(f"{figures_dir}/{name}.png", dpi=300, bbox_inches="tight")
    fig.savefig(f"{figures_dir}/{name}.svg", bbox_inches="tight")
    plt.close(fig)


def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except (ValueError, TypeError):
        return None


def load(csv_path):
    df = pd.read_csv(csv_path, dtype=str)
    df["frame.time_epoch"] = pd.to_numeric(df["frame.time_epoch"], errors="coerce")
    df["frame.len"] = pd.to_numeric(df["frame.len"], errors="coerce")
    df["ip.proto_name"] = df["ip.proto"].map(lambda x: PROTO_MAP.get(str(x), str(x) if pd.notna(x) else "Other/L2"))
    df = df.dropna(subset=["frame.time_epoch"]).sort_values("frame.time_epoch")
    df["t0"] = df["frame.time_epoch"] - df["frame.time_epoch"].min()
    return df


def protocol_distribution(df, device, fig_dir, tab_dir):
    counts = df["ip.proto_name"].value_counts()
    counts.to_csv(f"{tab_dir}/{device}_protocol_distribution.csv", header=["packet_count"])
    fig, ax = plt.subplots(figsize=(6, 4))
    counts.plot(kind="bar", ax=ax, color="#4C72B0")
    ax.set_title(f"{device.capitalize()}: Protocol Distribution")
    ax.set_xlabel("Protocol")
    ax.set_ylabel("Packet count")
    save(fig, fig_dir, f"{device}_protocol_distribution")


def packet_size_histogram(df, device, fig_dir):
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.hist(df["frame.len"].dropna(), bins=50, color="#55A868")
    ax.set_title(f"{device.capitalize()}: Packet Size Distribution")
    ax.set_xlabel("Packet length (bytes)")
    ax.set_ylabel("Frequency")
    save(fig, fig_dir, f"{device}_packet_size_histogram")


def packet_rate(df, device, fig_dir, bin_s, label, suffix):
    df = df.copy()
    df["bin"] = (df["t0"] // bin_s) * bin_s
    ts = df.groupby("bin").size()
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(ts.index, ts.values, color="#C44E52")
    ax.set_title(f"{device.capitalize()}: {label}")
    ax.set_xlabel("Seconds since capture start")
    ax.set_ylabel(f"Packets per {bin_s}s")
    save(fig, fig_dir, f"{device}_{suffix}")
    return ts


def traffic_volume(df, device, fig_dir, tab_dir, bin_s=10):
    df = df.copy()
    df["bin"] = (df["t0"] // bin_s) * bin_s
    ts = df.groupby("bin").agg(packets=("frame.len", "count"), bytes=("frame.len", "sum"))
    ts.to_csv(f"{tab_dir}/{device}_traffic_volume_timeline.csv")
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(ts.index, ts["bytes"], color="#8172B2")
    ax.set_title(f"{device.capitalize()}: Traffic Volume Over Time")
    ax.set_xlabel("Seconds since capture start")
    ax.set_ylabel(f"Bytes per {bin_s}s bin")
    save(fig, fig_dir, f"{device}_traffic_volume")
    return ts


def flow_key(row):
    proto = row["ip.proto_name"]
    sport = row.get("tcp.srcport") or row.get("udp.srcport") or ""
    dport = row.get("tcp.dstport") or row.get("udp.dstport") or ""
    a, b = str(row["ip.src"]), str(row["ip.dst"])
    pa, pb = str(sport), str(dport)
    if (a, pa) > (b, pb):
        a, b, pa, pb = b, a, pb, pa
    return f"{proto}|{a}:{pa}<->{b}:{pb}"


def flow_analysis(df, device, fig_dir, tab_dir):
    d = df.dropna(subset=["ip.src", "ip.dst"]).copy()
    d["flow"] = d.apply(flow_key, axis=1)
    flows = d.groupby("flow").agg(
        start=("frame.time_epoch", "min"),
        end=("frame.time_epoch", "max"),
        packets=("frame.len", "count"),
        bytes=("frame.len", "sum"),
    )
    flows["duration_s"] = flows["end"] - flows["start"]
    flows = flows.sort_values("bytes", ascending=False)
    flows.to_csv(f"{tab_dir}/{device}_flow_summary.csv")

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.hist(flows["duration_s"].clip(upper=flows["duration_s"].quantile(0.99)), bins=40, color="#CCB974")
    ax.set_title(f"{device.capitalize()}: Flow Duration Distribution")
    ax.set_xlabel("Flow duration (s)")
    ax.set_ylabel("Number of flows")
    save(fig, fig_dir, f"{device}_flow_duration_histogram")

    # Inter-arrival times for the single largest flow (most forensically meaningful)
    if len(flows) and flows["packets"].iloc[0] > 5:
        top_flow_name = flows.index[0]
        times = d[d["flow"] == top_flow_name]["frame.time_epoch"].sort_values()
        iat = times.diff().dropna()
        iat = iat[iat < iat.quantile(0.99)] if len(iat) > 10 else iat
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.hist(iat, bins=50, color="#64B5CD")
        ax.set_title(f"{device.capitalize()}: Inter-Arrival Times (largest flow: {top_flow_name[:40]})")
        ax.set_xlabel("Inter-arrival time (s)")
        ax.set_ylabel("Frequency")
        save(fig, fig_dir, f"{device}_inter_arrival_times")
    return flows


def tcp_flags(df, device, fig_dir, tab_dir):
    flags = df["tcp.flags.str"].dropna()
    if flags.empty:
        return
    counts = flags.value_counts().head(15)
    counts.to_csv(f"{tab_dir}/{device}_tcp_flags_distribution.csv", header=["packet_count"])
    fig, ax = plt.subplots(figsize=(8, 4))
    counts.plot(kind="bar", ax=ax, color="#937860")
    ax.set_title(f"{device.capitalize()}: TCP Flag Combinations")
    ax.set_xlabel("Flag combination")
    ax.set_ylabel("Packet count")
    plt.xticks(rotation=45, ha="right")
    save(fig, fig_dir, f"{device}_tcp_flags_distribution")


def port_distribution(df, device, fig_dir, tab_dir):
    dports = pd.concat([df["tcp.dstport"], df["udp.dstport"]]).dropna()
    sports = pd.concat([df["tcp.srcport"], df["udp.srcport"]]).dropna()
    for series, name, title in [(dports, "destination", "Top Destination Ports"),
                                  (sports, "source", "Top Source Ports")]:
        counts = series.value_counts().head(15)
        counts.to_csv(f"{tab_dir}/{device}_top_{name}_ports.csv", header=["packet_count"])
        fig, ax = plt.subplots(figsize=(7, 4))
        counts.plot(kind="bar", ax=ax, color="#DA8BC3")
        ax.set_title(f"{device.capitalize()}: {title}")
        ax.set_xlabel("Port")
        ax.set_ylabel("Packet count")
        save(fig, fig_dir, f"{device}_top_{name}_ports")

    udp = df[df["ip.proto_name"] == "UDP"]
    udp_ports = udp["udp.dstport"].dropna().value_counts().head(15)
    if not udp_ports.empty:
        udp_ports.to_csv(f"{tab_dir}/{device}_udp_port_distribution.csv", header=["packet_count"])
        fig, ax = plt.subplots(figsize=(7, 4))
        udp_ports.plot(kind="bar", ax=ax, color="#8C8C8C")
        ax.set_title(f"{device.capitalize()}: UDP Destination Port Distribution")
        ax.set_xlabel("UDP port")
        ax.set_ylabel("Packet count")
        save(fig, fig_dir, f"{device}_udp_port_distribution")


def endpoints_and_conversations(df, device, fig_dir, tab_dir, n=15):
    d = df.dropna(subset=["ip.src", "ip.dst"])
    convo = d.groupby(["ip.src", "ip.dst"]).agg(
        packets=("frame.len", "count"), bytes=("frame.len", "sum")
    ).sort_values("bytes", ascending=False)
    convo.to_csv(f"{tab_dir}/{device}_top_conversations.csv")

    fig, ax = plt.subplots(figsize=(8, 5))
    top = convo.head(n)
    labels = [f"{a}\n->{b}" for a, b in top.index]
    ax.barh(labels[::-1], top["bytes"].values[::-1], color="#4C72B0")
    ax.set_title(f"{device.capitalize()}: Top {n} Conversations by Bytes")
    ax.set_xlabel("Bytes")
    save(fig, fig_dir, f"{device}_top_conversations")

    # Endpoints (top talkers): total bytes sent+received per IP
    sent = d.groupby("ip.src")["frame.len"].sum()
    recv = d.groupby("ip.dst")["frame.len"].sum()
    endpoints = pd.concat([sent, recv], axis=1, keys=["bytes_sent", "bytes_received"]).fillna(0)
    endpoints["total_bytes"] = endpoints["bytes_sent"] + endpoints["bytes_received"]
    endpoints = endpoints.sort_values("total_bytes", ascending=False)
    endpoints.to_csv(f"{tab_dir}/{device}_top_endpoints_talkers.csv")

    fig, ax = plt.subplots(figsize=(8, 5))
    top_e = endpoints.head(n)
    ax.barh(top_e.index[::-1], top_e["total_bytes"].values[::-1], color="#55A868")
    ax.set_title(f"{device.capitalize()}: Top {n} Endpoints (Talkers) by Total Bytes")
    ax.set_xlabel("Total bytes")
    save(fig, fig_dir, f"{device}_top_endpoints")

    # Conversation heatmap for top-N endpoints
    top_ips = endpoints.head(min(n, 10)).index.tolist()
    mat = pd.DataFrame(0, index=top_ips, columns=top_ips, dtype=float)
    sub = convo.reset_index()
    sub = sub[sub["ip.src"].isin(top_ips) & sub["ip.dst"].isin(top_ips)]
    for _, row in sub.iterrows():
        mat.loc[row["ip.src"], row["ip.dst"]] = row["bytes"]
    fig, ax = plt.subplots(figsize=(7, 6))
    im = ax.imshow(mat.values, cmap="viridis")
    ax.set_xticks(range(len(top_ips))); ax.set_xticklabels(top_ips, rotation=90, fontsize=7)
    ax.set_yticks(range(len(top_ips))); ax.set_yticklabels(top_ips, fontsize=7)
    ax.set_title(f"{device.capitalize()}: Conversation Heatmap (bytes, top endpoints)")
    fig.colorbar(im, ax=ax, label="Bytes")
    save(fig, fig_dir, f"{device}_conversation_heatmap")

    return endpoints, convo


def internal_external(df, device, fig_dir, tab_dir):
    d = df.dropna(subset=["ip.src", "ip.dst"]).copy()
    d["src_private"] = d["ip.src"].map(is_private)
    d["dst_private"] = d["ip.dst"].map(is_private)

    def classify(row):
        if row["src_private"] and row["dst_private"]:
            return "internal (LAN-to-LAN)"
        if row["src_private"] and row["dst_private"] is False:
            return "external (outbound to cloud)"
        if row["src_private"] is False and row["dst_private"]:
            return "external (inbound from cloud)"
        return "other/unclassified"

    d["traffic_scope"] = d.apply(classify, axis=1)
    counts = d["traffic_scope"].value_counts()
    counts.to_csv(f"{tab_dir}/{device}_internal_external_split.csv", header=["packet_count"])

    fig, ax = plt.subplots(figsize=(6, 4))
    counts.plot(kind="pie", ax=ax, autopct="%1.1f%%", ylabel="")
    ax.set_title(f"{device.capitalize()}: Internal vs. External Traffic")
    save(fig, fig_dir, f"{device}_internal_vs_external")

    cloud_ips = sorted(set(d[d["traffic_scope"].str.startswith("external")]["ip.dst"]).union(
        set(d[d["traffic_scope"].str.startswith("external")]["ip.src"])) - set(d[d["src_private"] == True]["ip.src"]))
    return counts


def main():
    device, csv_path, fig_dir, tab_dir = sys.argv[1:5]
    df = load(csv_path)
    print(f"[{device}] {len(df)} packets loaded for traffic_stats")

    protocol_distribution(df, device, fig_dir, tab_dir)
    packet_size_histogram(df, device, fig_dir)
    packet_rate(df, device, fig_dir, 1, "Packets per Second", "packets_per_second")
    packet_rate(df, device, fig_dir, 60, "Packets per Minute", "packets_per_minute")
    traffic_volume(df, device, fig_dir, tab_dir)
    flow_analysis(df, device, fig_dir, tab_dir)
    tcp_flags(df, device, fig_dir, tab_dir)
    port_distribution(df, device, fig_dir, tab_dir)
    endpoints_and_conversations(df, device, fig_dir, tab_dir)
    internal_external(df, device, fig_dir, tab_dir)
    print(f"[{device}] traffic_stats complete")


if __name__ == "__main__":
    main()
