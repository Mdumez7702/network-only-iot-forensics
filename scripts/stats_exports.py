#!/usr/bin/env python3
"""
Part 11 - Screenshots substitute.

This project was produced in a non-interactive session with no GUI
automation tool available to drive the Wireshark application, and the
capture host's display belongs to the investigator's live desktop
session, so scripting mouse/keyboard control over it was avoided as
unnecessarily invasive. Rather than fabricate screenshots, this module
exports the equivalent evidentiary content Wireshark's Statistics menu
would show (Protocol Hierarchy, Conversations, Endpoints) directly via
tshark, and renders each as a captioned, monospace figure. The IO Graph
equivalent is the packets-per-second figure already produced by
traffic_stats.py. Genuine Wireshark GUI screenshots (Follow TCP Stream,
colourised packet list, etc.) can be captured manually by the
investigator in a few minutes using the prepared pcaps in pcaps/ if the
dissertation requires the literal application chrome.

Usage: python3 stats_exports.py <device> <pcap> <screenshots_dir>
"""
import sys
import subprocess
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def render_text_figure(text, title, out_path_base, figsize=(9, None)):
    lines = text.rstrip().splitlines()
    height = max(2.5, 0.19 * len(lines) + 1)
    fig, ax = plt.subplots(figsize=(figsize[0], height))
    ax.axis("off")
    ax.set_title(title, fontsize=12, fontweight="bold", loc="left")
    ax.text(0.01, 0.98, "\n".join(lines), family="monospace", fontsize=7.2,
            va="top", ha="left", transform=ax.transAxes)
    fig.savefig(f"{out_path_base}.png", dpi=300, bbox_inches="tight")
    fig.savefig(f"{out_path_base}.svg", bbox_inches="tight")
    plt.close(fig)


def run_tshark_stat(pcap, z_arg):
    return subprocess.run(
        ["tshark", "-r", pcap, "-q", "-z", z_arg],
        capture_output=True, text=True,
    ).stdout


def main():
    device, pcap, out_dir = sys.argv[1:4]

    phs = run_tshark_stat(pcap, "io,phs")
    with open(f"{out_dir}/{device}_protocol_hierarchy.txt", "w") as f:
        f.write(phs)
    render_text_figure(phs, f"{device.capitalize()}: Protocol Hierarchy Statistics (tshark -z io,phs)",
                        f"{out_dir}/{device}_protocol_hierarchy")

    conv = run_tshark_stat(pcap, "conv,ip")
    conv_lines = conv.splitlines()
    # Trim to header + top 20 conversations to keep the figure readable
    trimmed = "\n".join(conv_lines[:5] + conv_lines[5:25])
    with open(f"{out_dir}/{device}_conversations.txt", "w") as f:
        f.write(conv)
    render_text_figure(trimmed, f"{device.capitalize()}: IP Conversations (tshark -z conv,ip, top 20)",
                        f"{out_dir}/{device}_conversations")

    endpoints = run_tshark_stat(pcap, "endpoints,ip")
    ep_lines = endpoints.splitlines()
    trimmed_ep = "\n".join(ep_lines[:5] + ep_lines[5:25])
    with open(f"{out_dir}/{device}_endpoints.txt", "w") as f:
        f.write(endpoints)
    render_text_figure(trimmed_ep, f"{device.capitalize()}: IP Endpoints (tshark -z endpoints,ip, top 20)",
                        f"{out_dir}/{device}_endpoints")

    print(f"[{device}] Statistics exports written to {out_dir}/")


if __name__ == "__main__":
    main()
