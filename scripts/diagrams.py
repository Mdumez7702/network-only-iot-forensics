#!/usr/bin/env python3
"""
Part 1 - Methodology flowchart, and
Part 17 - Proposed Network-Only Forensic Reconstruction Framework diagram.

Rendered with matplotlib (no external graphviz dependency), exported as
PNG (300dpi), SVG and PDF.

Usage: python3 diagrams.py <methodology_dir>
"""
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch


def draw_flowchart(steps, title, out_path_base, box_color="#4C72B0", text_color="white", width=6.5):
    n = len(steps)
    box_h = 0.8
    gap = 0.55
    fig_h = n * (box_h + gap) + 0.5
    fig, ax = plt.subplots(figsize=(width, fig_h * 0.62))
    ax.set_xlim(0, width)
    ax.set_ylim(0, fig_h)
    ax.axis("off")
    ax.set_title(title, fontsize=13, fontweight="bold", pad=14)

    y = fig_h - 0.6
    centers = []
    for step in steps:
        box = FancyBboxPatch((0.4, y - box_h), width - 0.8, box_h,
                              boxstyle="round,pad=0.08,rounding_size=0.12",
                              linewidth=1.2, edgecolor="#2C3E50", facecolor=box_color)
        ax.add_patch(box)
        ax.text(width / 2, y - box_h / 2, step, ha="center", va="center",
                 fontsize=9.5, color=text_color, fontweight="medium", wrap=True)
        centers.append(y - box_h / 2)
        y -= (box_h + gap)

    for i in range(len(centers) - 1):
        arrow = FancyArrowPatch((width / 2, centers[i] - box_h / 2 - 0.02),
                                 (width / 2, centers[i + 1] + box_h / 2 + 0.02),
                                 arrowstyle="-|>", mutation_scale=14, color="#2C3E50", linewidth=1.3)
        ax.add_patch(arrow)

    fig.tight_layout()
    for ext in ("png", "svg", "pdf"):
        kwargs = {"dpi": 300} if ext == "png" else {}
        fig.savefig(f"{out_path_base}.{ext}", bbox_inches="tight", **kwargs)
    plt.close(fig)


def main():
    out_dir = sys.argv[1]

    methodology_steps = [
        "PCAP Acquisition\n(public IoT-23 benign device captures)",
        "Evidence Verification\n(hash/size integrity, source documentation review)",
        "Packet Extraction\n(tshark field extraction to structured CSV)",
        "Flow Reconstruction\n(5-tuple session grouping, duration/frequency)",
        "Protocol Identification\n(L3/L4 protocol mix, TCP flags, port usage)",
        "DNS Analysis\n(query domains, cloud/CDN classification)",
        "TLS/SNI Analysis\n(handshake versions, JA3 fingerprinting, certificates)",
        "Conversation Analysis\n(top talkers, endpoints, conversation heatmap)",
        "Traffic Burst Detection\n(z-score packet-rate segmentation)",
        "Behaviour Reconstruction\n(rule-based decision engine)",
        "Timeline Reconstruction\n(time-ordered forensic event log)",
        "Evaluation\n(confidence scoring; accuracy vs. ground truth where available)",
    ]
    draw_flowchart(methodology_steps, "Forensic Methodology: Network-Only IoT Activity Reconstruction",
                    f"{out_dir}/methodology_flowchart", box_color="#4C72B0")

    framework_steps = [
        "PCAP Evidence\n(public dataset, any smart-home IoT device)",
        "Evidence Verification\n(integrity check, provenance, licence review)",
        "Packet Parsing\n(protocol dissection, structured field extraction)",
        "Protocol Identification\n(L3/L4 mix, TCP flags, DNS/TLS presence)",
        "Flow Reconstruction\n(session grouping, duration, frequency)",
        "Traffic Feature Extraction\n(rate, volume, periodicity, JA3, DNS/SNI classification)",
        "Behaviour Analysis\n(burst/idle/heartbeat state segmentation)",
        "Decision Engine\n(explicit rule set mapping features -> candidate activities)",
        "Confidence Assessment\n(High/Medium/Low per declared scoring policy)",
        "Activity Reconstruction\n(candidate activity + reasoning per event)",
        "Forensic Timeline\n(time-ordered, exportable event log)",
        "Investigation Report\n(figures, tables, interpretation, limitations)",
    ]
    draw_flowchart(framework_steps, "Proposed Network-Only Forensic Reconstruction Framework",
                    f"{out_dir}/proposed_framework_diagram", box_color="#55A868")

    print("Diagrams written:", f"{out_dir}/methodology_flowchart.{{png,svg,pdf}}",
          f"{out_dir}/proposed_framework_diagram.{{png,svg,pdf}}")


if __name__ == "__main__":
    main()
