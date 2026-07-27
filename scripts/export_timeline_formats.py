#!/usr/bin/env python3
"""
Part 8 - Export the forensic timeline in CSV (already produced by
activity_engine.py), Excel, Markdown and PNG formats.

Usage: python3 export_timeline_formats.py <device> <results_dir>
"""
import sys
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def main():
    device, res_dir = sys.argv[1:3]
    df = pd.read_csv(f"{res_dir}/{device}_forensic_timeline.csv")

    df.to_excel(f"{res_dir}/{device}_forensic_timeline.xlsx", index=False, engine="openpyxl")

    display_cols = ["event_id", "time_s", "evidence", "protocols", "likely_activity", "confidence"]
    with open(f"{res_dir}/{device}_forensic_timeline.md", "w") as f:
        f.write(f"# Forensic Timeline: {device.capitalize()}\n\n")
        f.write(df[display_cols].to_markdown(index=False))
        f.write("\n")

    fig_h = max(3, 0.28 * len(df) + 1)
    fig, ax = plt.subplots(figsize=(16, fig_h))
    ax.axis("off")
    ax.set_title(f"{device.capitalize()}: Forensic Timeline", fontsize=13, fontweight="bold", loc="left")
    color_map = {"High": "#DFF0D8", "Medium": "#FCF8E3", "Low": "#F2DEDE"}
    cell_colors = [[color_map.get(row["confidence"], "white")] * len(display_cols) for _, row in df.iterrows()]
    table = ax.table(
        cellText=df[display_cols].astype(str).apply(lambda c: c.str.slice(0, 60)).values,
        colLabels=display_cols, loc="center", cellLoc="left", cellColours=cell_colors,
    )
    table.auto_set_font_size(False)
    table.set_fontsize(6.5)
    table.scale(1, 1.15)
    fig.savefig(f"{res_dir}/{device}_forensic_timeline.png", dpi=200, bbox_inches="tight")
    plt.close(fig)

    print(f"[{device}] Timeline exported: .xlsx, .md, .png (in addition to existing .csv)")


if __name__ == "__main__":
    main()
