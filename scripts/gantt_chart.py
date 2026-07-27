#!/usr/bin/env python3
"""
Project Gantt chart (1 July - 1 August), planned vs. actual, for Appendix B.

Phase timings reflect the account given in Dissertation.md Section 5.3:
literature review completed close to schedule; implementation expanded
considerably beyond the original estimate (particularly the JA3/periodicity
stage, owing to the session-level periodicity redesign and tshark's
field-export limitation); evaluation likewise expanded once the ground-truth
gap reshaped it from a metrics-based to a confidence-scoring approach.

Note: this script is project-management documentation tooling for the
dissertation and presentation deliverables (Dissertation/Appendices.md
Appendix B; Presentations/*), not part of the forensic analysis pipeline --
it is intentionally not invoked by scripts/run_all.sh or documented in
README.md.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
import datetime as dt

START = dt.date(2026, 7, 1)

def d(day):
    return (dt.date(2026, 7, day) - START).days if day <= 31 else (dt.date(2026, 8, day - 31) - START).days

# (label, planned_start, planned_end, actual_start, actual_end)
phases = [
    ("Literature review & background research",           d(1),  d(6),  d(1),  d(6)),
    ("Dataset selection & evidence verification",          d(6),  d(9),  d(6),  d(9)),
    ("Pipeline implementation: extraction, device ID,\nDNS/TLS analysis", d(9),  d(15), d(9),  d(17)),
    ("Advanced analysis: JA3, session periodicity,\ndecision engine",     d(15), d(21), d(17), d(25)),
    ("Evaluation & results analysis",                      d(21), d(26), d(25), d(29)),
    ("Write-up & finalisation",                             d(26), d(32), d(29), d(32)),
]

fig, ax = plt.subplots(figsize=(9, 4.2))
bar_h = 0.32
colors_plan, colors_act = "#B0BEC5", "#4C72B0"

for i, (label, ps, pe, aslot, aend) in enumerate(phases):
    y = len(phases) - i
    ax.broken_barh([(ps, pe - ps)], (y - 0.38, bar_h), facecolors=colors_plan)
    ax.broken_barh([(aslot, aend - aslot)], (y - 0.38 - bar_h - 0.04, bar_h), facecolors=colors_act)
    ax.text(-1, y - 0.38 - bar_h / 2 - 0.02, label, ha="right", va="center", fontsize=8)

ax.set_xlim(0, 32)
ax.set_ylim(0, len(phases) + 1)
xticks = list(range(0, 33, 7))
xticklabels = [(START + dt.timedelta(days=t)).strftime("%d %b") for t in xticks]
ax.set_xticks(xticks)
ax.set_xticklabels(xticklabels)
ax.set_yticks([])
ax.set_title("Project Timeline: Planned vs. Actual (1 July – 1 August)", fontsize=12, fontweight="bold")
ax.legend(handles=[Patch(color=colors_plan, label="Planned"), Patch(color=colors_act, label="Actual")],
          loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=2, frameon=False)
ax.spines[["top", "right", "left"]].set_visible(False)
ax.grid(axis="x", linestyle=":", alpha=0.5)

fig.tight_layout()
for ext in ("png", "svg", "pdf"):
    kwargs = {"dpi": 300} if ext == "png" else {}
    fig.savefig(f"/home/zubair/nofr-project/IoT_Forensics/Methodology/gantt_chart.{ext}",
                bbox_inches="tight", **kwargs)
plt.close(fig)
print("Gantt chart written to Methodology/gantt_chart.{png,svg,pdf}")
