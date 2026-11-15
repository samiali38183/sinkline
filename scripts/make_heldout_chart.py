"""Draw the held-out result chart from bench/heldout/results/<name>/results.json.
Usage: python scripts/make_heldout_chart.py bench/heldout/results/2026-11-14 out.png"""
import json
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

res = json.load(open(sys.argv[1] + "/results.json"))["results"]
tools = [("sinkline", "sinkline", "#1f4e79"), ("bandit", "Bandit 1.9.4", "#c77c0e"), ("semgrep", "Semgrep 1.185.0", "#5a7d2a")]
fig, axes = plt.subplots(1, 2, figsize=(10, 4.2), sharey=True)
for ax, tier, title in ((axes[0], "taint", "Taint classes (219 labeled bugs)"), (axes[1], "property", "Property classes (127 labeled bugs)")):
    for i, (key, label, col) in enumerate(tools):
        t = res[key]["tiers"][tier]
        for j, (m, lo_hi) in enumerate((("recall", "recall_ci95"), ("precision", "precision_ci95"))):
            v, (lo, hi) = t[m], t[lo_hi]
            x = j + (i - 1) * 0.25
            if m == "precision" and t["tp"] == 0:
                ax.text(x, 0.02, "no hits", ha="center", fontsize=8)
                continue
            ax.bar(x, v, 0.23, color=col, label=label if j == 0 else None)
            ax.errorbar(x, v, yerr=[[v - lo], [hi - v]], color="black", capsize=3, lw=1)
            ax.text(x, hi + 0.02, f"{v:.2f}", ha="center", fontsize=9)
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["recall (bugs found)", "precision (findings that are real)"])
    ax.set_title(title, fontsize=11)
    ax.set_ylim(0, 1.12)
    ax.spines[["top", "right"]].set_visible(False)
axes[0].set_ylabel("fraction (bars show 95% intervals)")
h, lab = axes[0].get_legend_handles_labels()
fig.legend(h, lab, frameon=False, loc="lower center", ncol=3)
fig.suptitle("Held-out set: CodeQL Python query tests, labels fixed before any run", fontsize=12)
fig.tight_layout(rect=(0, 0.07, 1, 1))
fig.savefig(sys.argv[2], dpi=160)
