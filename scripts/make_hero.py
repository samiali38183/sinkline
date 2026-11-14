"""Render docs/img/hero.png from the saved OWASP BenchmarkPython results.

Every number comes from bench/external/results/<version>/summary.csv (the "taint categories (10)"
rows). Nothing is typed in. Run from the repo root:  python scripts/make_hero.py
Needs matplotlib and Pillow (not runtime dependencies of sinkline).
"""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "bench" / "external" / "results"
SCOPE = "taint categories (10)"

# Shared look across samiali38183 repos: light background, dark text, large type.
TEXT, MUTED, LINE, PANEL = "#111827", "#4b5563", "#d1d5db", "#f3f4f6"
ACCENT = "#1d4ed8"
plt.rcParams["font.family"] = "DejaVu Sans"


def load(version: str, tool: str) -> dict[str, int]:
    with (RES / version / "summary.csv").open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            if row["tool"] == tool and row["category"] == SCOPE:
                return {k: int(row[k]) for k in ("TP", "FN", "FP", "TN")}
    raise SystemExit(f"no {tool} row for {SCOPE} in {version}")


def box(ax, x, y, w, h, fc, ec=LINE, lw=1.5, r=1.2) -> None:
    ax.add_patch(
        FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0,rounding_size={r}", fc=fc, ec=ec, lw=lw)
    )


def main() -> None:
    rows = [
        ("sinkline 0.5.0", "after fixes drawn from this suite", load("v0.5.0", "sinkline"), ACCENT),
        ("sinkline 0.4.1", "before I read this suite's misses", load("v0.4.1", "sinkline"), "#93b4f0"),
        ("Bandit 1.9.4", "default rules", load("v0.5.0", "bandit"), "#4b5563"),
        ("Semgrep 1.185.0", "OSS, registry rules", load("v0.5.0", "semgrep"), "#9ca3af"),
    ]
    real = rows[0][2]["TP"] + rows[0][2]["FN"]
    safe = rows[0][2]["FP"] + rows[0][2]["TN"]

    fig = plt.figure(figsize=(9, 5.5), dpi=200, facecolor="white")
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_xlim(0, 180)
    ax.set_ylim(0, 110)
    ax.axis("off")

    ax.text(6, 101, "Finds more real bugs than Bandit or Semgrep", fontsize=20, fontweight="bold",
            color=TEXT, va="center")
    ax.text(6, 92, f"OWASP BenchmarkPython v0.1, the 10 data-flow categories: {real} vulnerable and "
            f"{safe} safe test cases.", fontsize=11.5, color=MUTED, va="center")

    box(ax, 6, 19, 168, 64, PANEL)
    ax.text(62, 77, "Real bugs found", fontsize=11, fontweight="bold", color=TEXT, va="center")
    ax.text(62, 73, "higher is better", fontsize=9, color=MUTED, va="center")
    ax.text(121, 77, "Safe code wrongly flagged", fontsize=11, fontweight="bold", color=TEXT, va="center")
    ax.text(121, 73, "lower is better", fontsize=9, color=MUTED, va="center")

    scale = 34 / 1.0
    for i, (name, sub, c, col) in enumerate(rows):
        y = 63 - i * 12.5
        ax.text(10, y + 1.2, name, fontsize=11, fontweight="bold", color=TEXT, va="center")
        ax.text(10, y - 2.6, sub, fontsize=8.3, color=MUTED, va="center")
        for x0, num, den in ((62, c["TP"], real), (121, c["FP"], safe)):
            frac = num / den
            box(ax, x0, y - 3.5, scale * frac, 7, col, ec=col, lw=0, r=0.5)
            ax.text(x0 + scale * frac + 1.5, y + 1.2, f"{round(100 * frac)}%", fontsize=13,
                    fontweight="bold", color=TEXT, va="center")
            ax.text(x0 + scale * frac + 1.5, y - 3.4, f"{num} of {den}", fontsize=8.5, color=MUTED,
                    va="center")

    fpr = [round(100 * r[2]["FP"] / safe) for r in rows]
    ax.text(6, 14, f"The cost: more false alarms ({fpr[0]}% against {fpr[2]}% and {fpr[3]}%), and it skips "
            "4 of the suite's 14 categories.", fontsize=10.2, color=TEXT, va="center")
    ax.text(6, 9, "Scored with my own script, not the official one. 0.5.0 was tuned on this suite's failures, "
            "so 0.4.1 is the independent measure.", fontsize=8.8, color=MUTED, va="center")
    ax.text(6, 4, "Source: bench/external/results/*/summary.csv.  Reproduce: python scripts/make_hero.py",
            fontsize=8.8, color=MUTED, va="center")

    out = ROOT / "docs" / "img" / "hero.png"
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, dpi=200, facecolor="white")
    Image.open(out).convert("RGB").quantize(colors=64, dither=Image.Dither.NONE).save(
        out, optimize=True
    )
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
