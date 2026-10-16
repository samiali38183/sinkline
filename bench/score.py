"""Score sinkline against the labeled corpus.

Ground truth comes from inline tags:
    # VULN:CWE-89     this line must produce a finding with that CWE
    # SAFE            this line must produce NO finding
Lines marked "-- known FN class" / "-- known FP class" are counted separately so the
honest headline numbers include them but the breakdown shows what's a design limit.

Usage:  python bench/score.py [--json out.json] [--verbose]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sinkline import scan_path  # noqa: E402
from sinkline.model import CWE_TO_NAME  # noqa: E402

CORPUS = ROOT / "bench" / "corpus"
TAG = re.compile(r"#\s*(VULN:(CWE-\d+)|SAFE)\b(.*)$")


def load_truth():
    truth = {}  # (file, line) -> ("vuln", cwe, known) | ("safe", None, known)
    for p in sorted(CORPUS.glob("*.py")):
        if p.name.startswith("smoke"):
            continue
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            m = TAG.search(line)
            if not m:
                continue
            known = "known" in (m.group(3) or "")
            if m.group(2):
                truth[(p.name, i)] = ("vuln", m.group(2), known)
            else:
                truth[(p.name, i)] = ("safe", None, known)
    return truth


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    ap.add_argument("--verbose", "-v", action="store_true")
    a = ap.parse_args()

    truth = load_truth()
    res = scan_path(str(CORPUS))
    hits = defaultdict(set)  # (file,line) -> set(cwe)
    for f in res.findings:
        if f.file.startswith("smoke"):
            continue
        hits[(f.file, f.line)].add(f.cwe)

    tp = fp = fn = tn = 0
    per_cwe = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    known_fn = known_fp = 0
    rows = []
    for key, (kind, cwe, known) in sorted(truth.items()):
        got = hits.get(key, set())
        if kind == "vuln":
            if cwe in got:
                tp += 1
                per_cwe[cwe]["tp"] += 1
                rows.append(("TP", key, cwe, sorted(got)))
            else:
                fn += 1
                per_cwe[cwe]["fn"] += 1
                if known:
                    known_fn += 1
                rows.append(("FN", key, cwe, sorted(got)))
        else:
            if got:
                fp += 1
                for c in got:
                    per_cwe[c]["fp"] += 1
                if known:
                    known_fp += 1
                rows.append(("FP", key, "-", sorted(got)))
            else:
                tn += 1
                rows.append(("TN", key, "-", []))

    # findings on lines with no label at all are *unlabeled* — report but don't score
    unlabeled = [(k, sorted(v)) for k, v in hits.items() if k not in truth]

    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0

    print(f"corpus: {len(truth)} labeled lines ({sum(1 for v in truth.values() if v[0]=='vuln')} vuln, {sum(1 for v in truth.values() if v[0]=='safe')} safe)")
    print(f"TP {tp}  FP {fp}  FN {fn}  TN {tn}")
    print(f"precision {prec:.3f}  recall {rec:.3f}  F1 {f1:.3f}")
    print(f"  of which known-limitation: FN {known_fn}, FP {known_fp}")
    if fn + fp - known_fn - known_fp == 0:
        print("  -> every miss is a documented design limit")
    print()
    print(f"{'CWE':<10}{'name':<34}{'TP':>4}{'FP':>4}{'FN':>4}")
    for cwe in sorted(per_cwe):
        c = per_cwe[cwe]
        print(f"{cwe:<10}{CWE_TO_NAME.get(cwe, '')[:33]:<34}{c['tp']:>4}{c['fp']:>4}{c['fn']:>4}")
    if a.verbose:
        print()
        for r in rows:
            if r[0] in ("FP", "FN"):
                print(f"  {r[0]}  {r[1][0]}:{r[1][1]}  expected {r[2]}  got {r[3]}")
    if unlabeled:
        print(f"\n{len(unlabeled)} finding(s) on unlabeled lines (not scored):")
        for k, v in sorted(unlabeled):
            print(f"  {k[0]}:{k[1]}  {v}")

    if a.json:
        Path(a.json).write_text(json.dumps({
            "labeled": len(truth), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
            "known_fn": known_fn, "known_fp": known_fp,
            "per_cwe": per_cwe, "unlabeled": [[k[0], k[1], v] for k, v in unlabeled],
        }, indent=2), encoding="utf-8")
    return 0 if (fn - known_fn) == 0 and (fp - known_fp) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
