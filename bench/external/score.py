"""Score tool output against OWASP BenchmarkPython's expected-results CSV.

This is NOT the official scorer. The official one is BenchmarkUtils (Java, Maven
`create-scorecard`). This script follows the same definitions:

  TPR   = TP / (TP + FN)       over test cases that are real vulnerabilities
  FPR   = FP / (FP + TN)       over test cases that are not
  score = TPR - FPR            (Youden's J; 0 = a coin flip, 1 = perfect)

A test case counts as "flagged" when the tool reports at least one finding in that
test's file whose CWE is in the accepted set for the test's category (see CATEGORY_CWES;
child CWEs such as CWE-95 for CWE-94 are accepted so that a tool is not penalised for
reporting a more specific id). Findings with other CWEs in the same file are ignored,
as are findings in files that are not test cases.

Overall figures are given two ways: pooled (all test cases of the chosen categories
together) and macro (mean of the per-category scores, the way the official scorecard
averages). Categories a tool has no rule for still count in the "all categories" row.

Usage:
  python score.py --expected expectedresults-0.1.csv --out-dir results/NAME \
      sinkline=sinkline.json bandit=bandit.json semgrep=semgrep.json
Tool name decides the parser: names starting with sinkline, bandit or semgrep.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple

CATEGORY_CWES: Dict[str, Set[int]] = {
    "sqli": {89},
    "cmdi": {78, 77, 88},
    "codeinj": {94, 95, 96},
    "xss": {79, 80},
    "pathtraver": {22, 23, 36, 73},
    "redirect": {601},
    "deserialization": {502},
    "ldapi": {90},
    "xpathi": {643},
    "xxe": {611, 776},
    "hash": {328, 327, 326, 916},
    "weakrand": {330, 331, 335, 338},
    "securecookie": {614, 1004, 1275},
    "trustbound": {501},
}
# Categories that are data-flow (source reaching a sink); the others are properties of a
# single call or flag, which a taint tool is not designed to report.
TAINT_CATEGORIES = ["sqli", "cmdi", "codeinj", "xss", "pathtraver", "redirect",
                    "deserialization", "ldapi", "xpathi", "xxe"]
NON_TAINT_CATEGORIES = ["hash", "weakrand", "securecookie", "trustbound"]
TEST_RE = re.compile(r"BenchmarkTest(\d+)")


def _cwe_num(text: object) -> int | None:
    m = re.match(r"\s*(?:CWE-)?(\d+)", str(text))
    return int(m.group(1)) if m else None


def parse_results(kind: str, path: Path) -> Dict[str, Set[int]]:
    """Return {test number: set of CWE numbers reported in that test's file}."""
    data = json.loads(path.read_text(encoding="utf-8"))
    by: Dict[str, Set[int]] = defaultdict(set)
    if kind.startswith("sinkline"):
        for f in data["findings"]:
            m, c = TEST_RE.search(f["file"]), _cwe_num(f["cwe"])
            if m and c:
                by[m.group(1)].add(c)
    elif kind.startswith("bandit"):
        for r in data["results"]:
            m, c = TEST_RE.search(r["filename"]), _cwe_num(r["issue_cwe"]["id"])
            if m and c:
                by[m.group(1)].add(c)
    elif kind.startswith("semgrep"):
        for r in data["results"]:
            m = TEST_RE.search(r["path"])
            cw = r["extra"].get("metadata", {}).get("cwe") or []
            if isinstance(cw, str):
                cw = [cw]
            for x in cw:
                c = _cwe_num(x)
                if m and c:
                    by[m.group(1)].add(c)
    else:
        raise SystemExit(f"unknown tool kind {kind!r}")
    return by


def load_expected(path: Path) -> List[Tuple[str, str, bool]]:
    rows = []
    for r in csv.reader(path.read_text(encoding="utf-8").splitlines()):
        if not r or r[0].startswith("#"):
            continue
        m = TEST_RE.search(r[0])
        if m:
            rows.append((m.group(1), r[1].strip(), r[2].strip().lower() == "true"))
    return rows


def rates(tp: int, fn: int, fp: int, tn: int) -> Tuple[float, float, float]:
    tpr = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return tpr, fpr, tpr - fpr


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--expected", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("tools", nargs="+", help="name=path/to/result.json")
    a = ap.parse_args()

    expected = load_expected(Path(a.expected))
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    flagged: Dict[str, Dict[str, Set[int]]] = {}
    for spec in a.tools:
        name, _, p = spec.partition("=")
        flagged[name] = parse_results(name, Path(p))
    names = list(flagged)

    # per-test table
    with (out / "per_test.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["test", "category", "real_vulnerability"] + [f"{n}_flagged" for n in names])
        for num, cat, real in expected:
            w.writerow([f"BenchmarkTest{num}", cat, str(real).lower()]
                       + [int(bool(flagged[n].get(num, set()) & CATEGORY_CWES[cat])) for n in names])

    stats: Dict[str, Dict[str, List[int]]] = {n: defaultdict(lambda: [0, 0, 0, 0]) for n in names}
    for n in names:
        for num, cat, real in expected:
            pred = bool(flagged[n].get(num, set()) & CATEGORY_CWES[cat])
            i = (0 if pred else 1) if real else (2 if pred else 3)
            stats[n][cat][i] += 1

    lines = []
    csv_rows = [["tool", "category", "TP", "FN", "FP", "TN", "TPR", "FPR", "score"]]

    def emit(n: str, label: str, cats: List[str]) -> None:
        t = [sum(stats[n][c][i] for c in cats) for i in range(4)]
        tpr, fpr, sc = rates(*t)
        prec = t[0] / (t[0] + t[2]) if t[0] + t[2] else 0.0
        macro = sum(rates(*stats[n][c])[2] for c in cats) / len(cats)
        csv_rows.append([n, label, *t, f"{tpr:.3f}", f"{fpr:.3f}", f"{sc:.3f}"])
        lines.append(f"| {n} | {label} | {t[0]} | {t[1]} | {t[2]} | {t[3]} | {tpr:.3f} | {fpr:.3f} | {sc:.3f} | {prec:.3f} | {macro:.3f} |")

    hdr = "| tool | scope | TP | FN | FP | TN | TPR | FPR | TPR-FPR | precision | macro score |\n|---|---|---|---|---|---|---|---|---|---|---|"
    lines.append("### Overall (pooled counts; macro score = mean of per-category scores)\n")
    lines.append(hdr)
    for n in names:
        emit(n, "taint categories (10)", TAINT_CATEGORIES)
    for n in names:
        emit(n, "all categories (14)", TAINT_CATEGORIES + NON_TAINT_CATEGORIES)
    lines.append("\n### Per category\n")
    lines.append("| tool | category | TP | FN | FP | TN | TPR | FPR | TPR-FPR | precision | macro score |\n|---|---|---|---|---|---|---|---|---|---|---|")
    for cat in TAINT_CATEGORIES + NON_TAINT_CATEGORIES:
        for n in names:
            emit(n, cat, [cat])
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    with (out / "summary.csv").open("w", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerows(csv_rows)
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
