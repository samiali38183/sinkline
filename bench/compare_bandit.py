"""Score bandit (pattern-based) on the same labeled corpus, for an honest side-by-side.

Lenient scoring: ANY bandit issue on a VULN line counts as a true positive, regardless of CWE.
Usage: python bench/compare_bandit.py   (requires `pip install bandit`)
"""
import collections
import json
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
CORPUS = ROOT / "bench" / "corpus"
TAG = re.compile(r"#\s*(VULN:(CWE-\d+)|SAFE)\b")


def main():
    out = pathlib.Path(tempfile.mkdtemp()) / "bandit.json"
    subprocess.run([sys.executable, "-m", "bandit", "-q", "-f", "json", "-r", str(CORPUS), "-o", str(out)],
                   capture_output=True)
    if not out.exists():
        print("bandit not installed: pip install bandit")
        return 2
    b = json.loads(out.read_text(encoding="utf-8"))
    hits = collections.defaultdict(set)
    for r in b["results"]:
        hits[(pathlib.Path(r["filename"]).name, r["line_number"])].add(r["test_id"])

    tp = fp = fn = tn = 0
    for p in sorted(CORPUS.glob("*.py")):
        if p.name.startswith("smoke"):
            continue
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            m = TAG.search(line)
            if not m:
                continue
            got = hits.get((p.name, i), set())
            if m.group(2):
                tp, fn = (tp + 1, fn) if got else (tp, fn + 1)
            else:
                fp, tn = (fp + 1, tn) if got else (fp, tn + 1)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    print(f"bandit: {len(b['results'])} raw issues on the corpus")
    print(f"bandit on labeled lines: TP {tp}  FP {fp}  FN {fn}  TN {tn}")
    print(f"precision {prec:.3f}  recall {rec:.3f}  F1 {f1:.3f}   (lenient: any bandit hit on a VULN line counts)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
