"""Run sinkline, Bandit and Semgrep on the frozen held-out set and score them.

Everything the score depends on is fixed by PROTOCOL.md and manifest.json. This script
  1. fetches the pinned CodeQL test files (sparse, one commit) and checks every file hash against the manifest,
  2. stages them into a scratch tree (one directory per test directory, no `test` in any path),
  3. runs each tool once per configuration,
  4. matches findings to labeled lines and writes results.

Usage:
  python run_eval.py --work WORKDIR --out results/NAME [--codeql CHECKOUT] [--tools sinkline,bandit,semgrep]
The Bandit and Semgrep executables are taken from --bandit / --semgrep (default: on PATH).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Sequence, Set, Tuple

HERE = Path(__file__).resolve().parent
TOL = 3  # a finding matches a labeled line if it is at most this many lines away (PROTOCOL.md, "Matching")

# A location is (first_line, last_line); a finding offers one or more locations.
Loc = Tuple[int, int]


# ---------------------------------------------------------------- staging
def fetch_codeql(dest: Path, commit: str, repo: str, path: str) -> Path:
    if (dest / path).exists():
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    run = lambda *a: subprocess.run(["git", "-C", str(dest), *a], check=True, capture_output=True)  # noqa: E731
    run("init", "-q")
    run("remote", "add", "origin", repo)
    run("sparse-checkout", "init", "--cone")
    run("sparse-checkout", "set", path)
    run("fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", commit)
    run("checkout", "-q", "FETCH_HEAD")
    return dest


def stage(manifest: dict, checkout: Path, work: Path) -> Path:
    src = manifest["source"]
    base = checkout / src["path"]
    root = work / "evalroot"
    if root.exists():
        shutil.rmtree(root)
    for d, info in manifest["dirs"].items():
        for rel, meta in info["files"].items():
            data = (base / d / rel).read_bytes()
            if hashlib.sha256(data).hexdigest() != meta["sha256"]:
                raise SystemExit(f"hash mismatch for {d}/{rel}: the checkout is not the frozen one")
            out = root / d / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
        # an empty .semgrepignore replaces Semgrep's default ignore list (which skips test-like paths)
        (root / d / ".semgrepignore").write_text("", encoding="utf-8")
    (root / ".semgrepignore").write_text("", encoding="utf-8")
    return root


# ---------------------------------------------------------------- tool runners and parsers
def _cwe_nums(vals) -> Set[int]:
    import re

    out: Set[int] = set()
    for v in vals if isinstance(vals, (list, tuple)) else [vals]:
        m = re.match(r"\s*(?:CWE-)?(\d+)", str(v))
        if m:
            out.add(int(m.group(1)))
    return out


class F:
    """One finding: the file it is in (relative to the staged root, posix), accepted-class CWEs, locations."""

    def __init__(self, file: str, cwes: Set[int], locs: List[Loc], rule: str = ""):
        self.file, self.cwes, self.locs, self.rule = file, cwes, locs, rule


def run_sinkline(root: Path, manifest: dict, ablate: str, py: str) -> Tuple[List[F], float]:
    env = dict(os.environ, SINKLINE_ABLATE=ablate, PYTHONPATH=str(HERE.parents[1]), PYTHONIOENCODING="utf-8")
    out: List[F] = []
    t0 = time.perf_counter()
    for d in manifest["dirs"]:
        r = subprocess.run([py, "-m", "sinkline", "scan", str(root / d), "--format", "json"],
                           capture_output=True, env=env)
        data = json.loads(r.stdout.decode("utf-8"))
        for f in data["findings"]:
            locs = [(f["line"], f.get("end_line", f["line"]))]
            sinks = [s for s in f.get("flow", []) if s["kind"] == "sink" and s["file"] == f["file"]]
            if sinks:
                locs.append((sinks[-1]["line"], sinks[-1]["line"]))
            out.append(F(f"{d}/{f['file']}", _cwe_nums(f["cwe"]), locs, f["rule_id"]))
    return out, time.perf_counter() - t0


def run_bandit(root: Path, exe: str) -> Tuple[List[F], float]:
    t0 = time.perf_counter()
    r = subprocess.run([exe, "-r", ".", "-f", "json", "-q"], cwd=root, capture_output=True)
    dt = time.perf_counter() - t0
    data = json.loads(r.stdout.decode("utf-8"))
    out = []
    for x in data["results"]:
        rng = x.get("line_range") or [x["line_number"]]
        fn = Path(x["filename"]).as_posix().lstrip("./")
        out.append(F(fn, _cwe_nums(x["issue_cwe"]["id"]), [(min(rng), max(rng))], x["test_id"]))
    return out, dt


def run_semgrep(root: Path, exe: str, cfgs: Sequence[Path]) -> Tuple[List[F], float]:
    args = [exe, "scan", "--json", "--metrics=off", "--quiet", "--disable-version-check", "--no-git-ignore"]
    for c in cfgs:
        args += ["--config", str(c)]
    t0 = time.perf_counter()
    r = subprocess.run(args + ["."], cwd=root, capture_output=True, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    dt = time.perf_counter() - t0
    data = json.loads(r.stdout.decode("utf-8"))
    out = []
    for x in data["results"]:
        md = x["extra"].get("metadata", {})
        fn = Path(x["path"]).as_posix().lstrip("./")
        out.append(F(fn, _cwe_nums(md.get("cwe", [])), [(x["start"]["line"], x["end"]["line"])], x["check_id"]))
    return out, dt


# ---------------------------------------------------------------- scoring
def dist(line: int, loc: Loc) -> int:
    lo, hi = loc
    return 0 if lo <= line <= hi else min(abs(line - lo), abs(line - hi))


def score_file(pos: List[int], neg: List[int], findings: List[F]) -> dict:
    """One-to-one greedy matching, nearest first, within TOL lines. `findings` are already class-filtered."""
    pairs = []
    for i, L in enumerate(pos):
        for j, f in enumerate(findings):
            d = min(dist(L, loc) for loc in f.locs)
            if d <= TOL:
                pairs.append((d, L, i, j))
    pairs.sort()
    used_p: Set[int] = set()
    used_f: Set[int] = set()
    matched: Dict[int, int] = {}
    for _d, _L, i, j in pairs:
        if i in used_p or j in used_f:
            continue
        used_p.add(i)
        used_f.add(j)
        matched[i] = j
    fp = [findings[j] for j in range(len(findings)) if j not in used_f]
    on_neg = sum(1 for f in fp if any(dist(n, loc) <= TOL for n in neg for loc in f.locs))
    return {"tp": len(matched), "fn": len(pos) - len(matched), "fp": len(fp), "fp_on_labeled_safe": on_neg,
            "missed": [pos[i] for i in range(len(pos)) if i not in matched],
            "fp_lines": sorted({f.locs[0][0] for f in fp})}


def wilson(k: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (max(0.0, c - h), min(1.0, c + h))


def score_tool(manifest: dict, findings: List[F]) -> dict:
    by_file: Dict[str, List[F]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)
    per_dir: Dict[str, dict] = {}
    ignored = 0
    for d, info in manifest["dirs"].items():
        accepted = set(info["cwes"])
        agg = {"tier": info["tier"], "tp": 0, "fn": 0, "fp": 0, "fp_on_labeled_safe": 0, "files": {}}
        for rel, meta in info["files"].items():
            key = f"{d}/{rel}"
            allf = by_file.get(key, [])
            inclass = [f for f in allf if f.cwes & accepted]
            ignored += len(allf) - len(inclass)
            r = score_file([p["line"] for p in meta["positives"]], [n["line"] for n in meta["negatives"]], inclass)
            for k in ("tp", "fn", "fp", "fp_on_labeled_safe"):
                agg[k] += r[k]
            agg["files"][rel] = r
        per_dir[d] = agg
    out = {"ignored_other_class_findings": ignored, "per_dir": per_dir, "tiers": {}}
    for tier in ("taint", "property"):
        ds = [v for v in per_dir.values() if v["tier"] == tier]
        tp, fn, fp = (sum(v[k] for v in ds) for k in ("tp", "fn", "fp"))
        rec = tp / (tp + fn) if tp + fn else 0.0
        prec = tp / (tp + fp) if tp + fp else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        macro = [v["tp"] / (v["tp"] + v["fn"]) for v in ds if v["tp"] + v["fn"]]
        out["tiers"][tier] = {
            "tp": tp, "fn": fn, "fp": fp, "fp_on_labeled_safe": sum(v["fp_on_labeled_safe"] for v in ds),
            "recall": rec, "precision": prec, "f1": f1,
            "recall_ci95": wilson(tp, tp + fn), "precision_ci95": wilson(tp, tp + fp),
            "macro_recall_over_dirs": sum(macro) / len(macro) if macro else 0.0,
        }
    return out


# ---------------------------------------------------------------- reporting
def fmt_row(name: str, t: dict, secs: float) -> str:
    lo, hi = t["recall_ci95"]
    plo, phi = t["precision_ci95"]
    return (f"| {name} | {t['tp']} | {t['fn']} | {t['fp']} | {t['precision']:.2f} ({plo:.2f}-{phi:.2f}) | "
            f"{t['recall']:.2f} ({lo:.2f}-{hi:.2f}) | {t['f1']:.2f} | {t['macro_recall_over_dirs']:.2f} | {secs:.1f} |")


def write_outputs(out: Path, manifest: dict, results: Dict[str, dict], times: Dict[str, float], meta: dict) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps({"meta": meta, "times": times, "results": results}, indent=1) + "\n",
                                      encoding="utf-8", newline="\n")
    lines = ["# Held-out results", "", f"Manifest sha256: `{meta['manifest_sha256']}`", ""]
    head = ("| tool | TP | FN | FP | precision (95% CI) | recall (95% CI) | F1 | macro recall | seconds |\n"
            "|---|---|---|---|---|---|---|---|---|")
    for tier, title in (("taint", "Taint classes (sinkline has rules for these)"),
                        ("property", "Property classes (sinkline does not attempt these)")):
        lines += [f"## {title}", "", head]
        for name, r in results.items():
            lines.append(fmt_row(name, r["tiers"][tier], times[name]))
        lines.append("")
    lines += ["## Per directory (TP / FN / FP)", "",
              "| directory | tier | " + " | ".join(results) + " |", "|---|---|" + "---|" * len(results)]
    for d, info in manifest["dirs"].items():
        row = [f"{r['per_dir'][d]['tp']}/{r['per_dir'][d]['fn']}/{r['per_dir'][d]['fp']}" for r in results.values()]
        lines.append(f"| {d} | {info['tier']} | " + " | ".join(row) + " |")
    lines += ["", "FP counts every in-class finding that is not matched to a labeled positive line. "
              "Findings of a CWE outside the directory's class are ignored: "
              + ", ".join(f"{n}: {r['ignored_other_class_findings']}" for n, r in results.items()) + "."]
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    with (out / "per_line.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["tool", "directory", "file", "missed_positive_lines", "unmatched_finding_lines"])
        for name, r in results.items():
            for d, v in r["per_dir"].items():
                for rel, x in v["files"].items():
                    w.writerow([name, d, rel, " ".join(map(str, x["missed"])), " ".join(map(str, x["fp_lines"]))])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--codeql")
    ap.add_argument("--tools", default="sinkline,bandit,semgrep")
    ap.add_argument("--bandit", default="bandit")
    ap.add_argument("--semgrep", default="semgrep")
    ap.add_argument("--semgrep-config", action="append", default=[])
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--manifest", default=str(HERE / "manifest.json"))
    a = ap.parse_args()

    mtext = Path(a.manifest).read_bytes()
    msha = hashlib.sha256(mtext).hexdigest()
    frozen = (HERE / "MANIFEST.sha256").read_text().split()[0]
    if msha != frozen:
        raise SystemExit("manifest.json does not match MANIFEST.sha256")
    manifest = json.loads(mtext)
    work = Path(a.work)
    src = manifest["source"]
    checkout = Path(a.codeql) if a.codeql else fetch_codeql(work / "codeql", src["commit"], src["repo"], src["path"])
    root = stage(manifest, checkout, work)

    tools = a.tools.split(",")
    results: Dict[str, dict] = {}
    times: Dict[str, float] = {}
    meta = {"manifest_sha256": msha, "codeql_commit": src["commit"], "tolerance_lines": TOL, "python": sys.version.split()[0]}
    if "sinkline" in tools:
        for label, ab in (("sinkline", ""), ("sinkline-no-interproc", "interproc"), ("sinkline-no-guards", "guards")):
            f, dt = run_sinkline(root, manifest, ab, a.python)
            results[label], times[label] = score_tool(manifest, f), dt
    if "bandit" in tools:
        f, dt = run_bandit(root, a.bandit)
        results["bandit"], times["bandit"] = score_tool(manifest, f), dt
        meta["bandit"] = subprocess.run([a.bandit, "--version"], capture_output=True, text=True).stdout.split("\n")[0]
    if "semgrep" in tools:
        cfgs = [Path(c).resolve() for c in a.semgrep_config]
        f, dt = run_semgrep(root, a.semgrep, cfgs)
        results["semgrep"], times["semgrep"] = score_tool(manifest, f), dt
        meta["semgrep"] = subprocess.run([a.semgrep, "--version"], capture_output=True, text=True).stdout.strip()
        meta["semgrep_configs"] = {Path(c).name: hashlib.sha256(Path(c).read_bytes()).hexdigest() for c in cfgs}
    write_outputs(Path(a.out), manifest, results, times, meta)
    print((Path(a.out) / "summary.md").read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
