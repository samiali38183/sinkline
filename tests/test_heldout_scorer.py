"""Unit tests for the held-out label parser and matcher, on synthetic input only."""

import importlib.util
from pathlib import Path

HELD = Path(__file__).resolve().parents[1] / "bench" / "heldout"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HELD / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bm = _load("build_manifest")
ev = _load("run_eval")


def test_classify_rules():
    c = bm.classify
    assert c("# $ Alert")[0] == "pos"
    assert c("# $ Alert result=BAD")[0] == "pos"
    assert c("# $ Alert[py/full-ssrf]")[0] == "pos"
    assert c("# $ MISSING: Alert[py/partial-ssrf]") == ("pos", "missing")
    assert c("# $ Alert SPURIOUS: result=BAD")[0] == "neg"
    assert c("# $ SPURIOUS: Alert")[0] == "neg"
    assert c("# $ result=OK - sanitized")[0] == "neg"
    assert c("# $ Source")[0] is None
    assert c("# BAD: plain comments are not labels")[0] is None


def test_matching_is_one_to_one_and_nearest_first():
    f = lambda *locs: ev.F("a.py", {89}, [(n, n) for n in locs])  # noqa: E731
    r = ev.score_file([10, 11], [], [f(10)])          # one finding cannot satisfy two positives
    assert (r["tp"], r["fn"], r["fp"]) == (1, 1, 0)
    r = ev.score_file([10], [], [f(10), f(11)])       # the second finding is a false positive
    assert (r["tp"], r["fp"]) == (1, 1)
    r = ev.score_file([10], [], [f(20)])              # too far away
    assert (r["tp"], r["fn"], r["fp"]) == (0, 1, 1)
    r = ev.score_file([10], [30], [f(30)])            # on a labeled-safe line
    assert (r["fp"], r["fp_on_labeled_safe"]) == (1, 1)
    r = ev.score_file([10], [], [ev.F("a.py", {89}, [(1, 1), (12, 12)])])  # any offered location may match
    assert r["tp"] == 1


def test_wilson_bounds():
    lo, hi = ev.wilson(50, 100)
    assert 0.40 < lo < 0.41 and 0.59 < hi < 0.60
    assert ev.wilson(0, 0) == (0.0, 0.0)
