"""The labeled corpus is a regression gate: precision/recall must not drop below the recorded floor."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_corpus_scores():
    out = ROOT / "bench" / "_ci_results.json"
    proc = subprocess.run([sys.executable, str(ROOT / "bench" / "score.py"), "--json", str(out)],
                          capture_output=True, text=True, cwd=str(ROOT))
    assert out.exists(), proc.stdout + proc.stderr
    r = json.loads(out.read_text())
    out.unlink()
    assert r["precision"] >= 0.98, r
    assert r["recall"] >= 0.95, r
    # every miss must be a documented design limit
    assert r["fn"] == r["known_fn"], r
    assert r["fp"] == r["known_fp"], r
