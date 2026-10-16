"""sinkline command-line interface.

    sinkline scan PATH [--format text|json|sarif|html] [-o FILE] [--fail-on SEVERITY]
                       [--baseline FILE] [--min-confidence low|medium|high] [--exclude-tests]
    sinkline rules      # list rules with OWASP/CWE mapping
    sinkline explain RULE_ID
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .engine import scan_path
from .model import CWE_TO_NAME, OWASP_NAMES, SINKS
from .report import to_html, to_json, to_sarif, to_text

_SEV = ["low", "medium", "high", "critical"]
_CONF = ["low", "medium", "high"]


def _cmd_scan(a: argparse.Namespace) -> int:
    res = scan_path(a.path, exclude_tests=a.exclude_tests)
    minc = _CONF.index(a.min_confidence)
    res.findings = [f for f in res.findings if _CONF.index(f.confidence) >= minc]
    if a.rule:
        wanted = set(a.rule)
        res.findings = [f for f in res.findings if f.rule_id in wanted or f.owasp in wanted or f.cwe in wanted]

    if a.baseline:
        try:
            base = json.loads(Path(a.baseline).read_text(encoding="utf-8"))
            known = {f["fingerprint"] for f in base.get("findings", [])}
            res.findings = [f for f in res.findings if f.fingerprint not in known]
        except (OSError, ValueError) as e:
            print(f"sinkline: cannot read baseline: {e}", file=sys.stderr)
            return 2

    fmt = a.format
    if fmt == "json":
        out = to_json(res, __version__)
    elif fmt == "sarif":
        out = to_sarif(res, __version__)
    elif fmt == "html":
        out = to_html(res, __version__, a.path)
    else:
        color = sys.stdout.isatty() and not a.no_color and os.environ.get("NO_COLOR") is None
        out = to_text(res, color=color)

    if a.output:
        Path(a.output).write_text(out, encoding="utf-8")
        print(f"sinkline: wrote {a.output} ({len(res.findings)} findings)", file=sys.stderr)
    else:
        try:
            sys.stdout.write(out + "\n")
        except UnicodeEncodeError:
            sys.stdout.buffer.write((out + "\n").encode("utf-8", errors="replace"))

    if a.fail_on:
        thr = _SEV.index(a.fail_on)
        if any(_SEV.index(f.severity) >= thr for f in res.findings):
            return 1
    return 0


def _cmd_rules(a: argparse.Namespace) -> int:
    seen = {}
    for s in SINKS:
        seen.setdefault(s.rule_id, s)
    rows = sorted(seen.values(), key=lambda s: (s.owasp, s.rule_id))
    cur = None
    for s in rows:
        if s.owasp != cur:
            cur = s.owasp
            print(f"\n{cur}  {OWASP_NAMES.get(cur, '')}")
        print(f"  {s.rule_id:<14} {s.cwe:<9} {s.severity:<8} {s.title}")
    print(f"\n{len(rows)} rules, {len(SINKS)} sink signatures")
    return 0


def _cmd_explain(a: argparse.Namespace) -> int:
    hits = [s for s in SINKS if s.rule_id == a.rule_id]
    if not hits:
        print(f"unknown rule {a.rule_id}", file=sys.stderr)
        return 2
    s = hits[0]
    print(f"{s.rule_id}  {s.title}")
    print(f"  OWASP  {s.owasp} {OWASP_NAMES.get(s.owasp, '')}")
    print(f"  CWE    {s.cwe} {CWE_TO_NAME.get(s.cwe, '')}")
    print(f"  Sev    {s.severity}")
    print("  Sinks:")
    for h in hits:
        gate = f"  [gate {h.requires_truthy_kw[0]}={h.requires_truthy_kw[1]}]" if h.requires_truthy_kw else ""
        print(f"    {h.qualname}  args={list(h.args)}{gate}")
    if s.fix:
        print(f"  Fix    {s.fix}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sinkline", description="Interprocedural taint analysis for Python web apps, mapped to the OWASP Top 10.")
    p.add_argument("--version", action="version", version=f"sinkline {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a file or directory")
    s.add_argument("path")
    s.add_argument("--format", "-f", choices=["text", "json", "sarif", "html"], default="text")
    s.add_argument("--output", "-o")
    s.add_argument("--fail-on", choices=_SEV, help="exit 1 if any finding at or above this severity")
    s.add_argument("--baseline", help="JSON report; suppress findings whose fingerprint is already in it")
    s.add_argument("--min-confidence", choices=_CONF, default="low")
    s.add_argument("--rule", action="append", help="only these rule ids / OWASP categories / CWEs (repeatable)")
    s.add_argument("--exclude-tests", action="store_true")
    s.add_argument("--no-color", action="store_true")
    s.set_defaults(fn=_cmd_scan)

    r = sub.add_parser("rules", help="list rules")
    r.set_defaults(fn=_cmd_rules)

    e = sub.add_parser("explain", help="explain a rule id")
    e.add_argument("rule_id")
    e.set_defaults(fn=_cmd_explain)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
