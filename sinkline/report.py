"""Reporters: terminal, JSON, SARIF 2.1.0, and a self-contained HTML report."""

from __future__ import annotations

import datetime as _dt
import html
import json
from typing import Dict, List

from .engine import ScanResult
from .finding import Finding
from .model import CWE_TO_NAME, OWASP_NAMES, SINKS

_SEV_SARIF = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_SEV_SCORE = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0}


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def to_json(res: ScanResult, version: str) -> str:
    return json.dumps(
        {
            "tool": "sinkline",
            "version": version,
            "generated": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
            "files": res.files,
            "functions": res.functions,
            "errors": res.errors,
            "by_owasp": res.by_owasp(),
            "findings": [f.to_dict() for f in res.findings],
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# SARIF 2.1.0  (GitHub code scanning compatible)
# ---------------------------------------------------------------------------

def to_sarif(res: ScanResult, version: str) -> str:
    rules: Dict[str, dict] = {}
    for s in SINKS:
        if s.rule_id in rules:
            continue
        rules[s.rule_id] = {
            "id": s.rule_id,
            "name": s.title.replace(" ", ""),
            "shortDescription": {"text": s.title},
            "fullDescription": {"text": f"{s.title}. OWASP {s.owasp} {OWASP_NAMES.get(s.owasp, '')}; {s.cwe} {CWE_TO_NAME.get(s.cwe, '')}."},
            "help": {"text": s.fix or s.title, "markdown": f"**Fix:** {s.fix}" if s.fix else s.title},
            "defaultConfiguration": {"level": _SEV_SARIF[s.severity]},
            "properties": {
                "tags": ["security", f"external/owasp/{s.owasp.replace(':', '-')}", f"external/cwe/{s.cwe.lower()}"],
                "security-severity": str(_SEV_SCORE[s.severity]),
                "precision": "high" if s.severity in ("critical", "high") else "medium",
            },
        }
    rule_index = {rid: i for i, rid in enumerate(rules)}

    results = []
    for f in res.findings:
        loc = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": f.line, "startColumn": f.col, "endLine": f.end_line, "endColumn": f.end_col},
            }
        }
        thread_locs = [
            {
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {"uri": s.file, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": s.line, "startColumn": s.col + 1},
                    },
                    "message": {"text": f"{s.kind}: {s.note or s.text}"},
                },
                "importance": "essential" if s.kind in ("source", "sink") else "important",
            }
            for s in f.flow
        ]
        results.append(
            {
                "ruleId": f.rule_id,
                "ruleIndex": rule_index.get(f.rule_id, 0),
                "level": _SEV_SARIF[f.severity],
                "message": {"text": f"{f.title}: {f.message}" + (f" Fix: {f.fix}" if f.fix else "")},
                "locations": [loc],
                "codeFlows": [{"threadFlows": [{"locations": thread_locs}]}] if thread_locs else [],
                "partialFingerprints": {"sinkline/v1": f.fingerprint},
                "properties": {"confidence": f.confidence, "owasp": f.owasp, "cwe": f.cwe, "source": f.source, "sink": f.sink},
            }
        )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sinkline",
                        "version": version,
                        "informationUri": "https://github.com/samiali38183/sinkline",
                        "semanticVersion": version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": [{"level": "error", "message": {"text": e}} for e in res.errors]}],
            }
        ],
    }
    return json.dumps(sarif, indent=2)


# ---------------------------------------------------------------------------
# HTML (single file, no external assets)
# ---------------------------------------------------------------------------

_CSS = """
:root{--bg:#0b0e14;--panel:#111622;--line:#ffffff14;--fg:#e6edf3;--mut:#8b949e;--acc:#79c4ff;--crit:#ff6b6b;--high:#ff9f43;--med:#ffd56a;--low:#8bd5a0;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,Segoe UI,Inter,sans-serif}
header{padding:28px 32px 18px;border-bottom:1px solid var(--line);display:flex;gap:28px;align-items:flex-end;flex-wrap:wrap}
h1{margin:0;font-size:22px;letter-spacing:.01em}h1 small{color:var(--mut);font-weight:400;font-size:13px;margin-left:10px}
.kpis{display:flex;gap:12px;margin-left:auto}.kpi{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 14px;min-width:92px}
.kpi b{display:block;font-size:20px}.kpi span{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.08em}
main{padding:20px 32px 60px;max-width:1200px}
.bars{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px;margin:0 0 24px}
.bar{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.bar .lbl{display:flex;justify-content:space-between;color:var(--mut);font-size:12px}.bar .lbl b{color:var(--fg)}
.bar i{display:block;height:6px;border-radius:3px;background:var(--acc);margin-top:8px}
.f{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin:0 0 14px;overflow:hidden}
.f summary{list-style:none;cursor:pointer;display:grid;grid-template-columns:86px 1fr auto;gap:14px;align-items:center;padding:12px 16px}
.f summary::-webkit-details-marker{display:none}
.sev{font:600 11px/1 var(--mono);letter-spacing:.08em;padding:6px 8px;border-radius:6px;text-align:center;color:#000}
.critical{background:var(--crit)}.high{background:var(--high)}.medium{background:var(--med)}.low{background:var(--low)}
.t{font-weight:600}.t small{color:var(--mut);font-weight:400;margin-left:8px}.loc{font:12px var(--mono);color:var(--mut)}
.body{padding:0 16px 16px;border-top:1px solid var(--line)}.msg{color:var(--mut);margin:12px 0}
.flow{font:12.5px/1.6 var(--mono);background:#0a0d13;border:1px solid var(--line);border-radius:8px;padding:10px 12px;overflow-x:auto}
.step{display:grid;grid-template-columns:18px 86px 1fr;gap:10px;white-space:pre}.step .k{color:var(--mut)}.step.source .k,.step.sink .k{color:var(--acc)}
.step .ln{color:var(--mut)}.step .n{color:#8bd5a0}
.fix{margin-top:12px;padding:10px 12px;border-left:3px solid var(--acc);background:#79c4ff10;border-radius:6px;font-size:13px}
.meta{font:11.5px var(--mono);color:var(--mut);margin-top:10px}
footer{color:var(--mut);font-size:12px;padding:0 32px 32px}
.empty{padding:40px;text-align:center;color:var(--mut);border:1px dashed var(--line);border-radius:12px}
"""


def to_html(res: ScanResult, version: str, target: str = "") -> str:
    by = res.by_owasp()
    sev_counts: Dict[str, int] = {}
    for f in res.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    mx = max(by.values()) if by else 1
    bars = "".join(
        f'<div class="bar"><div class="lbl"><span>{k} {html.escape(OWASP_NAMES.get(k, ""))}</span><b>{v}</b></div><i style="width:{int(100 * v / mx)}%"></i></div>'
        for k, v in by.items()
    )

    def step_html(s):
        return (
            f'<div class="step {s.kind}"><span class="k">{"┌" if s.kind == "source" else ("└" if s.kind == "sink" else "│")}</span>'
            f'<span class="k">{html.escape(s.kind)}</span>'
            f'<span><span class="ln">{html.escape(s.file)}:{s.line}</span>  {html.escape(s.text[:140])}'
            + (f'  <span class="n"># {html.escape(s.note)}</span>' if s.note else "")
            + "</span></div>"
        )

    items = []
    for f in res.findings:
        items.append(
            f'<details class="f"><summary><span class="sev {f.severity}">{f.severity.upper()}</span>'
            f'<span class="t">{html.escape(f.title)}<small>{f.rule_id} · {f.owasp} · {f.cwe} · {html.escape(CWE_TO_NAME.get(f.cwe, ""))}</small></span>'
            f'<span class="loc">{html.escape(f.file)}:{f.line}:{f.col}</span></summary>'
            f'<div class="body"><div class="msg">{html.escape(f.message)}</div>'
            f'<div class="flow">{"".join(step_html(s) for s in f.flow)}</div>'
            + (f'<div class="fix"><b>Fix.</b> {html.escape(f.fix)}</div>' if f.fix else "")
            + f'<div class="meta">confidence {f.confidence} · source {html.escape(f.source)} · sink {html.escape(f.sink)} · fp {f.fingerprint}</div>'
            "</div></details>"
        )
    body = "".join(items) if items else '<div class="empty">No tainted flows reached a sink.</div>'
    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>sinkline report</title><style>{_CSS}</style></head><body>
<header><h1>sinkline <small>v{version} · {html.escape(target)} · {now}</small></h1>
<div class="kpis"><div class="kpi"><b>{len(res.findings)}</b><span>findings</span></div>
<div class="kpi"><b>{sev_counts.get("critical", 0)}</b><span>critical</span></div>
<div class="kpi"><b>{sev_counts.get("high", 0)}</b><span>high</span></div>
<div class="kpi"><b>{res.files}</b><span>files</span></div><div class="kpi"><b>{res.functions}</b><span>functions</span></div></div></header>
<main><div class="bars">{bars}</div>{body}</main>
<footer>Interprocedural taint analysis · OWASP Top 10:2021 · generated by sinkline</footer></body></html>"""


# ---------------------------------------------------------------------------
# Terminal
# ---------------------------------------------------------------------------

def to_text(res: ScanResult, color: bool = True) -> str:
    C = {
        "critical": "\033[91m", "high": "\033[93m", "medium": "\033[33m", "low": "\033[92m",
        "dim": "\033[2m", "acc": "\033[96m", "b": "\033[1m", "0": "\033[0m",
    } if color else {k: "" for k in ("critical", "high", "medium", "low", "dim", "acc", "b", "0")}
    out: List[str] = []
    for f in res.findings:
        out.append(f"{C[f.severity]}{C['b']}[{f.severity.upper()}]{C['0']} {C['acc']}{f.rule_id}{C['0']} {f.owasp} {f.cwe}  {C['b']}{f.file}:{f.line}:{f.col}{C['0']}")
        out.append(f"  {f.title}")
        out.append(f"  {C['dim']}{f.message}{C['0']}")
        for i, s in enumerate(f.flow):
            glyph = "┌" if i == 0 else ("└" if i == len(f.flow) - 1 else "│")
            kind = f"{C['acc']}{s.kind:<10}{C['0']}" if s.kind in ("source", "sink") else f"{C['dim']}{s.kind:<10}{C['0']}"
            note = f"  {C['dim']}# {s.note}{C['0']}" if s.note else ""
            out.append(f"  {glyph} {kind} {s.file}:{s.line}  {s.text[:96]}{note}")
        if f.fix:
            out.append(f"  {C['acc']}fix:{C['0']} {f.fix}")
        out.append("")
    by = res.by_owasp()
    summary = " · ".join(f"{k} {OWASP_NAMES.get(k, '')}: {v}" for k, v in by.items()) or "none"
    out.append(f"{C['b']}{len(res.findings)} finding(s){C['0']} in {res.files} file(s), {res.functions} function(s) summarized")
    out.append(f"{C['dim']}by OWASP: {summary}{C['0']}")
    for e in res.errors:
        out.append(f"{C['medium']}parse error:{C['0']} {e}")
    return "\n".join(out)
