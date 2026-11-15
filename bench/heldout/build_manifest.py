"""Build the frozen label manifest for the held-out evaluation.

Source of truth: the inline expectations in GitHub's CodeQL Python query tests
(github/codeql, python/ql/test/query-tests/Security), pinned to one commit. Nothing here looks at
any tool's output. See PROTOCOL.md for the rules this file implements.

Usage: python build_manifest.py <codeql-checkout-root> [--out manifest.json]
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import tokenize
from pathlib import Path
from typing import Dict, List, Set

REPO = "https://github.com/github/codeql"
COMMIT = "20ed6480fa1d8c44c99368be99dda541082dc968"
ROOT_REL = "python/ql/test/query-tests/Security"

# directory -> (tier, accepted CWE numbers). Tier "taint" is a source-to-sink class that sinkline has a
# rule for. Tier "property" is a single-call or configuration property that sinkline does not attempt;
# it is included so the held-out result is not limited to the categories sinkline was built for.
# Directories not listed here are excluded; the reasons are in PROTOCOL.md.
DIRS: Dict[str, tuple] = {
    "CWE-022-PathInjection": ("taint", {22, 23, 36, 73}),
    "CWE-022-TarSlip": ("taint", {22, 23}),
    "CWE-074-TemplateInjection": ("taint", {74, 94, 95, 1336}),
    "CWE-078-CommandInjection": ("taint", {77, 78, 88}),
    "CWE-079-ReflectedXss": ("taint", {79, 80}),
    "CWE-089-SqlInjection": ("taint", {89}),
    "CWE-090-LdapInjection": ("taint", {90}),
    "CWE-094-CodeInjection": ("taint", {94, 95, 96}),
    "CWE-117-LogInjection": ("taint", {117}),
    "CWE-502-UnsafeDeserialization": ("taint", {502}),
    "CWE-601-UrlRedirect": ("taint", {601}),
    "CWE-611-Xxe": ("taint", {611, 776}),
    "CWE-643-XPathInjection": ("taint", {643}),
    "CWE-730-RegexInjection": ("taint", {730, 1333}),
    "CWE-918-ServerSideRequestForgery": ("taint", {918}),
    "CWE-943-NoSqlInjection": ("taint", {943}),
    "CWE-079-Jinja2WithoutEscaping": ("property", {79, 94}),
    "CWE-209-StackTraceExposure": ("property", {209, 497}),
    "CWE-285-PamAuthorization": ("property", {285}),
    "CWE-295-MissingHostKeyValidation": ("property", {295, 297}),
    "CWE-295-RequestWithoutValidation": ("property", {295, 297}),
    "CWE-312-CleartextLogging": ("property", {312, 313, 315, 359, 532}),
    "CWE-312-CleartextStorage-py3": ("property", {312, 313, 315, 359, 532}),
    "CWE-942-CorsMisconfigurationMiddleware": ("property", {942}),
    "CWE-215-FlaskDebug": ("property", {215, 489, 94}),
    "CWE-326-WeakCryptoKey": ("property", {326, 327}),
    "CWE-327-BrokenCryptoAlgorithm": ("property", {327, 326, 328, 310}),
    "CWE-327-InsecureDefaultProtocol": ("property", {327, 326, 295}),
    "CWE-327-InsecureProtocol": ("property", {327, 326, 295}),
    "CWE-327-WeakSensitiveDataHashing": ("property", {327, 328, 916}),
    "CWE-377-InsecureTemporaryFile": ("property", {377, 379}),
    "CWE-614-InsecureCookie": ("property", {614, 1004, 1275}),
    "CWE-1004-NonHttpOnlyCookie": ("property", {614, 1004, 1275}),
    "CWE-1275-SameSiteNoneCookie": ("property", {614, 1004, 1275}),
    "CWE-732-WeakFilePermissions": ("property", {732, 276}),
    "CWE-798-HardcodedCredentials": ("property", {798, 259, 321, 547}),
}

_SPUR = re.compile(r"SPURIOUS\s*:")
_MISS = re.compile(r"MISSING\s*:")
_ALERT = re.compile(r"\bAlert\b(\[[^\]]*\]|=\w+)?")
_BAD = re.compile(r"result\s*=\s*BAD")
_OK = re.compile(r"result\s*=\s*OK")


def classify(comment: str):
    """Return ('pos'|'neg'|None, why). Implements the rules in PROTOCOL.md section 'Labels'."""
    m = re.match(r"#\s*\$(.*)", comment)
    if not m:
        return None, ""
    body = m.group(1)
    marks = sorted([(x.start(), "S", x.end()) for x in _SPUR.finditer(body)]
                   + [(x.start(), "M", x.end()) for x in _MISS.finditer(body)])
    segs = {"A": [], "S": [], "M": []}
    cur, pos = "A", 0
    for start, kind, end in marks:
        segs[cur].append(body[pos:start])
        cur, pos = kind, end
    segs[cur].append(body[pos:])
    actual, spur, miss = (" ".join(segs[k]) for k in ("A", "S", "M"))
    bad = lambda s: bool(_ALERT.search(s) or _BAD.search(s))  # noqa: E731
    if bad(spur):
        return "neg", "spurious"
    if bad(actual) or bad(miss):
        return "pos", "missing" if bad(miss) and not bad(actual) else "alert"
    if _OK.search(actual):
        return "neg", "result=OK"
    return None, ""


def file_labels(path: Path) -> Dict[str, list]:
    text = path.read_text(encoding="utf-8")
    pos: List[dict] = []
    neg: List[dict] = []
    for tok in tokenize.generate_tokens(io.StringIO(text).readline):
        if tok.type != tokenize.COMMENT:
            continue
        kind, why = classify(tok.string)
        if kind == "pos":
            pos.append({"line": tok.start[0], "why": why})
        elif kind == "neg":
            neg.append({"line": tok.start[0], "why": why})
    return {"positives": pos, "negatives": neg}


def build(root: Path) -> dict:
    base = root / ROOT_REL
    out = {"source": {"repo": REPO, "commit": COMMIT, "path": ROOT_REL}, "dirs": {}}
    for d, (tier, cwes) in sorted(DIRS.items()):
        files = {}
        for p in sorted((base / d).rglob("*.py")):
            rel = p.relative_to(base / d).as_posix()
            lab = file_labels(p)
            files[rel] = {"sha256": hashlib.sha256(p.read_bytes()).hexdigest(), **lab}
        out["dirs"][d] = {"tier": tier, "cwes": sorted(cwes), "files": files}
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("checkout")
    ap.add_argument("--out", default=str(Path(__file__).with_name("manifest.json")))
    a = ap.parse_args()
    m = build(Path(a.checkout))
    text = json.dumps(m, indent=1, sort_keys=True) + "\n"
    Path(a.out).write_text(text, encoding="utf-8", newline="\n")
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()
    Path(a.out).with_name("MANIFEST.sha256").write_text(f"{h}  manifest.json\n", encoding="utf-8", newline="\n")
    tot = {"taint": [0, 0], "property": [0, 0]}
    for d, info in m["dirs"].items():
        p = sum(len(f["positives"]) for f in info["files"].values())
        n = sum(len(f["negatives"]) for f in info["files"].values())
        tot[info["tier"]][0] += p
        tot[info["tier"]][1] += n
        print(f"{d:40s} {info['tier']:9s} files={len(info['files']):2d} positives={p:3d} negatives={n:2d}")
    print(tot, "sha256", h)
    return 0


if __name__ == "__main__":
    sys.exit(main())
