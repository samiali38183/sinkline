# Held-out evaluation protocol (frozen before any tool was run on this set)

Why this exists: the BenchmarkPython 0.5.0 gains were chosen by reading that benchmark's failures, and sinkline
trails Bandit over all 14 of its categories. This set is for a score that none of that tuning touched.
Nothing in `bench/heldout/` was used to change sinkline. No code change is allowed after this protocol is
merged and before results are produced, and no change is allowed because of the results. If a bug is found
later it is reported here, not fixed into the score.

## Data

GitHub's CodeQL Python query tests, `python/ql/test/query-tests/Security`, repo `github/codeql`, commit
`20ed6480fa1d8c44c99368be99dda541082dc968`. They are third-party Flask/Django/FastAPI/etc. snippets with inline
expectations, written for another analyzer. sinkline's author had not run sinkline on them before this
protocol. One caveat: while checking the annotation format, the author read one file
(`CWE-078-CommandInjection/command_injection.py`) before freezing. No code was changed because of it.

`manifest.json` holds, per file, a SHA-256 and the labeled lines. Its hash is in `MANIFEST.sha256` and is
committed before any run. `run_eval.py` refuses to run if the hash differs or any source file hash differs.

## Directories

Included, "taint" tier (a source-to-sink class sinkline has rules for): 16 directories, listed in
`build_manifest.py` (`DIRS`). Included, "property" tier (single-call or configuration checks that sinkline
does not attempt; included so the result is not limited to what sinkline was built for): the rest of `DIRS`.
The two tiers are never blended into one number.

Excluded, with reasons:
- Python 2 syntax: `CWE-078-CommandInjection-py2`, `CWE-312-CleartextStorage`.
- Needs a CodeQL-specific threat model or library-API view, not a web app: `CWE-089-SqlInjection-local-threat-model`,
  `CWE-078-UnsafeShellCommandConstruction`, `CWE-020-ExternalAPIs`.
- Static analysis of regex literals, which none of the three tools attempts: `CWE-020-IncompleteHostnameRegExp`,
  `CWE-020-IncompleteUrlSubstringSanitization`, `CWE-020-SuspiciousRegexpRange`, `CWE-116-BadTagFilter`,
  `CWE-730-ReDoS`, `CWE-730-PolynomialReDoS`.
- Class too generic to map to CWEs, or a single CVE regression: `CWE-020-CookieInjection`, `CVE-2018-1281`.
- No annotated alerts, checked by counting `Alert` annotations and not by running tools: `CWE-776-XmlBomb`,
  `CWE-113-HeaderInjection`.

## Labels (implemented in `build_manifest.py::classify`)

Only inline expectation comments that start with `# $` count. Text after `SPURIOUS:` or `MISSING:` is a
separate segment.
- Positive (a real vulnerability at that line): `Alert` (with or without `[query]`/`=name` suffix) or
  `result=BAD` outside a `SPURIOUS:` segment. `MISSING:` segments count, because the label says the bug is real
  and the CodeQL query missed it.
- Negative (safe): `Alert` or `result=BAD` inside a `SPURIOUS:` segment, or `result=OK`.
- Everything else, including plain `# BAD` / `# GOOD` comments, is unlabeled.

Most files label only positives. Safe code is mostly implicit, so false positives are counted by rule below,
not only on lines labeled safe.

## Tools and configuration

Same files for every tool, no per-tool filtering, no test-directory exclusion, default severity and confidence.
- sinkline: current `main` plus the ablation switch added in the freezing PR (default behavior unchanged,
  covered by a test). One scan per test directory (so cross-file resolution works inside a directory).
- Bandit 1.9.4, default rules, `bandit -r . -f json`.
- Semgrep OSS 1.185.0, local copies of the registry rulesets `p/python` (sha256
  `de5bc79d074c3b4146338a0bf95830406f169bd91ac590a2f1ef111f162e23f5`) and `p/owasp-top-ten` (sha256
  `080396209e0d55ccf0e3537ed96f3a98b7dde7e5784068ee3130c0159b4b2361`) downloaded 2026-11-14, `--metrics=off`.
  An empty `.semgrepignore` replaces Semgrep's default ignore list, which would skip test-like paths.
- Not run: CodeQL itself, Semgrep Pro / custom taint rules, Pysa, Joern.

## Matching and metrics

A finding is "in class" if its CWE (Semgrep: any CWE in its metadata) is in the directory's accepted set in
`DIRS`. Other findings are ignored and only counted. A finding offers its location line range (sinkline also
offers the line of the final `sink` step in the same file, since the call site and the sink can differ).
Findings are matched one-to-one to positive lines, nearest first, within 3 lines. Matched pair = TP. Unmatched
positive = FN. Unmatched in-class finding = FP (this includes findings on lines labeled safe, also reported
separately). Precision = TP/(TP+FP), recall = TP/(TP+FN), F1, 95% Wilson intervals, macro recall over
directories, and wall-clock seconds for the whole run. The scorer is unit-tested on synthetic input
(`tests/test_heldout_scorer.py`).

Limits stated up front: positives are CodeQL's labels, so a real bug on an unlabeled line shows up as a false
positive for every tool. The precision number is therefore a lower bound for all three. The set is snippet-sized,
SSRF contributes 89 of the taint positives (macro recall is reported for that reason), and the property tier has
no labeled-safe lines at all.

## Ablation

Same set, same scorer, sinkline with `SINKLINE_ABLATE=interproc` (call-site summaries not used, so flows
through user functions and sinks inside callees are lost) and `SINKLINE_ABLATE=guards` (validation guards
ignored).
