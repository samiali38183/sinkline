# External benchmark: OWASP BenchmarkPython v0.1

The labeled corpus in `bench/corpus/` was written and labeled by the same person who wrote the
engine, so its score says little about accuracy on code the engine has not seen. This directory
scores sinkline, Bandit and Semgrep OSS on an independent suite: the
[OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython) (v0.1, "a preliminary
initial release"), 1,230 small Flask test cases with an expected-results CSV.

Nothing from that project is copied here (it is GPL-3.0); `run.sh` clones it into a scratch directory.

## What was run

| item | value |
|---|---|
| benchmark | OWASP-Benchmark/BenchmarkPython, commit `f1291485808b66e20ddb6b01b10dc71b3df8c8ba` (2026-05-19), `expectedresults-0.1.csv` |
| sinkline | 0.4.1 (`9a36ba2`) and 0.5.0 (this branch), `sinkline scan . --format json` from the benchmark checkout root (cross-file flows need the `helpers/` package in the scan) |
| Bandit | 1.9.4, `bandit -r . -f json` |
| Semgrep OSS | 1.185.0, `semgrep scan --config p/python --config p/owasp-top-ten --json --metrics=off .` |
| Python | 3.12.2, Windows 11 (Bandit and Semgrep installed in a separate virtualenv) |

Reproduce: `bench/external/run.sh <workdir> <label> sinkline bandit semgrep` (needs
`pip install bandit==1.9.4 semgrep==1.185.0`). Results are in `results/<label>/`:
`summary.md` / `summary.csv` (per category and overall) and `per_test.csv` (one row per test case with
each tool's flagged/not-flagged decision). The scan root includes the benchmark's own `helpers/`
directory; its files are not test cases and are ignored when scoring.

## Scoring

`score.py` is **not** the official scorer. The official one is BenchmarkUtils (Java/Maven,
`create-scorecard`), which was not run here. The definitions are the same:

- TPR = TP / (TP + FN) over the real vulnerabilities, FPR = FP / (FP + TN) over the safe cases,
  score = TPR - FPR.
- A test case is "flagged" when the tool reports at least one finding in that test's file with a CWE
  accepted for the test's category (`CATEGORY_CWES` in `score.py`; for example CWE-94/95/96 for `codeinj`,
  CWE-77/78/88 for `cmdi`). Findings with other CWEs in the file are ignored.
- Overall rows pool all test cases of the selected categories; "macro" in `summary.md` is the mean of
  per-category scores. Differences from the official scorecard (CWE matching, how categories are
  averaged) are possible.

Categories: sinkline is a taint analyzer. Ten categories are source-to-sink flows and are in scope for it:
sqli, cmdi, codeinj, xss, pathtraver, redirect, deserialization, ldapi, xpathi, xxe. Four are not:
hash (weak algorithm), weakrand (weak PRNG), securecookie (cookie flags) and trustbound (what is stored
in the session). They are reported anyway (sinkline scores 0 on them), because the same suite scores
Bandit on them.

## Results (TPR / FPR / TPR-FPR)

| category (real / safe cases) | sinkline 0.4.1 | sinkline 0.5.0 | bandit 1.9.4 | semgrep 1.185.0 |
|---|---|---|---|---|
| sqli (5 / 11) | 0.80 / 0.00 / +0.80 | 0.80 / 0.00 / +0.80 | 1.00 / 1.00 / +0.00 | 0.00 / 0.00 / +0.00 |
| cmdi (13 / 7) | 0.31 / 0.57 / -0.26 | 0.39 / 0.14 / +0.24 | 1.00 / 1.00 / +0.00 | 0.54 / 1.00 / -0.46 |
| codeinj (20 / 33) | 0.65 / 0.52 / +0.14 | 0.75 / 0.39 / +0.36 | 0.00 / 0.00 / +0.00 | 0.00 / 0.00 / +0.00 |
| xss (31 / 58) | 0.74 / 0.50 / +0.24 | 0.77 / 0.31 / +0.46 | 0.00 / 0.00 / +0.00 | 0.00 / 0.00 / +0.00 |
| pathtraver (65 / 103) | 0.31 / 0.08 / +0.23 | 0.66 / 0.09 / +0.57 | 0.00 / 0.00 / +0.00 | 0.03 / 0.02 / +0.01 |
| redirect (13 / 21) | 0.69 / 0.38 / +0.31 | 0.69 / 0.38 / +0.31 | 0.00 / 0.00 / +0.00 | 0.00 / 0.00 / +0.00 |
| deserialization (18 / 36) | 0.83 / 0.14 / +0.69 | 0.89 / 0.06 / +0.83 | 0.72 / 0.19 / +0.53 | 0.50 / 0.17 / +0.33 |
| ldapi (16 / 13) | 0.00 / 0.00 / +0.00 | 0.69 / 0.15 / +0.53 | 0.00 / 0.00 / +0.00 | 0.00 / 0.00 / +0.00 |
| xpathi (51 / 135) | 0.10 / 0.04 / +0.06 | 0.80 / 0.22 / +0.58 | 0.00 / 0.00 / +0.00 | 0.00 / 0.00 / +0.00 |
| xxe (8 / 20) | 0.75 / 0.65 / +0.10 | 0.88 / 0.50 / +0.38 | 0.00 / 0.00 / +0.00 | 0.00 / 0.00 / +0.00 |
| hash (71 / 80) | 0.00 / 0.00 / +0.00 | 0.00 / 0.00 / +0.00 | 1.00 / 0.00 / +1.00 | 0.76 / 0.00 / +0.76 |
| weakrand (99 / 227) | 0.00 / 0.00 / +0.00 | 0.00 / 0.00 / +0.00 | 0.78 / 0.00 / +0.78 | 0.00 / 0.00 / +0.00 |
| securecookie (24 / 15) | 0.00 / 0.00 / +0.00 | 0.00 / 0.00 / +0.00 | 0.00 / 0.00 / +0.00 | 0.00 / 0.00 / +0.00 |
| trustbound (18 / 19) | 0.00 / 0.00 / +0.00 | 0.00 / 0.00 / +0.00 | 0.00 / 0.00 / +0.00 | 0.00 / 0.00 / +0.00 |
| **taint categories (10)** | 0.41 / 0.20 / +0.21 | 0.73 / 0.21 / +0.52 | 0.13 / 0.06 / +0.07 | 0.07 / 0.03 / +0.04 |
| **all categories (14)** | 0.22 / 0.11 / +0.10 | 0.39 / 0.12 / +0.27 | 0.40 / 0.03 / +0.36 | 0.16 / 0.02 / +0.14 |

Counts for the two overall rows (TP / FN / FP / TN): sinkline 0.4.1 99 / 141 / 89 / 348 and 0.5.0 175 / 65 / 93 / 344
on the 10 taint categories; Bandit 31 / 209 / 25 / 412 and Semgrep 18 / 222 / 15 / 422 on the same.
Over all 14 categories: sinkline 0.5.0 175 / 277 / 93 / 685, Bandit 179 / 273 / 25 / 753, Semgrep 72 / 380 / 15 / 763.

## How to read this

- On the taint categories sinkline finds far more than the pattern tools (TPR 0.73 against 0.13 and 0.07)
  at a higher false-positive rate (0.21 against 0.06 and 0.03). On pooled counts that is precision 0.65
  against 0.55 for both. Bandit and Semgrep have no rules for most of these categories, so their zeros mostly
  mean "no rule", not "bad rule". Bandit's 1.00 / 1.00 on sqli and cmdi means it flags every file of that category.
- Over all 14 categories Bandit scores higher (+0.36 against +0.27) because it covers `hash` and `weakrand`,
  which sinkline does not attempt.
- sinkline's FPR is high. A large share of the remaining false positives are the suite's deliberately
  obfuscated safe variants (see "Left open").
- **The 0.5.0 numbers are not a held-out score.** The 0.4.1 to 0.5.0 changes were chosen by reading this
  benchmark's failures (sink coverage such as `codecs.open` and `elementpath.select`, branch pruning, `match`
  handling, helper-returned receiver types). Treat 0.4.1 as the independent measurement and 0.5.0 as
  "what the fixes recover on the suite that motivated them". The benchmark is a single synthetic suite of
  templated cases (many cases share one shape), v0.1, and small in the sqli, cmdi and xxe categories (5 to 13 real cases).

## Left open (0.5.0 does not handle)

Counted from the 0.5.0 per-test results; each is a design limit, not a bug fix waiting to land.

- Position-sensitive lists: `lst = []; lst.append("safe"); lst.append(param); lst.pop(0); bar = lst[1]`
  is safe, but a list is tracked as a whole container. This is the largest single source of false
  positives (xpathi, plus other categories).
- Stateful objects: taint stored with `ConfigParser.set` and read back with `.get`, and request data
  carried through a user-defined wrapper object (`helpers.separate_request`), are lost (false negatives in
  xss, pathtraver, xpathi, codeinj).
- Non-standard guards, for example an `eval` argument validated by `startswith("'")` / `endswith("'")` checks.
- XXE: parsing with a parser object configured elsewhere (`xml.sax.make_parser()`); sinkline reports the parse.
- `os.path.exists()` style probes as path-traversal sinks (the suite counts them; sinkline does not).
- Taint through module globals shared between requests (already a known limit in `docs/DESIGN.md`).
- Run time: about 50 to 60 seconds for the 1,230-file tree on the machine used (Bandit a few seconds).
