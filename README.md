# sinkline

[![ci](https://github.com/samiali38183/sinkline/actions/workflows/ci.yml/badge.svg)](https://github.com/samiali38183/sinkline/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.9%E2%80%933.13-blue)
![deps](https://img.shields.io/badge/dependencies-0-brightgreen)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

A static analyzer for Python web apps. It follows user input (Flask/FastAPI/Django request data,
`sys.argv`, etc.) through your code and flags it when it reaches something dangerous like a SQL
query or a shell command without being sanitized first. Findings map to the OWASP Top 10 and CWE,
and it can output SARIF for GitHub code scanning. No dependencies; it's built on Python's `ast` module.

```
$ sinkline scan bench/corpus/flask_app.py

[CRITICAL] SL-SQLI-001 A03:2021 CWE-89  flask_app.py:67:5
  SQL built from tainted data
  flask.request.args reaches sqlite3.Connection.execute (inside _lookup, flask_app.py:62) without a sanitizer for CWE-89.
  ┌ source     flask_app.py:67  _lookup(request.args["name"])                      # flask.request.args
  │ call       flask_app.py:67  _lookup(request.args["name"])                      # passed as `name` to _lookup()
  └ sink       flask_app.py:62  return db.execute("SELECT * FROM t WHERE name = '" + name + "'")  # sqlite3.Connection.execute inside _lookup()
  fix: Use parameterized queries: conn.execute('... WHERE id = ?', (user_id,))
```

The reason I built it: tools that just pattern-match flag every `db.execute(...)` call. sinkline only
reports the ones user input can actually reach, shows the path it took, and doesn't flag the
parameterized query a few lines below.

## Quick start

Python 3.9+, no dependencies.

```bash
pip install git+https://github.com/samiali38183/sinkline
sinkline scan path/to/app                      # text report with source → sink paths
sinkline scan . --format sarif -o out.sarif     # upload to GitHub code scanning
sinkline scan . --fail-on high                  # exit 1 for CI if anything high/critical
sinkline explain SL-CMDI-003                    # what a rule matches and why
```

To see it on the labeled benchmark instead of your own code:

```bash
git clone https://github.com/samiali38183/sinkline && cd sinkline
pip install -e ".[dev]"
sinkline scan bench/corpus/flask_app.py         # 21 findings, each with its flow
pytest -q                                       # 37 tests + corpus precision/recall gate
python bench/score.py                           # precision 0.983  recall 0.951  F1 0.967
```

## Results

**Labeled benchmark:** 109 hand-labeled lines across Flask, FastAPI, Django and CLI code
(61 vulnerable, 48 safe variants of the same patterns), scored by `bench/score.py`:

| tool | precision | recall | F1 |
|---|---|---|---|
| sinkline | 0.983 | 0.951 | 0.967 |
| bandit 1.8 (lenient: any hit on a vulnerable line counts) | 0.623 | 0.541 | 0.579 |

The 3 misses and 1 false positive are known limits, labeled in the corpus and listed under
[Limitations](#limitations). CI fails if the score drops (`tests/test_corpus.py`).

**Real apps:** I also ran it on four public Flask/aiohttp projects (checked out 2026-10-15):

| repo | commit | findings | notes |
|---|---|---|---|
| [fportantier/vulpy](https://github.com/fportantier/vulpy) | `5249cc8` | 3 × CWE-89 | all three in `bad/`, flowing `mod_user.py → libuser.py` across files; 0 in the `good/` tree, which has the same function names |
| [we45/Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) | `b6a4f97` | SSTI, SQLi, XSS, MD5 | four distinct OWASP categories |
| [anxolerd/dvpwa](https://github.com/anxolerd/dvpwa) | `a1d8f89` | 1 × CWE-89, 1 × CWE-117 | aiohttp, async handlers |
| [miguelgrinberg/microblog](https://github.com/miguelgrinberg/microblog) | `a975ef6` | 0 | well-written app; the `urlsplit(next).netloc != ''` redirect check is recognized as a guard |

Full output is in [`docs/examples/`](docs/examples/). The microblog result is a good sign too, since it
shows the tool isn't just flagging everything.

## What it handles

- Tracks data through assignments, f-strings, `%`/`.format`, slicing, string methods,
  containers, comprehensions, `await`, augmented assignment, loops (to fixpoint), `try/except`.
- Follows input across function calls and files. The first pass records what each function does with
  its parameters, the second uses that at each call site, so a sink two calls deep still gets found.
- Sanitizers only count for the bug type they fix. `shlex.quote` clears command injection but not SQL
  injection, `html.escape` clears XSS only, and `int()` clears everything.
- Recognizes validation checks like `if not x.isdigit(): abort()`, `if x not in ALLOWED: return 400`,
  `if ".." in f or f.startswith("/")`, `re.fullmatch`, `urlparse(x).netloc == ""`, `try: int(x) except: abort()`.
  A check only counts if it holds on every path where the value is still tainted.
- Looks at arguments that change the risk: `subprocess.run(..., shell=True)` vs `shell=False`; `yaml.load(..., Loader=SafeLoader)`;
  `torch.load(..., weights_only=True)`.
- Input sources: Flask `request.*`, FastAPI path params and `Query()`/`Form()`/`Header()`
  (typed `int`/`UUID` params are not tainted), Django `request.GET/POST/COOKIES/META`, aiohttp,
  `sys.argv`, `input()`, `os.environ`, sockets.
- 138 sink signatures and 42 rules covering all ten OWASP 2021 categories: SQLi, command injection,
  code injection, SSTI, XSS, path traversal, Zip/Tar Slip, open redirect, SSRF, deserialization
  (`pickle`, `yaml`, `torch.load`, `marshal`), weak hashing, log injection, XXE.

## Usage

```bash
sinkline scan path/to/app                      # text report
sinkline scan . --format sarif -o out.sarif     # GitHub code scanning
sinkline scan . --format html -o report.html    # shareable single file
sinkline scan . --fail-on high                  # exit 1 for CI
sinkline scan . --baseline old.json             # only new findings (stable fingerprints)
sinkline scan . --min-confidence high           # drop low-confidence flows
sinkline rules                                  # list 42 rules by OWASP category
sinkline explain SL-CMDI-003
```

As a GitHub Action:

```yaml
- uses: samiali38183/sinkline@main
  with:
    path: .
    fail-on: high
```

Python API:

```python
from sinkline import scan_path
res = scan_path("src/")
for f in res.findings:
    print(f.rule_id, f.cwe, f.file, f.line, [s.kind for s in f.flow])
```

## Design

Full writeup is in [`docs/DESIGN.md`](docs/DESIGN.md). Overview:

```
 files ──▶ ast.parse ──▶ resolve.py ──────────────▶ engine.py ─────────────────▶ report.py
                        imports, aliases,     pass 1: run every function      text / JSON /
                        receiver types        with params as param:i labels   SARIF 2.1.0 / HTML
                                              → Summary per function
                              ▲               pass 2: run with real sources,
                              │               consult summaries at call sites
                              │               → Finding(rule, flow, cwe)
                           model.py  ─────────────────┘
                           SOURCES · SINKS (keyword gates) · SANITIZERS (CWE-scoped) · PASSTHROUGH
```

The short version:

1. Each value carries a taint record: where it came from, which bug types it's been sanitized for,
   and the path so far. When two branches merge, a value only stays sanitized if it was sanitized on
   both branches.
2. Inside a function, the engine walks the code and tracks taint per variable. Branches are checked
   separately and merged; loops repeat until nothing changes.
3. Across functions, pass 1 builds a summary of each function and pass 2 uses those summaries at call
   sites. Summaries are keyed by full module path so same-named functions in different files don't mix.
4. Sources, sinks and sanitizers all live in a table in `model.py`, so adding a new sink is one line.

```
sinkline/
  engine.py    1190 lines  abstract interpreter, summaries, guards, fixpoint
  model.py      420 lines  sources / sinks / sanitizers / OWASP+CWE table
  resolve.py    150 lines  import + alias + receiver-type resolution
  report.py     230 lines  text / JSON / SARIF 2.1.0 / HTML
  cli.py        130 lines
bench/
  corpus/       labeled ground truth (VULN:CWE-xx / SAFE tags), incl. cross-file + adversarial cases
  score.py      precision / recall / F1 per CWE; CI gate
  compare_bandit.py
tests/          37 unit tests (one tiny program per engine feature) + corpus gate
```

## Limitations

These are labeled `known FN` / `known FP` in `bench/corpus/hard_app.py` so they count against the score.

- Object fields across methods: `self.target = request.args[...]` in `load()`, `os.system(self.target)`
  in `fire()`. Needs a heap model.
- Closures that capture tainted variables.
- Module globals across requests: `CACHE["q"] = tainted` in one handler, read in another.
- Dict keys: `{"id": 1, "note": tainted}["id"]` reads as tainted (the one FP).
- if/elif chains used as allowlists: `if t == "a": … elif t == "b": … else: abort()`.
- Dynamic dispatch, `getattr`, `exec`-generated code, decorators that rewrite arguments.

Also: this is a static analyzer. It cannot prove exploitability, only reachability without sanitization.
The benchmark is small (109 labeled lines) and I labeled it myself, so the four real-world repos are
the more independent check. More of those would make the numbers stronger.
Python only; no JavaScript templates, no modeling of ORM query builders beyond the raw-SQL entry points
(`sqlalchemy.text`, `QuerySet.raw`, `Session.execute`), no type inference beyond receiver resolution.

## Development

```bash
pip install -e ".[dev]"
pytest -q                      # 37 tests
python bench/score.py -v       # corpus P/R/F1 with per-line FP/FN listing
python bench/compare_bandit.py # needs: pip install bandit
```

## License

MIT
