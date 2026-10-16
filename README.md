# sinkline

[![ci](https://github.com/samiali38183/sinkline/actions/workflows/ci.yml/badge.svg)](https://github.com/samiali38183/sinkline/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.9%E2%80%933.13-blue)
![deps](https://img.shields.io/badge/dependencies-0-brightgreen)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

**Interprocedural taint analysis for Python web apps, mapped to the OWASP Top 10.**
Zero dependencies. Emits SARIF for GitHub code scanning. Built from `ast` up — no Semgrep, no CodeQL.

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

A pattern matcher sees `db.execute(...)` and reports every call. sinkline reports the ones an attacker
can actually reach, shows the path, and stays quiet on the parameterized query three lines below.

## Results

**Labeled benchmark** — 109 hand-labeled lines across Flask, FastAPI, Django and CLI code
(61 vulnerable, 48 safe variants of the same patterns), scored by `bench/score.py`:

| tool | precision | recall | F1 |
|---|---|---|---|
| **sinkline** | **0.983** | **0.951** | **0.967** |
| bandit 1.8 (lenient: any hit on a vulnerable line counts) | 0.623 | 0.541 | 0.579 |

Every sinkline miss (3 FN, 1 FP) is a labeled, documented design limit — see
[What it does not do](#what-it-deliberately-does-not-do). The score is a CI gate (`tests/test_corpus.py`).

**Real-world case study** — run against four public Flask/aiohttp apps as checked out on 2026-10-15:

| repo | commit | findings | notes |
|---|---|---|---|
| [fportantier/vulpy](https://github.com/fportantier/vulpy) | `5249cc8` | 3 × CWE-89 | all three in `bad/`, flowing `mod_user.py → libuser.py` across files; **0 in the `good/` tree** that defines the same function names |
| [we45/Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) | `b6a4f97` | SSTI, SQLi, XSS, MD5 | four distinct OWASP categories |
| [anxolerd/dvpwa](https://github.com/anxolerd/dvpwa) | `a1d8f89` | 1 × CWE-89, 1 × CWE-117 | aiohttp, async handlers |
| [miguelgrinberg/microblog](https://github.com/miguelgrinberg/microblog) | `a975ef6` | **0** | well-written app; the `urlsplit(next).netloc != ''` redirect check is recognized as a guard |

Full output in [`docs/examples/`](docs/examples/). The microblog result matters as much as the others:
a tool that cannot say "clean" is noise.

## What it understands

- **Flow-sensitive dataflow** through assignments, f-strings, `%`/`.format`, slicing, string methods,
  containers, comprehensions, `await`, augmented assignment, loops (to fixpoint), `try/except`.
- **Interprocedural summaries** — two-pass analysis: learn what every function does with each parameter
  (flows to return? reaches a sink? is a sanitizer wrapper?), then apply at call sites. Flows through
  helpers, methods, and other files are reported at the entry point with the path into the callee.
  Transitive: a sink two hops deep is still found.
- **CWE-scoped sanitizers** — `shlex.quote` clears command injection and nothing else; `html.escape`
  clears XSS and nothing else; `int()` clears everything. A shell-safe value is not SQL-safe.
- **Validation guards** — `if not x.isdigit(): abort()`, `if x not in ALLOWED: return 400`,
  `if ".." in f or f.startswith("/")`, `re.fullmatch`, `urlparse(x).netloc == ""`, `try: int(x) except: abort()`.
  Boolean combinations follow De Morgan; a guard only survives a branch merge if it holds on every
  path where the variable is still tainted.
- **Keyword gates** — `subprocess.run(..., shell=True)` vs `shell=False`; `yaml.load(..., Loader=SafeLoader)`;
  `torch.load(..., weights_only=True)`.
- **Framework sources** — Flask `request.*`, FastAPI path params and `Query()`/`Form()`/`Header()`
  (typed `int`/`UUID` params are not tainted), Django `request.GET/POST/COOKIES/META`, aiohttp,
  `sys.argv`, `input()`, `os.environ`, sockets.
- **138 sink signatures / 42 rules** across all ten OWASP 2021 categories: SQLi, command injection,
  code injection, SSTI, XSS, path traversal, Zip/Tar Slip, open redirect, SSRF, deserialization
  (`pickle`, `yaml`, `torch.load`, `marshal`), weak hashing, log injection, XXE.

## Install & use

```bash
pip install git+https://github.com/samiali38183/sinkline
sinkline scan path/to/app                      # text report
sinkline scan . --format sarif -o out.sarif     # GitHub code scanning
sinkline scan . --format html -o report.html    # shareable single file
sinkline scan . --fail-on high                  # exit 1 for CI
sinkline scan . --baseline old.json             # only new findings (stable fingerprints)
sinkline rules                                  # list rules by OWASP category
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

## How it works

Read [`docs/DESIGN.md`](docs/DESIGN.md) for the full writeup. The short version:

1. **Abstract domain.** A `Taint` is `(labels, cleared_cwes, trail)`. Join = union of labels,
   *intersection* of cleared CWEs (sanitized on one path ≠ sanitized). A sink for CWE `c` fires when
   labels ≠ ∅ and `c ∉ cleared`.
2. **Intraprocedural.** An abstract interpreter over function bodies keeps `env: name → Taint`.
   Branches are analyzed separately and joined (may-analysis). Branches that exit don't join.
   Loops iterate to a fixpoint.
3. **Interprocedural.** Pass 1 runs every function with parameters bound to `param:i` labels and
   records a `Summary`. Pass 2 runs with real sources and consults summaries at call sites.
   Summaries are keyed by module-qualified name derived from the file path, so `bad/libuser.py` and
   `good/libuser.py` don't collide; ambiguous short names are poisoned rather than guessed.
4. **Everything else is data.** `model.py` is a declarative table of sources, sinks (with keyword
   gates), sanitizers (with the CWEs they clear), and passthrough functions. Adding a sink is one line.

```
sinkline/
  engine.py    1100 lines  abstract interpreter, summaries, guards, fixpoint
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

## What it deliberately does not do

These are labeled `known FN` / `known FP` in `bench/corpus/hard_app.py` so the score keeps them visible.

- **Object fields across methods** — `self.target = request.args[...]` in `load()`, `os.system(self.target)`
  in `fire()`. Needs a heap model.
- **Closures capturing outer taint.**
- **Module globals across requests** — `CACHE["q"] = tainted` in one handler, read in another.
- **Key-sensitive containers** — `{"id": 1, "note": tainted}["id"]` reads as tainted (the one FP).
- **Equality chains as allowlists** — `if t == "a": … elif t == "b": … else: abort()`.
- Dynamic dispatch, `getattr`, `exec`-generated code, decorators that rewrite arguments.

Also: this is a static analyzer. It cannot prove exploitability, only reachability without sanitization.

## Development

```bash
pip install -e ".[dev]"
pytest -q                      # 37 tests
python bench/score.py -v       # corpus P/R/F1 with per-line FP/FN listing
python bench/compare_bandit.py # needs: pip install bandit
```

## License

MIT
