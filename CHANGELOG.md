# Changelog

## 0.5.0 (2026-11-11)

External benchmark (OWASP BenchmarkPython v0.1, commit `f129148`, scored with `bench/external/score.py`, not the
official scorer; see `bench/external/README.md`). On the 10 taint categories sinkline 0.4.1 scored TPR 0.41 /
FPR 0.20 (TPR-FPR +0.21); 0.5.0 scores 0.73 / 0.21 (+0.52). Bandit 1.9.4 scores 0.13 / 0.06 (+0.07) and
Semgrep OSS 1.185.0 (`p/python`, `p/owasp-top-ten`) 0.07 / 0.03 (+0.04). Over all 14 categories, including
weak hash, weak PRNG, cookie flags and trust boundary that sinkline does not cover, 0.5.0 scores +0.27 and
Bandit +0.36. The 0.5.0 changes were chosen by reading the 0.4.1 failures, so these numbers are not held out.
The self-labeled corpus is unchanged (TP 60, FP 0, FN 1, TN 48; F1 0.992), and the README now puts the
external result next to it.

Analysis
- A returned call result is XSS when it is the tainted string itself (`return request.args.get("q")`,
  `.strip()`, `.format()`, `str()`, a user helper that returns its argument). Response constructors, redirects,
  JSON and renderers are still excluded; an unknown call is not guessed at.
- `HTMLResponse(content=...)`, `HttpResponse(content=...)`, `Response(response=...)` keyword bodies are sinks;
  `render_template_string` with a tainted template is also reported as XSS (next to SSTI);
  `make_response((body, headers))` only checks the body.
- Dicts built by constant-key assignment (`m = {}; m["a"] = ...`) keep per-key taint (they were whole-container
  tainted).
- `match` is a branch: cases are joined (before, the last case silently overwrote earlier ones), captured names
  take the subject's taint, and a `match` on a constant subject runs only the matching case.
- Statically decided `if` / ternary conditions on literals and known-constant locals prune the dead branch.
- Receiver types come through a helper that returns an instance (`conn = get_connection()`), and
  `base / name` keeps the `pathlib.Path` type.
- Sinks added: `codecs.open`, `elementpath.select` / `iter_select`, `lxml.etree._ElementTree.xpath`,
  `pathlib.Path` read / write / open / unlink / exists / is_file (SL-PATH-008, 43 rules, 151 sink signatures).
  A quote check (`"'" in x`) is a guard for XPath only.
- Several sinks of one call qualname with different CWEs are now all reported (one finding per call per CWE).

Supply chain
- Every GitHub Action in `.github/workflows/*.yml` and `action.yml` is pinned by full commit SHA with a version
  comment; workflow permissions are `{}` with per-job `contents: read` and `security-events: write` only on the
  SARIF job; checkouts do not persist credentials. zizmor 1.32.0: no findings at the default persona (was 25,
  12 high, 5 medium); 8 pedantic/auditor-only style notes remain (anonymous job definitions, undocumented permission
  comments, concurrency limits).

Tests 91 to 138.

## 0.4.1 (2026-11-10)

Benchmark (`python bench/score.py`): recall 0.967 to 0.984, F1 0.983 to 0.992 (TP 59 to 60, FN 2 to 1);
precision stays 1.000 (FP 0). Tests 46 to 91. The four public projects in the README were re-scanned
at their pinned commits with this release: vulpy, Vulnerable-Flask-App and dvpwa produce output identical to
`docs/examples/`, and microblog still produces 0 findings.

Security
- GitHub Action: inputs (`path`, `fail-on`, `min-confidence`) were interpolated straight into a shell
  line with `${{ inputs.* }}`, so a workflow that passed an untrusted or attacker-influenced value
  (for example a branch name or PR-derived string) could run arbitrary commands on the runner
  (CWE-78 / GitHub Actions script injection). Inputs now go through `env:`, are used quoted as single
  arguments in `scripts/action-scan.sh`, and `fail-on` / `min-confidence` are validated against an
  allow-list. A path starting with `-` is no longer parsed as an option. `tests/test_action.py` runs
  the script with hostile values; the README section "Using the GitHub Action safely" shows the unsafe
  and safe forms. If you used the action with any input you do not fully control, upgrade and pin to a
  tag or commit.

Analysis
- Closures: a nested `def` now starts from the enclosing function's taint at the point of the `def`
  (pass 2 only, excluding its own parameters), so `raw = request.args.get("q")` followed by an inner
  function that reads `raw` is reported. Pass 1 is unchanged: there the enclosing environment holds
  `param:N` labels of the outer function, which would corrupt the inner function's summary. Closes the
  known FN at `hard_app.py:211`.

Fixes
- try/except: taint after a `try` is now the join of the try body (plus `else`) and each handler that
  does not exit, with handlers entering from the join of every state the body passed through. Before,
  the handler body was visited in sequence, so `host = request.args["h"]` followed by
  `except: host = "localhost"` lost the taint (false negative). `docs/DESIGN.md` already described a join.
- `--exclude-tests` matched the substring `test` in a file name, so `latest.py`, `attestation.py` and
  `contest/app.py` were skipped, and any scan root below a directory named `tests` skipped everything.
  It now matches path segments relative to the scan root (`test/`, `tests/`, `testing/`) and the file
  names `test_*.py`, `*_test.py`, `tests.py`, `conftest.py`.
- `_returns_html` ended in `... or True`, which made the preceding `"<" in src` and `isinstance` checks
  dead code. The behavior was already "flag any tainted string return except JSON-like values"; the
  dead expression is removed and that behavior is pinned by tests. Narrowing to returns that contain
  `<` would miss `return request.args["q"]`, which Flask serves as HTML.

Docs
- README: first-person wording replaced with neutral wording about who labeled the corpus.

Tests
- Two mutants survived the suite and are now killed: a loop iteration cap of 1 (a value that moves
  between variables inside a loop needs a second round) and a bare-attribute fallback in the
  function-summary lookup (`asyncio.run(x)` must not resolve to a user function named `run`). Each new
  test was checked to fail with the mutant applied.

## 0.4.0 (2026-11-10)

Benchmark (`python bench/score.py`): precision 0.983 to 1.000, recall 0.951 to 0.967, F1 0.967 to
0.983 (TP 58 to 59, FP 1 to 0, FN 3 to 2). Results on the four public projects in the README are
unchanged.

Analysis
- Instance fields across methods: request data stored in `self.<attr>` by one method is seen by
  other methods of the same class that read it. Reported at medium confidence, with a flow step
  naming the method that stored it. Closes the known FN at `hard_app.py:183`.
- Key-sensitive dict literals: `{"id": 1, "note": tainted}["id"]` is clean; `["note"]`,
  `.get("note")` and `.pop("note")` are tainted; `d["k"] = v` updates one key. Removes the known FP
  at `hard_app.py:84`.

Fixes
- The summary pass now runs to a fixpoint instead of two fixed rounds. A chain of three or more
  helpers defined caller-first was missed before.
- `re.escape` no longer clears SQL injection (CWE-89). It escapes regex metacharacters, not SQL, so
  `"... '" + re.escape(x) + "'"` passed to `execute` is now reported.
- Duplicate sink entries no longer accumulate in function summaries across pass-1 rounds.
- `hard_app.py:128` was labeled as a known FP for `if/elif` equality chains, but the engine already
  treats `if/elif ... else: abort()` as a guard and never flagged it. The label and the README
  limitation were wrong; both are corrected and the case has a test.

Tooling
- `.pre-commit-hooks.yaml`: run sinkline as a pre-commit hook.
- `.github/workflows/pages.yml`: publishes the HTML report for the benchmark corpus to GitHub Pages,
  in a workflow separate from CI.
- `ruff` and `mypy` configured in `pyproject.toml` and clean; new `lint` job in CI.
- The corpus gate in `tests/test_corpus.py` is raised to precision 0.99 and recall 0.96.
- 46 tests (was 37).

## 0.3.0

Initial version on GitHub: two-pass interprocedural taint analysis, 42 rules / 138 sink signatures,
CWE-scoped sanitizers, validation guards, text/JSON/SARIF/HTML output, GitHub Action, labeled
benchmark and bandit comparison.
