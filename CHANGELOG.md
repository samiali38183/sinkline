# Changelog

## Unreleased

- A view that returns the result of a sanitizer that does not clear CWE-79 is now reported as XSS. Before, any
  sanitizer call in a `return` was treated as safe, so `return shlex.quote(request.args["x"])` and
  `return os.path.basename(...)` were missed. A sanitizer that clears CWE-79 (`escape`, `html.escape`) is still safe.
  Benchmarks are unchanged (corpus TP 60, FP 0, FN 1, TN 48; BenchmarkPython 10 taint categories 0.73 / 0.21).
- SARIF: `invocations[0].executionSuccessful` is false when a file could not be parsed (it was always true, even next
  to an error-level `SL-NOTIFY-PARSE` notification).
- Tests 184 to 186.

## 0.5.1 (2026-11-11)

Fixes from an outside review of 0.5.0. Benchmarks are unchanged: corpus TP 60, FP 0, FN 1, TN 48 (P 1.000 /
R 0.984 / F1 0.992); OWASP BenchmarkPython 10 taint categories TPR 0.73 / FPR 0.21 (per-test table identical to
0.5.0). Tests 138 to 184.

Behavior changes (read before upgrading a CI gate)
- A path that does not exist now exits 2 with `path not found` (0.5.0 printed "0 finding(s) in 0 file(s)" and
  exited 0). The GitHub Action therefore fails on a mistyped `path`.
- `--fail-on` now exits 3 when no Python file was analyzed (empty directory, only unparseable files, everything
  excluded by `--exclude-tests`). 0.5.0 exited 0. Without `--fail-on` the scan still exits 0, with a warning.
- New `--fail-on-parse-error` (Action input `fail-on-parse-error`, default `false`): exit 3 if any file could not
  be read or parsed. Without it, parse failures do not change the exit code, as before.
- Exit codes are now documented: 0 clean, 1 findings at/above `--fail-on`, 2 error, 3 incomplete scan. An unwritable
  `-o` file is exit 2 (it was a traceback).
- Parse failures are listed on stderr (count and names), as `files_failed` next to `errors` in JSON, and as SARIF
  `toolExecutionNotifications` with a file location (`SL-NOTIFY-PARSE`, plus `SL-NOTIFY-NOFILES` for an empty scan).
  A file with null bytes no longer reports "line None".
- The Action skips the SARIF upload when no report was written and names the failing exit code.
- Public-project output changes (more findings, all through the fixes below): vulpy 3 to 5 findings, microblog 0 to 1,
  dvpwa same count with a different source line. `docs/examples/` regenerated.

Analysis
- A lambda bound to a name and called (`f = lambda c: subprocess.run(c, shell=True); f(x)`) or called in place is
  analyzed at the call with its arguments bound; 0.5.0 evaluated nothing inside a lambda. Not followed: lambdas passed as
  callbacks, stored in containers or attributes, returned, or called from another function.
- Calling a source attribute (`request.get_json()`, `request.get_data()`, `await request.post()`) now returns tainted
  data. 0.5.0 lost the taint when the result was assigned or used in a `match` subject
  (`match request.get_json(): case {"cmd": c}: os.system(c)` produced no finding); `request.get_json()["k"]`
  written inline was already found. The `match` shape in the review (`match request.args.get("a"): case str() as s`)
  was already handled in 0.5.0 and is now pinned by a test.
- Summaries are now registered in a first round before names are resolved. In 0.5.0 a call in `good/libapi.py` to
  `libuser.login` could resolve to a same-named function in a sibling package (`bad/libuser.py`) when the file
  defining the right one sorted later, and the wrong sink stuck. Found while checking vulpy after the `get_json` fix.

Docs
- README: exit-code table, Action inputs, a prior-art note (Semgrep taint mode, CodeQL, Pysa, Joern) and a statement
  that the Semgrep column is the default registry rules, not taint mode with custom rules.

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
