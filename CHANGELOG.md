# Changelog

## 0.4.1 (2026-11-10)

Benchmark (`python bench/score.py`): recall 0.967 to 0.984, F1 0.983 to 0.992 (TP 59 to 60, FN 2 to 1);
precision stays 1.000 (FP 0). Tests 46 to 91. Public-project results in the README were not re-run for
this release.

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
