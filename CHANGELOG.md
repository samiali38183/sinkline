# Changelog

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
