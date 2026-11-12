# Design notes

## Why taint analysis, and why from scratch

Pattern-matching linters (bandit, semgrep without taint mode) answer "is there a dangerous call here?".
That produces one finding per `cursor.execute` regardless of whether the argument came from a config
file or from `request.args`. Taint analysis answers the question a security reviewer actually asks:
**can attacker-controlled bytes reach this sink without passing through a sanitizer?**

sinkline is written against the Python `ast` module only. No tree-sitter, no Semgrep, no CodeQL
database. The point is to own every decision in the pipeline: how taint is represented, how it moves
through expressions, how branches merge, how calls are summarized, and when a sanitizer counts.

## The abstract domain

A `Taint` value is a triple:

```
labels   : frozenset[str]   # which sources this value may have come from ("flask.request.args", "param:0", ...)
cleared  : frozenset[str]   # CWE ids this value has been sanitized against ("CWE-78", "*")
trail    : tuple[FlowStep]  # provenance, for the report
```

`EMPTY` (no labels) is bottom. The join is set union on labels, set **intersection** on `cleared`
(a value that is sanitized on one path and not on the other is not sanitized), and trail concatenation.
A sink with CWE `c` fires when `labels` is non-empty and `c ∉ cleared` and `"*" ∉ cleared`.

Sanitizers are deliberately CWE-scoped: `shlex.quote` clears CWE-78 and nothing else. `html.escape`
clears CWE-79 and nothing else. `int()` clears everything, because its output can only be a number.
Treating sanitization as a global boolean is the most common source of false negatives in homegrown
taint tools; a value that is shell-safe is not SQL-safe.

## Intraprocedural analysis

The core is a flow-sensitive abstract interpreter over function bodies (`FileAnalyzer` in `engine.py`).
`env: dict[str, Taint]` maps variable names (and `self.attr`) to their current taint.

* **Assignment** evaluates the RHS to a `Taint` and binds it to each target, destructuring tuples.
* **Expressions** propagate conservatively: `BinOp`, `JoinedStr`, `Subscript`, `Attribute`, `IfExp`,
  comprehensions, `await`, and a table of string methods all return the union of their operands.
* **Branches** (`if`) are analyzed separately and the environments are joined (may-analysis). A branch
  that unconditionally exits (`return`, `raise`, `abort()`, `sys.exit()`) does not contribute to the join.
* **Loops** iterate until the environment stops changing, bounded at 3 rounds (`MAX_LOOP_ROUNDS`).
* **Dict literals with constant string keys** keep per-key taint alongside the container taint, so
  `row = {"id": 1, "note": tainted}` makes `row["note"]` and `row.get("note")` tainted and `row["id"]`
  clean. `row["k"] = v` updates one key. A `**spread` or computed key, or any value that is not a
  plain dict literal, falls back to container-level taint. At a branch join two keyed dicts are joined
  key by key; a keyed dict joined with anything else loses its keys.
* **try/except** joins the body with every handler; an `except` that exits removes the "exception path"
  from consideration, which is how `try: x = int(x) except ValueError: abort(400)` is understood.

## Validation guards

Not every sanitizer is a function call. Real code validates with conditions:

```python
if not uid.isdigit(): abort(400)          # uid is numeric below this line
if ".." in f or f.startswith("/"): abort() # f cannot escape its directory below this line
if host not in ALLOWED: return 400        # host is one of N constants below this line
if not re.fullmatch(r"[a-z]+", h): abort()
if urlparse(nxt).netloc != "": abort()    # same-origin redirect
```

`_guards_from_test` turns a test expression into two maps — guards that hold when the test is true and
when it is false — then `visit_If` applies the right map to each branch. Guards are also CWE-scoped:
`".." in f` is a path guard, not a shell guard. Boolean combinations follow De Morgan: `(A or B)` being
false means both `A` and `B` are false, so the false-branch guard is the **union** of the parts;
`(A and B)` being true means both are true, so the true-branch guard is the union; the other
two cases are intersections.

When branches rejoin, a guard survives only if it holds on every path on which the variable is still
tainted. That is what distinguishes

```python
if q.isdigit():
    db.execute("..." + q)   # safe
else:
    db.execute("..." + q)   # vulnerable
```

from an early-return guard.

## Interprocedural analysis

Two passes over the whole project:

**Pass 1 — summaries.** Every function and method is analyzed with each parameter bound to the synthetic
label `param:i`. The result is a `Summary`:

```
returns_from   : set[int]            # which parameters flow to the return value
returns_source : bool                # the return value is tainted regardless (wraps request.args)
sinks_from     : dict[int, [InnerSink]]  # which parameters reach which sinks, including transitively
sanitizes      : frozenset[str]      # the function is a thin wrapper around a known sanitizer
```

`sinks_from` is transitive: if `outer(x)` calls `inner(x)` and `inner` has a sink, `outer`'s summary
records that sink too, so a multi-hop flow is reported with the full path. Pass 1 is repeated over
all files until no summary changes (capped at 10 rounds). Summaries only grow, so this terminates,
and the result does not depend on the order functions are defined in.

Pass 1 also records **instance fields**: when a method stores request data in `self.<attr>`, that
taint is kept per class (`module.Class.attr`). In pass 2, a method that reads `self.<attr>` without
assigning it first sees the stored taint, so `load()` setting `self.target` from `request.args` and
`fire()` passing it to `os.system` is reported, with a flow step naming the method that stored it.
This is flow-insensitive across methods (it does not know whether `load()` runs before `fire()`), so
these findings are reported at medium confidence. Parameter taint stored on `self` is not recorded
(it depends on the caller and is already covered by summaries), and inheritance is not followed.

**Pass 2 — report.** Function bodies are analyzed again with real sources (`request.args`, route
parameters, `sys.argv`). At each call site the summary is consulted: tainted arguments flow to the
return value (`returns_from`), reach sinks inside the callee (`sinks_from`, reported at the call site
with a flow step pointing into the callee's file), or get cleared (`sanitizes`).

Summaries are context-insensitive (one summary per function, not per call site). This is the standard
trade-off: it keeps the analysis linear in program size and in practice loses very little precision
on web handler code, which is shallow.

### Name resolution across files

Summaries are keyed by module-qualified name derived from the file path: `bad/libuser.py::login` becomes
`bad.libuser.login`, with the shorter aliases `libuser.login` and `login`. Shorter aliases are only
usable when unambiguous; when two files define the same short name, that alias is poisoned and callers
must match a longer path. Call sites first try to resolve relative to their own package (in
`bad/mod_user.py`, `libuser.login` means `bad.libuser.login`), which is how the `vulpy` case study
reports the `bad/` tree and stays silent on the `good/` tree even though both define `libuser.login`.

Library names never resolve to user functions through a bare-name fallback. `subprocess.run(...)` cannot
hit a user function called `run`; only `ast.Name` call targets and `self.`/user-class receivers use
bare lookups.

## Sources, sinks, sanitizers are data

`model.py` is a declarative table. Adding a sink is one line:

```python
_s("torch.load", "SL-DESER-003", "Unsafe torch.load (pickle) of tainted path", "A08:2021", "CWE-502",
   "critical", gate=("weights_only", False), gate_default=True)
```

`gate` expresses "only dangerous when this keyword is / defaults to this value", which handles
`subprocess.run(..., shell=True)`, `yaml.load(..., Loader=SafeLoader)`, and `torch.load(..., weights_only=True)`
without special-casing in the engine. `recv=True` marks sinks where the *receiver* is the tainted
thing (`tarfile.open(user_path).extractall()`).

Framework knowledge is also data: FastAPI route decorators mark path parameters as sources, except
those annotated `int`/`float`/`bool`/`UUID`, which pydantic will have coerced. Django views take a
`request` parameter whose `GET`/`POST`/`COOKIES`/`META` attributes are sources.

## What it deliberately does not do

* **A heap model.** Instance fields are tracked per class, not per object, and not through
  inheritance, aliases (`other = self`) or attributes of non-`self` objects.
* **Closures beyond definition-time capture.** A nested `def` starts from a copy of the enclosing
  function's taint at the point of the `def` (pass 2 only, minus its own parameters). Variables assigned
  in the enclosing function after the `def`, and closures returned and called elsewhere, are not tracked.
* **Lambdas beyond direct calls.** `f = lambda c: sink(c); f(x)` and `(lambda c: sink(c))(x)` are analyzed
  at the call site: the body is evaluated with the parameters bound to the argument taints (no summary, so it is
  re-evaluated per call and sees the caller's variables as of the call; depth-limited to 3). A lambda passed as a
  callback, stored in a container or attribute, or returned is not followed.
* **Module globals across requests.** Writing `CACHE["q"]` in one handler and reading it in another.
* **Key-sensitive containers beyond dict literals.** Lists, `dict(...)` calls and dicts built up in
  loops are tracked as a whole.

The module-global case is labeled in `bench/corpus/hard_app.py` as `known FN` so the
score keeps it visible instead of hiding it.

## Output

* **text** — one block per finding with the full source→sink flow.
* **json** — machine-readable with stable fingerprints (rule + file + function + normalized sink text;
  deliberately excludes line numbers so a baseline survives unrelated edits).
* **sarif** — SARIF 2.1.0 with `codeFlows`/`threadFlows`, so GitHub code scanning renders the path
  step-by-step in the PR.
* **html** — self-contained single file for sharing.

Files that cannot be parsed (and a scan that analyzes no file) are part of the output, not silent: they appear on
stderr, in the JSON `errors` / `files_failed` fields and as SARIF `toolExecutionNotifications`. Exit codes are
0 clean, 1 findings at/above `--fail-on`, 2 error (missing or unreadable path), 3 incomplete scan
(`--fail-on-parse-error`, or zero files analyzed under `--fail-on`); see the README table.
