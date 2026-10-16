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

The core is a flow-sensitive abstract interpreter over function bodies (`TaintVisitor` in `engine.py`).
`env: dict[str, Taint]` maps variable names (and `self.attr`) to their current taint.

* **Assignment** evaluates the RHS to a `Taint` and binds it to each target, destructuring tuples.
* **Expressions** propagate conservatively: `BinOp`, `JoinedStr`, `Subscript`, `Attribute`, `IfExp`,
  comprehensions, `await`, and a table of string methods all return the union of their operands.
* **Branches** (`if`) are analyzed separately and the environments are joined (may-analysis). A branch
  that unconditionally exits (`return`, `raise`, `abort()`, `sys.exit()`) does not contribute to the join.
* **Loops** iterate to a fixpoint (bounded at 8 rounds; the domain is finite so this always converges
  on real code).
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
records that sink too, so a two-hop flow is reported with the full path.

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

* **Field-sensitive object state across methods.** `self.target = request.args[...]` in one method and
  `os.system(self.target)` in another is not connected. Doing this well requires a heap model.
* **Closures capturing outer taint.** An inner `def` that reads an enclosing tainted local is not tracked.
* **Module globals across requests.** Writing `CACHE["q"]` in one handler and reading it in another.
* **Key-sensitive containers.** `row = {"id": 1, "note": tainted}` taints the whole dict, so `row["id"]`
  reads as tainted. This is the one false positive in the benchmark corpus.
* **Equality chains as allowlists.** `if t == "a": ... elif t == "b": ... else: abort()` is not recognized
  as a guard (the `not in (...)` form is).

Each of these is labeled in `bench/corpus/hard_app.py` as a `known FN`/`known FP` so the score keeps
them visible instead of hiding them.

## Output

* **text** — one block per finding with the full source→sink flow.
* **json** — machine-readable with stable fingerprints (rule + file + function + normalized sink text;
  deliberately excludes line numbers so a baseline survives unrelated edits).
* **sarif** — SARIF 2.1.0 with `codeFlows`/`threadFlows`, so GitHub code scanning renders the path
  step-by-step in the PR.
* **html** — self-contained single file for sharing.
