"""The taint engine.

Design (what an interviewer will ask about):

* **Abstract domain.** Each variable maps to a `Taint` — a set of labels (where the data came
  from) plus the provenance chain (file/line hops) that got it there. Absence = untainted.
* **Flow-sensitive, intraprocedural core.** We walk each function body in order, with a
  simple fixpoint over loops (iterate until the environment stops changing, max N rounds).
  Branches merge by union (may-analysis: we care about *any* path reaching a sink).
* **Interprocedural via summaries.** Pass 1 computes, for every function, which parameter
  indexes flow to its return value (a *summary*). Pass 2 uses summaries at call sites so
  `clean = normalize(user)` stays tainted if `normalize` returns its argument. Pass 1 also
  records which parameters reach a sink *inside* the callee, so tainted arguments to
  `run_query(sql)` are reported at the call site with the full interprocedural path.
* **Sanitizers are CWE-scoped.** `shlex.quote` clears command-injection taint but not
  path-traversal taint. Coercions like `int()` clear everything.
* **Validation guards.** `if not x.isdigit(): abort()` / `if x in ALLOWED:` / `if re.fullmatch`
  are recognized; inside the guarded branch (or after an early return) the name is treated as
  sanitized. This is the single biggest false-positive killer on real code.
* **Field sensitivity.** `request.args` is tainted; `request.method` is not. Dict/attr access on
  a tainted value stays tainted; access on a container that merely *holds* a tainted value is
  tainted unless we can prove the key is a different constant (we don't try - conservative).
* **Sink gates.** `subprocess.run(cmd, shell=True)` fires; `shell=False` doesn't.
  `yaml.load(x)` fires unless `Loader=SafeLoader`. `torch.load(p)` fires unless weights_only=True.

Deliberate non-goals: no pointer analysis, no class hierarchy resolution beyond simple
constructor tracking, no alias tracking through mutable containers (`lst.append(t)` taints lst).
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from .finding import Finding, FlowStep
from .model import (
    PASSTHROUGH_FUNCS,
    STR_PROPAGATING_METHODS,
    Sanitizer,
    Sink,
    Source,
    build_indexes,
)
from .resolve import Resolver, Scope

_SOURCES, _SINKS, _SANITIZERS = build_indexes()

MAX_LOOP_ROUNDS = 3
MAX_FLOW_STEPS = 24


# ---------------------------------------------------------------------------
# Taint value
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Taint:
    labels: FrozenSet[str]                 # source labels
    cleared: FrozenSet[str] = frozenset()  # CWEs sanitized along the way ("*" = all)
    trail: Tuple[FlowStep, ...] = ()       # provenance

    def __bool__(self) -> bool:
        return bool(self.labels) and "*" not in self.cleared

    def is_safe_for(self, cwe: str) -> bool:
        return "*" in self.cleared or cwe in self.cleared

    def union(self, other: "Taint") -> "Taint":
        if not other.labels:
            return self
        if not self.labels:
            return other
        # merging: a value is only cleared for a CWE if BOTH paths cleared it
        trail = self.trail if len(self.trail) >= len(other.trail) else other.trail
        return Taint(self.labels | other.labels, self.cleared & other.cleared, trail)

    def step(self, s: FlowStep) -> "Taint":
        if len(self.trail) >= MAX_FLOW_STEPS:
            return self
        if self.trail and self.trail[-1].line == s.line and self.trail[-1].file == s.file and self.trail[-1].kind == s.kind:
            return self
        return Taint(self.labels, self.cleared, self.trail + (s,))

    def sanitize(self, cwes: FrozenSet[str], s: FlowStep) -> "Taint":
        return Taint(self.labels, self.cleared | cwes, self.trail + (s,))


EMPTY = Taint(frozenset())


# ---------------------------------------------------------------------------
# Function summaries (pass 1)
# ---------------------------------------------------------------------------

_MISSING = object()


@dataclass
class Summary:
    name: str
    params: List[str]
    returns_from: Set[int] = field(default_factory=set)   # param indexes that reach return
    returns_source: bool = False                          # return is tainted regardless
    sinks_from: Dict[int, List["InnerSink"]] = field(default_factory=dict)  # param idx -> sinks reachable from that param
    file: str = ""
    sanitizes: FrozenSet[str] = frozenset()               # if the function is itself a sanitizer wrapper
    is_route: bool = False
    returns_http: bool = False


@dataclass(frozen=True)
class InnerSink:
    sink: Sink
    file: str
    line: int
    col: int
    text: str
    fn: str


# ---------------------------------------------------------------------------
# Per-file analysis
# ---------------------------------------------------------------------------

class FileAnalyzer(ast.NodeVisitor):
    def __init__(self, path: str, source: str, tree: ast.Module, summaries: Dict[str, Summary], collect: bool):
        self.path = path
        self.lines = source.splitlines()
        self.tree = tree
        self.summaries = summaries
        self.collect = collect  # pass 1 (collect summaries) vs pass 2 (report)
        self.module_names = self._module_names(path)
        self.resolver = Resolver()
        self.scope = self.resolver.module_scope
        self.env: Dict[str, Taint] = {}
        self.findings: List[Finding] = []
        self.current_fn: Optional[str] = None
        self.current_summary: Optional[Summary] = None
        self.param_index: Dict[str, int] = {}
        self.in_http_view = False
        self.class_stack: List[str] = []
        self.loop_depth = 0
        self.guards: Dict[str, FrozenSet[str]] = {}  # name -> cwes cleared by validation guard in this block

    # -- helpers -------------------------------------------------------------
    def _register_alias(self, alias: str, summ: "Summary") -> None:
        """Shorter names are only usable when unambiguous: bad/libuser.login vs good/libuser.login both
        claim `libuser.login` and `login`, so those aliases are poisoned (None) and callers must match
        a longer path."""
        cur = self.summaries.get(alias, _MISSING)
        if cur is _MISSING:
            self.summaries[alias] = summ
        elif cur is not summ:
            self.summaries[alias] = None  # type: ignore[assignment]

    @staticmethod
    def _module_names(path: str) -> List[str]:
        """'app/auth/routes.py' -> ['app.auth.routes', 'auth.routes', 'routes']; 'pkg/__init__.py' -> ['pkg']."""
        p = path.replace("\\", "/")
        if p.endswith(".py"):
            p = p[:-3]
        parts = [x for x in p.split("/") if x and x not in (".", "..")]
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        if not parts:
            return []
        return [".".join(parts[i:]) for i in range(len(parts))]
    def text(self, node: ast.AST) -> str:
        try:
            return self.lines[node.lineno - 1].strip()
        except Exception:  # pragma: no cover
            return ""

    def fs(self, node: ast.AST, kind: str, note: str = "") -> FlowStep:
        return FlowStep(self.path, getattr(node, "lineno", 0), getattr(node, "col_offset", 0), kind, self.text(node), note)

    def qual(self, node: ast.AST) -> Optional[str]:
        return self.resolver.qualname(node, self.scope)

    def lookup_sink(self, qual: Optional[str]) -> List[Sink]:
        if not qual:
            return []
        for cand in Resolver.candidate_qualnames(qual):
            if cand in _SINKS:
                return _SINKS[cand]
        return []

    def lookup_sanitizer(self, qual: Optional[str]) -> Optional[Sanitizer]:
        if not qual:
            return None
        for cand in Resolver.candidate_qualnames(qual):
            if cand in _SANITIZERS:
                return _SANITIZERS[cand]
        # user-defined sanitizer wrappers discovered in pass 1
        s = self.summaries.get(qual) or self.summaries.get(qual.split(".")[-1])
        if s and s.sanitizes:
            return Sanitizer(qual, s.sanitizes, "user sanitizer")
        return None

    def get(self, name: str) -> Taint:
        t = self.env.get(name, EMPTY)
        g = self.guards.get(name)
        if t and g:
            return Taint(t.labels, t.cleared | g, t.trail)
        return t

    # -- scopes / imports ----------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        self.resolver.visit_import(node, self.scope)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.resolver.visit_import_from(node, self.scope)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.class_stack.append(node.name)
        for b in node.body:
            self.visit(b)
        self.class_stack.pop()

    # -- functions -----------------------------------------------------------
    def _fn_key(self, node: ast.AST) -> str:
        return ".".join(self.class_stack + [node.name]) if self.class_stack else node.name

    def _decorator_quals(self, node) -> List[str]:
        out = []
        for d in node.decorator_list:
            target = d.func if isinstance(d, ast.Call) else d
            q = self.qual(target)
            if q:
                out.append(q)
        return out

    def _is_route(self, decos: List[str]) -> Tuple[bool, bool]:
        """(params tainted?, http view?)"""
        params = False
        http = False
        for q in decos:
            for cand in Resolver.candidate_qualnames(q):
                s = _SOURCES.get(cand)
                if s and s.params:
                    params = True
                    http = True
            last = q.split(".")[-1]
            if last in {"route", "get", "post", "put", "delete", "patch", "api_view", "view", "websocket"}:
                http = True
            if "login_required" in q or "csrf_exempt" in q or "require_http_methods" in q:
                http = True
        return params, http

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        pass

    def _function(self, node) -> None:
        key = self._fn_key(node)
        saved = (self.env, self.scope, self.current_fn, self.current_summary, self.param_index, self.in_http_view, self.guards)
        self.env = {}
        self.guards = {}
        self.scope = Scope(self.scope)
        self.current_fn = key
        args = node.args
        names = [a.arg for a in args.posonlyargs + args.args]
        if args.vararg:
            names.append(args.vararg.arg)
        names += [a.arg for a in args.kwonlyargs]
        if args.kwarg:
            names.append(args.kwarg.arg)
        self.param_index = {n: i for i, n in enumerate(names)}

        decos = self._decorator_quals(node)
        params_tainted, http_view = self._is_route(decos)
        self.in_http_view = http_view
        qkey = f"{self.module_names[0]}.{key}" if self.module_names else key
        summ = self.summaries.get(qkey)
        if summ is None:
            summ = Summary(key, names, file=self.path)
            self.summaries[qkey] = summ
            # every shorter module suffix: app.auth.routes.login -> auth.routes.login -> routes.login -> login
            for mod in self.module_names[1:]:
                self._register_alias(f"{mod}.{key}", summ)
            self._register_alias(key, summ)
        summ.is_route = http_view
        self.current_summary = summ

        # Pass 1: treat every param as tainted with its own label so we learn flows.
        # Pass 2: params are tainted only if the function is a route or we are in a route.
        for i, n in enumerate(names):
            if n in ("self", "cls"):
                continue
            ann = self._annotation_of(node, n)
            typed_scalar = ann in {"int", "float", "bool", "UUID", "uuid.UUID", "datetime", "date", "Decimal"}
            if self.collect:
                self.env[n] = Taint(frozenset({f"param:{i}"}))
            elif params_tainted and not typed_scalar:
                self.env[n] = Taint(frozenset({"route param"}), trail=(self.fs(node, "source", f"route parameter `{n}`"),))
            # Django style: def view(request, ...) -> request is a source via model 'request'
            if n == "request" and not self.collect:
                self.env[n] = Taint(frozenset({"request"}), trail=(self.fs(node, "source", "HttpRequest parameter"),))
            # Parameters annotated with fastapi dependency sources: name: str = Query(...)
        for a, d in zip(reversed(args.args), reversed(args.defaults)):
            dq = self.qual(d.func) if isinstance(d, ast.Call) else self.qual(d)
            if dq:
                for cand in Resolver.candidate_qualnames(dq):
                    s = _SOURCES.get(cand)
                    if s and s.is_call and not self.collect:
                        ann = self._annotation_of(node, a.arg)
                        if ann in {"int", "float", "bool", "UUID", "uuid.UUID"}:
                            continue
                        self.env[a.arg] = Taint(frozenset({s.label}), trail=(self.fs(node, "source", f"{s.label} parameter `{a.arg}`"),))

        for stmt in node.body:
            self.visit(stmt)

        (self.env, self.scope, self.current_fn, self.current_summary, self.param_index, self.in_http_view, self.guards) = saved

    @staticmethod
    def _annotation_of(fn, name: str) -> Optional[str]:
        for a in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs:
            if a.arg == name and a.annotation is not None:
                ann = a.annotation
                if isinstance(ann, ast.Name):
                    return ann.id
                if isinstance(ann, ast.Attribute):
                    return ann.attr
                if isinstance(ann, ast.Subscript):  # Optional[int] / Annotated[int, ...]
                    inner = ann.slice
                    if isinstance(inner, ast.Tuple) and inner.elts:
                        inner = inner.elts[0]
                    if isinstance(inner, ast.Name):
                        return inner.id
        return None

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is None:
            return
        t = self.eval(node.value)
        summ = self.current_summary
        if self.collect and summ is not None:
            for lab in t.labels:
                if lab.startswith("param:"):
                    summ.returns_from.add(int(lab.split(":")[1]))
                else:
                    summ.returns_source = True
            # does this function look like a sanitizer wrapper? (returns the result of a sanitizer applied to a param)
            if t.cleared and t.labels and all(l.startswith("param:") for l in t.labels):
                summ.sanitizes = t.cleared
        if not self.collect and self.in_http_view and t and self._returns_html(node.value, t):
            self._report_sink(_SINKS["__return_http__"][0], node, t, node.value)

    def _returns_html(self, value: ast.AST, t: Taint) -> bool:
        """Only flag `return <tainted string>` when it's plausibly rendered as HTML."""
        if t.is_safe_for("CWE-79"):
            return False
        # returning dict/list -> JSON (Flask jsonify / FastAPI) -> not XSS
        if isinstance(value, (ast.Dict, ast.List, ast.Tuple)):
            return False
        if isinstance(value, ast.Call):
            q = self.qual(value.func) or ""
            if any(k in q for k in ("jsonify", "JSONResponse", "json", "redirect", "render_template", "send_", "Response", "make_response", "abort")):
                return False
            if q.split(".")[-1] in {"str", "format"}:
                return True
            return False
        # f-string / concat / % formatting / plain tainted name
        if isinstance(value, (ast.JoinedStr, ast.BinOp, ast.Name, ast.Attribute, ast.Subscript)):
            src = self.text(value)
            return "<" in src or isinstance(value, (ast.JoinedStr, ast.BinOp)) or True
        return False

    # -- statements ----------------------------------------------------------
    def visit_Assign(self, node: ast.Assign) -> None:
        t = self.eval(node.value)
        # constructor tracking: cur = conn.cursor()  /  h = Handler()
        if isinstance(node.value, ast.Call):
            cq = self.qual(node.value.func)
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and cq:
                    self.resolver.bind_instance(tgt.id, cq, self.scope)
                    inst = self.resolver.qualname(node.value, self.scope)
                    if inst and inst != cq:
                        self.scope.bind(tgt.id, inst)
                    else:
                        # user-defined class? bind the instance name to the class so h.method resolves to Class.method
                        for cand in Resolver.candidate_qualnames(cq):
                            if any(k.startswith(cand + ".") for k in self.summaries):
                                self.scope.bind(tgt.id, cand)
                                break
        for tgt in node.targets:
            self._assign_target(tgt, t, node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._assign_target(node.target, self.eval(node.value), node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        t = self.eval(node.value)
        if isinstance(node.target, ast.Name):
            cur = self.get(node.target.id)
            merged = cur.union(t)
            if merged:
                merged = merged.step(self.fs(node, "propagate", f"`{node.target.id}` += tainted"))
            self.env[node.target.id] = merged
        else:
            self._assign_target(node.target, t, node)

    def _assign_target(self, tgt: ast.AST, t: Taint, node: ast.AST) -> None:
        if isinstance(tgt, ast.Name):
            if t:
                t = t.step(self.fs(node, "propagate", f"assigned to `{tgt.id}`"))
            self.env[tgt.id] = t
            self.guards.pop(tgt.id, None)
        elif isinstance(tgt, (ast.Tuple, ast.List)):
            for e in tgt.elts:
                self._assign_target(e, t, node)
        elif isinstance(tgt, ast.Starred):
            self._assign_target(tgt.value, t, node)
        elif isinstance(tgt, (ast.Attribute, ast.Subscript)):
            # self.x = tainted  /  d['k'] = tainted  -> taint the root container (conservative)
            root = self._root_name(tgt)
            if root is not None:
                if root == "self":
                    key = "self." + self._attr_path(tgt)
                    self.env[key] = t.step(self.fs(node, "propagate", f"stored in `{key}`")) if t else t
                else:
                    cur = self.get(root)
                    merged = cur.union(t)
                    if t:
                        merged = merged.step(self.fs(node, "propagate", f"stored into `{root}`"))
                    self.env[root] = merged
            # flask.session[...] = tainted
            q = self.qual(tgt.value) if isinstance(tgt, ast.Subscript) else None
            if q and t and not self.collect and q.endswith("session"):
                pass  # intentionally not a finding: session storage of request data is normal

    def _root_name(self, node: ast.AST) -> Optional[str]:
        while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
            node = node.value if not isinstance(node, ast.Call) else node.func
        return node.id if isinstance(node, ast.Name) else None

    def _attr_path(self, node: ast.AST) -> str:
        parts = []
        while isinstance(node, (ast.Attribute, ast.Subscript)):
            if isinstance(node, ast.Attribute):
                parts.append(node.attr)
            else:
                parts.append("[]")
            node = node.value
        return ".".join(reversed(parts))

    def visit_Expr(self, node: ast.Expr) -> None:
        self.eval(node.value)

    def visit_For(self, node: ast.For) -> None:
        it = self.eval(node.iter)
        self._assign_target(node.target, it, node)
        self._loop(node.body)
        for s in node.orelse:
            self.visit(s)

    visit_AsyncFor = visit_For

    def visit_While(self, node: ast.While) -> None:
        self.eval(node.test)
        self._loop(node.body)
        for s in node.orelse:
            self.visit(s)

    def _loop(self, body) -> None:
        self.loop_depth += 1
        for _ in range(MAX_LOOP_ROUNDS):
            before = dict(self.env)
            for s in body:
                self.visit(s)
            if self.env == before:
                break
        self.loop_depth -= 1

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            t = self.eval(item.context_expr)
            if item.optional_vars is not None:
                # with open(tainted) as f: -> f content is attacker-influenced? No; the sink is open().
                # Keep f untainted unless the context expr is a tainted *value* source (io.BytesIO(t)).
                q = self.qual(item.context_expr.func) if isinstance(item.context_expr, ast.Call) else None
                if q and q.split(".")[-1] in {"BytesIO", "StringIO", "ZipFile", "TarFile", "open"} and q not in {"builtins.open", "io.open"}:
                    self._assign_target(item.optional_vars, t, node)
                else:
                    self._assign_target(item.optional_vars, EMPTY, node)
                if isinstance(item.context_expr, ast.Call) and q and isinstance(item.optional_vars, ast.Name):
                    self.resolver.bind_instance(item.optional_vars.id, q, self.scope)
        for s in node.body:
            self.visit(s)

    visit_AsyncWith = visit_With

    def visit_If(self, node: ast.If) -> None:
        self.eval(node.test)
        guard_true, guard_false = self._guards_from_test(node.test)

        pre_env, pre_guards = dict(self.env), dict(self.guards)
        # then-branch
        self.guards = dict(pre_guards)
        for n, c in guard_true.items():
            self.guards[n] = self.guards.get(n, frozenset()) | c
        for s in node.body:
            self.visit(s)
        then_env, then_guards = self.env, self.guards
        then_exits = self._block_exits(node.body)

        # else-branch
        self.env, self.guards = dict(pre_env), dict(pre_guards)
        for n, c in guard_false.items():
            self.guards[n] = self.guards.get(n, frozenset()) | c
        for s in node.orelse:
            self.visit(s)
        else_env, else_guards = self.env, self.guards
        else_exits = self._block_exits(node.orelse) if node.orelse else False

        # merge
        if then_exits and not else_exits:
            self.env, self.guards = else_env, else_guards
        elif else_exits and not then_exits:
            self.env, self.guards = then_env, then_guards
        else:
            merged: Dict[str, Taint] = {}
            for k in set(then_env) | set(else_env):
                merged[k] = then_env.get(k, EMPTY).union(else_env.get(k, EMPTY))
            self.env = merged
            # a guard survives the merge only if it holds on every path where the variable is still tainted
            mg: Dict[str, FrozenSet[str]] = {}
            for k in set(then_guards) | set(else_guards):
                tg, eg = then_guards.get(k, frozenset()), else_guards.get(k, frozenset())
                tt, et = bool(then_env.get(k, EMPTY)), bool(else_env.get(k, EMPTY))
                if tt and et:
                    g = tg & eg
                elif tt:
                    g = tg
                elif et:
                    g = eg
                else:
                    g = tg | eg
                if g:
                    mg[k] = g
            self.guards = mg

    @staticmethod
    def _block_exits(body) -> bool:
        if not body:
            return False
        last = body[-1]
        if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
            return True
        if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
            q = last.value.func
            name = q.attr if isinstance(q, ast.Attribute) else getattr(q, "id", "")
            if name in {"abort", "exit", "sys_exit", "fail", "raise_for_status"} or name.startswith("raise"):
                return True
        return False

    def _guards_from_test(self, test: ast.AST) -> Tuple[Dict[str, FrozenSet[str]], Dict[str, FrozenSet[str]]]:
        """Return (guards_when_true, guards_when_false) as name -> cleared CWEs."""
        t: Dict[str, FrozenSet[str]] = {}
        f: Dict[str, FrozenSet[str]] = {}
        ALL = frozenset({"*"})
        PATH = frozenset({"CWE-22", "CWE-601", "CWE-918"})

        def name_of(n):
            # unwrap str(x) / os.fspath(x) / x.resolve() so `str(p).startswith(...)` guards `p`
            while True:
                if isinstance(n, ast.Call) and len(n.args) == 1 and isinstance(n.func, ast.Name) and n.func.id in {"str", "os.fspath", "fspath", "abspath", "normpath", "realpath"}:
                    n = n.args[0]
                    continue
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in {"resolve", "absolute", "strip", "lower", "as_posix", "normpath", "abspath", "realpath"}:
                    n = n.func.value
                    continue
                if isinstance(n, ast.Call) and len(n.args) == 1 and isinstance(n.func, ast.Attribute) and n.func.attr in {"abspath", "normpath", "realpath", "fspath"}:
                    n = n.args[0]
                    continue
                break
            if isinstance(n, ast.Name):
                return n.id
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "self":
                return "self." + n.attr
            return None

        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            inner_t, inner_f = self._guards_from_test(test.operand)
            return inner_f, inner_t

        if isinstance(test, ast.BoolOp):
            parts = [self._guards_from_test(v) for v in test.values]
            if isinstance(test.op, ast.And):
                # (A and B) true  -> both hold: union of true-guards
                for vt, _ in parts:
                    for k, c in vt.items():
                        t[k] = t.get(k, frozenset()) | c
                # (A and B) false -> at least one false: intersection of false-guards
                fs = [vf for _, vf in parts]
                for k in set.intersection(*[set(d) for d in fs]) if fs else set():
                    c = frozenset.intersection(*[d[k] for d in fs])
                    if c:
                        f[k] = c
            else:
                # (A or B) true  -> at least one true: intersection of true-guards
                ts = [vt for vt, _ in parts]
                for k in set.intersection(*[set(d) for d in ts]) if ts else set():
                    c = frozenset.intersection(*[d[k] for d in ts])
                    if c:
                        t[k] = c
                # (A or B) false -> all false: union of false-guards   (this is the `if ".." in x or x.startswith("/"): abort()` idiom)
                for _, vf in parts:
                    for k, c in vf.items():
                        f[k] = f.get(k, frozenset()) | c
            return t, f

        # x.isdigit() / x.isalnum() / x.isalpha() / x.isnumeric()
        if isinstance(test, ast.Call) and isinstance(test.func, ast.Attribute):
            n = name_of(test.func.value)
            if n and test.func.attr in {"isdigit", "isalnum", "isalpha", "isnumeric", "isdecimal", "isidentifier"}:
                t[n] = ALL
                return t, f
            if n and test.func.attr == "startswith" and test.args:
                a0 = test.args[0]
                # x.startswith("/") or x.startswith("..") -> the FALSE branch is the safe one
                if isinstance(a0, ast.Constant) and isinstance(a0.value, str) and a0.value.startswith(("/", "..", "\\", "~")):
                    f[n] = frozenset({"CWE-22"})
                    return t, f
                # str(p).startswith(str(BASE)) -> containment check: TRUE branch safe
                t[n] = PATH
                return t, f
            if n and test.func.attr == "is_relative_to":
                t[n] = PATH
                return t, f
            # re.fullmatch / re.match(PATTERN, x)
            q = self.qual(test.func)
            if q in {"re.fullmatch", "re.match"} and len(test.args) >= 2:
                n2 = name_of(test.args[1])
                if n2:
                    t[n2] = ALL
                return t, f
            if q and q.split(".")[-1] in {"is_safe_url", "url_has_allowed_host_and_scheme", "is_valid", "validate", "is_allowed", "allowed_file"}:
                for a in test.args:
                    n3 = name_of(a)
                    if n3:
                        t[n3] = frozenset({"CWE-601", "CWE-918", "CWE-22"}) if "url" in q.lower() else ALL
                return t, f

        # x in ALLOWED / x not in ALLOWED
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            op = test.ops[0]
            left, right = test.left, test.comparators[0]
            n = name_of(left)
            # urlparse(x).netloc == "" / not urlparse(x).netloc  -> same-origin redirect check
            if isinstance(left, ast.Attribute) and left.attr in {"netloc", "hostname", "scheme"} and isinstance(left.value, ast.Call) and left.value.args:
                n_url = name_of(left.value.args[0])
                if n_url and isinstance(right, ast.Constant):
                    if isinstance(op, ast.Eq):
                        t[n_url] = frozenset({"CWE-601", "CWE-918"})
                    elif isinstance(op, ast.NotEq):
                        f[n_url] = frozenset({"CWE-601", "CWE-918"})
                    return t, f
                if n_url and isinstance(op, ast.In) and self._is_constant_collection(right):
                    t[n_url] = frozenset({"CWE-601", "CWE-918"})
                    return t, f
            if n and isinstance(op, ast.In) and self._is_constant_collection(right):
                t[n] = ALL
            if n and isinstance(op, ast.NotIn) and self._is_constant_collection(right):
                f[n] = ALL
            # x == "literal"
            if n and isinstance(op, ast.Eq) and isinstance(right, ast.Constant):
                t[n] = ALL
            if n and isinstance(op, ast.NotEq) and isinstance(right, ast.Constant):
                f[n] = ALL
            # ".." in x  -> false branch is path-safe-ish
            if isinstance(left, ast.Constant) and isinstance(left.value, str) and left.value in ("..", "../", "..\\") and isinstance(op, ast.In):
                n2 = name_of(right)
                if n2:
                    f[n2] = frozenset({"CWE-22"})
            if isinstance(left, ast.Constant) and isinstance(left.value, str) and left.value in ("..",) and isinstance(op, ast.NotIn):
                n2 = name_of(right)
                if n2:
                    t[n2] = frozenset({"CWE-22"})
        return t, f

    def _is_constant_collection(self, node: ast.AST) -> bool:
        if isinstance(node, (ast.Set, ast.List, ast.Tuple, ast.Dict)):
            return all(isinstance(e, ast.Constant) for e in (node.keys if isinstance(node, ast.Dict) else node.elts) if e is not None)
        if isinstance(node, ast.Name):
            return node.id.isupper() or node.id.endswith(("_WHITELIST", "_ALLOWLIST", "_ALLOWED", "ALLOWED", "WHITELIST", "ALLOWLIST"))
        if isinstance(node, ast.Attribute):
            return node.attr.isupper()
        return False

    def visit_Try(self, node: ast.Try) -> None:
        for s in node.body:
            self.visit(s)
        for h in node.handlers:
            for s in h.body:
                self.visit(s)
        for s in node.orelse + node.finalbody:
            self.visit(s)

    visit_TryStar = visit_Try

    def visit_Match(self, node: ast.Match) -> None:  # pragma: no cover
        self.eval(node.subject)
        for c in node.cases:
            for s in c.body:
                self.visit(s)

    # -- expressions ---------------------------------------------------------
    def eval(self, node: Optional[ast.AST]) -> Taint:
        if node is None:
            return EMPTY
        m = getattr(self, "e_" + type(node).__name__, None)
        if m is not None:
            return m(node)
        # generic: union of children
        t = EMPTY
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                t = t.union(self.eval(child))
        return t

    def e_Constant(self, node: ast.Constant) -> Taint:
        return EMPTY

    def e_Name(self, node: ast.Name) -> Taint:
        t = self.get(node.id)
        if t:
            return t
        q = self.qual(node)
        return self._source_taint(q, node)

    def e_Attribute(self, node: ast.Attribute) -> Taint:
        # self.x where self.x was tainted
        if isinstance(node.value, ast.Name) and node.value.id == "self":
            key = "self." + node.attr
            if key in self.env and self.env[key]:
                return self.env[key]
        q = self.qual(node)
        st = self._source_taint(q, node)
        if st:
            return st
        base = self.eval(node.value)
        if base and node.attr in STR_PROPAGATING_METHODS | {"filename", "stream", "name", "value", "text", "content", "data", "args", "form", "json", "body", "query_params", "path_params", "headers", "cookies"}:
            return base
        if base and not node.attr.startswith("is") and node.attr not in {"method", "scheme", "is_secure", "is_json", "endpoint", "blueprint"}:
            return base
        return EMPTY

    def e_Subscript(self, node: ast.Subscript) -> Taint:
        base = self.eval(node.value)
        q = self.qual(node.value)
        st = self._source_taint(q, node)
        if st:
            return st.step(self.fs(node, "source", f"{q}[...]"))
        if base:
            return base
        return EMPTY

    def e_JoinedStr(self, node: ast.JoinedStr) -> Taint:
        t = EMPTY
        for v in node.values:
            if isinstance(v, ast.FormattedValue):
                t = t.union(self.eval(v.value))
        if t:
            t = t.step(self.fs(node, "propagate", "f-string"))
        return t

    def e_BinOp(self, node: ast.BinOp) -> Taint:
        l, r = self.eval(node.left), self.eval(node.right)
        t = l.union(r)
        if t:
            op = "%-format" if isinstance(node.op, ast.Mod) else "concat"
            t = t.step(self.fs(node, "propagate", op))
        return t

    def e_BoolOp(self, node: ast.BoolOp) -> Taint:
        t = EMPTY
        for v in node.values:
            t = t.union(self.eval(v))
        return t

    def e_IfExp(self, node: ast.IfExp) -> Taint:
        self.eval(node.test)
        return self.eval(node.body).union(self.eval(node.orelse))

    def e_Compare(self, node: ast.Compare) -> Taint:
        self.eval(node.left)
        for c in node.comparators:
            self.eval(c)
        return EMPTY  # comparisons yield booleans

    def e_Lambda(self, node: ast.Lambda) -> Taint:
        return EMPTY

    def e_ListComp(self, node: ast.ListComp) -> Taint:
        return self._comp(node, node.elt)

    def e_SetComp(self, node: ast.SetComp) -> Taint:
        return self._comp(node, node.elt)

    def e_GeneratorExp(self, node: ast.GeneratorExp) -> Taint:
        return self._comp(node, node.elt)

    def e_DictComp(self, node: ast.DictComp) -> Taint:
        return self._comp(node, node.value).union(self._comp(node, node.key))

    def _comp(self, node, elt) -> Taint:
        saved = dict(self.env)
        for g in node.generators:
            it = self.eval(g.iter)
            self._assign_target(g.target, it, node)
            for cond in g.ifs:
                self.eval(cond)
        t = self.eval(elt)
        self.env = saved
        return t

    def e_Await(self, node: ast.Await) -> Taint:
        return self.eval(node.value)

    def e_Starred(self, node: ast.Starred) -> Taint:
        return self.eval(node.value)

    def e_NamedExpr(self, node: ast.NamedExpr) -> Taint:
        t = self.eval(node.value)
        self._assign_target(node.target, t, node)
        return t

    def e_Dict(self, node: ast.Dict) -> Taint:
        t = EMPTY
        for k, v in zip(node.keys, node.values):
            if k is not None:
                t = t.union(self.eval(k))
            t = t.union(self.eval(v))
        return t

    def _source_taint(self, q: Optional[str], node: ast.AST) -> Taint:
        if not q:
            return EMPTY
        for cand in Resolver.candidate_qualnames(q):
            # exact match on a non-call source with attrs restriction
            for sq, s in _SOURCES.items():
                if s.is_call or s.params:
                    continue
                if cand == sq and not s.attrs:
                    return Taint(frozenset({s.label}), trail=(self.fs(node, "source", s.label),))
                if cand.startswith(sq + "."):
                    rest = cand[len(sq) + 1:].split(".")[0]
                    if not s.attrs or rest in s.attrs:
                        return Taint(frozenset({f"{s.label}.{rest}"}), trail=(self.fs(node, "source", f"{s.label}.{rest}"),))
        return EMPTY

    # -- calls (the heart) ---------------------------------------------------
    def e_Call(self, node: ast.Call) -> Taint:
        func_q = self.qual(node.func)
        arg_taints = [self.eval(a) for a in node.args]
        kw_taints = {kw.arg: self.eval(kw.value) for kw in node.keywords}
        any_arg = EMPTY
        for a in arg_taints:
            any_arg = any_arg.union(a)
        for a in kw_taints.values():
            any_arg = any_arg.union(a)

        # 1. sanitizer?
        san = self.lookup_sanitizer(func_q)
        if san is not None:
            if any_arg:
                return any_arg.sanitize(san.clears, self.fs(node, "sanitizer", f"{san.qualname}: clears {', '.join(sorted(san.clears))}"))
            return EMPTY

        # 2. source call?  input(), fastapi.Query(), requests.get() result
        if func_q:
            for cand in Resolver.candidate_qualnames(func_q):
                s = _SOURCES.get(cand)
                if s and s.is_call:
                    src_t = Taint(frozenset({s.label}), trail=(self.fs(node, "source", s.label),))
                    # requests.get(tainted) is ALSO an SSRF sink, handled below; result is tainted either way
                    self._check_sinks(func_q, node, arg_taints, kw_taints)
                    return src_t.union(any_arg) if any_arg else src_t

        # 3. sink?
        self._check_sinks(func_q, node, arg_taints, kw_taints)

        # 4. passthrough builtins / stdlib (checked before "sink consumes" because re.sub/pathlib.Path are both)
        if func_q:
            for cand in Resolver.candidate_qualnames(func_q):
                if cand in PASSTHROUGH_FUNCS:
                    return any_arg.step(self.fs(node, "propagate", f"{cand}()")) if any_arg else EMPTY

        # 5. a sink call consumes its arguments; its result (Response object, cursor, ...) is not a string to re-flag
        if self.lookup_sink(func_q):
            return EMPTY

        # 6. method on a tainted receiver -> stays tainted (x.strip(), d.get(k))
        recv_t = EMPTY
        if isinstance(node.func, ast.Attribute):
            recv_t = self.eval(node.func.value)
            if recv_t and node.func.attr in STR_PROPAGATING_METHODS:
                out = recv_t.union(any_arg)
                return out.step(self.fs(node, "propagate", f".{node.func.attr}()"))
            # mutating a container with tainted data: lst.append(t) -> lst tainted
            if any_arg and node.func.attr in {"append", "extend", "insert", "add", "update", "setdefault", "write", "writelines", "put"}:
                root = self._root_name(node.func.value)
                if root is not None and root != "self":
                    self.env[root] = self.get(root).union(any_arg).step(self.fs(node, "propagate", f".{node.func.attr}() into `{root}`"))
            # "".join(tainted) / "%s".format(tainted) on a constant receiver
            if isinstance(node.func.value, ast.Constant) and node.func.attr in {"join", "format"} and any_arg:
                return any_arg.step(self.fs(node, "propagate", f"str.{node.func.attr}()"))

        # 7. user-defined function with summary
        summ = self._summary_for(node.func, func_q)
        if summ is not None:
            out = EMPTY
            # map positional args
            offset = 1 if (summ.params and summ.params[0] in ("self", "cls")) else 0
            for i, at in enumerate(arg_taints):
                pi = i + offset
                if pi in summ.returns_from and at:
                    out = out.union(at)
                # tainted arg flows to a sink inside callee -> report at call site with full path
                if at and pi in summ.sinks_from:
                    if self.collect:
                        self._record_transitive_sinks(at, summ.sinks_from[pi])
                    else:
                        for inner in summ.sinks_from[pi]:
                            self._report_interproc(inner, node, at, summ, pi)
            for kw in node.keywords:
                if kw.arg in summ.params:
                    pi = summ.params.index(kw.arg)
                    kt = kw_taints.get(kw.arg, EMPTY)
                    if pi in summ.returns_from and kt:
                        out = out.union(kt)
                    if kt and pi in summ.sinks_from:
                        if self.collect:
                            self._record_transitive_sinks(kt, summ.sinks_from[pi])
                        else:
                            for inner in summ.sinks_from[pi]:
                                self._report_interproc(inner, node, kt, summ, pi)
            if summ.returns_source:
                out = out.union(Taint(frozenset({f"{summ.name}()"}), trail=(self.fs(node, "source", f"{summ.name}() returns request data"),)))
            if out:
                out = out.step(self.fs(node, "call", f"through {summ.name}()"))
            if summ.sanitizes and any_arg:
                return any_arg.sanitize(summ.sanitizes, self.fs(node, "sanitizer", f"{summ.name}() (user sanitizer)"))
            return out

        # 8. unknown function: conservatively propagate (may-analysis), but mark lower confidence
        if any_arg and not self.collect:
            return Taint(any_arg.labels | {"~unknown-call"}, any_arg.cleared, any_arg.trail).step(self.fs(node, "call", f"{func_q or '?'}() (unknown; assumed passthrough)"))
        if any_arg and self.collect:
            return any_arg
        return recv_t if recv_t else EMPTY

    def _record_transitive_sinks(self, t: Taint, inner: List["InnerSink"]) -> None:
        """Pass 1: a parameter of the current function reaches a sink inside a callee.
        Record it on the current summary so callers two+ hops away still get reported."""
        summ = self.current_summary
        if summ is None:
            return
        for lab in t.labels:
            if lab.startswith("param:"):
                pi = int(lab.split(":")[1])
                bucket = summ.sinks_from.setdefault(pi, [])
                for item in inner:
                    if item not in bucket:
                        bucket.append(item)

    def _summary_for(self, func: ast.AST, func_q: Optional[str]) -> Optional[Summary]:
        """Find the user-function summary for a call target without colliding with library names.

        `subprocess.run(...)` must never resolve to a user function called `run`. We only fall
        back to a bare method name when the receiver is `self`/`cls` or a user-defined class.
        """
        if not func_q:
            return None
        # sibling-module resolution: in bad/mod_user.py, `libuser.login` means bad.libuser.login before anything else
        pkgs = self.module_names[0].split(".")[:-1] if self.module_names else []
        for depth in range(len(pkgs), 0, -1):
            prefix = ".".join(pkgs[:depth])
            for cand in Resolver.candidate_qualnames(func_q):
                hit = self.summaries.get(f"{prefix}.{cand}")
                if hit:
                    return hit
        if self.summaries.get(func_q):
            return self.summaries[func_q]
        # module-qualified user function/class: hard_helpers.Shell.run -> Shell.run (never a bare name: subprocess.run must not hit `run`)
        for cand in Resolver.candidate_qualnames(func_q)[1:]:
            if "." in cand and self.summaries.get(cand):
                return self.summaries[cand]
        if isinstance(func, ast.Name):
            return self.summaries.get(func.id)
        if isinstance(func, ast.Attribute):
            root = self._root_name(func)
            if root in ("self", "cls") and self.class_stack:
                return self.summaries.get(".".join(self.class_stack + [func.attr])) or self.summaries.get(func.attr)
            # receiver is a known user class (instantiated or referenced): Store(conn).get / store.get where store = Store(...)
            recv_q = self.qual(func.value) or ""
            head = recv_q.split(".")[0]
            if self.summaries.get(f"{head}.{func.attr}"):
                return self.summaries[f"{head}.{func.attr}"]
        return None

    # -- sink checks ---------------------------------------------------------
    def _gate_open(self, sink: Sink, node: ast.Call) -> bool:
        if sink.requires_truthy_kw is None:
            return True
        key, want = sink.requires_truthy_kw
        for kw in node.keywords:
            if kw.arg == key:
                if want == "unsafe":
                    # yaml.load(x, Loader=...) -> dangerous unless Loader is SafeLoader/BaseLoader
                    name = self.text(kw.value) if not isinstance(kw.value, (ast.Name, ast.Attribute)) else (self.qual(kw.value) or "")
                    return not any(s in name for s in ("SafeLoader", "BaseLoader", "CSafeLoader"))
                if isinstance(kw.value, ast.Constant):
                    return bool(kw.value.value) is bool(want)
                return True  # non-constant: assume dangerous
        return sink.default_kw_truthy

    def _check_sinks(self, func_q: Optional[str], node: ast.Call, arg_taints: List[Taint], kw_taints: Dict[Optional[str], Taint]) -> None:
        sinks = self.lookup_sink(func_q)
        if not sinks:
            return
        recv_taint = EMPTY
        if isinstance(node.func, ast.Attribute):
            recv_taint = self.eval(node.func.value)
        for sink in sinks:
            if not self._gate_open(sink, node):
                continue
            hit: Optional[Taint] = None
            if sink.recv and recv_taint and not recv_taint.is_safe_for(sink.cwe):
                hit = recv_taint
            if -1 in sink.args:
                for at in arg_taints:
                    if at and not at.is_safe_for(sink.cwe):
                        hit = at if hit is None else hit.union(at)
            else:
                for idx in sink.args:
                    if idx < len(arg_taints):
                        at = arg_taints[idx]
                        if at and not at.is_safe_for(sink.cwe):
                            hit = at if hit is None else hit.union(at)
            for k in sink.kwargs:
                kt = kw_taints.get(k)
                if kt and not kt.is_safe_for(sink.cwe):
                    hit = kt if hit is None else hit.union(kt)
            # common keyword spellings for the first positional ("url=", "cmd=", "path=", "sql=")
            if hit is None and 0 in sink.args:
                for k in ("url", "cmd", "args", "command", "path", "file", "filename", "sql", "query", "source", "s", "data", "location", "template_string", "stream", "f", "fp"):
                    kt = kw_taints.get(k)
                    if kt and not kt.is_safe_for(sink.cwe):
                        hit = kt
                        break
            if hit is None:
                continue
            if self.collect:
                summ = self.current_summary
                if summ is not None:
                    for lab in hit.labels:
                        if lab.startswith("param:"):
                            summ.sinks_from.setdefault(int(lab.split(":")[1]), []).append(
                                InnerSink(sink, self.path, node.lineno, node.col_offset, self.text(node), self.current_fn or ""))
            else:
                self._report_sink(sink, node, hit, node)
            break  # one finding per call per sink group

    def _report_sink(self, sink: Sink, node: ast.AST, t: Taint, sink_expr: ast.AST) -> None:
        flow = list(t.trail) + [self.fs(node, "sink", f"{sink.qualname}")]
        self._emit(sink, node, t, flow)

    def _report_interproc(self, inner: "InnerSink", call: ast.Call, t: Taint, summ: Summary, pi: int) -> None:
        pname = summ.params[pi] if pi < len(summ.params) else f"arg{pi}"
        flow = list(t.trail) + [
            self.fs(call, "call", f"passed as `{pname}` to {summ.name}()"),
            FlowStep(inner.file, inner.line, inner.col, "sink", inner.text, f"{inner.sink.qualname} inside {inner.fn or summ.name}()"),
        ]
        self._emit(inner.sink, call, t, flow, inside=inner.fn or summ.name, sink_line=inner.line, sink_file=inner.file)

    def _emit(self, sink: Sink, node: ast.AST, t: Taint, flow: List[FlowStep], inside: Optional[str] = None, sink_line: Optional[int] = None, sink_file: Optional[str] = None) -> None:
        labels = sorted(l for l in t.labels if not l.startswith("param:"))
        unknown = "~unknown-call" in t.labels
        labels = [l for l in labels if l != "~unknown-call"]
        src = ", ".join(labels) or "parameter"
        conf = "high"
        if unknown:
            conf = "medium"
        if "route param" in labels and sink.cwe not in ("CWE-22", "CWE-89", "CWE-78", "CWE-918", "CWE-601"):
            conf = "medium"
        if inside:
            conf = "medium" if conf == "high" else "low"
        where = f" (inside {inside}, {sink_file or self.path}:{sink_line})" if inside else ""
        msg = f"{src} reaches {sink.qualname}{where} without a sanitizer for {sink.cwe}."
        fp = hashlib.sha1(f"{sink.rule_id}|{self.path}|{self.current_fn}|{self.text(node)}".encode()).hexdigest()[:16]
        f = Finding(
            rule_id=sink.rule_id, owasp=sink.owasp, cwe=sink.cwe, title=sink.title,
            severity=sink.severity, confidence=conf, file=self.path,
            line=node.lineno, col=node.col_offset + 1,
            end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
            end_col=(getattr(node, "end_col_offset", node.col_offset) or node.col_offset) + 1,
            sink=sink.qualname, source=src, message=msg, flow=flow, fix=sink.fix, fingerprint=fp,
        )
        if not any(x.fingerprint == fp for x in self.findings):
            self.findings.append(f)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    findings: List[Finding]
    files: int
    functions: int
    errors: List[str]

    def by_owasp(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.owasp] = out.get(f.owasp, 0) + 1
        return dict(sorted(out.items()))


_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "site-packages", ".tox", "dist", "build", ".mypy_cache", ".pytest_cache", "migrations"}


def _iter_py(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*.py")):
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        yield p


def scan_source(source: str, filename: str = "<string>") -> ScanResult:
    return _scan([(filename, source)])


def scan_path(path: str, exclude_tests: bool = False) -> ScanResult:
    root = Path(path)
    items = []
    errors = []
    for p in _iter_py(root):
        if exclude_tests and ("test" in p.name or "tests" in p.parts):
            continue
        try:
            items.append((str(p.relative_to(root) if root.is_dir() else p.name).replace("\\", "/"), p.read_text(encoding="utf-8", errors="replace")))
        except OSError as e:  # pragma: no cover
            errors.append(f"{p}: {e}")
    res = _scan(items)
    res.errors = errors + res.errors
    return res


def _scan(items: List[Tuple[str, str]]) -> ScanResult:
    trees: List[Tuple[str, str, ast.Module]] = []
    errors: List[str] = []
    for name, src in items:
        try:
            trees.append((name, src, ast.parse(src, filename=name)))
        except SyntaxError as e:
            errors.append(f"{name}: {e.msg} (line {e.lineno})")

    summaries: Dict[str, Summary] = {}
    # Pass 1: summaries (two rounds so callee-of-callee flows settle)
    for _ in range(2):
        for name, src, tree in trees:
            fa = FileAnalyzer(name, src, tree, summaries, collect=True)
            fa.visit(tree)
    # Pass 2: report
    findings: List[Finding] = []
    nfunc = sum(1 for s in summaries.values())
    for name, src, tree in trees:
        fa = FileAnalyzer(name, src, tree, summaries, collect=False)
        fa.visit(tree)
        findings.extend(fa.findings)

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (sev_rank.get(f.severity, 9), f.file, f.line))
    return ScanResult(findings=findings, files=len(trees), functions=nfunc, errors=errors)
