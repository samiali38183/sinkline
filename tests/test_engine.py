"""Unit tests for the taint engine. Each test is a tiny program + expected CWEs on specific lines."""
import textwrap

import pytest

from sinkline import scan_source


def _src(src: str) -> str:
    # tests write FLASK + """<indented body>""" — dedent the body, not the prefix
    if src.startswith(FLASK):
        return FLASK + textwrap.dedent(src[len(FLASK):])
    return textwrap.dedent(src)


def cwes_by_line(src: str):
    res = scan_source(_src(src), "t.py")
    out = {}
    for f in res.findings:
        out.setdefault(f.line, set()).add(f.cwe)
    return out


FLASK = "from flask import Flask, request, redirect, send_file\napp = Flask(__name__)\nimport os, subprocess, sqlite3, shlex\ndb = sqlite3.connect(':memory:')\n"


# ---- basic source -> sink ----------------------------------------------------

def test_direct_sqli():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        db.execute("SELECT " + request.args['q'])
    """)
    assert r == {8: {"CWE-89"}}


def test_parameterized_query_is_safe():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        db.execute("SELECT ?", (request.args['q'],))
    """)
    assert r == {}


def test_int_coercion_sanitizes_everything():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        n = int(request.args['n'])
        db.execute("SELECT %d" % n)
        os.system("echo " + str(n))
    """)
    assert r == {}


# ---- propagation --------------------------------------------------------------

@pytest.mark.parametrize("expr", [
    '"SELECT " + q',
    '"SELECT %s" % q',
    '"SELECT {}".format(q)',
    'f"SELECT {q}"',
    '"SELECT " + q.strip().lower()',
    '" ".join(["SELECT", q])',
    '"SELECT " + q[1:]',
    '"SELECT " + q.replace("x", "y")',
])
def test_string_propagation(expr):
    r = cwes_by_line(FLASK + f"""
    @app.route('/')
    def v():
        q = request.args['q']
        db.execute({expr})
    """)
    assert 9 in r and "CWE-89" in r[9]


def test_container_propagation():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        d = {"k": request.args['q']}
        lst = [request.args['q']]
        db.execute("SELECT " + d["k"])
        db.execute("SELECT " + lst[0])
    """)
    assert set(r) == {10, 11}


def test_augassign_and_loop_fixpoint():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        cmd = "ls"
        for _ in range(3):
            cmd += request.args.get('f', '')
        os.system(cmd)
    """)
    assert r == {11: {"CWE-78"}}


# ---- sanitizers are CWE-scoped -------------------------------------------------

def test_shlex_quote_clears_cmdi_only():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        x = shlex.quote(request.args['x'])
        subprocess.run("ls " + x, shell=True)
        db.execute("SELECT " + x)
    """)
    assert r == {10: {"CWE-89"}}


def test_shell_false_gate():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        subprocess.run(["ls", request.args['x']])
        subprocess.run("ls " + request.args['x'], shell=False)
        subprocess.run("ls " + request.args['x'], shell=True)
    """)
    assert r == {10: {"CWE-78"}}


def test_html_escape_clears_xss_only():
    r = cwes_by_line(FLASK + """
    from markupsafe import escape
    @app.route('/')
    def v():
        n = escape(request.args['n'])
        db.execute("SELECT " + n)
        return "<b>" + n + "</b>"
    """)
    assert r == {10: {"CWE-89"}}


# ---- validation guards -------------------------------------------------------------

def test_isdigit_guard_early_return():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        q = request.args['q']
        if not q.isdigit():
            return "bad"
        db.execute("SELECT " + q)
    """)
    assert r == {}


def test_isdigit_guard_only_in_true_branch():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        q = request.args['q']
        if q.isdigit():
            db.execute("SELECT " + q)
        else:
            db.execute("SELECT " + q)
    """)
    assert r == {12: {"CWE-89"}}


def test_allowlist_guard():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        t = request.args['t']
        if t not in ("a", "b"):
            return "bad"
        db.execute("SELECT * FROM " + t)
    """)
    assert r == {}


def test_dotdot_or_slash_guard_is_path_scoped():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        f = request.args['f']
        if ".." in f or f.startswith("/"):
            return "bad"
        open("/srv/" + f)
        os.system("cat " + f)
    """)
    assert r == {12: {"CWE-78"}}


def test_regex_fullmatch_guard():
    r = cwes_by_line(FLASK + """
    import re
    @app.route('/')
    def v():
        h = request.args['h']
        if not re.fullmatch(r"[a-z.]+", h):
            return "bad"
        os.system("host " + h)
    """)
    assert r == {}


def test_try_int_except_abort():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        q = request.args['q']
        try:
            q = int(q)
        except ValueError:
            return "bad"
        db.execute("SELECT %d" % q)
    """)
    assert r == {}


# ---- interprocedural --------------------------------------------------------------

def test_helper_returns_tainted():
    r = cwes_by_line(FLASK + """
    def build(n):
        return "SELECT " + n
    @app.route('/')
    def v():
        db.execute(build(request.args['n']))
    """)
    assert r == {10: {"CWE-89"}}


def test_sink_inside_helper_reported_at_call_site():
    r = cwes_by_line(FLASK + """
    def run(sql):
        db.execute(sql)
    @app.route('/')
    def v():
        run(request.args['n'])
    """)
    assert r == {10: {"CWE-89"}}
    res = scan_source(_src(FLASK + """
    def run(sql):
        db.execute(sql)
    @app.route('/')
    def v():
        run(request.args['n'])
    """), "t.py")
    kinds = [s.kind for s in res.findings[0].flow]
    assert kinds[0] == "source" and kinds[-1] == "sink" and "call" in kinds


def test_two_hop_sink():
    r = cwes_by_line(FLASK + """
    def inner(sql):
        db.execute(sql)
    def outer(x):
        inner("SELECT " + x)
    @app.route('/')
    def v():
        outer(request.args['n'])
    """)
    assert r == {12: {"CWE-89"}}



def test_deep_helper_chain_defined_caller_first():
    # summaries are computed to a fixpoint, so a chain longer than the old two fixed
    # rounds is found even when every helper is defined before its callee
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        h0(request.args['x'])
    def h0(a):
        h1(a)
    def h1(b):
        h2(b)
    def h2(c):
        h3(c)
    def h3(d):
        os.system(d)
    """)
    assert r == {8: {"CWE-78"}}


def test_re_escape_is_not_a_sql_sanitizer():
    r = cwes_by_line(FLASK + """
    import re
    @app.route('/')
    def v():
        q = re.escape(request.args['q'])
        db.execute("SELECT * FROM t WHERE n = '" + q + "'")
        re.search(q, "haystack")
    """)
    assert r == {10: {"CWE-89"}}


def test_elif_equality_chain_with_else_abort_is_a_guard():
    r = cwes_by_line(FLASK + """
    from flask import abort
    @app.route('/')
    def v():
        t = request.args['t']
        if t == "users":
            pass
        elif t == "orders":
            pass
        else:
            abort(400)
        db.execute("SELECT * FROM " + t)
    """)
    assert r == {}

def test_user_sanitizer_wrapper():
    r = cwes_by_line(FLASK + """
    from werkzeug.utils import secure_filename
    def clean(n):
        return secure_filename(n)
    @app.route('/')
    def v():
        return send_file("/srv/" + clean(request.args['f']))
    """)
    assert r == {}


def test_method_on_user_class():
    r = cwes_by_line(FLASK + """
    class Store:
        def get(self, k):
            return db.execute("SELECT " + k)
        def get_safe(self, k):
            return db.execute("SELECT ?", (k,))
    @app.route('/')
    def v():
        s = Store()
        s.get(request.args['k'])
        s.get_safe(request.args['k'])
        Store().get(request.args['k'])
    """)
    assert set(r) == {14, 16}


def test_library_name_does_not_collide_with_user_function():
    """`subprocess.run` must not resolve to a user function named `run`."""
    r = cwes_by_line(FLASK + """
    def run(x):
        return x
    @app.route('/')
    def v():
        subprocess.run(["ls", request.args['x']])
    """)
    assert r == {}


# ---- frameworks ---------------------------------------------------------------------

def test_fastapi_path_param_and_typed_int():
    r = cwes_by_line("""
    import sqlite3
    from fastapi import FastAPI, Query
    app = FastAPI()
    db = sqlite3.connect(':memory:')
    @app.get('/a/{x}')
    def a(x: str):
        db.execute("SELECT " + x)
    @app.get('/b/{x}')
    def b(x: int):
        db.execute(f"SELECT {x}")
    @app.get('/c')
    def c(q: str = Query("")):
        db.execute("SELECT " + q)
    """)
    assert set(r) == {8, 14}


def test_django_request_param():
    r = cwes_by_line("""
    from django.http import HttpResponse
    from django.utils.html import escape
    def view(request):
        return HttpResponse("<b>" + request.GET['n'] + "</b>")
    def safe(request):
        return HttpResponse("<b>" + escape(request.GET['n']) + "</b>")
    """)
    assert r == {5: {"CWE-79"}}


def test_torch_load_weights_only():
    r = cwes_by_line("""
    import torch
    from fastapi import FastAPI, Form
    app = FastAPI()
    @app.post('/m')
    def m(name: str = Form(...)):
        torch.load("/models/" + name)
        torch.load("/models/" + name, weights_only=True)
    """)
    assert r == {7: {"CWE-502"}}


def test_yaml_loader_gate():
    r = cwes_by_line(FLASK + """
    import yaml
    @app.route('/')
    def v():
        yaml.load(request.data)
        yaml.load(request.data, Loader=yaml.SafeLoader)
        yaml.safe_load(request.data)
    """)
    assert r == {9: {"CWE-502"}}


def test_open_redirect_same_origin_check():
    r = cwes_by_line(FLASK + """
    from urllib.parse import urlparse
    @app.route('/')
    def v():
        n = request.args.get('next', '/')
        if urlparse(n).netloc == "":
            return redirect(n)
        return redirect(n)
    """)
    assert r == {12: {"CWE-601"}}


# ---- reports -------------------------------------------------------------------------

def test_sarif_shape():
    from sinkline.report import to_sarif
    import json
    res = scan_source(_src(FLASK + """
    @app.route('/')
    def v():
        db.execute("SELECT " + request.args['q'])
    """), "t.py")
    doc = json.loads(to_sarif(res, "test"))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["results"][0]["ruleId"] == "SL-SQLI-001"
    assert run["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "SL-SQLI-001" in rule_ids


def test_fingerprint_stable_across_line_shift():
    a = scan_source(_src(FLASK + """
    @app.route('/')
    def v():
        db.execute("SELECT " + request.args['q'])
    """), "t.py").findings[0].fingerprint
    b = scan_source(_src(FLASK + """

    # moved down two lines
    @app.route('/')
    def v():
        db.execute("SELECT " + request.args['q'])
    """), "t.py").findings[0].fingerprint
    assert a == b


def test_syntax_error_is_reported_not_raised():
    res = scan_source("def (:\n", "bad.py")
    assert res.errors and not res.findings


# ---- key-sensitive dict literals ----------------------------------------------

def test_dict_literal_clean_key_is_not_tainted():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        row = {"id": 1, "note": request.form["note"]}
        db.execute("INSERT INTO t VALUES (%d)" % row["id"])
        db.execute("SELECT " + row.get("id", ""))
        db.execute("SELECT " + row["note"])
        db.execute("SELECT " + row.get("note"))
    """)
    assert r == {11: {"CWE-89"}, 12: {"CWE-89"}}


def test_dict_literal_key_store_and_branch_merge():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        d = {"a": "x", "b": request.args["b"]}
        d["a"] = request.args["a"]
        os.system(d["a"])
        e = {"k": "safe", "t": request.args["t"]}
        if request.args.get("flip"):
            e = {"k": request.args["k"], "t": "safe"}
        os.system(e["k"])
    """)
    assert r == {10: {"CWE-78"}, 14: {"CWE-78"}}


def test_dict_without_constant_keys_stays_container_level():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        extra = {"n": request.args["n"]}
        d = {"id": 1, **extra}
        db.execute("SELECT %s" % d["id"])
        k = request.args["k"]
        e = {k: 1}
        db.execute("SELECT %s" % e["x"])
    """)
    assert r == {10: {"CWE-89"}, 13: {"CWE-89"}}


# ---- instance fields across methods ---------------------------------------------

def test_self_field_set_in_one_method_used_in_another():
    res = scan_source(_src(FLASK + """
    class Pinger:
        def load(self):
            self.target = request.args.get("target")
        def fire(self):
            os.system("ping " + self.target)
    """), "t.py")
    assert [(f.line, f.cwe, f.confidence) for f in res.findings] == [(10, "CWE-78", "medium")]
    notes = [s.note for s in res.findings[0].flow]
    assert any("stored in `self.target` by Pinger.load()" in n for n in notes)


def test_self_field_reassigned_locally_or_clean_is_safe():
    r = cwes_by_line(FLASK + """
    class A:
        def load(self):
            self.target = request.args.get("target")
        def fire(self):
            self.target = "localhost"
            os.system("ping " + self.target)
    class B:
        def load(self, t):
            self.target = t
        def fire(self):
            os.system("ping " + self.target)
    class C:
        def load(self):
            self.target = shlex.quote(request.args.get("target"))
        def fire(self):
            os.system("ping " + self.target)
    """)
    assert r == {}


def test_self_field_is_per_class():
    r = cwes_by_line(FLASK + """
    class A:
        def load(self):
            self.target = request.args.get("target")
    class B:
        def fire(self):
            os.system("ping " + self.target)
    """)
    assert r == {}


# ---- try/except join ---------------------------------------------------------

def test_try_except_keeps_taint_when_handler_reassigns():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        try:
            host = request.args["h"]
        except KeyError:
            host = "localhost"
        os.system("ping " + host)
    """)
    assert r == {12: {"CWE-78"}}


def test_try_except_pre_try_taint_survives_handler_overwrite():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        host = request.args["h"]
        try:
            int(host)
        except ValueError:
            host = "localhost"
        os.system("ping " + host)
    """)
    assert r == {13: {"CWE-78"}}


def test_try_except_clean_on_every_path_is_clean():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        try:
            host = shlex.quote(request.args["h"])
        except KeyError:
            host = "localhost"
        os.system("ping " + host)
    """)
    assert r == {}


def test_try_except_aborting_handler_is_not_a_path():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        try:
            host = shlex.quote(request.args["h"])
        except KeyError:
            host = request.args["raw"]
            raise ValueError("bad")
        os.system("ping " + host)
    """)
    assert r == {}


def test_try_else_and_finally_run_after_join():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        host = "localhost"
        try:
            pass
        except KeyError:
            host = request.args["h"]
        finally:
            os.system("ping " + host)
    """)
    assert r == {14: {"CWE-78"}}


# ---- what a returned value counts as HTML ------------------------------------

@pytest.mark.parametrize("ret", [
    'request.args["q"]',            # bare subscript, no "<" anywhere in the source text
    'name',                         # plain tainted name
    '"<b>" + name',                 # concatenation
    'f"{name}"',                    # f-string with no markup
    'str(name)',
])
def test_returned_tainted_string_is_xss(ret):
    r = cwes_by_line(FLASK + f"""
    @app.route('/')
    def v():
        name = request.args["q"]
        return {ret}
    """)
    assert r == {9: {"CWE-79"}}


@pytest.mark.parametrize("ret", ["{'q': name}", "[name]", "(name, 200)", "jsonify(name)", "redirect(name)"])
def test_returned_json_like_value_is_not_xss(ret):
    r = cwes_by_line(FLASK + f"""
    from flask import jsonify
    @app.route('/')
    def v():
        name = request.args["q"]
        return {ret}
    """)
    assert not any("CWE-79" in cs for cs in r.values())


# ---- --exclude-tests is path-segment aware -----------------------------------

_VULN = 'from flask import Flask, request\nimport os\napp = Flask(__name__)\n@app.route("/")\ndef v():\n    os.system("ping " + request.args["h"])\n'


def _scanned(tmp_path, names, exclude=True):
    from sinkline.engine import scan_path
    for n in names:
        f = tmp_path / n
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(_VULN, encoding="utf-8")
    return sorted({f.file for f in scan_path(str(tmp_path), exclude_tests=exclude).findings})


def test_exclude_tests_skips_real_test_files(tmp_path):
    names = ["tests/a.py", "pkg/test/b.py", "test_c.py", "d_test.py", "tests.py", "pkg/conftest.py", "app.py"]
    assert _scanned(tmp_path, names) == ["app.py"]


def test_exclude_tests_does_not_match_substrings(tmp_path):
    names = ["latest.py", "attestation.py", "contest/app.py", "protest_handler.py", "testimony.py", "app.py"]
    assert _scanned(tmp_path, names) == sorted(names)


def test_exclude_tests_ignores_directories_above_the_root(tmp_path):
    from sinkline.engine import scan_path
    root = tmp_path / "tests" / "checkout"
    root.mkdir(parents=True)
    (root / "app.py").write_text(_VULN, encoding="utf-8")
    assert len(scan_path(str(root), exclude_tests=True).findings) == 1


def test_without_flag_test_files_are_scanned(tmp_path):
    assert _scanned(tmp_path, ["tests/a.py", "app.py"], exclude=False) == ["app.py", "tests/a.py"]


# ---- tests added to kill surviving mutants ------------------------------------

def test_loop_needs_second_round():
    # `c = b` reads the value `b` had at the end of the previous iteration, so the taint
    # only reaches `c` on the second pass over the body (MAX_LOOP_ROUNDS = 1 would miss it)
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        a = request.args["x"]
        b = ""
        c = ""
        for i in range(3):
            c = b
            b = a
        os.system("echo " + c)
    """)
    assert r == {14: {"CWE-78"}}


def test_loop_needs_third_round():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        a = request.args["x"]
        b = ""
        c = ""
        d = ""
        for i in range(3):
            d = c
            c = b
            b = a
        os.system("echo " + d)
    """)
    assert r == {16: {"CWE-78"}}


def test_attribute_call_never_resolves_to_same_named_user_function():
    # `asyncio.run` is not a sink, so nothing but _summary_for can connect it to `def run`
    r = cwes_by_line(FLASK + """
    import asyncio
    def run(cmd):
        os.system(cmd)
    @app.route('/')
    def v():
        asyncio.run(request.args["c"])
    """)
    assert r == {}


def test_plain_name_call_still_resolves_to_user_function():
    r = cwes_by_line(FLASK + """
    def run(cmd):
        os.system(cmd)
    @app.route('/')
    def v():
        run(request.args["c"])
    """)
    assert [c for cs in r.values() for c in cs] == ["CWE-78"]


# ---- closures: a nested def sees the enclosing function's taint ---------------

def test_nested_function_sees_outer_taint():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        raw = request.args.get("q")
        def inner():
            return db.execute("SELECT " + raw)
        return str(inner())
    """)
    assert r == {10: {"CWE-89"}}


def test_nested_function_parameter_shadows_outer_taint():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        q = request.args.get("q")
        def inner(q):
            return db.execute("SELECT " + q)
        return str(inner("1"))
    """)
    assert r == {}


def test_nested_function_reassignment_cleans_outer_taint():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        q = request.args.get("q")
        def inner():
            q = "1"
            return db.execute("SELECT " + q)
        return str(inner())
    """)
    assert r == {}


def test_nested_function_does_not_corrupt_outer_summary():
    # pass 1: the outer parameter label must not leak into the inner function's summary
    r = cwes_by_line(FLASK + """
    def helper(x):
        def inner():
            return x
        return "const"
    @app.route('/')
    def v():
        os.system(helper(request.args["c"]))
    """)
    assert r == {}
