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
