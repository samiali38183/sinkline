"""Regression tests for the gaps the external benchmark (OWASP BenchmarkPython) exposed in 0.4.1.

Each test is a tiny program plus the CWEs expected on specific lines, like tests/test_engine.py.
"""
import sys
import textwrap

import pytest

from sinkline import scan_source

needs_match = pytest.mark.skipif(sys.version_info < (3, 10), reason="match statements need Python 3.10+")

FLASK = "from flask import Flask, request, redirect, send_file\napp = Flask(__name__)\nimport os, subprocess, sqlite3, shlex\ndb = sqlite3.connect(':memory:')\n"


def _src(src: str) -> str:
    if src.startswith(FLASK):
        return FLASK + textwrap.dedent(src[len(FLASK):])
    return textwrap.dedent(src)


def cwes_by_line(src: str):
    res = scan_source(_src(src), "t.py")
    out = {}
    for f in res.findings:
        out.setdefault(f.line, set()).add(f.cwe)
    return out


# ---- returned call results are HTML when they are the tainted string itself ---------

@pytest.mark.parametrize("ret", [
    'request.args.get("q")',                 # the source call itself
    'request.args.get("q").strip()',         # string method on a source call
    'name.strip()',
    'name.upper()',
    '"<p>{}</p>".format(name)',
    'helper(name)',                          # user function that returns its argument
])
def test_returned_call_result_is_xss(ret):
    r = cwes_by_line(FLASK + f"""
    def helper(x):
        return x
    @app.route('/')
    def v():
        name = request.args["q"]
        return {ret}
    """)
    assert r == {11: {"CWE-79"}}


@pytest.mark.parametrize("ret", [
    "jsonify(name)", "redirect(name)", "render(name)", "url_for('v', q=name)", "json.dumps(name)",
    "name.isdigit()", "int(name)", "escape(name)", "name.strip().isdigit()",
])
def test_returned_call_result_that_is_not_html(ret):
    r = cwes_by_line(FLASK + f"""
    import json
    from flask import jsonify, url_for
    from markupsafe import escape
    def render(x):
        return {{"v": 1}}
    @app.route('/')
    def v():
        name = request.args["q"]
        return {ret}
    """)
    assert not any("CWE-79" in cs for cs in r.values())


def test_fastapi_htmlresponse_content_keyword():
    r = cwes_by_line("""
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse
    app = FastAPI()
    @app.get("/")
    def v(q: str):
        return HTMLResponse(content="<p>" + q + "</p>")
    """)
    assert r == {7: {"CWE-79"}}


def test_django_httpresponse_content_keyword():
    r = cwes_by_line("""
    from django.http import HttpResponse
    def v(request):
        return HttpResponse(content="<p>" + request.GET["q"] + "</p>")
    """)
    assert r == {4: {"CWE-79"}}


def test_render_template_string_with_tainted_template_is_also_xss():
    r = cwes_by_line(FLASK + """
    from flask import render_template_string
    @app.route('/')
    def v():
        return render_template_string("<p>" + request.args["q"] + "</p>")
    """)
    assert r == {9: {"CWE-79", "CWE-1336"}}


def test_render_template_string_with_tainted_variable_only_is_not_xss():
    r = cwes_by_line(FLASK + """
    from flask import render_template_string
    @app.route('/')
    def v():
        return render_template_string("<p>{{ q }}</p>", q=request.args["q"])
    """)
    assert r == {}


def test_make_response_tuple_only_body_counts():
    # (body, headers): a tainted value in the headers dict is not an HTML body
    r = cwes_by_line(FLASK + """
    from flask import make_response
    @app.route('/')
    def v():
        q = request.args["q"]
        return make_response(("ok", {"X-Q": q}))
    @app.route('/b')
    def w():
        q = request.args["q"]
        return make_response((q, {"X-Q": "1"}))
    """)
    assert r == {14: {"CWE-79"}}


# ---- dicts built by subscript assignment keep per-key taint -------------------------

def test_dict_built_by_subscript_assignment_is_key_sensitive():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        m = {}
        m["a"] = "const"
        m["b"] = request.args["q"]
        os.system(m["a"])
        os.system(m["b"])
    """)
    assert r == {12: {"CWE-78"}}


def test_dict_literal_then_subscript_assignment():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        m = {"a": "const"}
        m["b"] = request.args["q"]
        os.system(m["a"])
        os.system(m["b"])
    """)
    assert r == {11: {"CWE-78"}}


def test_dict_overwrite_of_a_key_clears_it():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        m = {}
        m["a"] = request.args["q"]
        m["a"] = "const"
        os.system(m["a"])
    """)
    assert r == {}


def test_dict_with_computed_key_falls_back_to_whole_container():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        m = {}
        k = request.args["k"]
        m[k] = request.args["q"]
        os.system(m["a"])
    """)
    assert r == {11: {"CWE-78"}}


def test_dict_get_on_subscript_built_dict():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        m = {}
        m["a"] = "const"
        m["b"] = request.args["q"]
        os.system(m.get("a"))
        os.system(m.get("b"))
    """)
    assert r == {12: {"CWE-78"}}


def test_dict_passed_whole_is_still_tainted():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        m = {}
        m["a"] = request.args["q"]
        os.system(str(m))
    """)
    assert r == {10: {"CWE-78"}}


def test_dict_key_set_in_one_branch_only_stays_tainted_after_join():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        m = {}
        if request.args["x"]:
            m["a"] = request.args["q"]
        else:
            m["a"] = "const"
        os.system(m["a"])
    """)
    assert r == {13: {"CWE-78"}}


# ---- match is a branch, not a sequence ----------------------------------------------

@needs_match
def test_match_cases_are_joined():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        param = request.args["q"]
        mode = request.args["m"]
        match mode:
            case "a":
                bar = param
            case _:
                bar = "const"
        os.system(bar)
    """)
    assert r == {15: {"CWE-78"}}


@needs_match
def test_match_without_wildcard_keeps_prior_value():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        bar = request.args["q"]
        match request.args["m"]:
            case "a":
                bar = "const"
            case "b":
                bar = "other"
        os.system(bar)
    """)
    assert r == {14: {"CWE-78"}}


@needs_match
def test_match_with_wildcard_where_every_case_is_clean():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        bar = request.args["q"]
        match request.args["m"]:
            case "a":
                bar = "const"
            case _:
                bar = "other"
        os.system(bar)
    """)
    assert r == {}


@needs_match
def test_match_capture_pattern_binds_tainted_subject():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        match request.args["q"]:
            case str() as s:
                os.system(s)
            case [first, *rest]:
                os.system(first)
    """)
    assert r == {10: {"CWE-78"}, 12: {"CWE-78"}}


# ---- sink and receiver coverage seen in the external benchmark -----------------------

def test_lxml_parse_result_xpath():
    r = cwes_by_line(FLASK + """
    import lxml.etree
    @app.route('/')
    def v():
        root = lxml.etree.parse("employees.xml")
        return str(root.xpath("//e[@id='" + request.args["q"] + "']"))
    """)
    assert r[10] == {"CWE-643"}


def test_elementpath_select():
    r = cwes_by_line(FLASK + """
    import elementpath
    import xml.etree.ElementTree as ET
    @app.route('/')
    def v():
        root = ET.parse("employees.xml")
        nodes = elementpath.select(root, "//e[@id='" + request.args["q"] + "']")
        return ""
    """)
    assert r == {11: {"CWE-643"}}


def test_codecs_open_path():
    r = cwes_by_line(FLASK + """
    import codecs
    @app.route('/')
    def v():
        f = codecs.open("/srv/files/" + request.args["f"], "r", "utf-8")
        return ""
    """)
    assert r == {9: {"CWE-22"}}


def test_pathlib_join_operator_then_read():
    r = cwes_by_line(FLASK + """
    import pathlib
    BASE = pathlib.Path("/srv/files")
    @app.route('/')
    def v():
        p = BASE / request.args["f"]
        q = BASE / "static.txt"
        q.read_text()
        return p.read_text()
    """)
    assert r == {13: {"CWE-22"}}


def test_pathlib_join_operator_on_local_path_object_exists_probe():
    r = cwes_by_line(FLASK + """
    import pathlib
    @app.route('/')
    def v():
        base = pathlib.Path("/srv/files")
        p = base / request.args["f"]
        if p.exists():
            return "yes"
        return "no"
    """)
    assert r == {11: {"CWE-22"}}


def test_pathlib_join_then_containment_check_is_clean():
    # the idiom sinkline itself recommends: resolve, then check the result is under BASE
    r = cwes_by_line(FLASK + """
    import pathlib
    BASE = pathlib.Path("/srv/files")
    @app.route('/')
    def v():
        p = (BASE / request.args["f"]).resolve()
        if not str(p).startswith(str(BASE)):
            return "no"
        return p.read_text()
    """)
    assert r == {}


def test_receiver_type_comes_through_a_helper_that_returns_the_instance():
    r = cwes_by_line(FLASK + """
    import ldap3
    def get_connection():
        conn = ldap3.Connection("srv")
        conn.bind()
        return conn
    @app.route('/')
    def v():
        conn = get_connection()
        conn.search("ou=u", "(uid=" + request.args["u"] + ")")
        return ""
    """)
    assert r == {14: {"CWE-90"}}


def test_sink_on_non_returned_unknown_object_is_not_guessed():
    r = cwes_by_line(FLASK + """
    def get_thing():
        return object()
    @app.route('/')
    def v():
        conn = get_thing()
        conn.search("ou=u", "(uid=" + request.args["u"] + ")")
        return ""
    """)
    assert r == {}


# ---- statically decided branches are pruned ----------------------------------------

def _branch(cond_setup: str, test: str) -> dict:
    return cwes_by_line(FLASK + f"""
    @app.route('/')
    def v():
        param = request.args["q"]
        {cond_setup}
        if {test}:
            bar = "const"
        else:
            bar = param
        os.system(bar)
    """)


def test_constant_arithmetic_condition_picks_the_live_branch():
    # 7*42 - 86 = 208 > 200: the "const" branch always runs
    assert _branch("num = 86", "7 * 42 - num > 200") == {}
    # 7*18 + 86 = 212 > 200 is true; with 'not' the tainted branch is live
    assert list(_branch("num = 86", "not (7 * 18 + num > 200)").values()) == [{"CWE-78"}]


def test_constant_string_membership_condition():
    assert _branch('s = "This should never happen"', "'should' in s") == {}
    assert list(_branch('s = "This should never happen"', "'should' not in s").values()) == [{"CWE-78"}]


def test_unknown_condition_still_joins_both_branches():
    assert list(_branch("", "request.args['x']").values()) == [{"CWE-78"}]


def test_constant_reassigned_in_a_loop_is_not_trusted():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        param = request.args["q"]
        n = 0
        for _ in range(3):
            if n > 0:
                os.system(param)
            n = n + 1
    """)
    assert list(r.values()) == [{"CWE-78"}]


def test_constant_differing_between_branches_is_not_trusted():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        param = request.args["q"]
        if request.args["m"]:
            n = 1
        else:
            n = 2
        if n > 1:
            os.system(param)
    """)
    assert list(r.values()) == [{"CWE-78"}]


def test_ternary_with_constant_condition():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        param = request.args["q"]
        num = 106
        bar = "safe" if 7 * 18 + num > 200 else param
        os.system(bar)
    """)
    assert r == {}


@needs_match
def test_match_on_constant_subject_takes_the_matching_case():
    r = cwes_by_line(FLASK + """
    @app.route('/')
    def v():
        param = request.args["q"]
        guess = "ABC"[1]
        match guess:
            case "A":
                bar = param
            case "B":
                bar = "const"
            case _:
                bar = param
        os.system(bar)
    """)
    assert r == {}


# ---- a quote check guards XPath string literals (and only XPath) ---------------------

def test_quote_rejection_guards_xpath_only():
    r = cwes_by_line(FLASK + """
    import lxml.etree
    @app.route('/')
    def v():
        q = request.args["q"]
        root = lxml.etree.parse("e.xml")
        if "'" in q:
            return "bad"
        root.xpath("//e[@id='" + q + "']")
        os.system(q)
        return ""
    """)
    assert list(r.values()) == [{"CWE-78"}]
