"""Labeled benchmark corpus — Flask.

Every line that should fire is tagged `# VULN:<CWE>`; every line that must NOT fire is tagged
`# SAFE`. bench/score.py reads these tags as ground truth and scores the analyzer.
"""
import os
import re
import shlex
import sqlite3
import subprocess
import pickle
import yaml
import requests
import hashlib
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, request, redirect, render_template, render_template_string, send_file, send_from_directory, make_response, jsonify, abort, Markup
from markupsafe import escape
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE = Path("/srv/files")
ALLOWED_HOSTS = {"api.internal", "cdn.example.com"}
db = sqlite3.connect(":memory:")


# ---- A03 Injection: SQL ----------------------------------------------------

@app.route("/u1")
def u1():
    uid = request.args.get("id")
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE id = " + uid)                      # VULN:CWE-89
    return jsonify(cur.fetchall())


@app.route("/u2")
def u2():
    uid = request.args.get("id")
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))                   # SAFE
    return jsonify(cur.fetchall())


@app.route("/u3")
def u3():
    uid = int(request.args.get("id"))
    db.execute(f"SELECT * FROM users WHERE id = {uid}")                       # SAFE
    return "ok"


@app.route("/u4")
def u4():
    q = request.form["q"]
    sql = "SELECT * FROM t WHERE name LIKE '%%%s%%'" % q
    db.execute(sql)                                                           # VULN:CWE-89
    return "ok"


def _lookup(name):
    return db.execute("SELECT * FROM t WHERE name = '" + name + "'")          # sink inside helper


@app.route("/u5")
def u5():
    _lookup(request.args["name"])                                             # VULN:CWE-89
    return "ok"


@app.route("/u6")
def u6():
    order = request.args.get("order", "id")
    if order not in ("id", "name", "created"):
        abort(400)
    db.execute("SELECT * FROM t ORDER BY " + order)                           # SAFE
    return "ok"


@app.route("/u7")
def u7():
    uid = request.args.get("id")
    if not uid.isdigit():
        return "bad", 400
    db.execute("SELECT * FROM users WHERE id = " + uid)                       # SAFE
    return "ok"


@app.route("/u8")
def u8():
    uid = request.args.get("id")
    if uid.isdigit():
        db.execute("SELECT * FROM users WHERE id = " + uid)                   # SAFE
    else:
        db.execute("SELECT * FROM users WHERE id = " + uid)                   # VULN:CWE-89
    return "ok"


# ---- A03 Injection: command ------------------------------------------------

@app.route("/c1")
def c1():
    host = request.args["host"]
    os.system("ping -c 1 " + host)                                            # VULN:CWE-78
    return "ok"


@app.route("/c2")
def c2():
    host = request.args["host"]
    subprocess.run(["ping", "-c", "1", host])                                 # SAFE
    return "ok"


@app.route("/c3")
def c3():
    host = request.args["host"]
    subprocess.run("ping -c 1 " + host, shell=True)                           # VULN:CWE-78
    return "ok"


@app.route("/c4")
def c4():
    host = request.args["host"]
    subprocess.run("ping -c 1 " + shlex.quote(host), shell=True)              # SAFE
    return "ok"


@app.route("/c5")
def c5():
    host = request.args["host"].strip().lower()
    subprocess.Popen(f"dig {host}", shell=True)                               # VULN:CWE-78
    return "ok"


@app.route("/c6")
def c6():
    host = request.args["host"]
    subprocess.run("ping -c 1 " + host, shell=False)                          # SAFE
    return "ok"


@app.route("/c7")
def c7():
    n = request.args["n"]
    if not re.fullmatch(r"[a-z0-9.-]+", n):
        abort(400)
    os.system("host " + n)                                                    # SAFE
    return "ok"


# ---- A03 Injection: code / SSTI / XSS ---------------------------------------

@app.route("/e1")
def e1():
    expr = request.args["expr"]
    return str(eval(expr))                                                    # VULN:CWE-95


@app.route("/e2")
def e2():
    import ast
    return jsonify(ast.literal_eval(request.args["expr"]))                   # SAFE


@app.route("/t1")
def t1():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello " + name + "</h1>")              # VULN:CWE-1336


@app.route("/t2")
def t2():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)     # SAFE


@app.route("/t3")
def t3():
    name = request.args.get("name", "")
    return render_template("hello.html", name=name)                          # SAFE


@app.route("/x1")
def x1():
    name = request.args.get("name", "")
    return "<p>Hi " + name + "</p>"                                           # VULN:CWE-79


@app.route("/x2")
def x2():
    name = request.args.get("name", "")
    return "<p>Hi " + escape(name) + "</p>"                                   # SAFE


@app.route("/x3")
def x3():
    name = request.args.get("name", "")
    return Markup("<b>" + name + "</b>")                                      # VULN:CWE-79


@app.route("/x4")
def x4():
    name = request.args.get("name", "")
    resp = make_response(f"<p>{name}</p>")                                    # VULN:CWE-79
    return resp


@app.route("/x5")
def x5():
    return jsonify({"name": request.args.get("name", "")})                   # SAFE


# ---- A01 Broken Access Control: path traversal / open redirect ---------------

@app.route("/f1")
def f1():
    name = request.args["f"]
    return send_file("/srv/files/" + name)                                    # VULN:CWE-22


@app.route("/f2")
def f2():
    name = request.args["f"]
    return send_from_directory("/srv/files", name)                            # SAFE


@app.route("/f3")
def f3():
    name = secure_filename(request.args["f"])
    return send_file(os.path.join("/srv/files", name))                        # SAFE


@app.route("/f4")
def f4():
    name = request.args["f"]
    with open(os.path.join("/srv/files", name)) as fh:                        # VULN:CWE-22
        return fh.read()


@app.route("/f5")
def f5():
    name = request.args["f"]
    if ".." in name or name.startswith("/"):
        abort(400)
    with open(os.path.join("/srv/files", name)) as fh:                        # SAFE
        return fh.read()


@app.route("/f6")
def f6():
    name = os.path.basename(request.args["f"])
    with open(BASE / name) as fh:                                             # SAFE
        return fh.read()


@app.route("/f7", methods=["POST"])
def f7():
    name = request.form["name"]
    os.remove("/tmp/uploads/" + name)                                         # VULN:CWE-22
    return "ok"


@app.route("/r1")
def r1():
    return redirect(request.args.get("next", "/"))                            # VULN:CWE-601


@app.route("/r2")
def r2():
    nxt = request.args.get("next", "/")
    if urlparse(nxt).netloc == "":
        return redirect(nxt)                                                  # SAFE (same-origin check)
    abort(400)


@app.route("/r3")
def r3():
    nxt = request.args.get("next", "/")
    if nxt in ("/", "/home", "/account"):
        return redirect(nxt)                                                  # SAFE
    abort(400)


# ---- A08 Integrity: deserialization -----------------------------------------

@app.route("/d1", methods=["POST"])
def d1():
    return jsonify(pickle.loads(request.data))                                # VULN:CWE-502


@app.route("/d2", methods=["POST"])
def d2():
    return jsonify(yaml.load(request.data))                                   # VULN:CWE-502


@app.route("/d3", methods=["POST"])
def d3():
    return jsonify(yaml.safe_load(request.data))                              # SAFE


@app.route("/d4", methods=["POST"])
def d4():
    return jsonify(yaml.load(request.data, Loader=yaml.SafeLoader))           # SAFE


@app.route("/d5", methods=["POST"])
def d5():
    import json
    return jsonify(json.loads(request.data))                                  # SAFE


# ---- A10 SSRF ----------------------------------------------------------------

@app.route("/s1")
def s1():
    return requests.get(request.args["url"]).text                             # VULN:CWE-918


@app.route("/s2")
def s2():
    host = request.args["host"]
    if host not in ALLOWED_HOSTS:
        abort(400)
    return requests.get(f"https://{host}/status").text                        # SAFE


@app.route("/s3")
def s3():
    path = request.args["path"]
    return requests.get("https://api.internal/" + path).text                  # VULN:CWE-918


@app.route("/s4")
def s4():
    return requests.get("https://api.internal/status").text                   # SAFE


# ---- A02 Crypto --------------------------------------------------------------

@app.route("/h1", methods=["POST"])
def h1():
    pw = request.form["password"]
    return hashlib.md5(pw.encode()).hexdigest()                               # VULN:CWE-328


@app.route("/h2", methods=["POST"])
def h2():
    pw = request.form["password"]
    return hashlib.sha256(pw.encode()).hexdigest()                            # SAFE
