"""Hard cases — written to stress the engine, not to pass.

Cross-file flow (see hard_helpers.py), class state, loops, try/except, async, closures,
dict/list containers, kwargs, walrus, comprehensions, decorators, globals.
Lines marked `-- known FN` / `-- known FP` are documented design limits.
"""
import asyncio
import json
import os
import sqlite3
import subprocess
from typing import Optional

from flask import Flask, request, jsonify, redirect, send_file, abort
from markupsafe import escape

from hard_helpers import build_query, Shell, sanitize_name, lookup_user, PathBox

app = Flask(__name__)
db = sqlite3.connect(":memory:")
CACHE = {}


# ---- cross-file --------------------------------------------------------------

@app.route("/x1")
def x1():
    db.execute(build_query(request.args["name"]))                              # VULN:CWE-89
    return "ok"


@app.route("/x2")
def x2():
    Shell().run(request.args["cmd"])                                           # VULN:CWE-78
    return "ok"


@app.route("/x3")
def x3():
    name = sanitize_name(request.args["f"])
    return send_file("/srv/" + name)                                           # SAFE (user sanitizer wraps secure_filename)


@app.route("/x4")
def x4():
    lookup_user(request.args["id"])                                            # VULN:CWE-89 (sink two hops deep)
    return "ok"


@app.route("/x5")
def x5():
    box = PathBox("/srv")
    return send_file(box.join(request.args["f"]))                              # VULN:CWE-22


# ---- containers ----------------------------------------------------------------

@app.route("/k1")
def k1():
    params = {"name": request.args["n"]}
    db.execute("SELECT * FROM t WHERE n = '" + params["name"] + "'")           # VULN:CWE-89
    return "ok"


@app.route("/k2")
def k2():
    parts = []
    for k in request.args:
        parts.append(request.args[k])
    subprocess.run(" ".join(parts), shell=True)                                # VULN:CWE-78
    return "ok"


@app.route("/k3")
def k3():
    cfg = {"host": "localhost", "port": 5432}
    db.execute("SELECT * FROM t WHERE h = '%s'" % cfg["host"])                 # SAFE
    return "ok"


@app.route("/k4")
def k4():
    row = {"id": 1, "note": request.form["note"]}
    db.execute("INSERT INTO t VALUES (%d)" % row["id"])                        # SAFE -- known FP (container-level taint, not key-sensitive)
    return "ok"


@app.route("/k5")
def k5():
    names = [n.strip() for n in request.args.getlist("n")]
    db.execute("SELECT * FROM t WHERE n IN (" + ",".join(names) + ")")         # VULN:CWE-89
    return "ok"


# ---- control flow --------------------------------------------------------------

@app.route("/c1")
def c1():
    uid = request.args.get("id")
    try:
        uid = int(uid)
    except ValueError:
        abort(400)
    db.execute("SELECT * FROM users WHERE id = %d" % uid)                      # SAFE
    return "ok"


@app.route("/c2")
def c2():
    uid = request.args.get("id")
    try:
        n = int(uid)
    except ValueError:
        n = 0
    db.execute("SELECT * FROM users WHERE id = " + uid)                        # VULN:CWE-89 (uid itself never converted)
    return "ok"


@app.route("/c3")
def c3():
    tbl = request.args.get("t")
    if tbl == "users":
        pass
    elif tbl == "orders":
        pass
    else:
        abort(400)
    db.execute("SELECT * FROM " + tbl)                                         # SAFE -- known FP (equality chain across elif/else not merged into a guard)
    return "ok"


@app.route("/c4")
def c4():
    tbl = request.args.get("t")
    if tbl not in ("users", "orders"):
        return jsonify(error="bad"), 400
    db.execute("SELECT * FROM " + tbl)                                         # SAFE
    return "ok"


@app.route("/c5")
def c5():
    cmd = "ls"
    while True:
        cmd = cmd + request.args.get("flag", "")
        if len(cmd) > 100:
            break
    os.system(cmd)                                                             # VULN:CWE-78
    return "ok"


@app.route("/c6")
def c6():
    if (q := request.args.get("q")) is not None:
        db.execute("SELECT * FROM t WHERE q = '" + q + "'")                    # VULN:CWE-89
    return "ok"


@app.route("/c7")
def c7():
    name = request.args.get("n", "")
    safe = escape(name) if name else ""
    return "<b>" + safe + "</b>"                                               # SAFE


@app.route("/c8")
def c8():
    name = request.args.get("n", "")
    out = escape(name) if len(name) < 10 else name
    return "<b>" + out + "</b>"                                                # VULN:CWE-79 (one branch unescaped)


# ---- class state ---------------------------------------------------------------

class Handler:
    def __init__(self):
        self.target = None

    def load(self):
        self.target = request.args.get("target")

    def fire(self):
        os.system("ping " + self.target)                                       # VULN:CWE-78 -- known FN (field flow across methods)

    def direct(self, t):
        self.t = t
        os.system("ping " + self.t)                                            # sink via self.t


@app.route("/h1")
def h1():
    h = Handler()
    h.direct(request.args["t"])                                                # VULN:CWE-78
    return "ok"


# ---- async / closures / globals -----------------------------------------------

@app.route("/a1")
async def a1():
    data = await asyncio.sleep(0, result=request.args.get("x"))
    db.execute("SELECT " + request.args.get("x"))                              # VULN:CWE-89
    return "ok"


@app.route("/n1")
def n1():
    raw = request.args.get("q")

    def inner():
        return db.execute("SELECT " + raw)                                     # VULN:CWE-89 -- known FN (closure captures outer taint)

    return str(inner())


@app.route("/g1")
def g1():
    CACHE["q"] = request.args.get("q")
    return "ok"


@app.route("/g2")
def g2():
    db.execute("SELECT " + CACHE["q"])                                         # VULN:CWE-89 -- known FN (taint through module global across requests)
    return "ok"


# ---- kwargs / format variants ---------------------------------------------------

@app.route("/f1")
def f1():
    db.execute("SELECT * FROM t WHERE n = '{}'".format(request.args["n"]))      # VULN:CWE-89
    return "ok"


@app.route("/f2")
def f2():
    db.execute("SELECT * FROM t WHERE n = '{n}'".format(n=request.args["n"]))   # VULN:CWE-89
    return "ok"


@app.route("/f3")
def f3():
    db.execute("SELECT * FROM t WHERE n = '%(n)s'" % {"n": request.args["n"]})  # VULN:CWE-89
    return "ok"


@app.route("/f4")
def f4():
    sql = "SELECT * FROM t WHERE n = ?"
    db.execute(sql, [request.args["n"]])                                        # SAFE
    return "ok"


@app.route("/f5")
def f5():
    subprocess.run(args="ls " + request.args["d"], shell=True)                  # VULN:CWE-78
    return "ok"


@app.route("/f6")
def f6():
    subprocess.run(["ls", request.args["d"]], shell=False, check=True)          # SAFE
    return "ok"


@app.route("/f7")
def f7():
    data = json.loads(request.data)
    os.system("echo " + data["msg"])                                           # VULN:CWE-78
    return "ok"


@app.route("/f8")
def f8():
    nxt = request.args.get("next")
    return redirect(nxt or "/")                                                # VULN:CWE-601
