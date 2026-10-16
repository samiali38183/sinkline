import os, sqlite3, subprocess, pickle, yaml, requests, shlex
from flask import Flask, request, redirect, render_template_string, send_file, make_response
from werkzeug.utils import secure_filename

app = Flask(__name__)
db = sqlite3.connect("x.db")

def run_query(sql):
    cur = db.cursor()
    cur.execute(sql)             # sink inside helper
    return cur.fetchall()

def normalize(s):
    return s.strip().lower()

def clean_cmd(s):
    return shlex.quote(s)

@app.route("/user")
def user():
    uid = request.args.get("id")
    return run_query("SELECT * FROM users WHERE id = " + uid)      # SQLi via helper

@app.route("/safe-user")
def safe_user():
    uid = int(request.args.get("id"))
    return run_query(f"SELECT * FROM users WHERE id = {uid}")      # int() -> safe

@app.route("/ping")
def ping():
    host = normalize(request.args["host"])
    subprocess.run("ping -c1 " + host, shell=True)                 # CMDi through normalize()
    subprocess.run(["ping", "-c1", host])                          # shell=False -> fine
    os.system("ping " + clean_cmd(host))                           # quoted -> fine
    return "ok"

@app.route("/dl")
def dl():
    name = request.args.get("f")
    if ".." in name:
        return "no", 400
    return send_file("/srv/files/" + name)                          # guarded -> no finding

@app.route("/dl2")
def dl2():
    name = request.args.get("f")
    return send_file(os.path.join("/srv", name))                    # path traversal

@app.route("/dl3")
def dl3():
    name = secure_filename(request.args.get("f"))
    return send_file(os.path.join("/srv", name))                    # sanitized

@app.route("/go")
def go():
    nxt = request.args.get("next", "/")
    if nxt in ALLOWED_TARGETS:
        return redirect(nxt)                                        # allow-listed
    return redirect(nxt)                                            # open redirect

@app.route("/tpl")
def tpl():
    return render_template_string("<h1>Hi " + request.args.get("n") + "</h1>")   # SSTI

@app.route("/hello")
def hello():
    return "<p>Hello " + request.args.get("n", "") + "</p>"          # reflected XSS

@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)                                # deser
    cfg = yaml.load(request.data)                                   # unsafe yaml
    cfg2 = yaml.load(request.data, Loader=yaml.SafeLoader)          # fine
    return "ok"

@app.route("/fetch")
def fetch():
    r = requests.get(request.args["url"])                           # SSRF
    return r.text

class Repo:
    def __init__(self, conn):
        self.conn = conn
    def find(self, name):
        return self.conn.execute("SELECT * FROM t WHERE n = '%s'" % name)

@app.route("/repo")
def repo():
    return str(Repo(db).find(request.args["n"]))                    # SQLi via method

def main():
    path = input("file? ")
    open(path).read()                                               # CLI path traversal (input source)

ALLOWED_TARGETS = {"/", "/home"}
