"""Labeled benchmark corpus — FastAPI + Django-style views + CLI/socket sources."""
import os
import subprocess
import sqlite3
import pickle
import sys
import tarfile
import zipfile
import logging
import torch
import yaml
from pathlib import Path

from fastapi import FastAPI, APIRouter, Query, Form, Header
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse, JSONResponse
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect as dj_redirect
from django.utils.safestring import mark_safe
from django.utils.html import escape as dj_escape

app = FastAPI()
router = APIRouter()
log = logging.getLogger(__name__)
conn = sqlite3.connect(":memory:")
MODEL_DIR = Path("/models")


# ---- FastAPI: path params / Query() are sources -----------------------------

@app.get("/items/{item_id}")
def read_item(item_id: str):
    conn.execute("SELECT * FROM items WHERE id = '" + item_id + "'")           # VULN:CWE-89
    return {"ok": True}


@app.get("/items2/{item_id}")
def read_item2(item_id: int):
    conn.execute(f"SELECT * FROM items WHERE id = {item_id}")                 # SAFE (typed int)
    return {"ok": True}


@app.get("/search")
def search(q: str = Query("")):
    conn.execute("SELECT * FROM items WHERE name LIKE '%" + q + "%'")         # VULN:CWE-89
    return {"ok": True}


@app.get("/search2")
def search2(q: str = Query("")):
    conn.execute("SELECT * FROM items WHERE name LIKE ?", ("%" + q + "%",))   # SAFE
    return {"ok": True}


@app.get("/page", response_class=HTMLResponse)
def page(name: str = Query("")):
    return HTMLResponse("<h1>" + name + "</h1>")                              # VULN:CWE-79


@app.get("/page2")
def page2(name: str = Query("")):
    return JSONResponse({"name": name})                                       # SAFE


@app.get("/go")
def go(url: str = Query("/")):
    return RedirectResponse(url)                                              # VULN:CWE-601


@app.get("/files/{name}")
def files(name: str):
    return FileResponse(MODEL_DIR / name)                                     # VULN:CWE-22


@app.get("/files2/{name}")
def files2(name: str):
    p = (MODEL_DIR / name).resolve()
    if not str(p).startswith(str(MODEL_DIR)):
        return JSONResponse({"error": "nope"}, status_code=400)
    return FileResponse(p)                                                    # SAFE


@router.post("/exec")
def run(cmd: str = Form(...)):
    subprocess.run(cmd, shell=True)                                           # VULN:CWE-78
    return {"ok": True}


@router.post("/exec2")
def run2(cmd: str = Form(...)):
    subprocess.run(["echo", cmd])                                             # SAFE
    return {"ok": True}


# ---- ML-flavored sinks (NVIDIA-relevant) ------------------------------------

@app.post("/load-model")
def load_model(name: str = Form(...)):
    model = torch.load(MODEL_DIR / name)                                      # VULN:CWE-502
    return {"loaded": str(type(model))}


@app.post("/load-model2")
def load_model2(name: str = Form(...)):
    model = torch.load(MODEL_DIR / name, weights_only=True)                   # SAFE (still path-tainted, but not deser)
    return {"loaded": str(type(model))}


@app.post("/upload-archive")
def upload_archive(path: str = Form(...)):
    with tarfile.open(path) as tf:
        tf.extractall("/tmp/out")                                             # VULN:CWE-22
    return {"ok": True}


@app.post("/upload-zip")
def upload_zip(path: str = Form(...)):
    with zipfile.ZipFile(path) as zf:
        zf.extractall("/tmp/out")                                             # VULN:CWE-22
    return {"ok": True}


@app.post("/cfg")
def cfg(text: str = Form(...)):
    return yaml.load(text, Loader=yaml.FullLoader)                            # VULN:CWE-502


# ---- Django-style views (request param is the source) -----------------------

def dj_profile(request):
    name = request.GET.get("name", "")
    return HttpResponse("<h1>" + name + "</h1>")                              # VULN:CWE-79


def dj_profile_safe(request):
    name = request.GET.get("name", "")
    return HttpResponse("<h1>" + dj_escape(name) + "</h1>")                   # SAFE


def dj_banner(request):
    return mark_safe(request.POST["html"])                                    # VULN:CWE-79


def dj_next(request):
    return HttpResponseRedirect(request.GET.get("next", "/"))                 # VULN:CWE-601


def dj_next2(request):
    return dj_redirect("home")                                                # SAFE


def dj_query(request):
    from django.db import connection
    with connection.cursor() as c:
        c.execute("SELECT 1 WHERE x = '%s'" % request.GET["x"])               # VULN:CWE-89
    return HttpResponse("ok")


def dj_log(request):
    log.info("login attempt for " + request.POST.get("user", ""))              # VULN:CWE-117
    return HttpResponse("ok")


def dj_log2(request):
    log.info("login attempt for %s", request.POST.get("user", ""))            # SAFE (parameterized logging)
    return HttpResponse("ok")


# ---- CLI / non-web sources ----------------------------------------------------

def cli_main():
    target = sys.argv[1]
    os.system("nmap " + target)                                               # VULN:CWE-78
    with open(target) as fh:                                                  # VULN:CWE-22
        data = fh.read()
    obj = pickle.loads(data.encode())                                         # SAFE (file content, not attacker-controlled)
    return obj


def cli_safe():
    target = sys.argv[1]
    subprocess.run(["nmap", target])                                          # SAFE
    return 0


class Store:
    def __init__(self, c):
        self.c = c

    def get(self, key):
        return self.c.execute("SELECT v FROM kv WHERE k = '" + key + "'")       # sink inside method

    def get_safe(self, key):
        return self.c.execute("SELECT v FROM kv WHERE k = ?", (key,))


@app.get("/kv/{key}")
def kv(key: str):
    return Store(conn).get(key)                                               # VULN:CWE-89


@app.get("/kv2/{key}")
def kv2(key: str):
    return Store(conn).get_safe(key)                                          # SAFE
