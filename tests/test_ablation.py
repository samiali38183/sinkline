"""The SINKLINE_ABLATE evaluation switch: off by default, and each setting removes one feature."""

from sinkline.engine import scan_source

CROSS = '''
import os
from flask import Flask, request
app = Flask(__name__)

def run(cmd):
    os.system(cmd)

@app.route("/a")
def a():
    run(request.args["c"])
'''

GUARDED = '''
import os
from flask import Flask, request
app = Flask(__name__)

@app.route("/b")
def b():
    n = request.args["n"]
    if not n.isdigit():
        return "bad"
    os.system("echo " + n)
'''


def test_default_analysis_is_unchanged(monkeypatch):
    monkeypatch.delenv("SINKLINE_ABLATE", raising=False)
    assert len(scan_source(CROSS).findings) == 1
    assert len(scan_source(GUARDED).findings) == 0


def test_interproc_off_loses_the_cross_function_flow(monkeypatch):
    monkeypatch.setenv("SINKLINE_ABLATE", "interproc")
    assert len(scan_source(CROSS).findings) == 0


def test_guards_off_reports_the_validated_value(monkeypatch):
    monkeypatch.setenv("SINKLINE_ABLATE", "guards")
    assert len(scan_source(GUARDED).findings) == 1
