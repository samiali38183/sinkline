"""Helpers imported by hard_app.py — cross-file summaries must be learned from here."""
import os
import sqlite3
import subprocess

from werkzeug.utils import secure_filename

_db = sqlite3.connect(":memory:")


def build_query(name):
    return "SELECT * FROM users WHERE name = '" + name + "'"


class Shell:
    def run(self, cmd):
        subprocess.call(cmd, shell=True)


def sanitize_name(n):
    return secure_filename(n)


def _exec(sql):
    _db.execute(sql)


def lookup_user(uid):
    _exec("SELECT * FROM users WHERE id = " + uid)


class PathBox:
    def __init__(self, base):
        self.base = base

    def join(self, name):
        return os.path.join(self.base, name)
