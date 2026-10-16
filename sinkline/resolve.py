"""Import and name resolution.

Turns `from flask import request as r; r.args` into the qualified name `flask.request.args`
so the model can be keyed on stable qualnames regardless of how a module aliases things.
Also tracks class instantiation so `cur = conn.cursor(); cur.execute(...)` resolves to a
cursor-ish execute.
"""

from __future__ import annotations

import ast
from typing import Dict, Optional

# Receiver-type hints: if a name was bound from a call to <key>, treat it as <value>
# so method calls on it resolve to the right sink qualname.
_INSTANCE_OF = {
    "sqlite3.connect": "sqlite3.Connection",
    "sqlite3.Connection.cursor": "sqlite3.Cursor",
    "psycopg2.connect": "psycopg2.connection",
    "psycopg2.connection.cursor": "psycopg2.cursor",
    "pymysql.connect": "pymysql.connections.Connection",
    "pymysql.connections.Connection.cursor": "pymysql.cursors.Cursor",
    "MySQLdb.connect": "MySQLdb.connections.Connection",
    "MySQLdb.connections.Connection.cursor": "MySQLdb.cursors.Cursor",
    "sqlalchemy.create_engine": "sqlalchemy.engine.Engine",
    "sqlalchemy.engine.Engine.connect": "sqlalchemy.engine.Connection",
    "sqlalchemy.orm.sessionmaker": "sqlalchemy.orm.Session",
    "sqlalchemy.orm.Session": "sqlalchemy.orm.Session",
    "django.db.connection.cursor": "django.db.connection.cursor",
    "flask.Flask": "flask.Flask",
    "flask.Blueprint": "flask.Blueprint",
    "fastapi.FastAPI": "fastapi.FastAPI",
    "fastapi.APIRouter": "fastapi.APIRouter",
    "requests.Session": "requests.Session",
    "httpx.Client": "httpx.Client",
    "httpx.AsyncClient": "httpx.AsyncClient",
    "aiohttp.ClientSession": "aiohttp.ClientSession",
    "ldap.initialize": "ldap.ldapobject.SimpleLDAPObject",
    "ldap3.Connection": "ldap3.Connection",
    "zipfile.ZipFile": "zipfile.ZipFile",
    "tarfile.open": "tarfile.TarFile",
    "tarfile.TarFile": "tarfile.TarFile",
    "logging.getLogger": "logging.Logger",
    "jinja2.Environment": "jinja2.Environment",
    "socket.socket": "socket.socket",
    "pymongo.MongoClient": "pymongo.MongoClient",
    "lxml.etree.fromstring": "lxml.etree._Element",
    "lxml.etree.parse": "lxml.etree._ElementTree",
    "argon2.PasswordHasher": "argon2.PasswordHasher",
}

_BUILTINS = {
    "open", "eval", "exec", "compile", "input", "__import__", "str", "bytes", "bytearray",
    "int", "float", "bool", "len", "list", "dict", "tuple", "set", "sorted", "reversed",
    "map", "filter", "zip", "enumerate", "next", "iter", "format", "getattr", "min", "max",
    "sum", "hash", "id", "isinstance", "repr", "bin", "hex", "oct", "chr", "ord", "print",
}

# Module aliases that appear in real code
_MODULE_CANON = {
    "cPickle": "pickle",
    "_pickle": "pickle",
    "posixpath": "os.path",
    "ntpath": "os.path",
    "ujson": "json",
    "simplejson": "json",
    "flask_sqlalchemy": "sqlalchemy",
    "starlette.requests": "starlette.requests",
}


class Scope:
    """Name -> qualified-name bindings, chained to the enclosing scope."""

    def __init__(self, parent: Optional["Scope"] = None):
        self.parent = parent
        self.names: Dict[str, str] = {}

    def bind(self, name: str, qual: str) -> None:
        self.names[name] = qual

    def lookup(self, name: str) -> Optional[str]:
        s: Optional[Scope] = self
        while s is not None:
            if name in s.names:
                return s.names[name]
            s = s.parent
        return None


class Resolver:
    def __init__(self) -> None:
        self.module_scope = Scope()

    # -- import bookkeeping ----------------------------------------------
    def visit_import(self, node: ast.Import, scope: Scope) -> None:
        for alias in node.names:
            mod = _MODULE_CANON.get(alias.name, alias.name)
            scope.bind(alias.asname or alias.name.split(".")[0], mod if alias.asname else mod.split(".")[0])
            if alias.asname is None and "." in alias.name:
                # import os.path  -> binds "os"
                scope.bind(alias.name.split(".")[0], alias.name.split(".")[0])

    def visit_import_from(self, node: ast.ImportFrom, scope: Scope) -> None:
        mod = node.module or ""
        mod = _MODULE_CANON.get(mod, mod)
        for alias in node.names:
            if alias.name == "*":
                continue
            qual = f"{mod}.{alias.name}" if mod else alias.name
            qual = _MODULE_CANON.get(qual, qual)
            scope.bind(alias.asname or alias.name, qual)

    def bind_instance(self, name: str, ctor_qual: str, scope: Scope) -> None:
        inst = _INSTANCE_OF.get(ctor_qual)
        if inst:
            scope.bind(name, inst)

    # -- expression -> qualname ------------------------------------------
    def qualname(self, node: ast.AST, scope: Scope) -> Optional[str]:
        """Best-effort qualified name for a Name / Attribute / Call chain."""
        if isinstance(node, ast.Name):
            q = scope.lookup(node.id)
            if q is not None:
                return q
            if node.id in _BUILTINS:
                return f"builtins.{node.id}"
            return node.id
        if isinstance(node, ast.Attribute):
            base = self.qualname(node.value, scope)
            if base is None:
                return None
            full = f"{base}.{node.attr}"
            return _MODULE_CANON.get(full, full)
        if isinstance(node, ast.Call):
            # e.g. conn.cursor().execute(...)
            fq = self.qualname(node.func, scope)
            if fq is None:
                return None
            return _INSTANCE_OF.get(fq, fq)
        if isinstance(node, ast.Subscript):
            return self.qualname(node.value, scope)
        return None

    @staticmethod
    def candidate_qualnames(qual: str) -> list:
        """Progressively less-specific names to try against the model.

        'a.b.c.execute' -> ['a.b.c.execute', 'b.c.execute', 'c.execute', 'execute']
        Lets a sink declared as 'cursor.execute' match 'self.db.cursor.execute'.
        """
        parts = qual.split(".")
        return [".".join(parts[i:]) for i in range(len(parts))]
