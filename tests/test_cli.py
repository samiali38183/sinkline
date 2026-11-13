"""Exit codes of `sinkline scan`: a CI gate must never pass because nothing was scanned.

0 = scanned, nothing at/above --fail-on; 1 = findings at/above --fail-on; 2 = error (missing or
unreadable path, bad baseline, unwritable output); 3 = scan incomplete (a file failed to parse with
--fail-on-parse-error, or no file was analyzed under --fail-on).
"""
import json
import subprocess
import sys

import pytest

VULN = "import os\nfrom flask import request\n\ndef v():\n    os.system(request.args['c'])\n"
CLEAN = "def f(x):\n    return x + 1\n"
BAD = "def f(:\n    pass\n"


def run(*args, cwd=None):
    return subprocess.run([sys.executable, "-m", "sinkline", *args], capture_output=True, text=True, cwd=cwd)


@pytest.fixture
def tree(tmp_path):
    for name, files in {
        "clean": {"a.py": CLEAN},
        "vuln": {"a.py": VULN},
        "only_bad": {"bad.py": BAD},
        "mixed": {"a.py": CLEAN, "bad.py": BAD},
        "empty": {"readme.txt": "no python here"},
    }.items():
        (tmp_path / name).mkdir()
        for fn, body in files.items():
            (tmp_path / name / fn).write_text(body)
    return tmp_path


# ---- the documented table -------------------------------------------------------------

def test_clean_scan_exits_0(tree):
    assert run("scan", str(tree / "clean"), "--fail-on", "low").returncode == 0


def test_findings_at_threshold_exit_1(tree):
    assert run("scan", str(tree / "vuln"), "--fail-on", "high").returncode == 1


def test_findings_without_fail_on_exit_0(tree):
    assert run("scan", str(tree / "vuln")).returncode == 0


@pytest.mark.parametrize("fmt", ["text", "json", "sarif", "html"])
def test_missing_path_is_exit_2_with_message(tree, fmt):
    p = run("scan", str(tree / "nonexistent"), "--fail-on", "high", "--format", fmt)
    assert p.returncode == 2
    assert "not found" in p.stderr and "nonexistent" in p.stderr
    assert p.stdout == ""  # no misleading "0 findings" report


def test_missing_path_is_exit_2_even_without_fail_on(tree):
    assert run("scan", str(tree / "nonexistent")).returncode == 2


def test_unwritable_output_path_is_exit_2(tree):
    p = run("scan", str(tree / "clean"), "-o", str(tree / "no_such_dir" / "out.json"))
    assert p.returncode == 2 and "cannot write" in p.stderr


def test_bad_baseline_is_exit_2(tree):
    assert run("scan", str(tree / "clean"), "--baseline", str(tree / "nope.json")).returncode == 2


# ---- parse failures ---------------------------------------------------------------------

def test_parse_failure_is_reported_on_stderr_but_default_exit_is_unchanged(tree):
    p = run("scan", str(tree / "mixed"))
    assert p.returncode == 0
    assert "1 file(s) could not be parsed" in p.stderr and "bad.py" in p.stderr


def test_fail_on_parse_error_exits_3(tree):
    p = run("scan", str(tree / "mixed"), "--fail-on-parse-error")
    assert p.returncode == 3 and "bad.py" in p.stderr


def test_fail_on_parse_error_with_no_failures_exits_0(tree):
    assert run("scan", str(tree / "clean"), "--fail-on-parse-error").returncode == 0


def test_findings_outrank_parse_failure(tree):
    (tree / "vuln" / "bad.py").write_text(BAD)
    p = run("scan", str(tree / "vuln"), "--fail-on", "high", "--fail-on-parse-error")
    assert p.returncode == 1


def test_null_byte_file_is_a_parse_failure_without_line_none(tree):
    (tree / "nullbyte").mkdir()
    (tree / "nullbyte" / "n.py").write_bytes(b"x = 1\n\x00\n")
    p = run("scan", str(tree / "nullbyte"), "--fail-on-parse-error")
    assert p.returncode == 3
    assert "line None" not in p.stdout + p.stderr


def test_parse_failures_listed_in_json(tree):
    d = json.loads(run("scan", str(tree / "mixed"), "--format", "json").stdout)
    assert d["files"] == 1 and d["files_failed"] == 1
    assert len(d["errors"]) == 1 and d["errors"][0].startswith("bad.py")


def test_parse_failures_listed_in_sarif_notifications(tree):
    inv = json.loads(run("scan", str(tree / "mixed"), "--format", "sarif").stdout)["runs"][0]["invocations"][0]
    notes = inv["toolExecutionNotifications"]
    assert inv["executionSuccessful"] is False
    assert len(notes) == 1 and notes[0]["level"] == "error"
    assert notes[0]["descriptor"]["id"] == "SL-NOTIFY-PARSE"
    assert notes[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "bad.py"
    assert "bad.py" in notes[0]["message"]["text"]


# ---- zero files analyzed -----------------------------------------------------------------

def test_zero_files_under_fail_on_exits_3_with_warning(tree):
    p = run("scan", str(tree / "empty"), "--fail-on", "high")
    assert p.returncode == 3 and "no Python files were analyzed" in p.stderr


def test_zero_files_without_fail_on_warns_and_exits_0(tree):
    p = run("scan", str(tree / "empty"))
    assert p.returncode == 0 and "no Python files were analyzed" in p.stderr


def test_only_unparseable_files_under_fail_on_exits_3(tree):
    p = run("scan", str(tree / "only_bad"), "--fail-on", "low")
    assert p.returncode == 3
    assert "no Python files were analyzed" in p.stderr and "bad.py" in p.stderr


def test_zero_files_is_a_sarif_notification(tree):
    inv = json.loads(run("scan", str(tree / "empty"), "--format", "sarif").stdout)["runs"][0]["invocations"][0]
    assert [n["descriptor"]["id"] for n in inv["toolExecutionNotifications"]] == ["SL-NOTIFY-NOFILES"]


def test_excluding_everything_counts_as_zero_files(tree):
    (tree / "t").mkdir()
    (tree / "t" / "test_a.py").write_text(VULN)
    assert run("scan", str(tree / "t"), "--exclude-tests", "--fail-on", "low").returncode == 3


def test_scan_path_raises_for_missing_path(tree):
    from sinkline import scan_path
    with pytest.raises(FileNotFoundError):
        scan_path(str(tree / "nonexistent"))
