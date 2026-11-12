"""action.yml must not turn workflow inputs into shell code.

The unsafe form is `run: sinkline scan ${{ inputs.path }}`: GitHub pastes the input into the script
text before bash parses it, so `path: ". ; touch pwned"` runs `touch pwned`. The safe form passes
inputs through `env:` and quotes them. These tests pin the safe form and run the real script with
hostile inputs.
"""
import os
import re
import shutil
import stat
import sys
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "action-scan.sh"


def _find_bash():
    b = shutil.which("bash")
    # on Windows runners `bash` can resolve to the WSL launcher in System32; use Git Bash instead
    if b and sys.platform == "win32" and "system32" in b.lower():
        for cand in (r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files\Git\usr\bin\bash.exe"):
            if os.path.exists(cand):
                return cand
        return None
    return b


BASH = _find_bash()

needs_bash = pytest.mark.skipif(BASH is None, reason="bash not available")


def _run_blocks(text: str):
    """Yield the text of every `run:` value in a workflow/action file."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)(?:- )?run:\s*(.*)$", lines[i])
        if not m:
            i += 1
            continue
        indent = len(m.group(1)) + (2 if lines[i].lstrip().startswith("- ") else 0)
        block = [m.group(2)]
        i += 1
        while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
            block.append(lines[i])
            i += 1
        yield "\n".join(block)


UNTRUSTED = ("${{ inputs.", "${{ github.event", "${{ github.head_ref")


def test_no_untrusted_expression_inside_any_run_block():
    for f in [ROOT / "action.yml", *(ROOT / ".github" / "workflows").glob("*.yml")]:
        for block in _run_blocks(f.read_text(encoding="utf-8")):
            assert not any(u in block for u in UNTRUSTED), f"{f.name}: untrusted expression in run block: {block!r}"


def test_action_yml_passes_inputs_via_env():
    text = (ROOT / "action.yml").read_text(encoding="utf-8")
    for name in ("path", "fail-on", "min-confidence"):
        assert f"${{{{ inputs.{name} }}}}" in text
    for block in _run_blocks(text):
        assert "inputs." not in block


@pytest.fixture
def stub(tmp_path):
    """A fake `sinkline` on PATH that records its argv one entry per line."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "sinkline"
    # Path.write_text(newline=) needs Python 3.10; this project supports 3.9
    with open(exe, "w", encoding="utf-8", newline="\n") as fh:
        fh.write('#!/usr/bin/env bash\nprintf "%s\n" "$@" > "$STUB_OUT"\nexit "${STUB_RC:-0}"\n')
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    return bindir


def _run(tmp_path, stub, rc=0, **inputs):
    env = dict(os.environ)
    env["PATH"] = str(stub) + os.pathsep + env["PATH"]
    env["STUB_OUT"] = str(tmp_path / "argv.txt")
    env["STUB_RC"] = str(rc)
    env["GITHUB_ENV"] = str(tmp_path / "ghenv.txt")
    for k, v in inputs.items():
        env["INPUT_" + k.upper()] = v
    p = subprocess.run([BASH, str(SCRIPT)], cwd=tmp_path, env=env, capture_output=True, text=True)
    argv = (tmp_path / "argv.txt").read_text(encoding="utf-8").splitlines() if (tmp_path / "argv.txt").exists() else None
    return p, argv


@needs_bash
@pytest.mark.parametrize("evil", [
    ". ; touch pwned",
    "$(touch pwned)",
    "`touch pwned`",
    ". && touch pwned",
    '"; touch pwned; "',
    "a b",
])
def test_path_is_one_argument_and_never_executed(tmp_path, stub, evil):
    p, argv = _run(tmp_path, stub, path=evil, fail_on="", min_confidence="low")
    assert p.returncode == 0
    assert not (tmp_path / "pwned").exists()
    assert argv[:2] == ["scan", evil]
    assert argv.count(evil) == 1 and "--fail-on" not in argv


@needs_bash
@pytest.mark.parametrize("evil", ["high; touch pwned", "$(touch pwned)", "HIGH", "urgent", "high --baseline x"])
def test_fail_on_is_allow_listed(tmp_path, stub, evil):
    p, argv = _run(tmp_path, stub, path=".", fail_on=evil, min_confidence="low")
    assert p.returncode == 2 and "::error::" in p.stdout
    assert argv is None  # sinkline never ran
    assert not (tmp_path / "pwned").exists()


@needs_bash
def test_min_confidence_is_allow_listed(tmp_path, stub):
    p, argv = _run(tmp_path, stub, path=".", fail_on="", min_confidence="low; touch pwned")
    assert p.returncode == 2 and argv is None and not (tmp_path / "pwned").exists()


@needs_bash
def test_option_looking_path_is_not_parsed_as_an_option(tmp_path, stub):
    p, argv = _run(tmp_path, stub, path="--baseline", fail_on="", min_confidence="low")
    assert argv[:2] == ["scan", "./--baseline"]


@needs_bash
def test_valid_inputs_reach_the_cli(tmp_path, stub):
    p, argv = _run(tmp_path, stub, path="src", fail_on="high", min_confidence="medium")
    assert argv == ["scan", "src", "--format", "sarif", "-o", "sinkline.sarif", "--min-confidence", "medium", "--fail-on", "high"]


@needs_bash
@pytest.mark.parametrize("rc", [1, 2])
def test_nonzero_exit_is_recorded_for_the_final_step(tmp_path, stub, rc):
    p, _ = _run(tmp_path, stub, rc=rc, path=".", fail_on="high", min_confidence="low")
    assert p.returncode == 0  # the SARIF upload step still has to run
    assert (tmp_path / "ghenv.txt").read_text(encoding="utf-8").strip() == f"SINKLINE_RC={rc}"


# ---- fail-on-parse-error input and real exit codes ------------------------------------------

@needs_bash
def test_fail_on_parse_error_true_adds_the_flag(tmp_path, stub):
    p, argv = _run(tmp_path, stub, path="src", fail_on="high", min_confidence="low", fail_on_parse_error="true")
    assert argv[-1] == "--fail-on-parse-error"
    assert argv[:2] == ["scan", "src"]


@needs_bash
@pytest.mark.parametrize("val", ["", "false"])
def test_fail_on_parse_error_off_by_default(tmp_path, stub, val):
    p, argv = _run(tmp_path, stub, path="src", fail_on="", min_confidence="low", fail_on_parse_error=val)
    assert "--fail-on-parse-error" not in argv


@needs_bash
@pytest.mark.parametrize("evil", ["TRUE", "yes", "true; touch pwned", "$(touch pwned)"])
def test_fail_on_parse_error_is_allow_listed(tmp_path, stub, evil):
    p, argv = _run(tmp_path, stub, path=".", fail_on="", min_confidence="low", fail_on_parse_error=evil)
    assert p.returncode == 2 and "::error::" in p.stdout and argv is None
    assert not (tmp_path / "pwned").exists()


@pytest.fixture
def real_cli(tmp_path):
    """A `sinkline` on PATH that runs the checked-out package, so the script sees real exit codes."""
    bindir = tmp_path / "realbin"
    bindir.mkdir()
    exe = bindir / "sinkline"
    with open(exe, "w", encoding="utf-8", newline="\n") as fh:
        fh.write('#!/usr/bin/env bash\nexec "$SL_PY" -m sinkline "$@"\n')
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    return bindir


def _run_real(tmp_path, real_cli, **inputs):
    env = dict(os.environ)
    env["PATH"] = str(real_cli) + os.pathsep + env["PATH"]
    env["SL_PY"] = sys.executable.replace("\\", "/")
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env["GITHUB_ENV"] = str(tmp_path / "ghenv.txt")
    for k, v in inputs.items():
        env["INPUT_" + k.upper()] = v
    p = subprocess.run([BASH, str(SCRIPT)], cwd=tmp_path, env=env, capture_output=True, text=True)
    gh = tmp_path / "ghenv.txt"
    rc = gh.read_text(encoding="utf-8").strip() if gh.exists() else None
    return p, rc


@needs_bash
def test_real_missing_path_records_rc_2(tmp_path, real_cli):
    p, rc = _run_real(tmp_path, real_cli, path="nonexistent", fail_on="high", min_confidence="low")
    assert p.returncode == 0 and rc == "SINKLINE_RC=2"


@needs_bash
def test_real_only_unparseable_file_records_rc_3_under_fail_on(tmp_path, real_cli):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "bad.py").write_text("def f(:\n")
    p, rc = _run_real(tmp_path, real_cli, path="src", fail_on="low", min_confidence="low")
    assert rc == "SINKLINE_RC=3"


@needs_bash
def test_real_parse_error_flag_gates_only_when_set(tmp_path, real_cli):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "ok.py").write_text("x = 1\n")
    (tmp_path / "src" / "bad.py").write_text("def f(:\n")
    _, rc = _run_real(tmp_path, real_cli, path="src", fail_on="high", min_confidence="low")
    assert rc is None
    _, rc = _run_real(tmp_path, real_cli, path="src", fail_on="high", min_confidence="low", fail_on_parse_error="true")
    assert rc == "SINKLINE_RC=3"


def test_action_yml_declares_the_input_and_names_each_exit_code():
    text = (ROOT / "action.yml").read_text(encoding="utf-8")
    assert "fail-on-parse-error:" in text and "${{ inputs.fail-on-parse-error }}" in text
    assert '"2"' in text and '"3"' in text
    assert "hashFiles('sinkline.sarif')" in text  # a failed scan must not turn into an upload error
