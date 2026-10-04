import os

import pytest

from agentshield.workspace_guard import diff, review, snapshot


def _flags(ws, before):
    after = snapshot(ws)
    return review(diff(before, after), after)


@pytest.fixture
def ws(tmp_path):
    (tmp_path / "main.py").write_text("print('hello')")
    return tmp_path


def test_makefile_is_flagged(ws):
    before = snapshot(ws)
    (ws / "Makefile").write_text("test:\n\techo hi\n")
    assert [f.path for f in _flags(ws, before)] == ["Makefile"]


def test_conftest_is_flagged(ws):
    before = snapshot(ws)
    (ws / "conftest.py").write_text("print('x')")
    assert [f.path for f in _flags(ws, before)] == ["conftest.py"]


def test_git_hook_is_flagged(ws):
    hooks = ws / ".git" / "hooks"
    hooks.mkdir(parents=True)
    before = snapshot(ws)
    (hooks / "pre-commit").write_text("#!/bin/sh\necho hi\n")
    assert any(f.path == ".git/hooks/pre-commit" for f in _flags(ws, before))


def test_new_symlink_is_flagged(ws):
    before = snapshot(ws)
    os.symlink("/etc/hosts", ws / "link")
    assert any("symlink" in f.reason for f in _flags(ws, before))


def test_new_executable_is_flagged(ws):
    before = snapshot(ws)
    f = ws / "tool"
    f.write_text("data")
    f.chmod(0o755)
    assert any("executable" in fl.reason for fl in _flags(ws, before))


def test_modifying_existing_risky_file_is_flagged(ws):
    (ws / "Makefile").write_text("test:\n\techo ok\n")
    before = snapshot(ws)
    (ws / "Makefile").write_text("test:\n\techo changed\n")
    flags = _flags(ws, before)
    assert flags and flags[0].change == "modified"


def test_normal_source_edit_is_not_flagged(ws):
    before = snapshot(ws)
    (ws / "main.py").write_text("print('edited')")
    assert _flags(ws, before) == []


@pytest.mark.xfail(strict=True, reason="KNOWN GAP: a malicious test_*.py has an innocent name")
def test_malicious_test_file_is_flagged(ws):
    before = snapshot(ws)
    (ws / "test_trap.py").write_text("open('/tmp/x','w')\n\ndef test_ok():\n    pass\n")
    assert _flags(ws, before) != []