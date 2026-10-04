"""V2: detect risky files an agent left in the workspace.
Snapshot before, diff after, flag anything that can execute later on the host."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

RISKY_NAMES = {
    "makefile", "gnumakefile", "conftest.py", "setup.py", "setup.cfg",
    "pyproject.toml", "tox.ini", "pytest.ini", "package.json", "dockerfile",
    "docker-compose.yml", ".envrc", "sitecustomize.py", "usercustomize.py",
    ".pre-commit-config.yaml",
}
RISKY_SUFFIXES = (".sh", ".bash", ".zsh", ".command", ".pth")
RISKY_DIRS = ("/.git/hooks/", "/.github/workflows/", "/.vscode/")


@dataclass(frozen=True)
class Changes:
    added: frozenset[str]
    modified: frozenset[str]
    deleted: frozenset[str]


@dataclass(frozen=True)
class Flag:
    path: str
    change: str   # "added" or "modified"
    reason: str


def snapshot(workspace: str | Path) -> dict[str, str]:
    """Map every file/symlink to a fingerprint. Symlinks are recorded, never followed."""
    ws = Path(workspace)
    snap: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(ws, followlinks=False):
        for name in dirnames + filenames:
            p = Path(dirpath) / name
            rel = p.relative_to(ws).as_posix()
            if p.is_symlink():
                snap[rel] = f"symlink:{os.readlink(p)}"
            elif p.is_file():
                x = "x" if p.stat().st_mode & 0o111 else "-"
                snap[rel] = f"file:{x}:{hashlib.sha256(p.read_bytes()).hexdigest()}"
    return snap


def diff(before: dict[str, str], after: dict[str, str]) -> Changes:
    return Changes(
        added=frozenset(after.keys() - before.keys()),
        modified=frozenset(k for k in before.keys() & after.keys() if before[k] != after[k]),
        deleted=frozenset(before.keys() - after.keys()),
    )


def _reasons(rel: str, fingerprint: str) -> list[str]:
    reasons = []
    if Path(rel).name.lower() in RISKY_NAMES:
        reasons.append("config/build file that runs code when used")
    if rel.lower().endswith(RISKY_SUFFIXES):
        reasons.append("script file")
    if any(part in "/" + rel for part in RISKY_DIRS):
        reasons.append("hook/automation directory")
    if fingerprint.startswith("symlink:"):
        reasons.append("symlink")
    if fingerprint.startswith("file:x:"):
        reasons.append("executable file")
    return reasons


def review(changes: Changes, after: dict[str, str]) -> list[Flag]:
    """Flag added/modified files that need human approval before host use."""
    flags = []
    for change, paths in (("added", changes.added), ("modified", changes.modified)):
        for rel in sorted(paths):
            reasons = _reasons(rel, after[rel])
            if reasons:
                flags.append(Flag(rel, change, "; ".join(reasons)))
    return flags