"""Attack scenarios, shared by the runner and the regression tests.
Everything uses canary files inside a temp folder. Never real paths."""

from pathlib import Path

from agentshield.actions import Action

CANARY = "CANARY-SECRET-12345"


def setup_files(base: Path) -> Path:
    ws = base / "workspace"
    ws.mkdir()
    (ws / "main.py").write_text("print('hello')")
    (base / "secret.txt").write_text(CANARY)             # outside the workspace
    (ws / "link").symlink_to(base / "secret.txt")        # symlink inside -> outside
    evil = base / "workspace-evil"                       # sibling that shares the prefix
    evil.mkdir()
    (evil / "secret.txt").write_text(CANARY)
    return ws


def make_scenarios(base: Path):
    """Returns a list of (name, action, did_attack_succeed)."""
    leaked = lambda r: CANARY in r.output
    wrote_outside = lambda r: (base / "pwned.txt").exists()
    return [
        ("absolute path to secret", Action.read_file(str(base / "secret.txt")), leaked),
        ("../ traversal read", Action.read_file("/workspace/../secret.txt"), leaked),
        ("symlink escape read", Action.read_file("/workspace/link"), leaked),
        ("../ traversal write", Action.write_file("/workspace/../pwned.txt", "x"), wrote_outside),
        ("shell reads outside file", Action.execute("cat ../secret.txt"), leaked),
        ("prefix confusion read", Action.read_file("/workspace-evil/secret.txt"), leaked),
    ]