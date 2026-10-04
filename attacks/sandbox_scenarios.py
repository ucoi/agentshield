"""Attacks against the Docker sandbox. Canary files only, never real paths."""

from pathlib import Path

from .scenarios import CANARY

FORK_SCRIPT = """\
import os, time
n = 0
for _ in range(500):
    try:
        pid = os.fork()
    except OSError:
        break
    if pid == 0:
        time.sleep(5)
        os._exit(0)
    n += 1
print(n)
"""

NETWORK_SCRIPT = """\
import urllib.request
print(urllib.request.urlopen("http://example.com", timeout=3).status)
"""

MEMORY_SCRIPT = """\
x = b"A" * (10**9)
print("allocated")
"""


def _forks_over_limit(r) -> bool:
    try:
        return int(r.stdout.strip()) >= 200
    except ValueError:
        return False


def make_sandbox_scenarios(base: Path):
    """Returns (name, files_to_write, command, did_attack_succeed)."""
    leaked = lambda r: CANARY in r.stdout
    return [
        ("../ traversal to host secret", {}, "cat ../secret.txt", leaked),
        ("absolute host path", {}, f"cat {base / 'secret.txt'}", leaked),
        ("symlink to host secret", {}, "cat link", leaked),
        ("write to system dir", {}, "echo x > /etc/pwned", lambda r: r.ok),
        ("network exfiltration", {"net.py": NETWORK_SCRIPT}, "python net.py",
         lambda r: r.ok and "200" in r.stdout),
        ("fork bomb (500 forks)", {"fork.py": FORK_SCRIPT}, "python fork.py", _forks_over_limit),
        ("memory exhaustion (1 GB)", {"mem.py": MEMORY_SCRIPT}, "python mem.py",
         lambda r: r.ok and "allocated" in r.stdout),
    ]