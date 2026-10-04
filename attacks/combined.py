"""All attacks as Actions, so every configuration can be run against the same list."""

from pathlib import Path

from agentshield.actions import Action

from .sandbox_scenarios import make_sandbox_scenarios
from .scenarios import make_scenarios

# Attacks that could hurt your real machine if run on the host without limits.
# They are SKIPPED in policy_only mode, never run.
UNSAFE_ON_HOST = {"fork bomb (500 forks)", "memory exhaustion (1 GB)", "write to system dir"}


def all_scenarios(base: Path):
    """Returns (name, files_to_write, action, did_attack_succeed, safe_on_host)."""
    out = [(n, {}, a, s, True) for n, a, s in make_scenarios(base)]
    for n, files, cmd, s in make_sandbox_scenarios(base):
        out.append((n, files, Action.execute(cmd), s, n not in UNSAFE_ON_HOST))
    return out