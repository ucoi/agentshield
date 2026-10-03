"""Usage: python -m attacks.run v0   |   python -m attacks.run v1"""

import sys
import tempfile
from pathlib import Path

from agentshield.actions import Action
from agentshield.naive_executor import NaiveExecutor
from agentshield.secure_executor import SecureExecutor

from .scenarios import make_scenarios, setup_files

EXECUTORS = {"v0": NaiveExecutor, "v1": SecureExecutor}


def main(version: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        ws = setup_files(base)
        ex = EXECUTORS[version](ws)

        assert ex.run(Action.read_file("/workspace/main.py")).ok  # normal use must work

        print(f"{version.upper()} results\n")
        bypassed = 0
        scenarios = make_scenarios(base)
        for name, action, succeeded in scenarios:
            hit = succeeded(ex.run(action))
            bypassed += hit
            print(f"  {'BYPASSED' if hit else 'BLOCKED':9} {name}")
        print(f"\n{len(scenarios)} attacks, {bypassed} bypassed, {len(scenarios) - bypassed} blocked")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "v0")