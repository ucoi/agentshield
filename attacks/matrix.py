"""Usage: python -m attacks.matrix"""

import tempfile
from pathlib import Path

from agentshield.actions import Action
from agentshield.audit import AuditLogger
from agentshield.shield import MODES, AgentShield

from .combined import all_scenarios
from .scenarios import setup_files


def run_mode(mode: str) -> dict[str, str]:
    cells = {}
    with tempfile.TemporaryDirectory() as tmp:  # fresh files for every configuration
        base = Path(tmp)
        ws = setup_files(base)
        shield = AgentShield(ws, mode=mode, audit=AuditLogger("results/audit.jsonl"))
        assert shield.run(Action.read_file("/workspace/main.py")).ok, f"{mode}: sanity check failed"

        for name, files, action, succeeded, safe_on_host in all_scenarios(base):
            if mode == "policy_only" and not safe_on_host:
                cells[name] = "SKIPPED"
                continue
            for fname, text in files.items():
                (ws / fname).write_text(text)
            r = shield.run(action)
            if succeeded(r):
                cells[name] = "BYPASSED"
            elif r.denied:
                cells[name] = "blocked:policy"
            else:
                cells[name] = "blocked:exec"
    return cells


def main() -> None:
    results = {m: run_mode(m) for m in MODES}
    names = list(results[MODES[0]])
    w = max(len(n) for n in names)

    print(f"{'attack':{w}}  " + "  ".join(f"{m:14}" for m in MODES))
    for n in names:
        print(f"{n:{w}}  " + "  ".join(f"{results[m][n]:14}" for m in MODES))

    print()
    for m in MODES:
        cells = results[m].values()
        print(f"{m:14} bypassed: {sum(c == 'BYPASSED' for c in cells)}"
              f"  skipped: {sum(c == 'SKIPPED' for c in cells)}  total: {len(results[m])}")


if __name__ == "__main__":
    main()