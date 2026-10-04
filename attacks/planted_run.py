"""Usage: python -m attacks.planted_run"""

import tempfile
from pathlib import Path

from agentshield.actions import Action
from agentshield.shield import MODES, AgentShield

from .planted import (benign_makefile, canary_exists, make_planted_scenarios,
                      trigger_available, trigger_on_host)
from .scenarios import setup_files


def run_one(mode: str, name: str, vpath: str, content: str, trigger, base: Path, ws: Path) -> str:
    shield = AgentShield(ws, mode=mode)
    write = shield.run(Action.write_file(vpath, content))
    if write.denied:
        return "blocked:policy"
    if not (ws / Path(vpath).name).exists():
        return "blocked:exec (file never written)"
    trigger_on_host(ws, trigger)
    return "BYPASSED" if canary_exists(base) else "blocked:trigger-failed"


def main() -> None:
    # Negative control: a harmless Makefile must NOT create the canary.
    if trigger_available(["make"]):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ws = setup_files(base)
            (ws / "Makefile").write_text(benign_makefile())
            trigger_on_host(ws, ["make", "test"])
            print(f"control (benign Makefile): canary created = {canary_exists(base)}  (want False)\n")

    print("Planted-file attacks (trap fires LATER, on the host)\n")
    for mode in MODES:
        for name, vpath, content, trigger in make_planted_scenarios(Path("/unused")):
            if not trigger_available(trigger):
                print(f"  {mode:13} {name:20} SKIPPED (make not installed)")
                continue
            with tempfile.TemporaryDirectory() as tmp:  # fresh folder per run
                base = Path(tmp)
                ws = setup_files(base)
                # rebuild scenario with the real canary path for this temp dir
                _, vpath, content, trigger = next(
                    s for s in make_planted_scenarios(base) if s[0] == name)
                print(f"  {mode:13} {name:20} {run_one(mode, name, vpath, content, trigger, base, ws)}")


if __name__ == "__main__":
    main()