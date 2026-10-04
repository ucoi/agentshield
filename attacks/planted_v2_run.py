"""Usage: python -m attacks.planted_v2_run
Planted-file attacks with the V2 workspace check acting as a gate:
if anything is flagged, the host step does NOT run (held for human approval)."""

import tempfile
from pathlib import Path

from agentshield.actions import Action
from agentshield.shield import AgentShield

from .planted import canary_exists, make_planted_scenarios, trigger_available, trigger_on_host
from .scenarios import setup_files


def main() -> None:
    # False-positive control: an ordinary source edit must NOT be flagged.
    with tempfile.TemporaryDirectory() as tmp:
        ws = setup_files(Path(tmp))
        shield = AgentShield(ws, mode="both")
        shield.snapshot()
        shield.run(Action.write_file("/workspace/main.py", "print('edited')"))
        print(f"control (normal edit to main.py): flags = {len(shield.review())}  (want 0)\n")

    print("Planted-file attacks, mode=both, with V2 workspace gate\n")
    names = [s[0] for s in make_planted_scenarios(Path("/unused"))]
    for name in names:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ws = setup_files(base)
            _, vpath, content, trigger = next(
                s for s in make_planted_scenarios(base) if s[0] == name)
            if not trigger_available(trigger):
                print(f"  {name:22} SKIPPED (make not installed)")
                continue
            shield = AgentShield(ws, mode="both")
            shield.snapshot()
            shield.run(Action.write_file(vpath, content))
            flags = shield.review()
            if flags:
                print(f"  {name:22} FLAGGED  -> {flags[0].reason}")
                continue
            trigger_on_host(ws, trigger)  # nothing flagged, so the "human" proceeds
            print(f"  {name:22} {'BYPASSED' if canary_exists(base) else 'blocked:trigger-failed'}"
                  "  (no flags raised)")


if __name__ == "__main__":
    main()