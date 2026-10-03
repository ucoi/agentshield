"""Run the first attacks against the naive V0 executor, using canary files only."""

import tempfile
from pathlib import Path

from agentshield.actions import Action
from agentshield.naive_executor import NaiveExecutor

CANARY = "CANARY-SECRET-12345"


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        ws = base / "workspace"
        ws.mkdir()
        (ws / "main.py").write_text("print('hello')")
        (base / "secret.txt").write_text(CANARY)  # lives OUTSIDE the workspace
        (ws / "link").symlink_to(base / "secret.txt")  # link inside -> secret outside
        outside_file = base / "pwned.txt"

        ex = NaiveExecutor(ws)

        # Sanity check: normal use must work, or the results below mean nothing.
        assert ex.run(Action.read_file("/workspace/main.py")).ok

        leaked = lambda r: CANARY in r.output
        wrote_outside = lambda r: outside_file.exists()

        attacks = [
            ("absolute path to secret", Action.read_file(str(base / "secret.txt")), leaked),
            ("../ traversal read", Action.read_file("/workspace/../secret.txt"), leaked),
            ("symlink escape read", Action.read_file("/workspace/link"), leaked),
            ("../ traversal write", Action.write_file("/workspace/../pwned.txt", "x"), wrote_outside),
            ("shell reads outside file", Action.execute("cat ../secret.txt"), leaked),
        ]

        bypassed = 0
        print("V0 results (naive executor)\n")
        for name, action, succeeded in attacks:
            outcome = "BYPASSED" if succeeded(ex.run(action)) else "BLOCKED"
            bypassed += outcome == "BYPASSED"
            print(f"  {outcome:9} {name}")

        print(f"\n{len(attacks)} attacks, {bypassed} bypassed, {len(attacks) - bypassed} blocked")


if __name__ == "__main__":
    main()