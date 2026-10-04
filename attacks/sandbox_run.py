"""Usage: python -m attacks.sandbox_run"""

import tempfile
from pathlib import Path

from agentshield.sandbox import DockerSandbox

from .sandbox_scenarios import make_sandbox_scenarios
from .scenarios import setup_files


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        ws = setup_files(base)
        sb = DockerSandbox(ws)

        # Sanity check: normal work must succeed, or the results mean nothing.
        sanity = sb.run("python -c \"print('hello')\"")
        assert sanity.ok and "hello" in sanity.stdout, sanity

        print("Docker sandbox results\n")
        scenarios = make_sandbox_scenarios(base)
        bypassed = 0
        for name, files, command, succeeded in scenarios:
            for fname, text in files.items():
                (ws / fname).write_text(text)
            r = sb.run(command)
            hit = succeeded(r)
            bypassed += hit
            print(f"  {'BYPASSED' if hit else 'BLOCKED':9} {name}")
        print(f"\n{len(scenarios)} attacks, {bypassed} bypassed, {len(scenarios) - bypassed} blocked")


if __name__ == "__main__":
    main()