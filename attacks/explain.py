"""Shows WHY each sandbox attack failed, plus a negative control."""

import tempfile
from pathlib import Path

from agentshield.sandbox import DockerSandbox

from .sandbox_scenarios import NETWORK_SCRIPT, make_sandbox_scenarios
from .scenarios import setup_files


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        ws = setup_files(base)
        sb = DockerSandbox(ws)

        for name, files, command, _ in make_sandbox_scenarios(base):
            for fname, text in files.items():
                (ws / fname).write_text(text)
            r = sb.run(command)
            print(f"[{name}]")
            print(f"  exit={r.exit_code} timed_out={r.timed_out}")
            print(f"  stdout: {r.stdout.strip()[:120]!r}")
            print(f"  stderr: {r.stderr.strip()[-160:]!r}\n")

        # Negative control: same network attack, but with networking turned ON.
        # If the attack scenario is valid, this MUST succeed (needs your internet).
        (ws / "net.py").write_text(NETWORK_SCRIPT)
        r = DockerSandbox(ws, network="bridge").run("python net.py")
        print("[CONTROL: network attack with networking enabled]")
        print(f"  exit={r.exit_code} stdout: {r.stdout.strip()[:60]!r}")
        print(f"  stderr: {r.stderr.strip()[-120:]!r}")


if __name__ == "__main__":
    main()