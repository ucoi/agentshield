"""V1 executor: asks the policy first, only acts on approved actions."""

from __future__ import annotations

import subprocess
from pathlib import Path

from .actions import Action, ActionType
from .naive_executor import Result
from .policy import Policy


class SecureExecutor:
    def __init__(self, host_workspace: str | Path, shell_enabled: bool = False):
        self.host_workspace = Path(host_workspace)
        self.policy = Policy(host_workspace, shell_enabled)

    def run(self, action: Action) -> Result:
        decision = self.policy.authorize(action)
        if not decision.allowed:
            return Result(False, error=f"DENIED: {decision.reason}")
        try:
            if action.type is ActionType.READ_FILE:
                return Result(True, decision.host_path.read_text())
            if action.type is ActionType.WRITE_FILE:
                decision.host_path.write_text(action.content)
                return Result(True)
            if action.type is ActionType.EXECUTE:
                proc = subprocess.run(
                    action.command, shell=True, cwd=self.host_workspace,
                    capture_output=True, text=True, timeout=10,
                )
                return Result(proc.returncode == 0, proc.stdout, proc.stderr)
            return Result(False, error="unknown action type")
        except Exception as exc:
            return Result(False, error=f"{type(exc).__name__}: {exc}")