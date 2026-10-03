"""V0: a deliberately naive executor. It runs on the host with weak checks.
Do NOT use this for anything real. It exists to be attacked."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from .actions import Action, ActionType

VIRTUAL_ROOT = "/workspace"


@dataclass
class Result:
    ok: bool
    output: str = ""
    error: str = ""


class NaiveExecutor:
    def __init__(self, host_workspace: str | Path):
        self.host_workspace = Path(host_workspace)

    def _to_host(self, virtual_path: str) -> Path:
        # The naive check: "does the string start with /workspace?"
        if not virtual_path.startswith(VIRTUAL_ROOT):
            raise PermissionError(f"{virtual_path} is outside {VIRTUAL_ROOT}")
        return Path(str(self.host_workspace) + virtual_path[len(VIRTUAL_ROOT):])

    def run(self, action: Action) -> Result:
        try:
            if action.type is ActionType.READ_FILE:
                return Result(True, self._to_host(action.path).read_text())

            if action.type is ActionType.WRITE_FILE:
                self._to_host(action.path).write_text(action.content)
                return Result(True)

            if action.type is ActionType.EXECUTE:
                proc = subprocess.run(
                    action.command,
                    shell=True,
                    cwd=self.host_workspace,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                return Result(proc.returncode == 0, proc.stdout, proc.stderr)

            return Result(False, error="unknown action type")
        except Exception as exc:  # naive: report anything as a failed result
            return Result(False, error=f"{type(exc).__name__}: {exc}")