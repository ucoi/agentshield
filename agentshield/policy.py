"""V1 policy engine: decides whether an action is allowed BEFORE anything runs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .actions import Action, ActionType

VIRTUAL_ROOT = "/workspace"


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    host_path: Path | None = None


class Policy:
    def __init__(self, host_workspace: str | Path, shell_enabled: bool = False):
        self.root = Path(host_workspace).resolve()
        self.shell_enabled = shell_enabled

    def authorize(self, action: Action) -> Decision:
        if action.type is ActionType.EXECUTE:
            if not self.shell_enabled:
                return Decision(False, "shell execution is disabled")
            return Decision(True, "shell allowed (NOT safe without a sandbox)")
        return self._check_path(action.path)

    def _check_path(self, virtual_path: str) -> Decision:
        # Fix 1: match the folder boundary, not just a string prefix.
        if virtual_path != VIRTUAL_ROOT and not virtual_path.startswith(VIRTUAL_ROOT + "/"):
            return Decision(False, "path is outside /workspace")
        relative = virtual_path[len(VIRTUAL_ROOT):].lstrip("/")
        try:
            # Fix 2: resolve() follows symlinks and collapses "..", giving the REAL target.
            resolved = (self.root / relative).resolve()
        except (ValueError, OSError):
            return Decision(False, "invalid path")
        # Fix 3: check the resolved path, not the string the agent sent.
        if not resolved.is_relative_to(self.root):
            return Decision(False, "resolved path escapes workspace")
        return Decision(True, "path permitted", resolved)