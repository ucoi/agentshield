"""AgentShield: policy check -> execution (host or Docker) -> audit log."""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .actions import Action, ActionType
from .audit import AuditLogger
from .policy import Decision, Policy
from .sandbox import DockerSandbox

MODES = ("policy_only", "sandbox_only", "both")


@dataclass
class ShieldResult:
    ok: bool
    output: str = ""
    error: str = ""
    denied: bool = False

    @property
    def stdout(self) -> str:  # lets attack checks treat all results the same way
        return self.output


class AgentShield:
    def __init__(self, host_workspace: str | Path, mode: str = "both",
                 audit: AuditLogger | None = None, timeout: int = 10):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        self.ws = Path(host_workspace).resolve()
        self.mode = mode
        self.audit = audit or AuditLogger()
        self.timeout = timeout
        # Shell is enabled because useful agents need it. In policy_only mode that
        # runs on the HOST, which is exactly the gap the comparison should expose.
        self.policy = Policy(self.ws, shell_enabled=True)
        self.sandbox = DockerSandbox(self.ws, timeout=timeout)

    def run(self, action: Action) -> ShieldResult:
        decision = None
        reason = "no policy layer"
        if self.mode in ("policy_only", "both"):
            decision = self.policy.authorize(action)
            reason = decision.reason
            if not decision.allowed:
                self.audit.log(action, self.mode, False, reason, ok=False)
                return ShieldResult(False, error=f"DENIED: {reason}", denied=True)

        if self.mode == "policy_only":
            result = self._run_on_host(action, decision)
        else:
            result = self._run_in_sandbox(action)
        self.audit.log(action, self.mode, True, reason, result.ok)
        return result

    def _run_on_host(self, action: Action, decision: Decision | None) -> ShieldResult:
        try:
            if action.type is ActionType.READ_FILE:
                return ShieldResult(True, decision.host_path.read_text())
            if action.type is ActionType.WRITE_FILE:
                decision.host_path.write_text(action.content)
                return ShieldResult(True)
            proc = subprocess.run(action.command, shell=True, cwd=self.ws,
                                  capture_output=True, text=True, timeout=self.timeout)
            return ShieldResult(proc.returncode == 0, proc.stdout, proc.stderr)
        except Exception as exc:
            return ShieldResult(False, error=f"{type(exc).__name__}: {exc}")

    def _run_in_sandbox(self, action: Action) -> ShieldResult:
        # File actions also run inside the container, so the host never touches
        # an agent-controlled path, even if the policy has a bug.
        if action.type is ActionType.READ_FILE:
            cmd = f"cat -- {shlex.quote(action.path)}"
        elif action.type is ActionType.WRITE_FILE:
            cmd = f"printf %s {shlex.quote(action.content)} > {shlex.quote(action.path)}"
        else:
            cmd = action.command
        r = self.sandbox.run(cmd)
        if r.timed_out:
            return ShieldResult(False, error="TIMEOUT")
        return ShieldResult(r.ok, r.stdout, r.stderr)