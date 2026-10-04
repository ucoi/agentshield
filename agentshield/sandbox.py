"""Runs a command inside a locked-down, disposable Docker container."""

from __future__ import annotations

import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

IMAGE = "python:3.12-slim"


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class DockerSandbox:
    def __init__(self, host_workspace: str | Path, memory: str = "256m",
                 cpus: str = "1", pids: int = 64, timeout: int = 10,
                 network: str = "none"):
        self.host_workspace = Path(host_workspace).resolve()
        self.memory = memory
        self.cpus = cpus
        self.pids = pids
        self.timeout = timeout
        self.network = network

    def run(self, command: str) -> SandboxResult:
        name = f"agentshield-{uuid.uuid4().hex[:12]}"
        cmd = [
            "docker", "run", "--rm", "--name", name,
            "--network", self.network,                          # no internet at all
            "--memory", self.memory,
            "--memory-swap", self.memory,                 # no swap escape hatch
            "--cpus", self.cpus,
            "--pids-limit", str(self.pids),               # stops fork bombs
            "--cap-drop", "ALL",                          # no extra Linux privileges
            "--security-opt", "no-new-privileges",
            "--read-only",                                # container filesystem is read-only
            "--tmpfs", "/tmp:size=16m",                   # small scratch space
            "-v", f"{self.host_workspace}:/workspace",    # the ONLY host folder it sees
            "-w", "/workspace",
            IMAGE, "sh", "-c", command,
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            return SandboxResult(proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired:
            # Killing the docker CLI is not enough; kill the container itself.
            subprocess.run(["docker", "kill", name], capture_output=True)
            return SandboxResult(-1, timed_out=True)