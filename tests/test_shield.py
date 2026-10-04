import json
import shutil
import subprocess
from pathlib import Path

import pytest

from agentshield.actions import Action
from agentshield.audit import AuditLogger
from agentshield.shield import AgentShield
from attacks.combined import all_scenarios
from attacks.scenarios import setup_files


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


needs_docker = pytest.mark.skipif(not _docker_available(), reason="Docker not running")
NAMES = [s[0] for s in all_scenarios(Path("/unused"))]


@needs_docker
@pytest.mark.parametrize("index", range(len(NAMES)), ids=NAMES)
def test_both_layers_block_attack(tmp_path, index):
    ws = setup_files(tmp_path)
    shield = AgentShield(ws, mode="both")
    _, files, action, succeeded, _ = all_scenarios(tmp_path)[index]
    for fname, text in files.items():
        (ws / fname).write_text(text)
    assert not succeeded(shield.run(action))


@needs_docker
def test_normal_work_still_allowed(tmp_path):
    ws = setup_files(tmp_path)
    shield = AgentShield(ws, mode="both")
    assert shield.run(Action.read_file("/workspace/main.py")).ok
    assert shield.run(Action.execute("python main.py")).output.strip() == "hello"


def test_policy_denial_is_audited(tmp_path):
    ws = setup_files(tmp_path)
    log = tmp_path / "audit.jsonl"
    shield = AgentShield(ws, mode="both", audit=AuditLogger(log))
    r = shield.run(Action.read_file("/workspace/../secret.txt"))
    assert r.denied
    last = json.loads(log.read_text().splitlines()[-1])
    assert last["allowed"] is False