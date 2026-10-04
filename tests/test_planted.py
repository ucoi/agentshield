import shutil
import subprocess
from pathlib import Path

import pytest

from agentshield.actions import Action
from agentshield.shield import MODES, AgentShield
from attacks.planted import (canary_exists, make_planted_scenarios,
                             trigger_available, trigger_on_host)
from attacks.scenarios import setup_files


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


NAMES = [s[0] for s in make_planted_scenarios(Path("/unused"))]


@pytest.mark.xfail(strict=True, reason="KNOWN GAP: trap files written to /workspace fire later on the host")
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("name", NAMES)
def test_planted_file_does_not_fire_on_host(tmp_path, mode, name):
    if mode != "policy_only" and not _docker_available():
        pytest.skip("Docker not running")
    ws = setup_files(tmp_path)
    _, vpath, content, trigger = next(s for s in make_planted_scenarios(tmp_path) if s[0] == name)
    if not trigger_available(trigger):
        pytest.skip("make not installed")
    AgentShield(ws, mode=mode).run(Action.write_file(vpath, content))
    trigger_on_host(ws, trigger)
    assert not canary_exists(tmp_path)