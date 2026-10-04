import shutil
import subprocess

import pytest

from agentshield.sandbox import DockerSandbox
from attacks.sandbox_scenarios import make_sandbox_scenarios
from attacks.scenarios import setup_files
from pathlib import Path


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


pytestmark = pytest.mark.skipif(not _docker_available(), reason="Docker not running")

NAMES = [s[0] for s in make_sandbox_scenarios(Path("/unused"))]


@pytest.fixture
def env(tmp_path):
    return tmp_path, setup_files(tmp_path)


@pytest.mark.parametrize("index", range(len(NAMES)), ids=NAMES)
def test_sandbox_blocks_attack(env, index):
    base, ws = env
    _, files, command, succeeded = make_sandbox_scenarios(base)[index]
    for fname, text in files.items():
        (ws / fname).write_text(text)
    assert not succeeded(DockerSandbox(ws).run(command))


def test_sandbox_runs_normal_code(env):
    _, ws = env
    r = DockerSandbox(ws).run("python main.py")
    assert r.ok and "hello" in r.stdout


def test_infinite_loop_is_killed(env):
    _, ws = env
    r = DockerSandbox(ws, timeout=3).run("python -c 'while True: pass'")
    assert r.timed_out