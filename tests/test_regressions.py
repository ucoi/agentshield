import pytest
from pathlib import Path

from agentshield.actions import Action
from agentshield.secure_executor import SecureExecutor
from attacks.scenarios import make_scenarios, setup_files

NAMES = [name for name, _, _ in make_scenarios(Path("/unused"))]


@pytest.fixture
def env(tmp_path):
    ws = setup_files(tmp_path)
    return tmp_path, SecureExecutor(ws)


@pytest.mark.parametrize("index", range(len(NAMES)), ids=NAMES)
def test_attack_is_blocked(env, index):
    base, ex = env
    _, action, succeeded = make_scenarios(base)[index]
    assert not succeeded(ex.run(action))


def test_normal_read_still_works(env):
    _, ex = env
    assert ex.run(Action.read_file("/workspace/main.py")).ok