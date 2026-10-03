import pytest

from agentshield.actions import Action, ActionType


def test_read_file_action():
    a = Action.read_file("/workspace/main.py")
    assert a.type is ActionType.READ_FILE
    assert a.path == "/workspace/main.py"


def test_execute_action_defaults_to_workspace():
    a = Action.execute("python tests.py")
    assert a.working_dir == "/workspace"


def test_missing_path_is_rejected():
    with pytest.raises(ValueError):
        Action(ActionType.READ_FILE)


def test_to_dict_is_json_friendly():
    d = Action.read_file("/workspace/a.txt").to_dict()
    assert d["type"] == "read_file"