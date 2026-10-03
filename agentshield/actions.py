"""Actions an agent can request. These are just data; nothing executes here."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from enum import Enum


class ActionType(str, Enum):
    READ_FILE = "read_file"
    WRITE_FILE = "write_file"
    EXECUTE = "execute"


@dataclass(frozen=True)
class Action:
    type: ActionType
    path: str | None = None
    content: str | None = None
    command: str | None = None
    working_dir: str = "/workspace"

    def __post_init__(self) -> None:
        # Reject malformed requests early, so later code can trust the shape.
        if self.type in (ActionType.READ_FILE, ActionType.WRITE_FILE) and not self.path:
            raise ValueError(f"{self.type.value} requires a path")
        if self.type is ActionType.WRITE_FILE and self.content is None:
            raise ValueError("write_file requires content")
        if self.type is ActionType.EXECUTE and not self.command:
            raise ValueError("execute requires a command")

    # Convenience constructors, so attacks read cleanly.
    @classmethod
    def read_file(cls, path: str) -> Action:
        return cls(ActionType.READ_FILE, path=path)

    @classmethod
    def write_file(cls, path: str, content: str) -> Action:
        return cls(ActionType.WRITE_FILE, path=path, content=content)

    @classmethod
    def execute(cls, command: str, working_dir: str = "/workspace") -> Action:
        return cls(ActionType.EXECUTE, command=command, working_dir=working_dir)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["type"] = self.type.value
        return d