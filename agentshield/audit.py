"""Append-only audit log: one JSON object per line."""

from __future__ import annotations

import json
import time
from pathlib import Path

from .actions import Action


class AuditLogger:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.records: list[dict] = []
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, action: Action, mode: str, allowed: bool, reason: str, ok: bool) -> None:
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "mode": mode,
            "action": action.to_dict(),
            "allowed": allowed,
            "reason": reason,
            "ok": ok,
        }
        self.records.append(record)
        if self.path:
            with self.path.open("a") as f:
                f.write(json.dumps(record) + "\n")