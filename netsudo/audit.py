"""Local audit logging."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any


def audit_path(path: str) -> Path:
    return Path(path).expanduser()


def write_audit(path: str, event: str, payload: dict[str, Any]) -> None:
    log_path = audit_path(path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "time": int(time.time()),
        "event": event,
        **payload,
    }
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    try:
        os.chmod(log_path, 0o600)
    except OSError:
        pass
