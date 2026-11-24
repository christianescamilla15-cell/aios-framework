"""Lock file — prevents concurrent AIOS operations from corrupting memory."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

LOCK_TIMEOUT = 30  # seconds


def acquire_lock(root: Path, operation: str = "unknown") -> bool:
    """Acquire a lock. Returns True if acquired."""
    lock_path = root / ".aios" / "lock.json"
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    if lock_path.exists():
        try:
            data = json.loads(lock_path.read_text(encoding="utf-8"))
            age = time.time() - data.get("timestamp", 0)
            if age < LOCK_TIMEOUT:
                return False  # Lock is held
            # Stale lock — remove
        except Exception:
            pass

    lock_data = {
        "pid": os.getpid(),
        "operation": operation,
        "timestamp": time.time(),
    }
    lock_path.write_text(json.dumps(lock_data), encoding="utf-8")
    return True


def release_lock(root: Path) -> None:
    """Release the lock."""
    lock_path = root / ".aios" / "lock.json"
    if lock_path.exists():
        lock_path.unlink()


def check_lock(root: Path) -> dict | None:
    """Check if lock is held. Returns lock info or None."""
    lock_path = root / ".aios" / "lock.json"
    if not lock_path.exists():
        return None
    try:
        data = json.loads(lock_path.read_text(encoding="utf-8"))
        age = time.time() - data.get("timestamp", 0)
        if age < LOCK_TIMEOUT:
            data["age_seconds"] = round(age)
            return data
    except Exception:
        pass
    return None
