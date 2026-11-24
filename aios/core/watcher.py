"""File Watcher — monitors changes and triggers analysis."""
from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Callable


def watch_changes(root: Path, callback: Callable, interval: int = 5, max_runs: int = 100):
    """Watch for file changes and trigger callback.

    Args:
        root: project root
        callback: function to call when changes detected
        interval: seconds between checks
        max_runs: max number of checks before stopping
    """
    last_hash = ""

    for _ in range(max_runs):
        try:
            result = subprocess.run(
                ["git", "diff", "--stat"], cwd=str(root),
                capture_output=True, text=True, timeout=5
            )
            current_hash = result.stdout.strip()

            if current_hash != last_hash and current_hash:
                callback(root, current_hash)
                last_hash = current_hash

            time.sleep(interval)
        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(interval)
