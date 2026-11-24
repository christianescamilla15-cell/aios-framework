"""Config Engine — project-level AIOS configuration."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any

DEFAULT_CONFIG = {
    "project_name": "",
    "policy": "default",
    "modules": [],
    "default_mode_detection": "hybrid",
    "release_gate": "standard",
    "memory_backend": "files",
    "prompt_backend": "cloudcode",
    "auto_detect_stacks": True,
}


def get_config_path(root: Path) -> Path:
    return root / ".aios" / "config.json"


def load_config(root: Path) -> Dict[str, Any]:
    """Load project config or return defaults."""
    path = get_config_path(root)
    if path.exists():
        try:
            return {**DEFAULT_CONFIG, **json.loads(path.read_text(encoding="utf-8"))}
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)


def save_config(root: Path, config: Dict[str, Any]) -> None:
    """Save project config."""
    path = get_config_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")


def init_config(root: Path, project_name: str = "", policy: str = "default", modules: list | None = None) -> Dict[str, Any]:
    """Initialize config for a project."""
    config = dict(DEFAULT_CONFIG)
    config["project_name"] = project_name or root.name
    config["policy"] = policy
    if modules:
        config["modules"] = modules
    save_config(root, config)
    return config
