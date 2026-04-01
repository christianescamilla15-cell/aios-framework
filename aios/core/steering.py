"""Steering Engine — conditional context loading (Kiro-compatible).

Steering files support 3 inclusion modes via YAML front-matter:
- always (default): included in every interaction
- fileMatch: included only when a matching file is in context
- manual: included only when explicitly requested

Example front-matter:
---
inclusion: fileMatch
fileMatchPattern: "*.py"
---
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional


def parse_front_matter(content: str) -> Dict[str, str]:
    """Parse YAML front-matter from a markdown file."""
    match = re.match(r'^---\s*\n(.*?)\n---\s*\n', content, re.DOTALL)
    if not match:
        return {}
    fm = {}
    for line in match.group(1).splitlines():
        if ':' in line:
            key, val = line.split(':', 1)
            fm[key.strip().lower()] = val.strip().strip('"').strip("'")
    return fm


def get_body(content: str) -> str:
    """Get content after front-matter."""
    match = re.match(r'^---\s*\n.*?\n---\s*\n', content, re.DOTALL)
    if match:
        return content[match.end():]
    return content


def resolve_file_references(content: str, root: Path) -> str:
    """Resolve #[[file:path]] references to actual file contents."""
    def replace_ref(match):
        filepath = match.group(1)
        full_path = root / filepath
        if full_path.exists():
            try:
                file_content = full_path.read_text(encoding="utf-8", errors="ignore")
                return f"\n--- [{filepath}] ---\n{file_content[:5000]}\n--- end [{filepath}] ---\n"
            except Exception:
                return f"\n[File not readable: {filepath}]\n"
        return f"\n[File not found: {filepath}]\n"

    return re.sub(r'#\[\[file:([^\]]+)\]\]', replace_ref, content)


def load_steering(root: Path, active_files: List[str] | None = None, manual_keys: List[str] | None = None) -> Dict[str, str]:
    """Load steering files respecting inclusion modes.

    Args:
        root: project root
        active_files: list of files currently open/active (for fileMatch)
        manual_keys: list of steering names explicitly requested

    Returns:
        dict of {filename: resolved_content}
    """
    steering_dir = root / "ai-system"
    if not steering_dir.exists():
        steering_dir = root / ".kiro" / "steering"
    if not steering_dir.exists():
        return {}

    active_files = active_files or []
    manual_keys = [k.lower() for k in (manual_keys or [])]
    result = {}

    for f in sorted(steering_dir.glob("*.md")):
        content = f.read_text(encoding="utf-8", errors="ignore")
        fm = parse_front_matter(content)
        body = get_body(content)

        inclusion = fm.get("inclusion", "always").lower()
        name = f.stem.lower()

        if inclusion == "always":
            result[f.name] = resolve_file_references(body, root)

        elif inclusion == "filematch":
            pattern = fm.get("filematchpattern", "*")
            # Check if any active file matches the pattern
            for af in active_files:
                if _matches_glob(af, pattern):
                    result[f.name] = resolve_file_references(body, root)
                    break

        elif inclusion == "manual":
            if name in manual_keys or f.name in manual_keys:
                result[f.name] = resolve_file_references(body, root)

    return result


def _matches_glob(filepath: str, pattern: str) -> bool:
    """Simple glob matching."""
    import fnmatch
    return fnmatch.fnmatch(filepath, pattern) or fnmatch.fnmatch(filepath.split("/")[-1], pattern)


def create_steering_file(root: Path, name: str, content: str, inclusion: str = "always", file_match_pattern: str = "") -> Path:
    """Create a new steering file with proper front-matter."""
    steering_dir = root / "ai-system"
    steering_dir.mkdir(parents=True, exist_ok=True)

    fm = ""
    if inclusion != "always" or file_match_pattern:
        fm = f"---\ninclusion: {inclusion}\n"
        if file_match_pattern:
            fm += f'fileMatchPattern: "{file_match_pattern}"\n'
        fm += "---\n\n"

    path = steering_dir / f"{name}.md"
    path.write_text(fm + content, encoding="utf-8")
    return path


def list_steering(root: Path) -> List[Dict]:
    """List all steering files with their inclusion mode."""
    steering_dir = root / "ai-system"
    if not steering_dir.exists():
        return []

    files = []
    for f in sorted(steering_dir.glob("*.md")):
        content = f.read_text(encoding="utf-8", errors="ignore")
        fm = parse_front_matter(content)
        files.append({
            "name": f.name,
            "inclusion": fm.get("inclusion", "always"),
            "pattern": fm.get("filematchpattern", ""),
            "size": f.stat().st_size,
        })
    return files
