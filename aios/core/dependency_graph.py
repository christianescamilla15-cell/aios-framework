"""Dependency Graph — analyzes imports to map module dependencies."""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set

from .file_scanner import scan_source_files


def build_python_deps(root: Path) -> Dict[str, List[str]]:
    """Build dependency graph for Python files."""
    graph: Dict[str, Set[str]] = defaultdict(set)
    py_files = scan_source_files(root, [".py"])

    for f in py_files:
        try:
            rel = str(f.relative_to(root)).replace("\\", "/")
            content = f.read_text(encoding="utf-8", errors="ignore")

            # from X import Y
            for match in re.finditer(r"from\s+([\w.]+)\s+import", content):
                dep = match.group(1)
                if not dep.startswith(("os", "sys", "re", "json", "pathlib", "typing", "datetime", "collections", "abc", "dataclasses", "logging", "io", "time", "uuid", "hashlib", "functools", "contextlib")):
                    graph[rel].add(dep)

            # import X
            for match in re.finditer(r"^import\s+([\w.]+)", content, re.MULTILINE):
                dep = match.group(1)
                if not dep.startswith(("os", "sys", "re", "json", "pathlib", "typing", "datetime")):
                    graph[rel].add(dep)

        except Exception:
            continue

    return {k: sorted(v) for k, v in graph.items()}


def build_js_deps(root: Path) -> Dict[str, List[str]]:
    """Build dependency graph for JS/TS files."""
    graph: Dict[str, Set[str]] = defaultdict(set)
    js_files = scan_source_files(root, [".js", ".jsx", ".ts", ".tsx"])

    for f in js_files:
        try:
            rel = str(f.relative_to(root)).replace("\\", "/")
            content = f.read_text(encoding="utf-8", errors="ignore")

            # import X from "Y"  or  require("Y")
            for match in re.finditer(r'(?:import\s+.*?\s+from\s+["\'](.+?)["\']|require\(["\'](.+?)["\']\))', content):
                dep = match.group(1) or match.group(2)
                if dep.startswith("."):
                    graph[rel].add(dep)

        except Exception:
            continue

    return {k: sorted(v) for k, v in graph.items()}


def build_dependency_graph(root: Path) -> Dict:
    """Build full dependency graph for the project."""
    py_deps = build_python_deps(root)
    js_deps = build_js_deps(root)

    # Merge
    all_deps = {**py_deps, **js_deps}

    # Find most-depended-on modules (highest fan-in)
    dep_count: Dict[str, int] = defaultdict(int)
    for deps in all_deps.values():
        for d in deps:
            dep_count[d] += 1

    critical = sorted(dep_count.items(), key=lambda x: -x[1])[:10]

    # Find files with most dependencies (highest fan-out)
    complex_files = sorted(all_deps.items(), key=lambda x: -len(x[1]))[:10]

    return {
        "total_files": len(all_deps),
        "total_edges": sum(len(v) for v in all_deps.values()),
        "critical_modules": [{"module": m, "depended_by": c} for m, c in critical],
        "complex_files": [{"file": f, "dependencies": len(d)} for f, d in complex_files],
        "graph": all_deps,
    }


def find_impact(root: Path, changed_file: str) -> List[str]:
    """Find all files that would be affected by changing a file."""
    graph = build_dependency_graph(root)["graph"]
    changed_module = changed_file.replace("\\", "/").replace(".py", "").replace("/", ".")

    affected = []
    for file, deps in graph.items():
        for dep in deps:
            if changed_module in dep or changed_file in dep:
                affected.append(file)
                break

    return affected
