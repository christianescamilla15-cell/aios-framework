"""Spec Refinement — analyze spec completeness and suggest improvements."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List


def analyze_spec(spec_dir: Path) -> Dict:
    """Analyze a spec's completeness and quality."""
    if not spec_dir.exists():
        return {"error": "Spec directory not found"}

    issues = []
    scores = {}

    for f in spec_dir.glob("*.md"):
        content = f.read_text(encoding="utf-8", errors="ignore")
        name = f.stem
        lines = [l for l in content.splitlines() if l.strip() and not l.startswith("#")]

        # Score by content length
        score = min(100, len(lines) * 10)

        # Check for empty sections
        sections = re.findall(r"^## (.+)", content, re.MULTILINE)
        empty_sections = []
        for i, section in enumerate(sections):
            # Find content between this section and next
            pattern = f"## {re.escape(section)}"
            match = re.search(pattern, content)
            if match:
                start = match.end()
                next_match = re.search(r"^## ", content[start:], re.MULTILINE)
                section_content = content[start:start + next_match.start()] if next_match else content[start:]
                section_lines = [l for l in section_content.splitlines() if l.strip() and not l.startswith("#")]
                if len(section_lines) < 2:
                    empty_sections.append(section)

        if empty_sections:
            issues.append({"file": f.name, "issue": f"Empty sections: {', '.join(empty_sections[:3])}"})
            score = max(0, score - len(empty_sections) * 15)

        # Check for placeholder text
        placeholders = content.count("TODO") + content.count("TBD") + content.count("FIXME")
        if placeholders:
            issues.append({"file": f.name, "issue": f"{placeholders} placeholder(s) found"})
            score = max(0, score - placeholders * 10)

        # Check for unchecked checkboxes
        unchecked = content.count("- [ ]")
        checked = content.count("- [x]")
        if unchecked > 0:
            issues.append({"file": f.name, "issue": f"{unchecked} unchecked items ({checked} done)"})

        scores[name] = min(score, 100)

    # Overall readiness
    avg_score = round(sum(scores.values()) / max(len(scores), 1))

    # Suggestions
    suggestions = []
    if avg_score < 30:
        suggestions.append("Most spec files are empty. Fill in requirements first, then design.")
    elif avg_score < 60:
        suggestions.append("Spec is partially complete. Focus on empty sections before implementing.")
    elif avg_score < 80:
        suggestions.append("Spec is mostly complete. Review TODOs and empty sections.")
    else:
        suggestions.append("Spec looks ready for implementation.")

    # Check for missing files
    expected = {"requirements.md", "design.md", "tasks.md", "validation.md", "risks.md"}
    existing = {f.name for f in spec_dir.glob("*.md")}
    missing = expected - existing
    if missing:
        suggestions.append(f"Missing files: {', '.join(missing)}")

    return {
        "spec": spec_dir.name,
        "scores": scores,
        "average": avg_score,
        "issues": issues,
        "suggestions": suggestions,
        "files": len(scores),
    }


def refine_all_specs(root: Path) -> List[Dict]:
    """Analyze all specs in the project."""
    specs_dir = root / "specs"
    if not specs_dir.exists():
        return []

    results = []
    for spec_dir in sorted(specs_dir.iterdir()):
        if spec_dir.is_dir():
            results.append(analyze_spec(spec_dir))
    return results
