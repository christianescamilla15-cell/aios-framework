"""Built-in troubleshooting guide and FAQ for Kiro/AIOS users."""
from __future__ import annotations

GUIDE = {
    "getting-started": {
        "title": "Getting Started with AIOS",
        "content": """
1. Run: aios init (in your project root)
2. Run: aios onboard (auto-setup for enterprise repos)
3. Edit ai-memory/product_context.md with your project info
4. Run: aios task --task "your first task"
5. Copy the generated prompt into your AI tool (Kiro/Claude Code)
6. When done: aios refresh --summary "what you did" --next-step "what's next"
""",
    },
    "specs": {
        "title": "Working with Specs",
        "content": """
Q: What goes in requirements.md?
A: Business goals, user impact, acceptance criteria, out of scope.

Q: What goes in design.md?
A: Current state, proposed changes, architecture impact, tradeoffs.

Q: What goes in tasks.md?
A: Numbered tasks with: description, owner agent, dependencies, validation.

Q: How do I reference files in specs?
A: Use #[[file:path/to/file.py]] — it gets resolved to the file content.

Q: My spec is too big — what do I do?
A: Split into multiple specs under /specs/. Each one is an independent workstream.
""",
    },
    "steering": {
        "title": "Steering Files",
        "content": """
Steering files go in ai-system/ (AIOS) or .kiro/steering/ (Kiro).

3 modes:
- always: included in every interaction (default)
- fileMatch: only when matching file is active
- manual: only when you explicitly request it

Add front-matter to set mode:
---
inclusion: fileMatch
fileMatchPattern: "*.py"
---

Q: When should I use fileMatch?
A: For language-specific rules (Python conventions only when editing .py files).

Q: When should I use manual?
A: For security guides, deployment checklists — things you need on-demand.
""",
    },
    "hooks": {
        "title": "Hooks (Automation)",
        "content": """
Hooks trigger actions on events:
- onSave: run linter/tests when you save
- onCommit: security scan + docs update
- onPR: architecture validation
- manual: click a button to trigger

In Kiro: use the Agent Hooks panel or command palette.
In AIOS: hooks are simulated in the execution prompt.

Q: My hook is too slow — what do I do?
A: Run only fast checks (lint) on save. Move heavy checks (full tests) to commit hooks.
""",
    },
    "large-codebase": {
        "title": "Working with Large Codebases (millions of lines)",
        "content": """
Q: AIOS analyze is slow — what do I do?
A: Use 'aios diff' instead — only analyzes changed files.

Q: How do I know what I might break?
A: Run 'aios impact --file path/to/changed/file.py' to see affected modules.

Q: How do I work in a monorepo?
A: AIOS auto-detects services. 'aios status' shows which service is active.

Q: The AI loses context in big repos — what do I do?
A: Use steering files to give persistent context. Use specs to scope work.

Q: How do I safely migrate a module?
A: Create a MIGRATION spec. Use strangler pattern. Keep backward compatibility.
   Run 'aios release' before merging to validate readiness.
""",
    },
    "enterprise": {
        "title": "Enterprise Best Practices",
        "content": """
Q: How do multiple developers use AIOS on the same repo?
A: ai-system/ and specs/ are committed to git. Each dev runs their own sessions.

Q: How do I enforce code quality?
A: Use enterprise policy: aios config set --key policy --value enterprise

Q: How do I do code review with AI?
A: Create a spec, run 'aios release' to check gates, review the handoff doc.

Q: How do I track migration progress?
A: Each service has its own spec. 'aios status' shows active work per service.

Q: What if the AI generates wrong code?
A: AI works from specs — if the spec is wrong, the code is wrong.
   Always review design.md before implementing. Use 'aios release' to gate.
""",
    },
    "kiro": {
        "title": "Kiro IDE Specifics",
        "content": """
Q: How is AIOS different from Kiro?
A: AIOS is a CLI companion. Kiro is a full IDE. They use the same workflow.

Q: Can I use AIOS with Kiro?
A: Yes. AIOS generates specs and steering that Kiro reads natively.

Q: What are Kiro's autonomy modes?
A: Autopilot (changes files freely) and Supervised (shows changes first).

Q: What is MCP in Kiro?
A: Model Context Protocol — connects external tools (AWS docs, DBs, APIs).
   Configure in .kiro/settings/mcp.json

Q: How do I configure steering in Kiro?
A: Put .md files in .kiro/steering/ with optional front-matter for inclusion mode.
""",
    },
    "troubleshooting": {
        "title": "Common Problems",
        "content": """
Problem: 'aios task' detects wrong mode
Solution: Use --mode flag to force: aios task --task "..." --mode BUGFIX

Problem: Checks find false positives in node_modules
Solution: Update AIOS — file_scanner now excludes node_modules automatically.

Problem: Release gate fails
Solution: Run 'aios doctor' to check what's missing. Fill in spec files.

Problem: AI doesn't follow project conventions
Solution: Add steering files with your conventions. They're loaded automatically.

Problem: Memory is stale from old sessions
Solution: Run 'aios refresh' to update, or edit ai-memory/ files directly.

Problem: Can't install AIOS
Solution: pip install git+https://github.com/christianescamilla15-cell/aios-framework.git
""",
    },
}


def get_topics() -> list:
    return list(GUIDE.keys())


def get_guide(topic: str | None = None) -> str:
    if topic and topic in GUIDE:
        g = GUIDE[topic]
        return f"\n  {g['title']}\n{'='*50}\n{g['content']}"

    # Show all topics
    result = "\n  AIOS Guide — Available Topics\n" + "=" * 50 + "\n"
    for key, val in GUIDE.items():
        result += f"\n  aios guide --topic {key:20} {val['title']}"
    result += "\n"
    return result
