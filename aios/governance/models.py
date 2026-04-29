"""AIOS Governance · models compartidos · GovernanceFinding · CheckReport · etc."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class CheckSeverity(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    CRITICAL = "CRITICAL"


@dataclass
class GovernanceFinding:
    rule_id: str
    severity: CheckSeverity
    category: str  # 'tier' · 'naming' · 'approvals' · 'stakeholders'
    message: str
    location: str | None = None
    suggestion: str | None = None


@dataclass
class CheckReport:
    app: str
    timestamp: datetime
    findings: list[GovernanceFinding] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == CheckSeverity.CRITICAL)

    @property
    def fail_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == CheckSeverity.FAIL)

    @property
    def warn_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == CheckSeverity.WARN)

    @property
    def pass_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == CheckSeverity.PASS)

    @property
    def is_passing(self) -> bool:
        return self.fail_count == 0 and self.critical_count == 0

    def by_category(self) -> dict[str, list[GovernanceFinding]]:
        cats: dict[str, list[GovernanceFinding]] = {}
        for f in self.findings:
            cats.setdefault(f.category, []).append(f)
        return cats
