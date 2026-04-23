"""Deploy-Ready Scaffolder · auto-detecta stack, vulns, tier y genera paquete completo.

Extensión de AIOS v1.5.0 · 21-abr-2026.
Genera deploy-ready/ por aplicativo con:
- C4 · ADR · BIA · SERVICIOS_AWS · checklist Gate 4
- Dockerfile + KMS + IAM + K8s manifests (tailored al stack)
- CI/CD pipelines (GitHub Actions · multi-stack)
- Regression tests por vulns conocidas (V-CR-*/V-HI-*)
- Runbook + rollback + observability

Trabaja con distinto nivel de info previa:
- Sin discovery docs → placeholders
- Con fase-1-discovery/ → datos reales
- Con código real → análisis profundo

Uso programático:
    from aios.core.deploy_ready import detect_profile, scaffold
    profile = detect_profile(Path("apps/02-arc"))
    scaffold(profile)

Uso CLI:
    aios scaffold-deploy-ready apps/02-arc
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .repo_analyzer import analyze_repo


# ══════════════════════════════════════════════════════════════════
# Data models
# ══════════════════════════════════════════════════════════════════

@dataclass
class VulnRef:
    """Vulnerabilidad conocida · extraída de fase-*-discovery/*vulns*.md"""
    vuln_id: str          # e.g. "V-CR-01"
    severity: str         # CRITICAL/HIGH/MEDIUM
    cwe: str              # e.g. "CWE-1188"
    title: str            # short description
    file_hint: str = ""   # file path hint · may be partial
    literal: str = ""     # forbidden literal if applicable


@dataclass
class AppProfile:
    """Profile completo de la app detectada."""
    app_id: str                       # e.g. "10-noshow"
    app_name: str                     # "NoShow Report"
    app_path: Path                    # absolute path to apps/10-noshow/
    primary_stack: str                # dotnet | python | java | cobol | php | node
    detected_stacks: List[str]        # all stacks found
    tier_proposed: str                # T0 | T1 | T2 | T3
    tier_rationale: str               # heuristic explanation
    criticality: str                  # CRITICAL | HIGH | MEDIUM | LOW
    is_batch: bool                    # True → CronJob · False → Deployment
    vulns_known: List[VulnRef] = field(default_factory=list)
    integrations: List[str] = field(default_factory=list)
    compliance: List[str] = field(default_factory=list)
    kms_services: List[str] = field(default_factory=lambda: ["ecr", "secrets", "logs", "ebs"])
    forbidden_literals: List[str] = field(default_factory=list)
    forbidden_regex: List[Tuple[str, str, str]] = field(default_factory=list)  # (pattern, severity, rule_id)
    has_discovery: bool = False
    has_code: bool = False
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["app_path"] = str(self.app_path)
        return d


@dataclass
class ScaffoldReport:
    files_created: List[str] = field(default_factory=list)
    files_skipped: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


# ══════════════════════════════════════════════════════════════════
# Detectors
# ══════════════════════════════════════════════════════════════════

# Priority: prefer modernization targets (Java/Python) over legacy (COBOL).
# PHP goes last because in the scope it's always co-existing with Python (Comisiones Indirectas).
_STACK_PRIORITY = ["dotnet", "java", "python", "php", "cobol", "node"]

_STACK_HINTS = {
    "dotnet": [".cs", ".csproj", ".sln", ".vb", ".vbproj"],
    "java": [".java", "pom.xml", "build.gradle"],
    "cobol": [".cbl", ".cob", ".cobol", ".cpy"],
    "python": [".py", "requirements.txt", "pyproject.toml", "setup.py"],
    "node": ["package.json", "yarn.lock", "package-lock.json", ".ts", ".tsx", ".jsx"],
    "php": [".php", "composer.json"],
}

_INTEGRATION_HINTS = {
    "SABRE": [r"\bsabre\b", r"SabreBO", r"SabreAdapter"],
    "SFTP": [r"\bsftp\b", r"SFTPAdapter", r"ssh\.net", r"paramiko"],
    "SQL Server": [r"sql\s*server", r"SqlClient", r"pyodbc", r"mssql"],
    "MySQL": [r"mysql\.connector", r"MySqlClient", r"pymysql"],
    "Oracle": [r"oracle\b", r"cx_Oracle", r"OracleClient"],
    "AS400/DB2": [r"\bas400\b", r"\bdb2\b", r"iSeries"],
    "PostgreSQL": [r"postgres", r"psycopg", r"Npgsql"],
    "SMTP/Email": [r"smtp\b", r"mailkit", r"smtplib", r"javax\.mail"],
    "S3": [r"\bs3\b", r"boto3", r"AmazonS3"],
    "COBOL calls": [r"EXEC\s+CICS", r"CALL\s+'[A-Z0-9]+'"],
    "SOAP": [r"soap\b", r"wsdl\b", r"WCF", r"zeep"],
    "REST/HTTP": [r"HttpClient", r"requests\.", r"axios", r"fetch\("],
}

_COMPLIANCE_KEYWORDS = {
    "SOX": [r"\bsox\b", r"sarbanes", r"oracle\s+contable", r"revenue\s+recognition"],
    "LFPDPPP": [r"lfpdppp", r"pii", r"passenger", r"pnr", r"datos\s+personales"],
    "PCI-DSS": [r"\bpci\b", r"cardholder", r"card\s+number", r"ccnumber"],
    "ISO 27001": [r"iso\s*27001"],
    "CFF-Art30": [r"\bcfdi\b", r"cff\s+art"],
}

_TIER_HINTS = {
    "T1": ["critical", "compliance", "sox", "pci", "revenue", "sabre", "24x7"],
    "T2": ["batch", "daily", "standard", "operation"],
    "T3": ["standby", "legacy", "deprecated"],
}


def _read_text_safe(path: Path, max_bytes: int = 5_000_000) -> str:
    try:
        if path.stat().st_size > max_bytes:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _find_vulns_file(app_path: Path) -> Optional[Path]:
    """Busca archivos de vulns en fase-*-discovery/ o directamente."""
    candidates = []
    for pattern in ["fase-*-discovery/05_vulns.md", "fase-*-discovery/*vulns*.md",
                    "*vulns*.md", "VULNERABILIDADES.md"]:
        candidates.extend(app_path.glob(pattern))
    return candidates[0] if candidates else None


def _parse_vulns_md(vulns_file: Path) -> Tuple[List[VulnRef], List[str]]:
    """Extrae VulnRefs + literales forbidden de un archivo markdown.

    Soporta múltiples convenciones:
    - V-CR-01 / V-HI-01 (NoShow style · prefix encodes severity)
    - VULN-01 (ARC style · severity from summary table)
    - CWE-NNNN mentions inside section text
    """
    content = _read_text_safe(vulns_file)
    vulns: List[VulnRef] = []
    literals: List[str] = []

    # Pass 1 · build severity map from summary table (if present)
    #   | VULN-01 | title | CWE-798 | 8.5 High | A02 | CRITICAL |
    severity_map: Dict[str, str] = {}
    cwe_map: Dict[str, str] = {}
    table_row = re.compile(
        r"^\|\s*(V(?:-[A-Z]{2})?-\d+|VULN-\d+)\s*\|.*?\|\s*(CWE-\d+(?:\s*/\s*CWE-\d+)?)?\s*\|.*?\|.*?\|\s*(CRITICAL|HIGH|MEDIUM|LOW)\s*\|",
        re.MULTILINE | re.IGNORECASE,
    )
    for m in table_row.finditer(content):
        vid = m.group(1).upper()
        severity_map[vid] = m.group(3).upper()
        if m.group(2):
            cwe_map[vid] = m.group(2).split("/")[0].strip()

    # Pass 2 · extract headers "### <ID> · [CWE-NNN ·] title"
    vuln_header = re.compile(
        r"^###\s+((?:V-[A-Z]{2}-|VULN-|V-)\d+)\s*·?\s*(CWE-\d+)?\s*·?\s*(.+?)$",
        re.MULTILINE | re.IGNORECASE,
    )
    id_prefix_sev = {"V-CR-": "CRITICAL", "V-HI-": "HIGH", "V-ME-": "MEDIUM", "V-LO-": "LOW"}

    for match in vuln_header.finditer(content):
        vuln_id = match.group(1).upper()
        cwe = (match.group(2) or cwe_map.get(vuln_id, "")).upper() if match.group(2) or cwe_map.get(vuln_id) else ""
        title = match.group(3).strip()
        sev = severity_map.get(vuln_id)
        if not sev:
            sev = next((v for k, v in id_prefix_sev.items() if vuln_id.startswith(k)), "MEDIUM")
        vulns.append(VulnRef(
            vuln_id=vuln_id, severity=sev, cwe=cwe, title=title[:120],
        ))

    # Extract literals from backtick blocks in vulns file (ATOS5246 style)
    for lit_match in re.finditer(r"`([A-Z0-9_\.\-!@#$%^&*]{5,30})`", content):
        lit = lit_match.group(1)
        # Filter: keep strings that look like secrets/IPs, drop obvious non-secrets
        if any(c.isdigit() for c in lit) or lit.isupper() or "." in lit:
            if lit not in literals and len(lit) >= 5:
                literals.append(lit)

    return vulns, literals[:20]  # cap


def _extract_integrations(app_path: Path) -> List[str]:
    """Busca indicadores de integraciones externas en código + discovery."""
    found: set[str] = set()
    # Scan selected file types for keyword hits
    for pattern in ["*.cs", "*.py", "*.java", "*.config", "*.md", "*.xml", "*.yaml", "*.json"]:
        for f in list(app_path.rglob(pattern))[:200]:  # limit depth/count
            if any(noise in str(f) for noise in ["bin/", "obj/", "packages/", ".vs/", "node_modules", "__pycache__"]):
                continue
            txt = _read_text_safe(f, max_bytes=500_000)
            for integration, patterns in _INTEGRATION_HINTS.items():
                if any(re.search(p, txt, re.IGNORECASE) for p in patterns):
                    found.add(integration)
            if len(found) >= len(_INTEGRATION_HINTS):
                break
        if len(found) >= len(_INTEGRATION_HINTS):
            break
    return sorted(found)


def _extract_compliance(app_path: Path) -> List[str]:
    found: set[str] = set()
    for pattern in ["*.md", "*.cs", "*.py", "fase-*-discovery/*.md"]:
        for f in list(app_path.rglob(pattern))[:100]:
            txt = _read_text_safe(f, max_bytes=200_000)
            for comp, patterns in _COMPLIANCE_KEYWORDS.items():
                if any(re.search(p, txt, re.IGNORECASE) for p in patterns):
                    found.add(comp)
    return sorted(found)


def _classify_tier(
    app_path: Path, vulns: List[VulnRef],
    compliance: List[str], integrations: List[str],
) -> Tuple[str, str]:
    """Heuristic tier classification. Returns (tier, rationale)."""
    score = 0
    reasons = []

    # Vulns severity signals
    if any(v.severity == "CRITICAL" for v in vulns):
        score += 2
        reasons.append("CRITICAL vulns present")

    # Compliance signals (strong → T1)
    if "SOX" in compliance or "PCI-DSS" in compliance:
        score += 3
        reasons.append(f"Compliance: {', '.join(c for c in compliance if c in ('SOX', 'PCI-DSS'))}")
    if "LFPDPPP" in compliance:
        score += 1
        reasons.append("LFPDPPP (PII)")

    # Integrations signals
    if "SABRE" in integrations:
        score += 2
        reasons.append("SABRE integration (revenue-critical)")
    if len(integrations) >= 3:
        score += 1
        reasons.append(f"Multiple integrations ({len(integrations)})")

    # App name hints · heuristic from memory
    name_lower = app_path.name.lower()
    if any(x in name_lower for x in ["sicofav", "cfdi", "revenue", "comisio"]):
        score += 1
        reasons.append(f"App name hints critical: {app_path.name}")

    # Classify
    if score >= 5:
        tier = "T1"
    elif score >= 2:
        tier = "T1"  # conservative default · policy v2.0 says prefer higher tier
    elif score >= 1:
        tier = "T2"
    else:
        tier = "T2"

    rationale = f"Score {score}: " + " · ".join(reasons) if reasons else "Default (low signal)"
    return tier, rationale


def _is_batch_app(app_path: Path, integrations: List[str]) -> bool:
    """True if app looks like a batch (cron/scheduled) vs service."""
    # Look for scheduler hints
    for pattern in ["*.cs", "*.py", "*.md", "*.config"]:
        for f in list(app_path.rglob(pattern))[:50]:
            txt = _read_text_safe(f, max_bytes=100_000)
            if re.search(r"\b(cron|quartz|CronJob|BackgroundService|WorkerService|schedule|batch)\b",
                         txt, re.IGNORECASE):
                return True
    # Heuristic: if no HTTP/REST/Ingress signals AND has SFTP/SMTP outputs, likely batch
    if "REST/HTTP" not in integrations and any(i in integrations for i in ["SFTP", "SMTP/Email"]):
        return True
    return False


def _pick_primary_stack(detected: List[str]) -> str:
    for stack in _STACK_PRIORITY:
        if stack in detected:
            return stack
    return detected[0] if detected else "unknown"


def _app_id_and_name(app_path: Path) -> Tuple[str, str]:
    """Extract app_id (01-sicofav) and human name from path + existing docs."""
    app_id = app_path.name
    # Try to find human name from discovery docs
    for candidate in app_path.glob("RESUMEN_*.md"):
        txt = _read_text_safe(candidate, max_bytes=10_000)
        m = re.search(r"^#\s+(.+?)$", txt, re.MULTILINE)
        if m:
            return app_id, m.group(1).strip()[:80]
    # Fallback: convert 01-sicofav → Sicofav
    parts = app_id.split("-", 1)
    friendly = parts[-1].replace("-", " ").title() if len(parts) > 1 else app_id.title()
    return app_id, friendly


def detect_profile(app_path: Path) -> AppProfile:
    """Detecta perfil completo de la app."""
    app_path = Path(app_path).resolve()
    if not app_path.exists():
        raise FileNotFoundError(f"App path not found: {app_path}")

    app_id, app_name = _app_id_and_name(app_path)

    # Stacks
    analysis = analyze_repo(app_path)
    detected_stacks = [s for s in analysis.get("stack", []) if s != "docker"]
    # Enrich with file-extension detection
    for stack, hints in _STACK_HINTS.items():
        if stack in detected_stacks:
            continue
        for hint in hints:
            if hint.startswith("."):
                if any(app_path.rglob(f"*{hint}")):
                    detected_stacks.append(stack)
                    break
            elif any(app_path.rglob(hint)):
                detected_stacks.append(stack)
                break
    primary_stack = _pick_primary_stack(detected_stacks)

    # Vulns from discovery
    vulns: List[VulnRef] = []
    literals: List[str] = []
    vulns_file = _find_vulns_file(app_path)
    has_discovery = vulns_file is not None
    if vulns_file:
        vulns, literals = _parse_vulns_md(vulns_file)

    # Integrations + compliance
    integrations = _extract_integrations(app_path)
    compliance = _extract_compliance(app_path)

    # Tier classification
    tier, rationale = _classify_tier(app_path, vulns, compliance, integrations)

    # Criticality (highest vuln severity)
    severities = [v.severity for v in vulns] or ["MEDIUM"]
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    criticality = next((s for s in order if s in severities), "MEDIUM")

    # Batch vs service
    is_batch = _is_batch_app(app_path, integrations)

    # Has code? (at least 5 source files in primary stack)
    stack_exts = [e for e in _STACK_HINTS.get(primary_stack, []) if e.startswith(".")]
    has_code = False
    if stack_exts:
        source_count = sum(1 for ext in stack_exts for _ in app_path.rglob(f"*{ext}"))
        has_code = source_count >= 5

    # Build forbidden_regex per-app from known AMX rules if relevant vulns present
    forbidden_regex: List[Tuple[str, str, str]] = []
    if any("829" in v.title for v in vulns):
        forbidden_regex.append((r'flight\s*=?\s*.*"829"', "CRITICAL", "AMX-VUELO-829"))

    notes = []
    if not has_code:
        notes.append("No source code detected in app_path · scaffold usa placeholders estructurales")
    if not has_discovery:
        notes.append("No fase-*-discovery/ found · vulns_known vacío · usar placeholders")
    if tier == "T1" and not ("SOX" in compliance or "PCI-DSS" in compliance):
        notes.append("Tier T1 propuesto por prudencia · revisar con doc Dynamo oficial")

    return AppProfile(
        app_id=app_id, app_name=app_name, app_path=app_path,
        primary_stack=primary_stack, detected_stacks=sorted(set(detected_stacks)),
        tier_proposed=tier, tier_rationale=rationale,
        criticality=criticality, is_batch=is_batch,
        vulns_known=vulns, integrations=integrations,
        compliance=compliance, forbidden_literals=literals,
        forbidden_regex=forbidden_regex,
        has_discovery=has_discovery, has_code=has_code,
        notes=notes,
    )


# ══════════════════════════════════════════════════════════════════
# Template substitution · simple {{VAR}} replacement
# ══════════════════════════════════════════════════════════════════

_TEMPLATE_VAR = re.compile(r"\{\{\s*([A-Z_][A-Z0-9_]*)\s*\}\}")


def _render(template_text: str, context: Dict[str, str]) -> str:
    """Substitute {{VAR}} with context[VAR] · missing vars → empty string."""
    return _TEMPLATE_VAR.sub(lambda m: context.get(m.group(1), ""), template_text)


def _app_id_short(app_id: str) -> str:
    """'10-noshow' → 'noshow' · '01-sicofav' → 'sicofav'."""
    parts = app_id.split("-", 1)
    return parts[-1] if len(parts) > 1 else app_id


def _pascal_case(name: str) -> str:
    """'NoShow Report' → 'NoShowReport' · 'arc' → 'Arc'."""
    cleaned = re.sub(r"[^a-zA-Z0-9\s]", "", name)
    return "".join(w.capitalize() for w in cleaned.split())


def _build_context(profile: AppProfile) -> Dict[str, str]:
    vulns_table = "\n".join(
        f"| {v.vuln_id} | {v.severity} | {v.cwe or '-'} | {v.title} |" for v in profile.vulns_known
    ) or "| _(no discovery docs found)_ | - | - | - |"

    integrations_list = "\n".join(f"- {i}" for i in profile.integrations) or "- _(none detected)_"
    compliance_list = "\n".join(f"- {c}" for c in profile.compliance) or "- _(none detected)_"
    stacks_list = ", ".join(profile.detected_stacks) or "(unknown)"
    workload_type = "CronJob (batch)" if profile.is_batch else "Deployment (service)"

    # Derived naming
    app_id_short = _app_id_short(profile.app_id)
    app_name_short = profile.app_name.split("·")[0].strip()[:30]
    app_name_pascal = _pascal_case(app_name_short)

    return {
        "APP_ID": profile.app_id,
        "APP_ID_SHORT": app_id_short,
        "APP_NAME": profile.app_name,
        "APP_NAME_SHORT": app_name_short,
        "APP_NAME_PASCAL": app_name_pascal,
        "PRIMARY_STACK": profile.primary_stack,
        "DETECTED_STACKS": stacks_list,
        "TIER": profile.tier_proposed,
        "TIER_RATIONALE": profile.tier_rationale,
        "CRITICALITY": profile.criticality,
        "WORKLOAD_TYPE": workload_type,
        "VULNS_TABLE": vulns_table,
        "INTEGRATIONS": integrations_list,
        "COMPLIANCE": compliance_list,
        "COUNT_CRITICAL": str(sum(1 for v in profile.vulns_known if v.severity == "CRITICAL")),
        "COUNT_HIGH": str(sum(1 for v in profile.vulns_known if v.severity == "HIGH")),
        "FORBIDDEN_LITERALS_TOML": ", ".join(f'"{l}"' for l in profile.forbidden_literals) or "",
        # Placeholders the user fills post-scaffold
        "AWS_ACCOUNT_ID": "ACCOUNT_ID_PLACEHOLDER",
        "AWS_REGION": "us-east-1",
    }


def _templates_root() -> Path:
    """Resolve templates root · package data dir."""
    return Path(__file__).resolve().parent.parent / "templates" / "deploy_ready"


def _select_template(templates_root: Path, rel_path: str, primary_stack: str) -> Optional[Path]:
    """Look for stack-specific template first, then common."""
    stack_path = templates_root / primary_stack / rel_path
    if stack_path.exists():
        return stack_path
    common_path = templates_root / "common" / rel_path
    return common_path if common_path.exists() else None


def _render_template_file(src: Path, dest: Path, context: Dict[str, str]) -> None:
    text = src.read_text(encoding="utf-8")
    rendered = _render(text, context)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(rendered, encoding="utf-8")


# ══════════════════════════════════════════════════════════════════
# Scaffolder · orchestrator
# ══════════════════════════════════════════════════════════════════

# Map of deploy-ready file → template relative path (stack-aware lookup)
_FILE_MAP = [
    # docs
    ("ARCHITECT_PACKAGE_README.md",                 "docs/ARCHITECT_PACKAGE_README.md.tmpl"),
    ("docs/ADR-001-stack-choice.md",                 "docs/ADR-001-stack-choice.md.tmpl"),
    ("docs/ADR-002-compute-choice.md",               "docs/ADR-002-compute-choice.md.tmpl"),
    ("docs/BIA.md",                                  "docs/BIA.md.tmpl"),
    ("docs/SERVICIOS_AWS_Y_KMS.md",                  "docs/SERVICIOS_AWS_Y_KMS.md.tmpl"),
    ("docs/G4_board_review_checklist.md",            "docs/G4_board_review_checklist.md.tmpl"),
    # infra · common
    ("infra/cloudformation/kms-cmks.yaml",           "infra/cloudformation/kms-cmks.yaml.tmpl"),
    ("infra/cloudformation/iam-roles-amx-r.yaml",    "infra/cloudformation/iam-roles-amx-r.yaml.tmpl"),
    # infra · stack-specific
    ("infra/docker/Dockerfile",                      "infra/docker/Dockerfile.tmpl"),
    ("infra/docker/.dockerignore",                   "infra/docker/.dockerignore.tmpl"),
    # pipelines · stack-specific
    ("pipelines/ci.yml",                             "pipelines/ci.yml.tmpl"),
    ("pipelines/cyber-scan.yml",                     "pipelines/cyber-scan.yml.tmpl"),
    ("pipelines/cd.yml",                             "pipelines/cd.yml.tmpl"),
    # runbook
    ("runbook/RUNBOOK.md",                           "runbook/RUNBOOK.md.tmpl"),
    ("runbook/ROLLBACK.md",                          "runbook/ROLLBACK.md.tmpl"),
    ("runbook/OBSERVABILITY.md",                     "runbook/OBSERVABILITY.md.tmpl"),
    # suppressions
    ("suppressions/cyber-exceptions.md",             "suppressions/cyber-exceptions.md.tmpl"),
]

# K8s: CronJob vs Deployment based on is_batch
_K8S_FILES = [
    ("infra/k8s/cronjob.yaml",                       "infra/k8s/cronjob.yaml.tmpl"),       # is_batch=True
    ("infra/k8s/deployment.yaml",                    "infra/k8s/deployment.yaml.tmpl"),    # is_batch=False
]

# Regression tests · stack-specific
_TEST_FILES_BY_STACK = {
    "dotnet": [
        ("tests/regression/NoVuelo829BlockTest.cs",     "tests/regression/NoVuelo829BlockTest.cs.tmpl"),
        ("tests/regression/NoSecretsInlineTest.cs",     "tests/regression/NoSecretsInlineTest.cs.tmpl"),
        ("tests/regression/NoHardcodedIpsTest.cs",      "tests/regression/NoHardcodedIpsTest.cs.tmpl"),
    ],
    "python": [
        ("tests/regression/test_no_secrets_inline.py",  "tests/regression/test_no_secrets_inline.py.tmpl"),
        ("tests/regression/test_no_hardcoded_ips.py",   "tests/regression/test_no_hardcoded_ips.py.tmpl"),
    ],
    "java": [
        ("tests/regression/NoSecretsInlineTest.java",   "tests/regression/NoSecretsInlineTest.java.tmpl"),
    ],
    "cobol": [
        ("tests/regression/run_regression.sh",          "tests/regression/run_regression.sh.tmpl"),
    ],
    "php": [
        ("tests/regression/NoSecretsInlineTest.php",    "tests/regression/NoSecretsInlineTest.php.tmpl"),
    ],
}


def scaffold(
    profile: AppProfile,
    output_dir: Optional[Path] = None,
    overwrite: bool = False,
) -> ScaffoldReport:
    """Genera el paquete deploy-ready/ a partir del profile."""
    output_dir = output_dir or (profile.app_path / "deploy-ready")
    templates_root = _templates_root()
    context = _build_context(profile)
    report = ScaffoldReport()

    if not templates_root.exists():
        report.warnings.append(f"Templates root not found: {templates_root}")
        return report

    # Core file map
    file_map = list(_FILE_MAP)

    # Add K8s manifest (cronjob OR deployment based on is_batch)
    if profile.is_batch:
        file_map.append(_K8S_FILES[0])
    else:
        file_map.append(_K8S_FILES[1])

    # Add stack-specific regression tests
    file_map.extend(_TEST_FILES_BY_STACK.get(profile.primary_stack, []))

    for rel_dest, rel_tmpl in file_map:
        dest = output_dir / rel_dest
        if dest.exists() and not overwrite:
            report.files_skipped.append(str(dest))
            continue
        src = _select_template(templates_root, rel_tmpl, profile.primary_stack)
        if src is None:
            report.warnings.append(f"Template missing: {rel_tmpl}")
            continue
        try:
            _render_template_file(src, dest, context)
            report.files_created.append(str(dest))
        except Exception as exc:
            report.warnings.append(f"Failed to render {rel_dest}: {exc}")

    # Write profile JSON for traceability + downstream consumers (Mythos TUT auto-register)
    profile_json = output_dir / ".aios-profile.json"
    if overwrite or not profile_json.exists():
        profile_json.parent.mkdir(parents=True, exist_ok=True)
        profile_json.write_text(
            json.dumps(profile.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )
        report.files_created.append(str(profile_json))

    return report


# ══════════════════════════════════════════════════════════════════
# Mythos TUT auto-register (post-scaffold)
# ══════════════════════════════════════════════════════════════════

def generate_mythos_tut(profile: AppProfile, repo_root: Path) -> Optional[Path]:
    """Create mythos/mythos-targets/<app>.toml from profile · returns written path."""
    tut_dir = repo_root / "mythos" / "mythos-targets"
    if not tut_dir.exists():
        return None

    tut_path = tut_dir / f"{profile.app_id}-{profile.primary_stack}.toml"

    scanners = ["secrets", "pii"]
    if profile.primary_stack in ("dotnet", "python", "java"):
        scanners.append("injection")
    if profile.primary_stack == "python":
        scanners.append("crypto")

    severity_gate = "HIGH"
    if profile.criticality == "CRITICAL":
        severity_gate = "HIGH"  # HIGH gate blocks HIGH+CRITICAL

    literals_toml = ", ".join(f'"{l}"' for l in profile.forbidden_literals[:10])
    regex_toml_lines = "\n".join(f"'{r[0]}'," for r in profile.forbidden_regex)

    content = f'''[target]
id = "{profile.app_id}-{profile.primary_stack}"
name = "{profile.app_name} · {profile.primary_stack.upper()}"
artifact_path = "{profile.app_path.relative_to(repo_root) if profile.app_path.is_relative_to(repo_root) else profile.app_path}"
primary_stack = "{profile.primary_stack}"
criticality = "{profile.criticality}"

[scanners]
enabled = {json.dumps(scanners)}
disabled = ["iac", "container"]

[policy]
severity_gate = "{severity_gate}"
allow_medium_in_prod = false

[amx_patterns]
forbidden_literals = [{literals_toml}]
forbidden_regex = [
{regex_toml_lines}
]

[known_findings]
fase1_refs = {json.dumps([v.vuln_id for v in profile.vulns_known[:20]])}
source_ref = "apps/{profile.app_id}/fase-1-discovery/05_vulns.md"
'''
    tut_path.write_text(content, encoding="utf-8")
    return tut_path


# ══════════════════════════════════════════════════════════════════
# CLI entry point
# ══════════════════════════════════════════════════════════════════

def run_scaffold_deploy_ready(
    app_path: str,
    overwrite: bool = False,
    register_mythos: bool = True,
    repo_root: Optional[str] = None,
) -> dict:
    """CLI-friendly · returns dict report."""
    profile = detect_profile(Path(app_path))
    result = {
        "profile": profile.to_dict(),
        "scaffold": None,
        "mythos_tut": None,
    }

    scaffold_report = scaffold(profile, overwrite=overwrite)
    result["scaffold"] = {
        "files_created": scaffold_report.files_created,
        "files_skipped": scaffold_report.files_skipped,
        "warnings": scaffold_report.warnings,
    }

    if register_mythos:
        root = Path(repo_root) if repo_root else Path.cwd()
        tut = generate_mythos_tut(profile, root)
        result["mythos_tut"] = str(tut) if tut else None

    return result
