"""Third-Party Exfil Heuristic · v2.3.0 · RFC-004c

Detecta referencias (emails · URLs · hosts SMTP/FTP) hacia dominios no
corporativos en configs y código, capturando un vector de data leak que
ningún SAST comercial automatiza sin reglas custom.

Ejemplo canónico NoShow real (2026-04-22):
- `distributionList` en config de producción con `@miatech.net`
  (dominio vendor · no AMX) → data siendo enviada fuera del perímetro

Heurística · NO confirmación:
- HIGH cuando el archivo parece config de producción y el recipient
  es no-corporativo
- MEDIUM cuando aparece en código (puede ser runtime-switch)
- INFO cuando aparece en tests / docs / samples

Uso canónico:
    detector = ExfilDetector(
        root=Path("."),
        corporate_domains=["aeromexico.com.mx", "am.com.mx"],
    )
    report = detector.detect()

CLI:
    aios exfil --root . \
        --corporate "aeromexico.com.mx,am.com.mx" \
        --format json

Severity:
- HIGH  · email/URL externo en archivo etiquetado production / prod
- MEDIUM· email/URL externo en config genérico o código
- INFO  · aparece en test / sample / doc
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# Default AMX corporate whitelist · sobrescribible por CLI
_DEFAULT_CORPORATE_DOMAINS = (
    "aeromexico.com.mx",
    "am.com.mx",
    "aeromexicocargo.com",
)

# Dominios que siempre deberían ignorarse aun cuando no estén en whitelist
# (infra común · no representan exfil)
_BENIGN_DOMAINS = (
    "localhost", "example.com", "example.org", "example.net",
    "test.com", "schema.org", "w3.org", "xmlns.com", "github.com",
    "microsoft.com", "amazonaws.com", "amazon.com",
    "nuget.org", "pypi.org", "npmjs.com",
    "openssl.org", "ibm.com", "oracle.com",
    "aeromexico.com", "aeromexico.com.mx",  # variantes corporativas default
)

# v3.1 fix · code-refs que el regex SMTP/FTP host matchea como si fueran
# hosts reales · son C# class/namespace references · no hosts.
_CODE_REF_SEGMENTS = (
    "ConfigurationManager", "AppSettings", "AppSetting", "MailMessage",
    "SmtpClient", "SftpClient", "HttpClient", "SqlConnection", "FileStream",
    "StreamReader", "StreamWriter", "WebClient", "WebRequest", "XmlDocument",
    "ArgumentNullException", "InvalidOperationException", "SocketException",
    "SftpPathNotFoundException",
)
_CODE_REF_PREFIXES = (
    "System.", "Microsoft.", "Renci.", "log4net.", "Business.", "Data.",
    "NoshowWS.", "CreateSession.", "GetPassengerList.", "GetReservation.",
    "TicketingDocumentServices",
)
# TLDs reales comunes · rechaza "PascalCase.PascalCase" como host
_VALID_TLD_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9.-]*\."
    r"(com|org|net|mx|co|us|io|dev|gov|edu|info|biz|mil|int|"
    r"ai|app|cloud|tech|services|global|arpa|[a-z]{2})$",
    re.IGNORECASE,
)


def _looks_like_code_ref(domain: str) -> bool:
    """True si el "dominio" capturado es realmente una referencia de
    codigo (C# class/namespace/identifier) · no un host real."""
    if not domain:
        return True
    for seg in _CODE_REF_SEGMENTS:
        if seg in domain:
            return True
    for pre in _CODE_REF_PREFIXES:
        if domain.startswith(pre):
            return True
    # PascalCase seguido de . seguido de PascalCase = identifier
    if re.match(r"^[A-Z][a-z]+[A-Z]\w*\.[A-Z]", domain):
        return True
    # No coincide con TLD conocido · rechaza
    if not _VALID_TLD_RE.match(domain):
        return True
    return False

# Extensiones que consideramos "código / config escaneable"
_SCAN_EXTS = {
    ".cs", ".py", ".java", ".js", ".ts", ".php", ".rb", ".go",
    ".config", ".xml", ".json", ".yaml", ".yml", ".ini", ".toml",
    ".properties", ".env", ".conf", ".cfg", ".sql", ".ps1", ".sh",
    ".bat",
}

_DEFAULT_EXCLUDES = {
    "bin", "obj", ".vs", ".git", ".github", "node_modules",
    "__pycache__", "packages", "dist", "build", ".venv", "venv",
}

# Patrones principales
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"
)
_URL_RE = re.compile(
    r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?:[:/][^\s\"'<>)]*)?",
    re.IGNORECASE,
)
_SMTP_HOST_RE = re.compile(
    r"(?:smtp|mail|imap|pop3)(?:[\.\-_]host)?\s*[:=]\s*[\"']?"
    r"([A-Za-z0-9.-]+\.[A-Za-z]{2,})",
    re.IGNORECASE,
)
_FTP_HOST_RE = re.compile(
    r"(?:ftp|sftp)(?:[\.\-_]host)?\s*[:=]\s*[\"']?"
    r"([A-Za-z0-9.-]+\.[A-Za-z]{2,})",
    re.IGNORECASE,
)


@dataclass
class ExfilFinding:
    kind: str  # email_external · url_external · smtp_external · ftp_external
    severity: str  # HIGH · MEDIUM · INFO
    file: str
    line: int
    domain: str
    recipient: str  # email completo o URL completo
    context: str  # línea snippet
    env_hint: str  # "prod" · "test" · "qa" · "unknown"
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ExfilReport:
    root: str
    corporate_domains: list[str]
    files_scanned: int = 0
    findings: list[ExfilFinding] = field(default_factory=list)

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "corporate_domains": self.corporate_domains,
            "files_scanned": self.files_scanned,
            "findings": [f.to_dict() for f in self.findings],
            "by_severity": self.by_severity(),
        }


def _normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def _is_corporate(domain: str, whitelist: tuple[str, ...]) -> bool:
    d = _normalize_domain(domain)
    for corp in whitelist:
        corp_norm = _normalize_domain(corp)
        if d == corp_norm or d.endswith("." + corp_norm):
            return True
    return False


def _is_benign(domain: str) -> bool:
    d = _normalize_domain(domain)
    for b in _BENIGN_DOMAINS:
        if d == b or d.endswith("." + b):
            return True
    return False


def _env_hint_for_path(path: Path) -> str:
    """Heurística · detectar ambiente a partir del path/filename."""
    parts = [p.lower() for p in path.parts]
    name = path.name.lower()
    for tag, hints in (
        ("prod", ("prod", "production", "release", "live")),
        ("test", ("test", "tests", "qa", "testing")),
        ("dev", ("dev", "development", "local", "sample", "demo", "example")),
    ):
        if any(h in name for h in hints):
            return tag
        if any(h in parts for h in hints):
            return tag
    return "unknown"


def _severity_for(kind: str, env_hint: str) -> str:
    if env_hint == "prod":
        return "HIGH"
    if env_hint in ("dev", "test"):
        return "INFO"
    return "MEDIUM"


def _scan_file(path: Path,
               whitelist: tuple[str, ...]) -> list[ExfilFinding]:
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return []
    findings: list[ExfilFinding] = []
    lines = content.splitlines()
    env_hint = _env_hint_for_path(path)

    def _add(kind: str, line_no: int, domain: str, recipient: str,
             snippet: str) -> None:
        if _is_corporate(domain, whitelist) or _is_benign(domain):
            return
        # v3.1 fix · reject code-references incorrectly parsed as hosts
        if _looks_like_code_ref(domain):
            return
        severity = _severity_for(kind, env_hint)
        findings.append(ExfilFinding(
            kind=kind,
            severity=severity,
            file=str(path),
            line=line_no,
            domain=_normalize_domain(domain),
            recipient=recipient,
            context=snippet[:200],
            env_hint=env_hint,
            message=(
                f"{kind.replace('_', ' ')} · {_normalize_domain(domain)} "
                f"(no corporativo) · env_hint={env_hint}"
            ),
        ))

    for idx, line in enumerate(lines, 1):
        for m in _EMAIL_RE.finditer(line):
            email = m.group(1)
            domain = email.split("@", 1)[1]
            _add("email_external", idx, domain, email, line.strip())
        for m in _URL_RE.finditer(line):
            domain = m.group(1)
            _add("url_external", idx, domain, m.group(0), line.strip())
        for m in _SMTP_HOST_RE.finditer(line):
            domain = m.group(1)
            _add("smtp_external", idx, domain, m.group(0), line.strip())
        for m in _FTP_HOST_RE.finditer(line):
            domain = m.group(1)
            _add("ftp_external", idx, domain, m.group(0), line.strip())

    return findings


class ExfilDetector:
    """Entry point · scan third-party exfil references."""

    def __init__(
        self,
        root: Path,
        corporate_domains: Optional[list[str]] = None,
        exclude_dirs: Optional[set[str]] = None,
        include_exts: Optional[set[str]] = None,
    ):
        self.root = Path(root).resolve()
        self.whitelist = tuple(
            _normalize_domain(d) for d in (corporate_domains or _DEFAULT_CORPORATE_DOMAINS)
        )
        self.exclude_dirs = exclude_dirs or _DEFAULT_EXCLUDES
        self.include_exts = include_exts or _SCAN_EXTS

    def detect(self) -> ExfilReport:
        report = ExfilReport(
            root=str(self.root),
            corporate_domains=list(self.whitelist),
        )
        if not self.root.exists():
            return report
        for path in self.root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in self.exclude_dirs for part in path.parts):
                continue
            if path.suffix.lower() not in self.include_exts:
                continue
            report.files_scanned += 1
            report.findings.extend(_scan_file(path, self.whitelist))
        return report


def detect_exfil(
    root: Path,
    corporate_domains: Optional[list[str]] = None,
) -> ExfilReport:
    """Convenience · alias del constructor + detect()."""
    return ExfilDetector(root, corporate_domains=corporate_domains).detect()
