"""Runtime Data File Scanner · v2.4.0 · RFC-004d

Escanea archivos que NO son código fuente pero se despliegan junto con
él: HTML templates, TXT de PNRs, logs, CSVs, dumps, samples. Estos
archivos suelen contener PII en runtime y quedan fuera del scan CWE
estándar por diseño.

Ejemplo canónico NoShow real (2026-04-22):
- `Email.html` templates con correos y datos de pasajero en plaintext
- `files/*.txt` con PNRs (locator alfanuméricos)
- logs de producción con session tokens o claves

Detectores incluidos:
- PNR locator (6-char alfanumérico Sabre/Amadeus style)
- Credit card · visa · mastercard · amex (Luhn check)
- Email addresses expuestos en cuerpo de archivo
- SSN / CURP / RFC México-like
- Passport numbers (heurístico)
- Phone numbers (E.164 / NANP / México)
- Session tokens / JWT / long base64 strings
- IP privadas expuestas

Uso canónico:
    scanner = RuntimeDataScanner(Path("."))
    report = scanner.scan()

CLI:
    aios runtime-data --root . --format json

Severity:
- HIGH · PAN (credit card) · session token · JWT · passport
- MEDIUM· PNR · email · CURP · SSN · phone
- INFO · IP privada · pattern débil
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# Extensiones de archivos runtime-data (NO código)
_RUNTIME_EXTS = {
    ".html", ".htm", ".txt", ".log", ".csv", ".tsv", ".dat",
    ".eml", ".msg", ".json", ".xml",  # incluyen payloads
    ".out", ".dump", ".bak",
    ".err",  # logs rotados sin numero
}

# v3.3.1 · detección de logs ROTADOS que no matchean _RUNTIME_EXTS
# por el suffix final (ej. noShow.log.1, app.log.2026-04-22, service.log.10)
# Issue real descubierto en NoShow: logs rotados quedaban fuera del scan
# · ~2.3M PNRs perdidos en una corrida fresca.
_ROTATED_LOG_PAT = re.compile(
    r"""\.(?:log|out|err|txt|csv|dat)"""
    r"""(?:\.\d+|\.\d{4}-\d{2}-\d{2}|\.\d{8}|\.old|\.prev|\.backup)$""",
    re.IGNORECASE,
)

# Paths que indican "runtime data" aun cuando la extensión sea ambigua
_RUNTIME_PATH_HINTS = (
    "files", "templates", "logs", "dumps", "samples", "data",
    "attachments", "reports", "exports",
)

_DEFAULT_EXCLUDES = {
    "bin", "obj", ".vs", ".git", ".github", "node_modules",
    "__pycache__", "packages", "dist", "build", ".venv", "venv",
    "tests", "test",  # tests tienen fixtures con PII de mentira
}

# Max bytes a leer por archivo (evita timeouts en logs gigantes)
_MAX_FILE_BYTES = 4 * 1024 * 1024  # 4 MB

# --- Patrones ---
_PNR_RE = re.compile(
    r"(?<![A-Z0-9])([A-Z]{2}[A-Z0-9]{4}|[A-Z0-9]{6})(?![A-Z0-9])"
)
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"
)
# Visa / MC / Amex / Discover · laxo · validación Luhn después
_PAN_RE = re.compile(
    r"(?<![0-9])((?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))"
    r"[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4})(?![0-9])"
)
_CURP_RE = re.compile(
    r"(?<![A-Z0-9])([A-Z][AEIOUX][A-Z]{2}\d{6}[HM]"
    r"(?:AS|BC|BS|CC|CS|CH|CL|CM|DF|DG|GT|GR|HG|JC|MC|MN|MS|NT|NL|OC|PL|QT|QR|SP|SL|SR|TC|TS|TL|VZ|YN|ZS|NE)"
    r"[BCDFGHJKLMNPQRSTVWXYZ]{3}[A-Z0-9]\d)(?![A-Z0-9])"
)
_RFC_MX_RE = re.compile(
    r"(?<![A-Z0-9])([A-Z&Ñ]{3,4}\d{6}[A-Z0-9]{3})(?![A-Z0-9])"
)
_SSN_US_RE = re.compile(
    r"(?<![0-9])(\d{3}-\d{2}-\d{4})(?![0-9])"
)
_PASSPORT_RE = re.compile(
    r"(?i)(?:passport|pasaporte)[^\n\r]{0,20}?"
    r"[\s:=\-]+([A-Z0-9]{6,12})"
)
_PHONE_MX_RE = re.compile(
    r"(?<![0-9])(?:\+?52[\s\-]?)?(?:1[\s\-]?)?(\d{2,3})"
    r"[\s\-]?(\d{3,4})[\s\-]?(\d{4})(?![0-9])"
)
_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
)
_SESSION_TOKEN_RE = re.compile(
    r"(?i)(?:session|sess|auth|bearer)[_\-]?(?:id|token|key)"
    r"[\s:=\"']+([A-Za-z0-9+/=_\-]{24,})"
)
_PRIVATE_IP_RE = re.compile(
    r"(?<![0-9])"
    r"(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3})"
    r"(?![0-9])"
)


@dataclass
class RuntimeDataFinding:
    kind: str  # pnr · email · pan · curp · rfc · ssn · passport · phone · jwt · token · private_ip
    severity: str  # HIGH · MEDIUM · INFO
    file: str
    line: int
    sample: str  # redacted sample de lo detectado
    context: str
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RuntimeDataReport:
    root: str
    files_scanned: int = 0
    findings: list[RuntimeDataFinding] = field(default_factory=list)

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "findings": [f.to_dict() for f in self.findings],
            "by_severity": self.by_severity(),
        }


def _luhn_ok(card: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", card)]
    if len(digits) < 13:
        return False
    total = 0
    reverse = digits[::-1]
    for i, d in enumerate(reverse):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _redact(value: str, keep: int = 4) -> str:
    """Redacción segura · conserva solo los primeros `keep` chars."""
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "*" * (len(value) - keep)


def _is_runtime_data_file(path: Path) -> bool:
    if path.suffix.lower() in _RUNTIME_EXTS:
        return True
    # v3.3.1 · detecta logs rotados (noShow.log.1 · app.log.2026-04-22)
    if _ROTATED_LOG_PAT.search(path.name):
        return True
    parts_lower = [p.lower() for p in path.parts]
    return any(h in parts_lower for h in _RUNTIME_PATH_HINTS)


def _scan_content(path: Path, content: str) -> list[RuntimeDataFinding]:
    findings: list[RuntimeDataFinding] = []
    lines = content.splitlines()

    def _add(kind: str, line_no: int, sample: str, snippet: str,
             severity: str, message: str) -> None:
        findings.append(RuntimeDataFinding(
            kind=kind,
            severity=severity,
            file=str(path),
            line=line_no,
            sample=sample,
            context=snippet[:200],
            message=message,
        ))

    # Skip PNR scan on common false-positive patterns (logs con hashes)
    is_html = path.suffix.lower() in (".html", ".htm")

    for idx, line in enumerate(lines, 1):
        line_stripped = line.strip()
        # JWT (HIGH) · antes que token genérico · más específico
        for m in _JWT_RE.finditer(line):
            _add("jwt", idx, _redact(m.group(0), 8), line_stripped,
                 "HIGH",
                 "JSON Web Token expuesto en runtime data · rotar")
        # Session / bearer token (HIGH)
        for m in _SESSION_TOKEN_RE.finditer(line):
            tok = m.group(1)
            if len(tok) < 24:
                continue
            _add("session_token", idx, _redact(tok, 6), line_stripped,
                 "HIGH",
                 "Session / bearer token expuesto · rotar + investigar alcance")
        # PAN credit card (HIGH)
        for m in _PAN_RE.finditer(line):
            pan = m.group(1)
            if not _luhn_ok(pan):
                continue
            _add("pan", idx, _redact(pan.replace(" ", "").replace("-", ""), 4),
                 line_stripped,
                 "HIGH",
                 "PAN credit-card en runtime data · "
                 "PCI-DSS violation · enmascarar/tokenizar")
        # Passport (HIGH)
        for m in _PASSPORT_RE.finditer(line):
            _add("passport", idx, _redact(m.group(1), 3), line_stripped,
                 "HIGH",
                 "Passport number en runtime data · PII alta · enmascarar")
        # CURP (MEDIUM) · PII MX identificable
        for m in _CURP_RE.finditer(line):
            _add("curp", idx, _redact(m.group(1), 4), line_stripped,
                 "MEDIUM",
                 "CURP (MX) en runtime data · LFPDPPP · enmascarar")
        # RFC MX (MEDIUM) · más prone a false positives
        for m in _RFC_MX_RE.finditer(line):
            # filter common false positives (3-4 letter words)
            val = m.group(1)
            if len(val) < 12:
                continue
            _add("rfc_mx", idx, _redact(val, 4), line_stripped,
                 "MEDIUM",
                 "RFC (MX) en runtime data · LFPDPPP · enmascarar")
        # SSN US (MEDIUM)
        for m in _SSN_US_RE.finditer(line):
            _add("ssn_us", idx, _redact(m.group(1), 3), line_stripped,
                 "MEDIUM",
                 "SSN US-like en runtime data · enmascarar")
        # PNR (MEDIUM) · skip en HTML (usualmente son IDs CSS/JS)
        if not is_html:
            for m in _PNR_RE.finditer(line):
                val = m.group(1)
                # Heurística · debe aparecer con keyword PNR / locator cerca
                ctx = line.lower()
                if "pnr" in ctx or "locator" in ctx or "record" in ctx:
                    _add("pnr", idx, val, line_stripped,
                         "MEDIUM",
                         "PNR locator en runtime data · PII viaje · enmascarar")
        # Emails (MEDIUM · solo en runtime data, no en código)
        for m in _EMAIL_RE.finditer(line):
            email = m.group(1)
            # skip "from:" / "to:" fields en logs son más INFO que MEDIUM
            _add("email", idx, email, line_stripped,
                 "MEDIUM",
                 "Email address en runtime data · PII · revisar scope")
        # Teléfono MX (MEDIUM) · pattern muy prone a FP · requiere hint
        if any(k in line.lower() for k in ("tel", "phone", "celular", "móvil", "movil")):
            for m in _PHONE_MX_RE.finditer(line):
                full = "".join(g for g in m.groups() if g)
                if len(full) < 8:
                    continue
                _add("phone", idx, _redact(full, 2), line_stripped,
                     "MEDIUM",
                     "Número telefónico en runtime data · PII · enmascarar")
        # Private IP (INFO)
        for m in _PRIVATE_IP_RE.finditer(line):
            _add("private_ip", idx, m.group(1), line_stripped,
                 "INFO",
                 "IP privada expuesta en runtime data · revisar si es intencional")

    return findings


class RuntimeDataScanner:
    """Entry point · scan runtime data files for PII / secrets leaks."""

    def __init__(
        self,
        root: Path,
        exclude_dirs: Optional[set[str]] = None,
        include_exts: Optional[set[str]] = None,
        max_file_bytes: int = _MAX_FILE_BYTES,
    ):
        self.root = Path(root).resolve()
        self.exclude_dirs = exclude_dirs or _DEFAULT_EXCLUDES
        self.include_exts = include_exts or _RUNTIME_EXTS
        self.max_file_bytes = max_file_bytes

    def scan(self) -> RuntimeDataReport:
        report = RuntimeDataReport(root=str(self.root))
        if not self.root.exists():
            return report
        for path in self.root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in self.exclude_dirs for part in path.parts):
                continue
            if not _is_runtime_data_file(path):
                continue
            try:
                if path.stat().st_size > self.max_file_bytes:
                    content = path.read_bytes()[:self.max_file_bytes].decode(
                        "utf-8", errors="ignore"
                    )
                else:
                    content = path.read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue
            report.files_scanned += 1
            report.findings.extend(_scan_content(path, content))
        return report


def scan_runtime_data(root: Path) -> RuntimeDataReport:
    """Convenience · alias del constructor + scan()."""
    return RuntimeDataScanner(root).scan()
