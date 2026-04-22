"""Cross-Copy Drift Detector · v2.2.0 · RFC-004a + RFC-004b

Detecta divergencias entre 2 copias del mismo servicio (source-tree vs
build-output vs prod-deployed). Captura 2 clases de findings que
ningún SAST comercial automatiza:

RFC-004a · CROSS-COPY-DRIFT
- Target framework distinto entre source y build
- Endpoints / cert paths / dist lists divergentes
- Versiones de paquetes NuGet/pip/npm desincronizadas
- Feature flags con valores diferentes

RFC-004b · CREDENTIAL-BYTE-IDENTITY
- Password/secret/token/key **byte-idéntico** en prod y test configs
- Indica "test ambiente compartido" · clásico vector de breach
- Ningún SAST detecta esto automatizadamente

Uso canónico:
    detector = DriftDetector(root_a=Path(source), root_b=Path(build))
    findings = detector.detect()

CLI:
    aios drift --source ~/proj/source --compare ~/proj/build

Severity mapping:
- CRITICAL · credential byte-identity cross-environment
- HIGH · target framework / endpoint / cert drift
- MEDIUM · package version drift · config value drift
- INFO · whitespace / comment drift

Deriva de análisis NoShow real · 2026-04-22 · donde el análisis humano
detectó: target framework 4.7.2→4.6.1, UserName/Password divergentes,
Sabre cert paths distintos, DB AIDX password byte-idéntica en 3
ambientes, SFTP passphrase también idéntica. Nada de esto aparecía en
Mythos CWE scan estándar.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# Credential field names to flag for byte-identity (RFC-004b)
_CREDENTIAL_KEYS = (
    "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
    "api-key", "credential", "privatekey", "private_key", "private-key",
    "passphrase", "auth_token", "bearer_token", "access_key", "client_secret",
)


@dataclass
class KeyValue:
    """Key-value extraido de un config file."""
    file: str
    line: int
    key: str
    value: str
    is_credential: bool = False

    def value_hash(self) -> str:
        return hashlib.sha256(self.value.encode("utf-8")).hexdigest()[:16]


@dataclass
class DriftFinding:
    """Un finding de divergencia cross-copy."""
    kind: str  # credential_identity · framework_drift · endpoint_drift · value_drift · missing_key · ...
    severity: str  # CRITICAL · HIGH · MEDIUM · INFO
    key: str
    message: str
    file_a: str = ""
    file_b: str = ""
    value_a: str = ""
    value_b: str = ""
    # Extra context · ej. listar los 3+ archivos donde aparece el mismo hash
    extra_occurrences: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DriftReport:
    """Resultado completo del análisis."""
    root_a: str
    root_b: str
    file_pairs_matched: int = 0
    files_only_in_a: list[str] = field(default_factory=list)
    files_only_in_b: list[str] = field(default_factory=list)
    findings: list[DriftFinding] = field(default_factory=list)

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "root_a": self.root_a,
            "root_b": self.root_b,
            "file_pairs_matched": self.file_pairs_matched,
            "files_only_in_a": self.files_only_in_a,
            "files_only_in_b": self.files_only_in_b,
            "findings": [f.to_dict() for f in self.findings],
            "by_severity": self.by_severity(),
        }


# ---------------------------------------------------------------------------
# Config parsers · extract key-value pairs per language
# ---------------------------------------------------------------------------

def _parse_xml_config(path: Path) -> list[KeyValue]:
    """Parser para Web.config · App.config · appSettings.config (.NET)."""
    out: list[KeyValue] = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return out
    lines = content.splitlines()
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        # Parser fallback por line · busca <add key="..." value="..."/>
        return _parse_xml_regex(content, str(path))

    def walk(elem, parent_path=""):
        tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        # <add key="X" value="Y"/> pattern
        if tag == "add" and "key" in elem.attrib:
            key = elem.attrib.get("key", "")
            val = elem.attrib.get("value", "")
            line = _find_line_for_pattern(lines, f'key="{key}"')
            out.append(KeyValue(
                file=str(path), line=line, key=key, value=val,
                is_credential=_is_credential_key(key),
            ))
        # Attribute-based configs · connectionString, ...
        for attr_key, attr_val in elem.attrib.items():
            if attr_key in ("name", "key") or not attr_val:
                continue
            full_key = f"{parent_path}.{tag}.@{attr_key}" if parent_path else f"{tag}.@{attr_key}"
            line = _find_line_for_pattern(lines, f'{attr_key}="{attr_val[:30]}')
            out.append(KeyValue(
                file=str(path), line=line, key=full_key, value=attr_val,
                is_credential=_is_credential_key(attr_key) or _is_credential_key(full_key),
            ))
        # Recurse
        new_parent = f"{parent_path}.{tag}" if parent_path else tag
        for child in elem:
            walk(child, new_parent)

    walk(root)
    return out


def _parse_xml_regex(content: str, file: str) -> list[KeyValue]:
    """Regex fallback si XML parse falla (XML malformed · comments con <)."""
    out: list[KeyValue] = []
    # <add key="..." value="..."/>
    pat = re.compile(
        r'<add\s+key\s*=\s*["\']([^"\']+)["\']\s+value\s*=\s*["\']([^"\']*)["\']',
        re.IGNORECASE,
    )
    for m in pat.finditer(content):
        line_no = content.count("\n", 0, m.start()) + 1
        out.append(KeyValue(
            file=file, line=line_no, key=m.group(1), value=m.group(2),
            is_credential=_is_credential_key(m.group(1)),
        ))
    return out


def _parse_json_config(path: Path) -> list[KeyValue]:
    """Parser para appsettings.json · package.json · manifest.json."""
    out: list[KeyValue] = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(content)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return out
    lines = content.splitlines()

    def walk(obj, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                full_key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    walk(v, full_key)
                else:
                    line = _find_line_for_pattern(lines, f'"{k}"')
                    out.append(KeyValue(
                        file=str(path), line=line, key=full_key,
                        value=str(v),
                        is_credential=_is_credential_key(k) or _is_credential_key(full_key),
                    ))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                walk(item, f"{prefix}[{i}]")

    walk(data)
    return out


def _parse_csproj(path: Path) -> list[KeyValue]:
    """Parser específico de .csproj · extrae TargetFramework + PackageReferences."""
    out: list[KeyValue] = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return out
    lines = content.splitlines()
    # TargetFramework
    m = re.search(r"<TargetFramework>([^<]+)</TargetFramework>", content)
    if m:
        line = _find_line_for_pattern(lines, "<TargetFramework>")
        out.append(KeyValue(
            file=str(path), line=line, key="TargetFramework",
            value=m.group(1).strip(),
        ))
    # TargetFrameworks (multi)
    m = re.search(r"<TargetFrameworks>([^<]+)</TargetFrameworks>", content)
    if m:
        line = _find_line_for_pattern(lines, "<TargetFrameworks>")
        out.append(KeyValue(
            file=str(path), line=line, key="TargetFrameworks",
            value=m.group(1).strip(),
        ))
    # PackageReference · <PackageReference Include="X" Version="Y" />
    for m in re.finditer(
        r'<PackageReference\s+Include\s*=\s*["\']([^"\']+)["\']\s+Version\s*=\s*["\']([^"\']+)["\']',
        content,
    ):
        line = content.count("\n", 0, m.start()) + 1
        out.append(KeyValue(
            file=str(path), line=line,
            key=f"PackageReference.{m.group(1)}",
            value=m.group(2),
        ))
    return out


def _parse_yaml_config(path: Path) -> list[KeyValue]:
    """Parser de YAML · requiere PyYAML · graceful degrade si no disponible."""
    out: list[KeyValue] = []
    try:
        import yaml as _yaml
    except ImportError:
        return out
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        data = _yaml.safe_load(content)
    except Exception:  # noqa: BLE001
        return out
    if not isinstance(data, (dict, list)):
        return out
    lines = content.splitlines()

    def walk(obj, prefix=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                full_key = f"{prefix}.{k}" if prefix else str(k)
                if isinstance(v, (dict, list)):
                    walk(v, full_key)
                else:
                    line = _find_line_for_pattern(lines, f"{k}:")
                    out.append(KeyValue(
                        file=str(path), line=line, key=full_key,
                        value=str(v) if v is not None else "",
                        is_credential=_is_credential_key(str(k)) or _is_credential_key(full_key),
                    ))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                walk(item, f"{prefix}[{i}]")

    walk(data)
    return out


def _is_credential_key(key: str) -> bool:
    """True si el key sugiere credencial sensible."""
    if not key:
        return False
    lower = key.lower()
    return any(k in lower for k in _CREDENTIAL_KEYS)


def _find_line_for_pattern(lines: list[str], pattern: str) -> int:
    """Encuentra la primera línea que contiene el pattern · 1 si no encuentra."""
    for i, ln in enumerate(lines, 1):
        if pattern in ln:
            return i
    return 1


def _parse_config(path: Path) -> list[KeyValue]:
    """Dispatch · retorna KVs según el tipo de archivo."""
    suffix = path.suffix.lower()
    if suffix == ".csproj":
        return _parse_csproj(path)
    if suffix in (".config", ".xml"):
        return _parse_xml_config(path)
    if suffix == ".json":
        return _parse_json_config(path)
    if suffix in (".yaml", ".yml"):
        return _parse_yaml_config(path)
    return []


# ---------------------------------------------------------------------------
# File pairing · fuzzy match entre root_a y root_b
# ---------------------------------------------------------------------------

_DEFAULT_EXCLUDES = {
    "bin", "obj", ".vs", ".git", ".github", "node_modules",
    "__pycache__", "packages", "libs", "dist", "build",
}
_CONFIG_EXTS = {".config", ".xml", ".json", ".yaml", ".yml", ".csproj"}


def _collect_config_files(root: Path,
                          exclude_dirs: Optional[set[str]] = None,
                          include_exts: Optional[set[str]] = None) -> dict[str, Path]:
    """Recolecta archivos config del root. Key = nombre base (sin path) para
    facilitar matching fuzzy entre 2 roots con estructuras distintas."""
    excludes = exclude_dirs or _DEFAULT_EXCLUDES
    exts = include_exts or _CONFIG_EXTS
    results: dict[str, list[Path]] = {}
    if not root.exists():
        return {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in excludes for part in path.parts):
            continue
        if path.suffix.lower() not in exts:
            continue
        # Key = nombre sin extensión "normalizado" (trim _test, .exe, etc)
        base = path.stem
        base_norm = re.sub(r"(_test|_prod|_qa|_dev|\.exe|\.dll)$", "",
                           base, flags=re.IGNORECASE)
        results.setdefault(base_norm.lower(), []).append(path)
    # Flatten · primer match por key (simplicidad · v2.2)
    flat: dict[str, Path] = {}
    for k, paths in results.items():
        flat[k] = paths[0]  # TODO v2.3 · manejar multi-match con ranking
    return flat


def _pair_files(files_a: dict[str, Path],
                files_b: dict[str, Path]) -> tuple[list[tuple[Path, Path]], list[Path], list[Path]]:
    """Retorna (pairs, only_in_a, only_in_b)."""
    pairs: list[tuple[Path, Path]] = []
    keys_a = set(files_a)
    keys_b = set(files_b)
    for k in keys_a & keys_b:
        pairs.append((files_a[k], files_b[k]))
    only_a = [files_a[k] for k in keys_a - keys_b]
    only_b = [files_b[k] for k in keys_b - keys_a]
    return pairs, only_a, only_b


# ---------------------------------------------------------------------------
# Diff engine · compara 2 key-value lists y emite DriftFindings
# ---------------------------------------------------------------------------

def _diff_kv_lists(a_kvs: list[KeyValue],
                   b_kvs: list[KeyValue]) -> list[DriftFinding]:
    """Compara keys/values entre 2 archivos y emite drifts."""
    findings: list[DriftFinding] = []
    a_map = {kv.key: kv for kv in a_kvs}
    b_map = {kv.key: kv for kv in b_kvs}
    for key, kv_a in a_map.items():
        if key not in b_map:
            findings.append(DriftFinding(
                kind="missing_key_in_b",
                severity="INFO",
                key=key,
                file_a=kv_a.file, file_b="",
                value_a=kv_a.value, value_b="",
                message=f"Key '{key}' existe en A pero no en B",
            ))
            continue
        kv_b = b_map[key]
        if kv_a.value != kv_b.value:
            severity = _severity_for_drift(key, kv_a.value, kv_b.value)
            findings.append(DriftFinding(
                kind=_kind_for_drift(key),
                severity=severity,
                key=key,
                file_a=kv_a.file, file_b=kv_b.file,
                value_a=kv_a.value[:120], value_b=kv_b.value[:120],
                message=f"'{key}' difiere · A={kv_a.value[:50]} · B={kv_b.value[:50]}",
            ))
    # Keys solo en B
    for key in set(b_map) - set(a_map):
        kv_b = b_map[key]
        findings.append(DriftFinding(
            kind="missing_key_in_a",
            severity="INFO",
            key=key,
            file_a="", file_b=kv_b.file,
            value_a="", value_b=kv_b.value,
            message=f"Key '{key}' existe en B pero no en A",
        ))
    return findings


def _severity_for_drift(key: str, val_a: str, val_b: str) -> str:
    """Asigna severity según el tipo de drift detectado."""
    key_lower = key.lower()
    # Target framework · endpoint · cert · auth
    if any(k in key_lower for k in (
        "targetframework", "targetframeworks",
    )):
        return "HIGH"
    if any(k in key_lower for k in (
        "endpoint", "baseurl", "base_url", "apiurl", "api_url",
        "host", "server",
    )):
        return "HIGH"
    if any(k in key_lower for k in (
        "cert", "certificate", "cacert", "ca_cert",
    )):
        return "HIGH"
    # Package version drift
    if "packagereference." in key_lower or "dependency." in key_lower:
        return "MEDIUM"
    return "MEDIUM"


def _kind_for_drift(key: str) -> str:
    """Classification del drift por key name."""
    key_lower = key.lower()
    if "targetframework" in key_lower:
        return "framework_drift"
    if any(k in key_lower for k in ("endpoint", "baseurl", "apiurl", "host", "server")):
        return "endpoint_drift"
    if any(k in key_lower for k in ("cert", "certificate")):
        return "cert_drift"
    if "packagereference." in key_lower:
        return "package_version_drift"
    return "value_drift"


# ---------------------------------------------------------------------------
# RFC-004b · Credential byte-identity detector
# ---------------------------------------------------------------------------

def _detect_credential_identity(all_kvs: list[KeyValue]) -> list[DriftFinding]:
    """Detecta credenciales byte-idénticas entre 2+ archivos.

    RFC-004b · CRITICAL finding · indica 'test ambiente compartido'.
    """
    findings: list[DriftFinding] = []
    cred_kvs = [kv for kv in all_kvs if kv.is_credential and kv.value]
    # Skip valores que son referencias (ARN · env var · placeholder)
    filtered: list[KeyValue] = []
    for kv in cred_kvs:
        v = kv.value.strip()
        if not v or len(v) < 4:
            continue
        if v.startswith(("arn:aws:", "${", "@Microsoft.KeyVault", "{{ssm:",
                         "ssm://", "aws-secret://", "<!--", "*", "?",
                         "CHANGE_ME", "REPLACE")):
            continue
        filtered.append(kv)
    # Agrupa por value hash
    by_hash: dict[str, list[KeyValue]] = {}
    for kv in filtered:
        by_hash.setdefault(kv.value_hash(), []).append(kv)
    # Emite finding por cada hash compartido en 2+ archivos
    for h, kvs in by_hash.items():
        if len(kvs) < 2:
            continue
        files = set(kv.file for kv in kvs)
        if len(files) < 2:
            continue  # duplicado en mismo archivo · no es cross-env
        # Heurística · si alguno de los files es "test" y otro "prod", CRITICAL
        file_names = [Path(kv.file).name.lower() for kv in kvs]
        is_cross_env = any(
            "test" in n or "qa" in n or "staging" in n for n in file_names
        ) and any(
            "prod" in n or "production" in n or (
                "test" not in n and "qa" not in n and "staging" not in n
            )
            for n in file_names
        )
        severity = "CRITICAL" if is_cross_env else "HIGH"
        findings.append(DriftFinding(
            kind="credential_byte_identity",
            severity=severity,
            key=kvs[0].key,
            file_a=kvs[0].file,
            file_b=kvs[1].file if len(kvs) > 1 else "",
            value_a=f"<redacted · hash={h}>",
            value_b=f"<redacted · hash={h}>",
            message=(
                f"Credencial '{kvs[0].key}' byte-idéntica en {len(kvs)} "
                f"archivos ({len(files)} distintos) · "
                + ("CROSS-ENVIRONMENT (prod + test) · rotar + separar"
                   if is_cross_env else
                   "duplicación · considerar Secrets Manager")
            ),
            extra_occurrences=[
                {"file": kv.file, "line": kv.line, "key": kv.key}
                for kv in kvs
            ],
        ))
    return findings


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------

class DriftDetector:
    """Entry point · detecta drift entre 2 roots."""

    def __init__(self, root_a: Path, root_b: Path,
                 exclude_dirs: Optional[set[str]] = None):
        self.root_a = Path(root_a).resolve()
        self.root_b = Path(root_b).resolve()
        self.exclude_dirs = exclude_dirs or _DEFAULT_EXCLUDES

    def detect(self) -> DriftReport:
        """Run detection · retorna reporte completo."""
        report = DriftReport(
            root_a=str(self.root_a),
            root_b=str(self.root_b),
        )
        files_a = _collect_config_files(self.root_a, self.exclude_dirs)
        files_b = _collect_config_files(self.root_b, self.exclude_dirs)
        pairs, only_a, only_b = _pair_files(files_a, files_b)
        report.file_pairs_matched = len(pairs)
        report.files_only_in_a = [str(p.relative_to(self.root_a)) for p in only_a]
        report.files_only_in_b = [str(p.relative_to(self.root_b)) for p in only_b]

        # Para cada par · diff kv + collect all KVs para credential identity
        all_kvs: list[KeyValue] = []
        for path_a, path_b in pairs:
            kvs_a = _parse_config(path_a)
            kvs_b = _parse_config(path_b)
            all_kvs.extend(kvs_a)
            all_kvs.extend(kvs_b)
            report.findings.extend(_diff_kv_lists(kvs_a, kvs_b))

        # Credentials de archivos unicos (solo en A o solo en B) también
        # participan del byte-identity check · se cruzan con los pair-kvs
        for path in only_a + only_b:
            all_kvs.extend(_parse_config(path))

        # RFC-004b · credential byte-identity cross-file
        report.findings.extend(_detect_credential_identity(all_kvs))

        return report


def detect_drift(root_a: Path, root_b: Path) -> DriftReport:
    """Convenience function · alias del constructor + detect()."""
    return DriftDetector(root_a, root_b).detect()
