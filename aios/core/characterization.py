"""Characterization Tests · v2.0.0 · RFC-003 Nivel 3

Behavior-preserving validation para refactors. Mecanismo:

1. **Pre-refactor capture**: extrae "behavior fingerprint" del archivo
   target (AST para Python · regex pragmático para C# · Java · PHP ·
   COBOL). Guarda en `.aios/characterization/<file-hash>.json`.

2. **Post-refactor verify**: re-ejecuta el mismo análisis sobre el
   archivo refactorizado · compara contra el fingerprint guardado ·
   clasifica delta según policy:
   - CRITICAL · method removed · signature changed · return type changed
   - WARN · new exception · modified visibility
   - INFO · added method · dependencies changed (non-breaking)

3. **Rollback trigger**: si hay CRITICAL delta → release_gate marca
   como fail · el refactor debe revertirse (git reset) antes de merge.

Diseño pragmático intencional:
- NO intentamos ejecutar código (sandbox · complejo · multi-lang)
- NO intentamos characterization tests "perfectos" (fuzzing · inputs)
- SI validamos contract/API estática · suficiente para 80% de casos
- Para behavior dinámico · dejamos hooks para v2.1+ (ejecutable subset)

Language support:
- python · AST module (built-in · preciso)
- csharp · regex heurístico (pragmático · cubre signatures públicos)
- java · regex heurístico
- php · regex heurístico
- cobol · regex (PROCEDURE DIVISION · PARAGRAPH · PROGRAM-ID)
- other · fallback file-hash only

Deriva de RFC-003 Nivel 3 · feedback LM-FRK70K: "que me asegura que el
refactor no sea generico · no lo detecte hasta el deploy".
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class MethodSig:
    """Signature publica observable de un method/function."""
    name: str
    args: list[str] = field(default_factory=list)  # list of "name: type" or just "name"
    return_type: str = ""
    visibility: str = "public"  # public · internal · private · protected
    is_async: bool = False
    is_static: bool = False
    decorators: list[str] = field(default_factory=list)  # Python · Java annotations
    raises: list[str] = field(default_factory=list)  # declared exceptions
    line: int = 0

    def canonical(self) -> str:
        """String canonico para comparar 2 signatures."""
        args_str = ",".join(self.args)
        async_str = "async " if self.is_async else ""
        static_str = "static " if self.is_static else ""
        return (
            f"{self.visibility} {static_str}{async_str}"
            f"{self.return_type} {self.name}({args_str})"
        )


@dataclass
class FieldSig:
    """Field/property/const publica observable."""
    name: str
    type_hint: str = ""
    visibility: str = "public"
    is_const: bool = False
    is_static: bool = False
    line: int = 0


@dataclass
class ClassSig:
    """Class/struct/interface observable."""
    name: str
    kind: str = "class"  # class · interface · struct · enum · module
    bases: list[str] = field(default_factory=list)
    line: int = 0


@dataclass
class BehaviorFingerprint:
    """Snapshot estático del behavior observable de un archivo."""
    file: str  # relative path
    language: str
    captured_at: str  # ISO 8601 UTC
    # Structural
    classes: list[ClassSig] = field(default_factory=list)
    methods: list[MethodSig] = field(default_factory=list)
    fields: list[FieldSig] = field(default_factory=list)
    # Dependencies
    imports: list[str] = field(default_factory=list)
    # Hashes
    ast_hash: str = ""  # hash estructural (sin whitespace ni nombres locales)
    source_hash: str = ""  # hash del source bruto (sanity check)
    # Stats
    line_count: int = 0
    complexity_markers: dict = field(default_factory=dict)  # "if_count", "loop_count"

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "language": self.language,
            "captured_at": self.captured_at,
            "classes": [asdict(c) for c in self.classes],
            "methods": [asdict(m) for m in self.methods],
            "fields": [asdict(f) for f in self.fields],
            "imports": list(self.imports),
            "ast_hash": self.ast_hash,
            "source_hash": self.source_hash,
            "line_count": self.line_count,
            "complexity_markers": self.complexity_markers,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BehaviorFingerprint":
        return cls(
            file=data.get("file", ""),
            language=data.get("language", ""),
            captured_at=data.get("captured_at", ""),
            classes=[ClassSig(**c) for c in data.get("classes", [])],
            methods=[MethodSig(**m) for m in data.get("methods", [])],
            fields=[FieldSig(**f) for f in data.get("fields", [])],
            imports=list(data.get("imports", [])),
            ast_hash=data.get("ast_hash", ""),
            source_hash=data.get("source_hash", ""),
            line_count=data.get("line_count", 0),
            complexity_markers=data.get("complexity_markers", {}),
        )


@dataclass
class Delta:
    """Un cambio individual detectado entre pre y post."""
    kind: str  # method_removed · method_added · signature_changed · return_changed · etc
    severity: str  # CRITICAL · WARN · INFO
    element: str  # name del elemento afectado
    pre: str = ""  # representación canonica pre
    post: str = ""  # representación canonica post
    message: str = ""


@dataclass
class VerifyResult:
    """Resultado de verificar behavior post-refactor vs baseline pre."""
    file: str
    passed: bool  # True si no hay CRITICAL deltas
    deltas: list[Delta] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for d in self.deltas:
            counts[d.severity] = counts.get(d.severity, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# Language detection + dispatch
# ---------------------------------------------------------------------------

_LANG_BY_EXT = {
    ".py": "python",
    ".cs": "csharp",
    ".java": "java",
    ".php": "php", ".phtml": "php",
    ".cbl": "cobol", ".cob": "cobol", ".cpy": "cobol",
    ".ts": "typescript", ".tsx": "typescript",
    ".js": "javascript", ".jsx": "javascript",
}


def detect_language(file_path: Path) -> str:
    return _LANG_BY_EXT.get(file_path.suffix.lower(), "unknown")


def capture_file(file_path: Path, root: Optional[Path] = None) -> BehaviorFingerprint:
    """Entry point · captura fingerprint de un archivo single."""
    content = file_path.read_text(encoding="utf-8", errors="ignore")
    rel = str(file_path.relative_to(root)) if root else str(file_path)
    lang = detect_language(file_path)
    fp = BehaviorFingerprint(
        file=rel,
        language=lang,
        captured_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        line_count=len(content.splitlines()),
        source_hash=hashlib.sha1(content.encode("utf-8")).hexdigest()[:16],
    )
    if lang == "python":
        _capture_python(content, fp)
    elif lang == "csharp":
        _capture_csharp(content, fp)
    elif lang == "java":
        _capture_java(content, fp)
    elif lang == "php":
        _capture_php(content, fp)
    elif lang == "cobol":
        _capture_cobol(content, fp)
    # Compute AST hash (excluir detalles volátiles)
    fp.ast_hash = _compute_fingerprint_hash(fp)
    return fp


# ---------------------------------------------------------------------------
# Python (AST module · preciso)
# ---------------------------------------------------------------------------

def _capture_python(content: str, fp: BehaviorFingerprint) -> None:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    fp.imports.append(alias.name)
            else:
                module = node.module or ""
                for alias in node.names:
                    fp.imports.append(f"{module}.{alias.name}" if module else alias.name)
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            bases = [_ast_node_to_str(b) for b in node.bases]
            fp.classes.append(ClassSig(
                name=node.name, kind="class", bases=bases, line=node.lineno,
            ))
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fp.methods.append(_python_method_sig(item, node.name))
                elif isinstance(item, ast.Assign):
                    for target in item.targets:
                        if isinstance(target, ast.Name):
                            vis = "private" if target.id.startswith("_") else "public"
                            fp.fields.append(FieldSig(
                                name=f"{node.name}.{target.id}",
                                visibility=vis, line=item.lineno,
                            ))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fp.methods.append(_python_method_sig(node, ""))
    # Complexity markers (simple counts)
    fp.complexity_markers = {
        "if_count": sum(isinstance(n, ast.If) for n in ast.walk(tree)),
        "loop_count": sum(isinstance(n, (ast.For, ast.While)) for n in ast.walk(tree)),
        "try_count": sum(isinstance(n, ast.Try) for n in ast.walk(tree)),
    }


def _python_method_sig(node, class_name: str) -> MethodSig:
    args = []
    for arg in node.args.args:
        type_str = _ast_node_to_str(arg.annotation) if arg.annotation else ""
        args.append(f"{arg.arg}: {type_str}" if type_str else arg.arg)
    return_type = _ast_node_to_str(node.returns) if node.returns else ""
    decorators = [_ast_node_to_str(d) for d in node.decorator_list]
    is_async = isinstance(node, ast.AsyncFunctionDef)
    is_static = any("staticmethod" in d for d in decorators)
    vis = "private" if node.name.startswith("_") else "public"
    full_name = f"{class_name}.{node.name}" if class_name else node.name
    raises = _find_raises_python(node)
    return MethodSig(
        name=full_name, args=args, return_type=return_type,
        visibility=vis, is_async=is_async, is_static=is_static,
        decorators=decorators, raises=raises, line=node.lineno,
    )


def _find_raises_python(node) -> list[str]:
    raised: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Raise) and sub.exc is not None:
            raised.add(_ast_node_to_str(sub.exc).split("(")[0])
    return sorted(raised)


def _ast_node_to_str(node) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except (AttributeError, TypeError):
        return ""


# ---------------------------------------------------------------------------
# C# (regex heurístico · cubre signatures públicos suficientemente)
# ---------------------------------------------------------------------------

_CS_METHOD_RE = re.compile(
    r"^\s*(?P<vis>public|internal|protected|private)?\s*"
    r"(?P<modifiers>(?:static|async|virtual|override|abstract|sealed|\s)*)"
    r"(?P<return>[A-Za-z_][\w<>\[\],\s]*?)\s+"
    r"(?P<name>[A-Z][\w]*)\s*"
    r"\((?P<args>[^)]*)\)",
    re.MULTILINE,
)
_CS_CLASS_RE = re.compile(
    r"^\s*(?:public|internal|protected|private)?\s*"
    r"(?:static|abstract|sealed|\s)*"
    r"(class|interface|struct|enum|record)\s+"
    r"(?P<name>[\w]+)"
    r"(?:\s*:\s*(?P<bases>[^{]+))?",
    re.MULTILINE,
)
_CS_USING_RE = re.compile(r"^\s*using\s+(?:static\s+)?([\w.]+)\s*;", re.MULTILINE)
_CS_FIELD_RE = re.compile(
    r"^\s*(public|internal|protected|private)\s+"
    r"(?:(static|const|readonly)\s+)?"
    r"(?P<type>[\w<>\[\],\s]+?)\s+(?P<name>\w+)\s*[;=]",
    re.MULTILINE,
)


def _capture_csharp(content: str, fp: BehaviorFingerprint) -> None:
    for m in _CS_USING_RE.finditer(content):
        fp.imports.append(m.group(1))
    for m in _CS_CLASS_RE.finditer(content):
        bases = []
        if m.group("bases"):
            bases = [b.strip() for b in m.group("bases").split(",")]
        fp.classes.append(ClassSig(
            name=m.group("name"),
            kind=m.group(1),
            bases=bases,
            line=content[:m.start()].count("\n") + 1,
        ))
    for m in _CS_METHOD_RE.finditer(content):
        modifiers = (m.group("modifiers") or "").strip()
        args_raw = (m.group("args") or "").strip()
        args = [a.strip() for a in args_raw.split(",") if a.strip()] if args_raw else []
        fp.methods.append(MethodSig(
            name=m.group("name"),
            args=args,
            return_type=(m.group("return") or "").strip(),
            visibility=m.group("vis") or "internal",
            is_async="async" in modifiers,
            is_static="static" in modifiers,
            line=content[:m.start()].count("\n") + 1,
        ))
    for m in _CS_FIELD_RE.finditer(content):
        fp.fields.append(FieldSig(
            name=m.group("name"),
            type_hint=(m.group("type") or "").strip(),
            visibility=m.group(1),
            is_const=(m.group(2) or "").strip() == "const",
            is_static=(m.group(2) or "").strip() == "static",
            line=content[:m.start()].count("\n") + 1,
        ))
    fp.complexity_markers = {
        "if_count": len(re.findall(r"\bif\s*\(", content)),
        "loop_count": len(re.findall(r"\b(?:for|while|foreach)\s*\(", content)),
        "try_count": len(re.findall(r"\btry\s*\{", content)),
    }


# ---------------------------------------------------------------------------
# Java (regex heurístico similar a C#)
# ---------------------------------------------------------------------------

_JAVA_METHOD_RE = re.compile(
    r"^\s*(?P<vis>public|private|protected|default)?\s*"
    r"(?P<modifiers>(?:static|final|abstract|synchronized|\s)*)"
    r"(?P<return>[A-Za-z_][\w<>\[\],\s]*?)\s+"
    r"(?P<name>\w+)\s*\((?P<args>[^)]*)\)\s*(?:throws\s+(?P<throws>[\w,\s]+))?",
    re.MULTILINE,
)
_JAVA_CLASS_RE = re.compile(
    r"^\s*(?:public|private|protected)?\s*"
    r"(?:abstract|final|static|\s)*"
    r"(class|interface|enum|record)\s+(?P<name>\w+)"
    r"(?:\s+extends\s+(?P<extends>\w+))?"
    r"(?:\s+implements\s+(?P<implements>[\w,\s]+))?",
    re.MULTILINE,
)
_JAVA_IMPORT_RE = re.compile(r"^\s*import\s+(?:static\s+)?([\w.*]+)\s*;", re.MULTILINE)


def _capture_java(content: str, fp: BehaviorFingerprint) -> None:
    for m in _JAVA_IMPORT_RE.finditer(content):
        fp.imports.append(m.group(1))
    for m in _JAVA_CLASS_RE.finditer(content):
        bases: list[str] = []
        if m.group("extends"):
            bases.append(m.group("extends"))
        if m.group("implements"):
            bases.extend(b.strip() for b in m.group("implements").split(","))
        fp.classes.append(ClassSig(
            name=m.group("name"),
            kind=m.group(1),
            bases=bases,
            line=content[:m.start()].count("\n") + 1,
        ))
    for m in _JAVA_METHOD_RE.finditer(content):
        modifiers = (m.group("modifiers") or "").strip()
        args_raw = (m.group("args") or "").strip()
        args = [a.strip() for a in args_raw.split(",") if a.strip()] if args_raw else []
        raises = []
        if m.group("throws"):
            raises = [r.strip() for r in m.group("throws").split(",") if r.strip()]
        fp.methods.append(MethodSig(
            name=m.group("name"),
            args=args,
            return_type=(m.group("return") or "").strip(),
            visibility=m.group("vis") or "default",
            is_static="static" in modifiers,
            raises=raises,
            line=content[:m.start()].count("\n") + 1,
        ))
    fp.complexity_markers = {
        "if_count": len(re.findall(r"\bif\s*\(", content)),
        "loop_count": len(re.findall(r"\b(?:for|while)\s*\(", content)),
        "try_count": len(re.findall(r"\btry\s*\{", content)),
    }


# ---------------------------------------------------------------------------
# PHP (regex heurístico)
# ---------------------------------------------------------------------------

_PHP_METHOD_RE = re.compile(
    r"^\s*(?P<vis>public|private|protected)?\s*"
    r"(?P<modifiers>(?:static|final|abstract|\s)*)"
    r"function\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)"
    r"(?:\s*:\s*(?P<return>[\w|?\\]+))?",
    re.MULTILINE,
)
_PHP_CLASS_RE = re.compile(
    r"^\s*(?:abstract|final|\s)*"
    r"(class|interface|trait|enum)\s+(?P<name>\w+)"
    r"(?:\s+extends\s+(?P<extends>\w+))?"
    r"(?:\s+implements\s+(?P<implements>[\w,\s]+))?",
    re.MULTILINE,
)
_PHP_USE_RE = re.compile(r"^\s*use\s+([\w\\]+)\s*;", re.MULTILINE)


def _capture_php(content: str, fp: BehaviorFingerprint) -> None:
    for m in _PHP_USE_RE.finditer(content):
        fp.imports.append(m.group(1))
    for m in _PHP_CLASS_RE.finditer(content):
        bases: list[str] = []
        if m.group("extends"):
            bases.append(m.group("extends"))
        if m.group("implements"):
            bases.extend(b.strip() for b in m.group("implements").split(","))
        fp.classes.append(ClassSig(
            name=m.group("name"),
            kind=m.group(1),
            bases=bases,
            line=content[:m.start()].count("\n") + 1,
        ))
    for m in _PHP_METHOD_RE.finditer(content):
        modifiers = (m.group("modifiers") or "").strip()
        args_raw = (m.group("args") or "").strip()
        args = [a.strip() for a in args_raw.split(",") if a.strip()] if args_raw else []
        fp.methods.append(MethodSig(
            name=m.group("name"),
            args=args,
            return_type=(m.group("return") or "").strip(),
            visibility=m.group("vis") or "public",
            is_static="static" in modifiers,
            line=content[:m.start()].count("\n") + 1,
        ))


# ---------------------------------------------------------------------------
# COBOL (regex · PROGRAM-ID + PROCEDURE DIVISION + paragraph names)
# ---------------------------------------------------------------------------

_COBOL_PROGRAM_RE = re.compile(
    r"^\s*PROGRAM-ID\s*\.\s*(\S+?)\s*\.", re.MULTILINE | re.IGNORECASE
)
_COBOL_PARA_RE = re.compile(r"^\s{0,7}([A-Z][\w-]*)\s*\.", re.MULTILINE)


def _capture_cobol(content: str, fp: BehaviorFingerprint) -> None:
    for m in _COBOL_PROGRAM_RE.finditer(content):
        fp.classes.append(ClassSig(
            name=m.group(1),
            kind="program",
            line=content[:m.start()].count("\n") + 1,
        ))
    # Paragraphs as "methods" · label + line
    in_procedure = False
    for lineno, line in enumerate(content.splitlines(), 1):
        if "PROCEDURE DIVISION" in line.upper():
            in_procedure = True
            continue
        if not in_procedure:
            continue
        stripped = line.rstrip()
        m = _COBOL_PARA_RE.match(line)
        if m and not stripped.startswith("*"):
            name = m.group(1).upper()
            # Skip reserved words que aparecen como labels
            if name not in ("PROGRAM-ID", "AUTHOR", "DATE-WRITTEN",
                            "IDENTIFICATION", "ENVIRONMENT", "DATA",
                            "CONFIGURATION", "INPUT-OUTPUT", "FILE",
                            "WORKING-STORAGE", "LINKAGE", "PROCEDURE"):
                fp.methods.append(MethodSig(
                    name=name, visibility="public", line=lineno,
                ))


# ---------------------------------------------------------------------------
# Fingerprint hashing (stable across formatting changes)
# ---------------------------------------------------------------------------

def _compute_fingerprint_hash(fp: BehaviorFingerprint) -> str:
    """Hash estable que ignora whitespace · docstrings · implementacion."""
    material = {
        "classes": sorted(
            f"{c.kind}:{c.name}:{','.join(sorted(c.bases))}" for c in fp.classes
        ),
        "methods": sorted(m.canonical() for m in fp.methods),
        "fields": sorted(
            f"{f.visibility}:{f.type_hint}:{f.name}" for f in fp.fields
        ),
        "imports": sorted(fp.imports),
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True).encode("utf-8")
    ).hexdigest()[:20]


# ---------------------------------------------------------------------------
# Persistence · .aios/characterization/<file>.json
# ---------------------------------------------------------------------------

def _safe_name(file_rel: str) -> str:
    """Nombre de archivo seguro basado en el path relativo."""
    return (file_rel
            .replace("\\", "/")
            .replace("/", "__")
            .replace(":", "_"))


def save_fingerprint(fp: BehaviorFingerprint, root: Path) -> Path:
    """Guarda fingerprint · retorna el path."""
    out_dir = root / ".aios" / "characterization"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{_safe_name(fp.file)}.json"
    out_file.write_text(
        json.dumps(fp.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return out_file


def load_fingerprint(file_rel: str, root: Path) -> Optional[BehaviorFingerprint]:
    """Carga fingerprint previo · None si no existe."""
    path = root / ".aios" / "characterization" / f"{_safe_name(file_rel)}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return BehaviorFingerprint.from_dict(data)
    except (json.JSONDecodeError, OSError):
        return None


# ---------------------------------------------------------------------------
# Diff · Pre vs Post
# ---------------------------------------------------------------------------

def diff_fingerprints(
    pre: BehaviorFingerprint, post: BehaviorFingerprint,
) -> VerifyResult:
    """Compara pre vs post · emite deltas clasificados por severity."""
    deltas: list[Delta] = []

    # Method-level diff
    pre_methods = {m.name: m for m in pre.methods}
    post_methods = {m.name: m for m in post.methods}
    for name, m in pre_methods.items():
        # Solo public methods generan CRITICAL · private cambian OK
        is_public = m.visibility in ("public", "protected", "default")
        if name not in post_methods:
            deltas.append(Delta(
                kind="method_removed",
                severity="CRITICAL" if is_public else "INFO",
                element=name,
                pre=m.canonical(), post="",
                message=(
                    f"Method {name} fue REMOVIDO · breaking change de API"
                    if is_public else
                    f"Private method {name} fue removido (no-breaking)"
                ),
            ))
            continue
        post_m = post_methods[name]
        if m.canonical() != post_m.canonical():
            deltas.append(Delta(
                kind="signature_changed",
                severity="CRITICAL" if is_public else "WARN",
                element=name,
                pre=m.canonical(), post=post_m.canonical(),
                message=f"Signature cambió · {name}",
            ))
        # Exception contract
        if sorted(m.raises) != sorted(post_m.raises):
            added = set(post_m.raises) - set(m.raises)
            removed = set(m.raises) - set(post_m.raises)
            if added:
                deltas.append(Delta(
                    kind="exception_added",
                    severity="WARN",
                    element=name,
                    pre=",".join(sorted(m.raises)),
                    post=",".join(sorted(post_m.raises)),
                    message=f"Nueva excepcion levantada por {name}: {','.join(added)}",
                ))
            if removed:
                deltas.append(Delta(
                    kind="exception_removed",
                    severity="WARN",
                    element=name,
                    pre=",".join(sorted(m.raises)),
                    post=",".join(sorted(post_m.raises)),
                    message=f"Excepcion ya no se levanta en {name}: {','.join(removed)}",
                ))
    for name, m in post_methods.items():
        if name not in pre_methods:
            deltas.append(Delta(
                kind="method_added", severity="INFO",
                element=name, pre="", post=m.canonical(),
                message=f"Nuevo method · {name}",
            ))

    # Class-level diff
    pre_classes = {c.name: c for c in pre.classes}
    post_classes = {c.name: c for c in post.classes}
    for name, c in pre_classes.items():
        if name not in post_classes:
            deltas.append(Delta(
                kind="class_removed", severity="CRITICAL",
                element=name,
                message=f"Class/Interface/Program {name} REMOVIDO",
            ))
        else:
            post_c = post_classes[name]
            if set(c.bases) != set(post_c.bases):
                deltas.append(Delta(
                    kind="inheritance_changed", severity="WARN",
                    element=name,
                    pre=",".join(sorted(c.bases)),
                    post=",".join(sorted(post_c.bases)),
                    message=f"Herencia/interfaces de {name} cambio",
                ))
    for name in post_classes:
        if name not in pre_classes:
            deltas.append(Delta(
                kind="class_added", severity="INFO",
                element=name,
                message=f"Nuevo class/interface · {name}",
            ))

    # Field-level diff (solo public · cambio breaking)
    pre_fields = {f.name: f for f in pre.fields if f.visibility == "public"}
    post_fields = {f.name: f for f in post.fields if f.visibility == "public"}
    for name in pre_fields:
        if name not in post_fields:
            deltas.append(Delta(
                kind="public_field_removed", severity="CRITICAL",
                element=name,
                message=f"Field publico {name} removido · breaking",
            ))

    # Summary
    summary = {
        "pre_fingerprint": pre.ast_hash,
        "post_fingerprint": post.ast_hash,
        "ast_changed": pre.ast_hash != post.ast_hash,
        "line_delta": post.line_count - pre.line_count,
    }

    critical = sum(1 for d in deltas if d.severity == "CRITICAL")
    return VerifyResult(
        file=post.file,
        passed=critical == 0,
        deltas=deltas,
        summary=summary,
    )


def verify(file_path: Path, root: Path) -> Optional[VerifyResult]:
    """Verifica un archivo contra su baseline · None si no hay baseline."""
    rel = str(file_path.relative_to(root))
    pre = load_fingerprint(rel, root)
    if pre is None:
        return None
    post = capture_file(file_path, root)
    return diff_fingerprints(pre, post)
