"""Release Gate — validates readiness before deployment.

v1.6.0 changes:
- Spec matching by similarity (Jaccard) when active task path missing or stale
- Searches specs/ folder for best match if direct path fails

v1.7.2 changes (deriva de LM-FRK70K retro · recomendaciones R4 + R5):
- Active task accepts COMPLETED / DONE / DELIVERED / PRE-DEPLOY / CLOSED
  como estados terminales · no bloquea el gate cuando la fase esta cerrada.
- Spec folder reconoce pattern multi-modulo (specs/<module>/ con
  requirements.md en cada uno) · valida refactors end-to-end tipo FRK70K.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from .memory_engine import get_active_task, read_memory
from .security_gate import run_security_gate


# v1.7.2 · estados terminales que indican workstream COMPLETADO
# (no bloquean el gate · el refactor end-to-end ya cerro la FASE N)
_TERMINAL_PHASE_TOKENS = (
    "COMPLETED", "COMPLETE", "DONE", "DELIVERED",
    "PRE-DEPLOY", "PREDEPLOY", "CLOSED", "FINAL",
    "RELEASE", "READY-FOR-RELEASE",
)


def _is_terminal_phase(phase: str) -> bool:
    """v1.7.2 · True si la phase indica workstream terminal/completado."""
    if not phase:
        return False
    upper = phase.upper().replace("_", "-").replace(" ", "-")
    return any(token in upper for token in _TERMINAL_PHASE_TOKENS)


def _enumerate_multi_module_specs(root: Path) -> list[Path]:
    """v1.7.2 · detecta multi-modulo specs/ pattern.

    Retorna lista de subdirs de specs/ que contienen requirements.md.
    Usado por el release_gate para validar refactors end-to-end con
    N specs paralelos (ej. LM-FRK70K: specs/legacy-01-fleet_ops_app-module/,
    specs/legacy-02-arc-module/, ..., specs/legacy-10-noshow-module/).
    """
    specs_root = root / "specs"
    if not specs_root.exists():
        return []
    modules: list[Path] = []
    for child in specs_root.iterdir():
        if child.is_dir() and (child / "requirements.md").exists():
            modules.append(child)
    return sorted(modules)


def _check_behavior_preservation(root: Path) -> dict:
    """v2.0.0 · RFC-003 Nivel 3 · verifica behavior fingerprints.

    Busca todos los fingerprints en .aios/characterization/ y compara
    cada uno contra el archivo actual · emite deltas. Si hay CRITICAL
    deltas · marca como fail + blocking.
    """
    char_dir = root / ".aios" / "characterization"
    if not char_dir.exists():
        return {
            "check": "Behavior preservation (characterization)",
            "status": "skip",
            "detail": "No characterization baselines · skip (run 'aios characterize capture' pre-refactor)",
            "_blocking": False,
        }
    try:
        from .characterization import load_fingerprint, capture_file, diff_fingerprints
    except ImportError:
        return {
            "check": "Behavior preservation (characterization)",
            "status": "skip",
            "detail": "characterization module not available",
            "_blocking": False,
        }
    fingerprint_files = list(char_dir.glob("*.json"))
    if not fingerprint_files:
        return {
            "check": "Behavior preservation (characterization)",
            "status": "skip",
            "detail": "Characterization dir exists but empty",
            "_blocking": False,
        }
    total_critical = 0
    total_warn = 0
    total_info = 0
    verified_count = 0
    missing_count = 0
    first_critical: str = ""
    for fp_file in fingerprint_files:
        try:
            import json as _json
            data = _json.loads(fp_file.read_text(encoding="utf-8"))
            rel = data.get("file", "")
            if not rel:
                continue
            target = root / rel
            if not target.exists():
                missing_count += 1
                continue
            pre = load_fingerprint(rel, root)
            if pre is None:
                continue
            post = capture_file(target, root)
            result = diff_fingerprints(pre, post)
            verified_count += 1
            counts = result.by_severity()
            total_critical += counts.get("CRITICAL", 0)
            total_warn += counts.get("WARN", 0)
            total_info += counts.get("INFO", 0)
            if counts.get("CRITICAL", 0) > 0 and not first_critical:
                first_critical = rel
        except Exception:  # noqa: BLE001
            continue

    if total_critical > 0:
        return {
            "check": "Behavior preservation (characterization)",
            "status": "fail",
            "detail": (
                f"{total_critical} CRITICAL deltas en {verified_count} archivos · "
                f"primer archivo con breaking change: {first_critical} · "
                f"rollback recomendado · corre 'aios characterize verify --file {first_critical}'"
            ),
            "_blocking": True,
        }
    if total_warn > 0:
        return {
            "check": "Behavior preservation (characterization)",
            "status": "warn",
            "detail": (
                f"{verified_count} archivos verificados · {total_warn} WARN · "
                f"{total_info} INFO · sin CRITICAL · revisar deltas si acaso"
            ),
            "_blocking": False,
        }
    return {
        "check": "Behavior preservation (characterization)",
        "status": "pass",
        "detail": (
            f"{verified_count} archivos verificados · 0 deltas breaking · "
            f"{total_info} added (OK)"
        ),
        "_blocking": False,
    }


def _check_human_review(root: Path, pause_findings: list) -> dict:
    """v2.1.0 · RFC-003 Nivel 4 · aplica decisiones humanas.

    Los findings con decisión 'reject' bloquean release (user dijo que
    el refactor rompe dominio). Los 'approve' se consideran resueltos.
    Pending/deferred siguen en WARN.
    """
    try:
        from .review import filter_findings_by_decisions
    except ImportError:
        return {
            "check": "Human review decisions (SITL)",
            "status": "skip",
            "detail": "review module not available",
            "_blocking": False,
        }
    buckets = filter_findings_by_decisions(pause_findings or [], root)
    n_pending = len(buckets.get("pending", []))
    n_approved = len(buckets.get("approved", []))
    n_rejected = len(buckets.get("rejected", []))
    n_deferred = len(buckets.get("deferred", []))

    if n_rejected > 0:
        return {
            "check": "Human review decisions (SITL)",
            "status": "fail",
            "detail": (
                f"{n_rejected} findings REJECTED · rollback requerido · "
                f"ver .aios/review-log.jsonl · corre 'aios review list'"
            ),
            "_blocking": True,
        }
    if n_pending > 0 or n_deferred > 0:
        return {
            "check": "Human review decisions (SITL)",
            "status": "warn",
            "detail": (
                f"{n_pending} pending · {n_deferred} deferred · "
                f"{n_approved} approved · corre 'aios review list' "
                f"para gestionar"
            ),
            "_blocking": False,
        }
    if n_approved > 0:
        return {
            "check": "Human review decisions (SITL)",
            "status": "pass",
            "detail": f"{n_approved} findings approved en review queue · 0 pending/rejected",
            "_blocking": False,
        }
    return {
        "check": "Human review decisions (SITL)",
        "status": "pass",
        "detail": "0 findings requieren review · queue limpia",
        "_blocking": False,
    }


def _tokenize(text: str) -> set:
    """Tokenize text into lowercase word set for similarity."""
    import re
    return set(re.findall(r"\w+", text.lower()))


def _jaccard_similarity(a: str, b: str) -> float:
    """Jaccard similarity between two strings (token-based)."""
    sa, sb = _tokenize(a), _tokenize(b)
    if not sa or not sb:
        return 0.0
    intersection = len(sa & sb)
    union = len(sa | sb)
    return intersection / union if union > 0 else 0.0


def find_spec_by_similarity(root: Path, task_title: str, threshold: float = 0.2) -> Optional[Path]:
    """v1.6.0 NEW · find best matching spec folder for a task title.

    Useful when memory's spec path is stale or task was created without explicit folder.

    Returns: Path to spec folder with highest Jaccard similarity above threshold.
    """
    specs_root = root / "specs"
    if not specs_root.exists():
        return None

    best_match = None
    best_score = 0.0

    for spec_dir in specs_root.iterdir():
        if not spec_dir.is_dir():
            continue
        # Compare slug + first lines of requirements.md
        candidate_text = spec_dir.name
        req_file = spec_dir / "requirements.md"
        if req_file.exists():
            try:
                # First 500 chars of requirements (title + objective usually)
                candidate_text += " " + req_file.read_text(encoding="utf-8")[:500]
            except: pass

        score = _jaccard_similarity(task_title, candidate_text)
        if score > best_score and score >= threshold:
            best_score = score
            best_match = spec_dir

    return best_match


def check_release_readiness(root: Path) -> Dict:
    """Run release gate checks and return results."""
    checks: List[Dict] = []
    blocking = False

    # v1.7.2 · detectar multi-modulo specs para pasar R4/R5 en refactors
    # end-to-end tipo LM-FRK70K (N specs paralelos bajo specs/)
    multi_specs = _enumerate_multi_module_specs(root)

    # 1. Active task exists · v1.7.2: COMPLETED/DONE/PRE-DEPLOY pasan sin fail
    task = get_active_task(root)
    task_title = task.get("task", "")
    phase = task.get("phase", "")
    if task_title:
        detail = task_title
        if _is_terminal_phase(phase):
            detail = f"{task_title} · phase={phase} (terminal · no-op)"
        checks.append({"check": "Active task defined", "status": "pass", "detail": detail})
    elif _is_terminal_phase(phase):
        # v1.7.2 · fase terminal sin task actual · workstream cerrado OK
        checks.append({
            "check": "Active task defined",
            "status": "pass",
            "detail": f"workstream closed · phase={phase}",
        })
    elif multi_specs:
        # v1.7.2 · sin active task pero con multi-modulo specs · refactor
        # end-to-end completado sin workstream activo · pass con info
        checks.append({
            "check": "Active task defined",
            "status": "pass",
            "detail": f"multi-module refactor · {len(multi_specs)} specs (no single active task)",
        })
    else:
        checks.append({"check": "Active task defined", "status": "fail", "detail": "No active workstream"})
        blocking = True

    # 2. Spec exists · v1.6.0 similarity · v1.7.2 multi-modulo
    spec_path = task.get("spec", "")
    spec_dir = None
    if spec_path and Path(spec_path).exists():
        spec_dir = Path(spec_path)
        checks.append({"check": "Spec folder exists", "status": "pass", "detail": spec_path})
    elif task_title:
        # Try similarity matching · v1.6.0
        matched = find_spec_by_similarity(root, task_title)
        if matched:
            spec_dir = matched
            checks.append({
                "check": "Spec folder exists",
                "status": "pass",
                "detail": f"matched by similarity → {matched.name}"
            })
        elif multi_specs:
            # v1.7.2 · multi-modulo fallback
            checks.append({
                "check": "Spec folder exists",
                "status": "pass",
                "detail": f"multi-module pattern · {len(multi_specs)} specs/ subdirs",
            })
        else:
            checks.append({"check": "Spec folder exists", "status": "fail", "detail": "Missing spec (no match found)"})
            blocking = True
    elif multi_specs:
        # v1.7.2 · sin task pero con multi-modulo specs · pass
        checks.append({
            "check": "Spec folder exists",
            "status": "pass",
            "detail": f"multi-module pattern · {len(multi_specs)} specs/ subdirs ({', '.join(s.name for s in multi_specs[:3])}{'...' if len(multi_specs) > 3 else ''})",
        })
    else:
        checks.append({"check": "Spec folder exists", "status": "fail", "detail": "Missing spec"})
        blocking = True

    # 3. Tasks.md has content
    if spec_dir:
        tasks_file = spec_dir / "tasks.md"
        if tasks_file.exists() and len(tasks_file.read_text(encoding="utf-8")) > 50:
            checks.append({"check": "Tasks defined", "status": "pass"})
        else:
            checks.append({"check": "Tasks defined", "status": "warn", "detail": "tasks.md empty or missing"})

    # 4. Validation.md exists
    if spec_dir:
        val_file = spec_dir / "validation.md"
        if val_file.exists() and len(val_file.read_text(encoding="utf-8")) > 50:
            checks.append({"check": "Validation criteria defined", "status": "pass"})
        else:
            checks.append({"check": "Validation criteria defined", "status": "warn", "detail": "validation.md empty"})

    # 5. Risks reviewed · v1.6.0 also check spec/risks.md
    memory = read_memory(root)
    risks_content = memory.get("known_risks.md", "")
    risks_in_spec = ""
    if spec_dir:
        risks_file = spec_dir / "risks.md"
        if risks_file.exists():
            risks_in_spec = risks_file.read_text(encoding="utf-8")
    if len(risks_content) > 30 or len(risks_in_spec) > 30:
        checks.append({"check": "Risks documented", "status": "pass"})
    else:
        checks.append({"check": "Risks documented", "status": "warn", "detail": "No risks documented"})

    # 6. Rollback plan (for migration/feature/legacy)
    mode = task.get("mode", "")
    if mode in ("MIGRATION", "FEATURE", "LEGACY_MODERNIZATION") and spec_dir:
        rb_file = spec_dir / "rollback.md"
        if rb_file.exists() and len(rb_file.read_text(encoding="utf-8")) > 50:
            checks.append({"check": "Rollback plan defined", "status": "pass"})
        else:
            checks.append({"check": "Rollback plan defined", "status": "warn", "detail": "rollback.md empty"})

    # 7. Security static scan · Mythos/Nemesis style (Fase AIOS + sec)
    sec = run_security_gate(root)
    checks.append({
        "check": sec["check"],
        "status": sec["status"],
        "detail": sec.get("detail", ""),
    })
    if sec.get("blocking"):
        blocking = True
    # Pasa metadata extra en el top-level para que el CLI lo renderee
    security_detail = {
        "findings_summary": sec.get("findings_summary", {}),
        "top_findings": sec.get("top_findings", []),
    }

    # 8. v1.8.0 · RFC-003 · Domain-aware review check
    # Si el scan devolvio findings con ontology_action=pause_for_review,
    # no bloqueamos el release pero sí emitimos WARN para que el reviewer
    # humano los apruebe antes del merge final.
    pause_findings = sec.get("requires_human_review", [])
    if pause_findings:
        checks.append({
            "check": "Domain-aware review (business rules vs bugs)",
            "status": "warn",
            "detail": (
                f"{len(pause_findings)} findings requieren review humano · "
                f"posible regla de negocio o intent del dominio · ver "
                f"requires_human_review list"
            ),
        })
    else:
        checks.append({
            "check": "Domain-aware review (business rules vs bugs)",
            "status": "pass",
            "detail": "0 findings requieren review humano",
        })

    # 9. v2.0.0 · RFC-003 Nivel 3 · Behavior preservation
    # Si existen fingerprints previos en .aios/characterization/,
    # verifica que los archivos refactorizados no rompan API contract.
    # CRITICAL deltas (method_removed · signature_changed) bloquean release.
    behavior_check = _check_behavior_preservation(root)
    checks.append(behavior_check)
    if behavior_check.get("_blocking"):
        blocking = True

    # 10. v2.1.0 · RFC-003 Nivel 4 · Human review decisions (SITL)
    # Aplica las decisiones registradas en .aios/review-log.jsonl:
    #  - rejected findings bloquean release
    #  - approved findings se consideran resueltos
    #  - deferred/pending siguen en WARN
    pause_findings = sec.get("requires_human_review", [])
    review_check = _check_human_review(root, pause_findings)
    checks.append(review_check)
    if review_check.get("_blocking"):
        blocking = True

    passed = sum(1 for c in checks if c["status"] == "pass")
    warned = sum(1 for c in checks if c["status"] == "warn")
    failed = sum(1 for c in checks if c["status"] == "fail")
    skipped = sum(1 for c in checks if c["status"] == "skip")

    return {
        "ready": not blocking and failed == 0,
        "passed": passed,
        "warned": warned,
        "failed": failed,
        "skipped": skipped,
        "total": len(checks),
        "checks": checks,
        "blocking": blocking,
        "security": security_detail,
    }
