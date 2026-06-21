"""
AIOS · AM-KIRO bridge · simula el CLI oficial am-kiro mientras no hay acceso al repo OYN-ACME/am-kiro.

Funciones:
    install(pack_name) · instala pack (lee manifest · resuelve DAG · copia archivos a .kiro/)
    remove(pack_name) · limpia archivos instalados usando registry
    list_packs() · packs disponibles + instalados
    status() · verifica archivos instalados y consistencia
    outdated() · compara versiones instaladas vs disponibles

Sigue el contrato visto en la slide 135735 del 20-abr · manifest.json + dependencies DAG + .am-kiro-registry.json.
"""
from __future__ import annotations
import json
import shutil
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Set


REGISTRY_FILENAME = ".am-kiro-registry.json"
KIRO_DIRECTORY = ".kiro"
MANIFEST_FILENAME = "manifest.json"


class AmKiroBridge:
    """Bridge entre AIOS y el modelo Plugin/Pack de AM-KIRO."""

    def __init__(self, project_root: Path, pack_sources: Optional[List[Path]] = None):
        """
        project_root: directorio del proyecto target (ej. NoShow workspace)
        pack_sources: lista de directorios donde buscar packs (ej. aios-framework/)
        """
        self.project_root = Path(project_root).resolve()
        self.kiro_dir = self.project_root / KIRO_DIRECTORY
        self.registry_path = self.project_root / REGISTRY_FILENAME
        self.pack_sources = [Path(p).resolve() for p in (pack_sources or [])]

    # ------------------------------------------------------------------
    # Registry management
    # ------------------------------------------------------------------
    def _load_registry(self) -> dict:
        if not self.registry_path.exists():
            return {"schema_version": 1, "packs": {}}
        return json.loads(self.registry_path.read_text(encoding="utf-8"))

    def _save_registry(self, data: dict) -> None:
        self.registry_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    # ------------------------------------------------------------------
    # Pack discovery
    # ------------------------------------------------------------------
    def _find_pack(self, pack_name: str) -> Optional[Path]:
        """Busca un pack en las fuentes configuradas."""
        for source in self.pack_sources:
            manifest = source / MANIFEST_FILENAME
            if manifest.exists():
                data = json.loads(manifest.read_text(encoding="utf-8"))
                if data.get("name") == pack_name:
                    return source
            # buscar también en subcarpetas (ej. packs/<pack>/manifest.json)
            for candidate in source.rglob(MANIFEST_FILENAME):
                try:
                    data = json.loads(candidate.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if data.get("name") == pack_name:
                    return candidate.parent
        return None

    def _read_manifest(self, pack_root: Path) -> dict:
        return json.loads((pack_root / MANIFEST_FILENAME).read_text(encoding="utf-8"))

    # ------------------------------------------------------------------
    # DAG resolution
    # ------------------------------------------------------------------
    # Packs marked as virtual · provided by the am-kiro host · never loaded from sources
    VIRTUAL_PACKS = {"core"}

    def _resolve_dag(self, pack_name: str, visited: Optional[Set[str]] = None) -> List[str]:
        """Resuelve dependencias topológicamente · detecta ciclos · omite packs virtuales."""
        visited = visited or set()
        if pack_name in visited:
            raise ValueError(f"Dependency cycle detected including '{pack_name}'")
        visited = visited | {pack_name}

        if pack_name in self.VIRTUAL_PACKS:
            return [pack_name]  # virtual · provided by host · no file copy needed

        pack_root = self._find_pack(pack_name)
        if pack_root is None:
            raise FileNotFoundError(f"Pack '{pack_name}' not found in sources")
        manifest = self._read_manifest(pack_root)
        deps = manifest.get("dependencies", [])

        order: List[str] = []
        for dep in deps:
            order.extend(d for d in self._resolve_dag(dep, visited) if d not in order)
        if pack_name not in order:
            order.append(pack_name)
        return order

    # ------------------------------------------------------------------
    # Install / remove
    # ------------------------------------------------------------------
    def install(self, pack_name: str, force: bool = False) -> dict:
        """Instala pack + dependencias. Retorna reporte."""
        self.kiro_dir.mkdir(exist_ok=True)
        (self.kiro_dir / "steering").mkdir(exist_ok=True)
        (self.kiro_dir / "hooks").mkdir(exist_ok=True)
        (self.kiro_dir / "settings").mkdir(exist_ok=True)

        order = self._resolve_dag(pack_name)
        registry = self._load_registry()
        report = {"installed": [], "skipped": [], "errors": []}

        for name in order:
            if name == "core" and not self._find_pack("core"):
                # core es virtual · no falla si no existe · AM-KIRO lo provee
                report["skipped"].append({"pack": "core", "reason": "virtual · provided by am-kiro host"})
                continue
            if name in registry["packs"] and not force:
                report["skipped"].append({"pack": name, "reason": "already installed (use force=True)"})
                continue
            try:
                files_installed = self._install_pack_files(name)
                pack_root = self._find_pack(name)
                manifest = self._read_manifest(pack_root) if pack_root else {}
                registry["packs"][name] = {
                    "version": manifest.get("version"),
                    "source": str(pack_root) if pack_root else None,
                    "installed_files": files_installed,
                    "dependencies": manifest.get("dependencies", []),
                }
                report["installed"].append({"pack": name, "files": len(files_installed)})
            except Exception as e:
                report["errors"].append({"pack": name, "error": str(e)})
                break

        self._save_registry(registry)
        return report

    def _install_pack_files(self, pack_name: str) -> List[str]:
        pack_root = self._find_pack(pack_name)
        if pack_root is None:
            return []
        manifest = self._read_manifest(pack_root)
        includes = manifest.get("includes", {})
        installed: List[str] = []

        # Copy steering files
        for filename in includes.get("steering", []):
            src = pack_root / ".kiro" / "steering" / filename
            if not src.exists():
                # Buscar en ai-system/ o fuera de .kiro/
                for candidate in [pack_root / "ai-system" / filename, pack_root / filename]:
                    if candidate.exists():
                        src = candidate
                        break
            if src.exists():
                dst = self.kiro_dir / "steering" / f"{pack_name}__{filename}"
                shutil.copy(src, dst)
                installed.append(str(dst.relative_to(self.project_root)))

        # Copy hooks
        for filename in includes.get("hooks", []):
            src = pack_root / ".kiro" / "hooks" / filename
            if src.exists():
                dst = self.kiro_dir / "hooks" / f"{pack_name}__{filename}"
                shutil.copy(src, dst)
                installed.append(str(dst.relative_to(self.project_root)))

        # Copy settings (merge JSON)
        for filename in includes.get("settings", []):
            src = pack_root / ".kiro" / "settings" / filename
            if src.exists():
                dst = self.kiro_dir / "settings" / f"{pack_name}__{filename}"
                shutil.copy(src, dst)
                installed.append(str(dst.relative_to(self.project_root)))

        return installed

    def remove(self, pack_name: str) -> dict:
        """Limpia archivos instalados por el pack usando registry."""
        registry = self._load_registry()
        if pack_name not in registry["packs"]:
            return {"removed": [], "errors": [f"Pack '{pack_name}' not installed"]}

        files = registry["packs"][pack_name].get("installed_files", [])
        removed = []
        errors = []
        for rel_path in files:
            path = self.project_root / rel_path
            if path.exists():
                try:
                    path.unlink()
                    removed.append(rel_path)
                except Exception as e:
                    errors.append(f"{rel_path}: {e}")

        del registry["packs"][pack_name]
        self._save_registry(registry)
        return {"removed": removed, "errors": errors}

    # ------------------------------------------------------------------
    # Listing / status
    # ------------------------------------------------------------------
    def list_packs(self) -> dict:
        """Lista packs disponibles y instalados."""
        available = {}
        for source in self.pack_sources:
            manifest = source / MANIFEST_FILENAME
            if manifest.exists():
                try:
                    data = json.loads(manifest.read_text(encoding="utf-8"))
                    available[data["name"]] = {
                        "version": data.get("version"),
                        "source": str(source),
                        "description": data.get("description", ""),
                    }
                except Exception:
                    continue

        registry = self._load_registry()
        return {
            "available": available,
            "installed": registry.get("packs", {}),
        }

    def status(self) -> dict:
        """Verifica consistencia de archivos instalados."""
        registry = self._load_registry()
        report = {}
        for pack_name, info in registry.get("packs", {}).items():
            missing = []
            for rel_path in info.get("installed_files", []):
                if not (self.project_root / rel_path).exists():
                    missing.append(rel_path)
            report[pack_name] = {
                "version": info.get("version"),
                "total_files": len(info.get("installed_files", [])),
                "missing_files": missing,
                "consistent": len(missing) == 0,
            }
        return report

    def outdated(self) -> dict:
        """Compara versiones instaladas vs disponibles."""
        registry = self._load_registry()
        available = self.list_packs()["available"]
        outdated = {}
        for pack_name, installed_info in registry.get("packs", {}).items():
            if pack_name in available:
                installed_ver = installed_info.get("version")
                available_ver = available[pack_name].get("version")
                if installed_ver != available_ver:
                    outdated[pack_name] = {
                        "installed": installed_ver,
                        "available": available_ver,
                    }
        return outdated


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------
def main():
    import argparse
    parser = argparse.ArgumentParser(
        prog="aios-kiro",
        description="AIOS · AM-KIRO bridge · simula el CLI am-kiro localmente",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    for cmd in ["install", "remove"]:
        sp = subparsers.add_parser(cmd)
        sp.add_argument("pack")
        sp.add_argument("--project", default=".", help="Project root (default: cwd)")
        sp.add_argument("--source", action="append", help="Pack source directory (can repeat)", default=[])
        if cmd == "install":
            sp.add_argument("--force", action="store_true")

    for cmd in ["list", "status", "outdated"]:
        sp = subparsers.add_parser(cmd)
        sp.add_argument("--project", default=".")
        sp.add_argument("--source", action="append", default=[])

    args = parser.parse_args()
    sources = args.source or [Path.cwd()]
    bridge = AmKiroBridge(Path(args.project).resolve(), sources)

    if args.command == "install":
        result = bridge.install(args.pack, force=getattr(args, "force", False))
    elif args.command == "remove":
        result = bridge.remove(args.pack)
    elif args.command == "list":
        result = bridge.list_packs()
    elif args.command == "status":
        result = bridge.status()
    elif args.command == "outdated":
        result = bridge.outdated()
    else:
        result = {"error": f"Unknown command {args.command}"}

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
