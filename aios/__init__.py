"""AIOS — AI Engineering Operating System.

v2.1.2 fix: lee __version__ dinámicamente de pyproject.toml via
importlib.metadata para evitar drift entre declaración y package.
Fallback hardcoded solo si el package no está instalado (dev local).
"""
from __future__ import annotations

try:
    from importlib.metadata import version as _pkg_version, PackageNotFoundError
    try:
        __version__ = _pkg_version("aios-kiro")
    except PackageNotFoundError:
        # Fallback · package aún no instalado (dev local fresh clone)
        __version__ = "3.7.2"
except ImportError:
    # Python < 3.8 fallback (no deberia ocurrir · requires-python >= 3.10)
    __version__ = "3.4.0"
