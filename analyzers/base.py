# analyzers/base.py
"""Interfaz de los analizadores secundarios (sección 4.4 de la guía).

Un analizador (p. ej. Semgrep) solo aporta datos de diagnóstico.
Nunca decide verified_repair, VRR ni FAR.
"""
from pathlib import Path
from typing import Protocol

from models import AnalyzerResult


class Analyzer(Protocol):
    name: str

    def run(self, original_dir: Path, candidate_dir: Path | None) -> AnalyzerResult:
        """Analiza el código original y, si existe, el candidato parcheado."""
        ...
