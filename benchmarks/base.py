# benchmarks/base.py
"""Interfaz del benchmark independiente (sección 4.4 de la guía).

El controlador solo conoce esta interfaz. Únicamente el adaptador
concreto (benchmarks/vul4py.py) sabe cómo está organizado Vul4Py,
así que cambiar de benchmark no obliga a cambiar el controlador.
"""
from pathlib import Path
from typing import Protocol

from models import EvaluationResult


class BenchmarkAdapter(Protocol):
    def valid_cases(self) -> list[str]:
        """Devuelve los casos utilizables (en Vul4Py: estado OK en el scan)."""
        ...

    def vulnerable_dir(self, case_id: str) -> Path:
        """Devuelve la carpeta del código vulnerable (lo único que ve el LLM)."""
        ...

    def apply_patch(self, case_id: str, patch: str) -> EvaluationResult:
        """Aplica el parche congelado sin modificarlo (A_i) y crea el candidato."""
        ...

    def evaluate(self, case_id: str, candidate_dir: Path) -> EvaluationResult:
        """Ejecuta los oráculos de seguridad (S_i) y funcional (F_i) del benchmark."""
        ...
