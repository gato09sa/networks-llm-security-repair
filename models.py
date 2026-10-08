# models.py
"""Contratos de datos del experimento (sección 4.4 de la guía).

Estas estructuras conectan los módulos sin acoplarlos entre sí:
el cliente LLM, el adaptador del benchmark y los analizadores
solo intercambian estos objetos.
"""
from dataclasses import dataclass
from pathlib import Path


@dataclass
class LLMResult:
    """Respuesta del LLM para un intento: (C_i, P_i, delta_i) y medidas de red."""
    claimed_success: bool               # C_i: el LLM afirma haber reparado la vulnerabilidad
    confidence: float                   # P_i: confianza autodeclarada, entre 0.0 y 1.0
    patch: str                          # delta_i: parche en formato unified diff
    raw_response: str                   # texto original de la API, sin modificar
    latency_ms: float                   # L_i: latencia extremo a extremo de la solicitud HTTPS
    input_tokens: int | None = None     # tokens enviados (si la API los reporta)
    output_tokens: int | None = None    # tokens generados (si la API los reporta)


@dataclass
class EvaluationResult:
    """Veredicto del benchmark independiente (Vul4Py) sobre el parche."""
    patch_applied: bool                 # A_i: el parche se aplicó sin errores
    security_test_pass: bool            # S_i: pasa el oráculo de seguridad (exploit test)
    functional_test_pass: bool          # F_i: pasa el oráculo funcional (baseline tests)
    candidate_dir: Path | None = None   # carpeta del proyecto parcheado (None si no aplicó)


@dataclass
class AnalyzerResult:
    """Resultado de un analizador secundario (p. ej. Semgrep). Solo diagnóstico."""
    name: str                           # nombre del analizador
    values: dict                        # campos normalizados, p. ej. hallazgos antes/después
