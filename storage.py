# storage.py
"""Persistencia de artefactos y resultados (secciones 4.7, 4.8 y 4.10 de la guía).

- save_frozen_response(): guarda llm_response.json y patch.diff ANTES de
  evaluar y los deja en solo lectura (respuesta congelada).
- save_result_row(): añade una fila inmutable a results/results.csv.
- export_case_artifacts(): copia los artefactos exigidos a results/cases/
  (runs/ no se sube a GitHub). Los originales no se modifican.
"""
import csv
import hashlib
import json
import shutil
import stat
from dataclasses import asdict
from pathlib import Path

from config import RESULTS_DIR, RUNS_DIR
from models import AnalyzerResult, EvaluationResult, LLMResult

RESULTS_CSV = RESULTS_DIR / "results.csv"
CASES_EXPORT_DIR = RESULTS_DIR / "cases"

# Columnas exigidas por la guía (sección 4.10), en este orden
RESULT_COLUMNS = [
    "case_id",
    "model",
    "timestamp",
    "llm_claimed_success",
    "llm_confidence",
    "patch_applied",
    "security_test_pass",
    "functional_test_pass",
    "verified_repair",
    "false_assurance",
    "latency_ms",
    "input_tokens",
    "output_tokens",
    "semgrep_findings_before",
    "semgrep_findings_after",
    "api_success",
    "error_type",
]


def _freeze(path: Path) -> None:
    """Deja el archivo en solo lectura (r--r--r--) para que no se modifique."""
    path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)


def save_frozen_response(
    case_id: str,
    llm: LLMResult | None,
    *,
    model: str,
    timestamp: str,
    api_success: bool,
    error_type: str | None = None,
    error_message: str | None = None,
    raw_response: str | None = None,
    runs_dir: Path = RUNS_DIR,
) -> Path:
    """Guarda y congela la respuesta del LLM de un caso.

    Si la API falló o la respuesta no pasó la validación, llm es None,
    pero se guarda igualmente el registro (y raw_response si existe).
    Nunca sobrescribe una respuesta ya congelada.
    """
    case_dir = runs_dir / case_id
    response_path = case_dir / "llm_response.json"
    if response_path.exists():
        raise FileExistsError(f"Ya existe una respuesta congelada: {response_path}")
    case_dir.mkdir(parents=True, exist_ok=True)

    record = {
        "case_id": case_id,
        "model": model,
        "timestamp": timestamp,
        "api_success": api_success,
        "error_type": error_type,
        "error_message": error_message,
        "llm": asdict(llm) if llm else None,
        "raw_response": llm.raw_response if llm else raw_response,
        "patch_sha256": None,
    }

    if llm is not None:
        patch_path = case_dir / "patch.diff"
        patch_path.write_text(llm.patch, encoding="utf-8")
        _freeze(patch_path)
        # Huella del parche: permite demostrar que no se modificó después
        record["patch_sha256"] = hashlib.sha256(llm.patch.encode("utf-8")).hexdigest()

    response_path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    _freeze(response_path)
    return response_path


def save_result_row(
    case_id: str,
    llm: LLMResult | None,
    evaluation: EvaluationResult | None,
    verified_repair: bool,
    false_assurance: bool,
    analyzer_result: AnalyzerResult | None,
    *,
    model: str,
    timestamp: str,
    api_success: bool,
    error_type: str | None = None,
    results_csv: Path = RESULTS_CSV,
) -> None:
    """Añade una fila a results.csv (crea el archivo con cabecera si no existe).

    Los valores desconocidos se dejan vacíos: nunca se inventan.
    """
    values = analyzer_result.values if analyzer_result else {}
    row = {
        "case_id": case_id,
        "model": model,
        "timestamp": timestamp,
        "llm_claimed_success": llm.claimed_success if llm else "",
        "llm_confidence": llm.confidence if llm else "",
        "patch_applied": evaluation.patch_applied if evaluation else "",
        "security_test_pass": evaluation.security_test_pass if evaluation else "",
        "functional_test_pass": evaluation.functional_test_pass if evaluation else "",
        "verified_repair": verified_repair,
        "false_assurance": false_assurance,
        "latency_ms": round(llm.latency_ms, 1) if llm else "",
        "input_tokens": llm.input_tokens if llm and llm.input_tokens is not None else "",
        "output_tokens": llm.output_tokens if llm and llm.output_tokens is not None else "",
        "semgrep_findings_before": values.get("findings_before", ""),
        "semgrep_findings_after": values.get("findings_after", ""),
        "api_success": api_success,
        "error_type": error_type or "",
    }

    results_csv.parent.mkdir(parents=True, exist_ok=True)
    new_file = not results_csv.exists()
    with open(results_csv, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=RESULT_COLUMNS)
        if new_file:
            writer.writeheader()
        writer.writerow(row)


def export_case_artifacts(
    case_id: str,
    extra_files: list[Path] | None = None,
    runs_dir: Path = RUNS_DIR,
    export_dir: Path = CASES_EXPORT_DIR,
) -> Path:
    """Copia los artefactos de un caso a una carpeta versionable.

    Copia patch.diff y llm_response.json desde runs/, y los archivos
    adicionales indicados (p. ej. eval.json, eval.log, salidas de Semgrep).
    """
    source = runs_dir / case_id
    target = export_dir / case_id
    target.mkdir(parents=True, exist_ok=True)
    files = [source / "patch.diff", source / "llm_response.json"] + list(extra_files or [])
    for path in files:
        if path.exists():
            # copyfile copia solo el contenido: la copia no hereda el modo solo lectura
            shutil.copyfile(path, target / path.name)
    return target
