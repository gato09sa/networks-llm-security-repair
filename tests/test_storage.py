# tests/test_storage.py
"""Pruebas de storage.py en carpetas temporales (datos sintéticos, NO resultados)."""
import csv
import json
import os

import pytest

from metrics import calculate_metrics
from models import AnalyzerResult, EvaluationResult, LLMResult
from storage import (
    RESULT_COLUMNS,
    export_case_artifacts,
    save_frozen_response,
    save_result_row,
)

LLM = LLMResult(True, 0.9, "--- a/x.py\n+++ b/x.py\n", '{"raw": true}', 1234.5, 100, 50)


def test_respuesta_congelada(tmp_path):
    path = save_frozen_response("CASO", LLM, model="m", timestamp="t",
                                api_success=True, runs_dir=tmp_path)
    data = json.loads(path.read_text())
    assert data["llm"]["claimed_success"] is True
    assert data["patch_sha256"]
    assert (tmp_path / "CASO" / "patch.diff").read_text() == LLM.patch
    # Solo lectura: no se puede escribir
    assert not os.access(path, os.W_OK) or os.geteuid() == 0
    # No se puede congelar dos veces el mismo caso
    with pytest.raises(FileExistsError):
        save_frozen_response("CASO", LLM, model="m", timestamp="t",
                             api_success=True, runs_dir=tmp_path)


def test_error_de_api_se_registra(tmp_path):
    path = save_frozen_response("CASO", None, model="m", timestamp="t",
                                api_success=False, error_type="RateLimitError",
                                runs_dir=tmp_path)
    data = json.loads(path.read_text())
    assert data["llm"] is None and data["error_type"] == "RateLimitError"
    assert not (tmp_path / "CASO" / "patch.diff").exists()


def test_fila_csv_y_metricas(tmp_path):
    csv_path = tmp_path / "results.csv"
    ev = EvaluationResult(True, False, True)
    save_result_row("A", LLM, ev, False, True, AnalyzerResult("semgrep", {"findings_before": 2, "findings_after": 1}),
                    model="m", timestamp="t", api_success=True, results_csv=csv_path)
    save_result_row("B", None, None, False, False, None,
                    model="m", timestamp="t", api_success=False, error_type="APITimeoutError",
                    results_csv=csv_path)
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == RESULT_COLUMNS
        rows = list(reader)
    assert rows[0]["semgrep_findings_before"] == "2"
    assert rows[1]["llm_claimed_success"] == ""      # desconocido: vacío, no inventado
    m = calculate_metrics(rows)
    assert m["N"] == 1 and m["api_errors"] == 1 and m["FAR"] == 1.0


def test_exportar_artefactos(tmp_path):
    runs, export = tmp_path / "runs", tmp_path / "export"
    save_frozen_response("CASO", LLM, model="m", timestamp="t",
                         api_success=True, runs_dir=runs)
    target = export_case_artifacts("CASO", runs_dir=runs, export_dir=export)
    assert sorted(p.name for p in target.iterdir()) == ["llm_response.json", "patch.diff"]
    # Exportar de nuevo no falla (las copias no son de solo lectura)
    export_case_artifacts("CASO", runs_dir=runs, export_dir=export)
