# tests/test_run_experiment.py
"""Prueba de extremo a extremo del controlador con LLM y benchmark FALSOS.

Comprueba el orden (congelar antes de evaluar), una sola llamada por caso
y el registro de errores. Son datos sintéticos, NO resultados del experimento.
"""
import json
from functools import partial

import pytest

import run_experiment
import storage
from benchmarks.base import BenchmarkError
from llm_client import LLMCallError
from metrics import calculate_metrics, load_rows
from models import EvaluationResult, LLMResult


class FakeBenchmark:
    def __init__(self, tmp_path, runs, verdicts):
        self.tmp_path, self.runs, self.verdicts = tmp_path, runs, verdicts

    def valid_cases(self):
        return list(self.verdicts)

    def vulnerable_dir(self, case_id):
        d = self.tmp_path / "ws" / case_id
        d.mkdir(parents=True, exist_ok=True)
        (d / "app.py").write_text("x = 1\n")
        return d

    def apply_patch(self, case_id, patch):
        # El parche ya debe estar congelado cuando se evalúa
        assert (self.runs / case_id / "patch.diff").read_text() == patch
        verdict = self.verdicts[case_id]
        if verdict == "infra":
            raise BenchmarkError("dependencia rota")
        (self.runs / case_id / "eval.json").write_text(json.dumps(verdict))
        return EvaluationResult(verdict[0], False, False, None)

    def evaluate(self, case_id, candidate_dir):
        a, s, f = self.verdicts[case_id]
        return EvaluationResult(a, s, f, candidate_dir)


@pytest.fixture
def entorno(tmp_path, monkeypatch):
    runs, results = tmp_path / "runs", tmp_path / "results"
    csv_path = results / "results.csv"
    monkeypatch.setattr(run_experiment, "RUNS_DIR", runs)
    monkeypatch.setattr(run_experiment, "RESULTS_DIR", results)
    monkeypatch.setattr(run_experiment, "RESULTS_CSV", csv_path)
    monkeypatch.setattr(run_experiment, "ENABLE_SEMGREP", False)
    monkeypatch.setattr(run_experiment, "load_frozen_response",
                        partial(storage.load_frozen_response, runs_dir=runs))
    monkeypatch.setattr(run_experiment, "save_frozen_response",
                        partial(storage.save_frozen_response, runs_dir=runs))
    monkeypatch.setattr(run_experiment, "save_result_row",
                        partial(storage.save_result_row, results_csv=csv_path))
    monkeypatch.setattr(run_experiment, "export_case_artifacts",
                        partial(storage.export_case_artifacts, runs_dir=runs,
                                export_dir=results / "cases"))
    return tmp_path, runs, csv_path


def fake_repair(monkeypatch, outcomes):
    calls = []

    def repair(source):
        calls.append(source)
        outcome = outcomes[len(calls) - 1]
        if isinstance(outcome, Exception):
            raise outcome
        return LLMResult(outcome, 0.9, "--- a/app.py\n+++ b/app.py\n", "{}", 10.0, 1, 1), {}

    monkeypatch.setattr(run_experiment, "repair", repair)
    return calls


def test_flujo_completo(entorno, monkeypatch):
    tmp_path, runs, csv_path = entorno
    bench = FakeBenchmark(tmp_path, runs, {
        "OK": (True, True, True),          # V=1
        "FA": (True, False, True),         # afirma éxito pero falla seguridad
        "NOAPLICA": (False, False, False),
        "INFRA": "infra",
    })
    calls = fake_repair(monkeypatch, [
        True, True, False, True,
        LLMCallError("http_429", "rate limit", api_success=False),
        LLMCallError("invalid_llm_response", "x", api_success=True, raw_response="??"),
    ])
    bench.verdicts.update({"API": None, "MALA": None})
    for case_id in ["OK", "FA", "NOAPLICA", "INFRA", "API", "MALA"]:
        run_experiment.run_case(bench, case_id)

    assert len(calls) == 6
    assert "x = 1" in calls[0]
    rows = {r["case_id"]: r for r in load_rows(csv_path)}
    assert rows["OK"]["verified_repair"] == "True"
    assert rows["FA"]["false_assurance"] == "True"
    assert rows["NOAPLICA"]["false_assurance"] == "False"   # C=0
    assert rows["INFRA"]["verified_repair"] == "" and rows["INFRA"]["error_type"] == "benchmark_error"
    assert rows["API"]["api_success"] == "False" and rows["API"]["error_type"] == "http_429"
    assert rows["MALA"]["verified_repair"] == "False"

    m = calculate_metrics(list(rows.values()))
    assert (m["N"], m["api_errors"], m["benchmark_errors"]) == (4, 1, 1)
    assert m["VRR"] == pytest.approx(1 / 4)          # OK / (OK, FA, NOAPLICA, MALA)
    assert m["FAR"] == pytest.approx(1 / 2)          # FA / (OK, FA)

    # La respuesta congelada guarda el error y el texto original
    mala = json.loads((runs / "MALA" / "llm_response.json").read_text())
    assert mala["raw_response"] == "??" and mala["llm"] is None
    assert (tmp_path / "results" / "cases" / "OK" / "eval.json").exists()


def test_reanudar_no_vuelve_a_llamar(entorno, monkeypatch):
    tmp_path, runs, csv_path = entorno
    bench = FakeBenchmark(tmp_path, runs, {"OK": (True, True, True)})
    calls = fake_repair(monkeypatch, [True])
    # Simula una ejecución interrumpida: respuesta congelada pero sin fila
    llm = LLMResult(True, 0.7, "--- a/app.py\n", "{}", 5.0)
    storage.save_frozen_response("OK", llm, model="m", timestamp="t",
                                 api_success=True, runs_dir=runs)
    run_experiment.run_case(bench, "OK")
    assert calls == []
    assert load_rows(csv_path)[0]["verified_repair"] == "True"
