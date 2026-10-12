# tests/test_vul4py_adapter.py
"""Pruebas del adaptador con un evaluate.py FALSO (no ejecuta Vul4Py real).

Solo comprueban la traducción eval.json -> EvaluationResult y los controles
de seguridad del adaptador. La prueba real está en tools/smoke_test_vul4py.py.
"""
import json
import textwrap

import pytest

from benchmarks.vul4py import BenchmarkError, Vul4PyAdapter

# evaluate.py falso: escribe el eval.json indicado en la primera línea del parche
FAKE_EVALUATE = textwrap.dedent("""
    import argparse, json
    from pathlib import Path
    ap = argparse.ArgumentParser()
    for a in ("--agent", "--vuln-id", "--workspaces", "--runs"):
        ap.add_argument(a)
    args = ap.parse_args()
    run_dir = Path(args.runs) / args.agent / args.vuln_id
    first = (run_dir / "patch.diff").read_text().splitlines()[0]
    (run_dir / "eval.json").write_text(first.removeprefix("# EVAL "))
""")


@pytest.fixture
def entorno(tmp_path):
    root = tmp_path / "vul4py"
    (root / "scripts").mkdir(parents=True)
    (root / "scripts" / "evaluate.py").write_text(FAKE_EVALUATE)
    ws = root / "workspaces"
    (ws / "CASO" / "vulnerable").mkdir(parents=True)
    (ws / "CASO" / "vulnerable" / "app.py").write_text("x = 1\n")
    (ws / "scan_report.tsv").write_text(
        "cve_id\tstatus\nCASO\tOK\nMALO\tINFRA_BROKEN\n")
    runs = tmp_path / "runs" / "student"
    return Vul4PyAdapter(root, runs), runs


def congelar(runs, eval_dict, extra=""):
    """Simula storage.save_frozen_response(): deja patch.diff en runs/student/CASO/."""
    patch = "# EVAL " + json.dumps(eval_dict) + "\n" + extra
    (runs / "CASO").mkdir(parents=True, exist_ok=True)
    (runs / "CASO" / "patch.diff").write_text(patch)
    return patch


def test_casos_validos(entorno):
    adapter, _ = entorno
    assert adapter.valid_cases() == ["CASO"]
    assert adapter.vulnerable_dir("CASO").name == "vulnerable"


def test_reparacion_verificada(entorno):
    adapter, runs = entorno
    patch = congelar(runs, {"apply_ok": True, "functional_rc": 0, "exploit_rc": 0})
    r = adapter.apply_patch("CASO", patch)
    assert r.patch_applied
    r = adapter.evaluate("CASO", r.candidate_dir)
    assert r.security_test_pass and r.functional_test_pass


def test_exploit_sigue_fallando(entorno):
    adapter, runs = entorno
    patch = congelar(runs, {"apply_ok": True, "functional_rc": 0, "exploit_rc": 1})
    r = adapter.evaluate("CASO", adapter.apply_patch("CASO", patch).candidate_dir)
    assert not r.security_test_pass and r.functional_test_pass


def test_parche_no_aplica(entorno):
    adapter, runs = entorno
    patch = congelar(runs, {"apply_ok": False, "functional_rc": None,
                            "exploit_rc": None, "notes": "patch did not apply"})
    r = adapter.apply_patch("CASO", patch)
    assert (r.patch_applied, r.security_test_pass, r.functional_test_pass) == (False, False, False)


def test_codigo_desconocido_es_error_de_infraestructura(entorno):
    adapter, runs = entorno
    patch = congelar(runs, {"apply_ok": True, "functional_rc": None, "exploit_rc": 0})
    r = adapter.apply_patch("CASO", patch)
    with pytest.raises(BenchmarkError):
        adapter.evaluate("CASO", r.candidate_dir)


def test_parche_distinto_al_congelado(entorno):
    adapter, runs = entorno
    congelar(runs, {"apply_ok": True, "functional_rc": 0, "exploit_rc": 0})
    with pytest.raises(BenchmarkError):
        adapter.apply_patch("CASO", "otro parche")


def test_no_se_evalua_dos_veces(entorno):
    adapter, runs = entorno
    patch = congelar(runs, {"apply_ok": True, "functional_rc": 0, "exploit_rc": 0})
    adapter.apply_patch("CASO", patch)
    with pytest.raises(BenchmarkError):
        adapter.apply_patch("CASO", patch)
