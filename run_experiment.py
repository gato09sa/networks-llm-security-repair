# run_experiment.py
"""Controlador del experimento (secciones 3.5 y 4.8 de la guía).

Para cada caso:
  1. carga x_i (código vulnerable, sin fixed/ ni pruebas del evaluador);
  2. UNA llamada al LLM -> (C_i, P_i, delta_i);
  3. congela llm_response.json y patch.diff (solo lectura) ANTES de evaluar;
  4. Vul4Py aplica el parche (A_i) y ejecuta los oráculos (S_i, F_i);
  5. V_i = A_i*S_i*F_i ; FA_i = C_i*(1 - V_i);
  6. Semgrep como diagnóstico secundario; fila en results.csv.
Al final calcula VRR y FAR.

El controlador solo usa las interfaces (BenchmarkAdapter, Analyzer); no
ejecuta comandos de Vul4Py ni de Semgrep directamente.

Uso:
  python run_experiment.py                 # todos los casos de CASE_IDS
  python run_experiment.py CVE-2021-32839  # solo los casos indicados
  python run_experiment.py --dry-run       # muestra el tamaño de la entrada, sin llamar a la API
"""
import argparse
import json
from datetime import datetime, timezone

from analyzers.semgrep import SemgrepAnalyzer
from benchmarks.base import BenchmarkError
from benchmarks.vul4py import Vul4PyAdapter
from config import (BENCHMARK_ROOT, CASE_IDS, ENABLE_SEMGREP,
                    MAX_ATTEMPTS_PER_CASE, MODEL, RESULTS_DIR, RUNS_DIR)
from llm_client import LLMCallError, build_input, repair
from metrics import calculate_metrics, format_metrics, load_rows
from models import EvaluationResult, LLMResult
from serializer import serialize_project
from storage import (RESULTS_CSV, export_case_artifacts, load_frozen_response,
                     recorded_case_ids, save_frozen_response, save_result_row)


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_llm_response(benchmark, case_id: str) -> tuple[LLMResult | None, dict]:
    """Devuelve la respuesta congelada del caso; llama a la API solo si no existe.

    Si ya hay una respuesta congelada (ejecución interrumpida), se reutiliza:
    nunca se hace una segunda solicitud para el mismo caso.
    """
    frozen = load_frozen_response(case_id)
    if frozen is not None:
        print("  respuesta ya congelada: se reutiliza (no se llama a la API)")
    else:
        source = serialize_project(benchmark.vulnerable_dir(case_id))
        timestamp = now_utc()
        print(f"  enviando solicitud HTTPS ({len(source)} caracteres de código)...")
        try:
            llm, metadata = repair(source)
            save_frozen_response(case_id, llm, model=MODEL, timestamp=timestamp,
                                 api_success=True, metadata=metadata)
        except LLMCallError as exc:
            save_frozen_response(case_id, None, model=MODEL, timestamp=timestamp,
                                 api_success=exc.api_success, error_type=exc.error_type,
                                 error_message=str(exc), raw_response=exc.raw_response,
                                 metadata=exc.metadata)
        frozen = load_frozen_response(case_id)

    llm = LLMResult(**frozen["llm"]) if frozen["llm"] else None
    return llm, frozen


def evaluate_patch(benchmark, case_id: str, llm: LLMResult) -> EvaluationResult:
    """Verificación independiente: A_i y, si aplica, S_i y F_i."""
    if (RUNS_DIR / case_id / "eval.json").exists():
        # Reanudación: Vul4Py ya evaluó este parche; solo se lee su veredicto
        return benchmark.evaluate(case_id, None)
    evaluation = benchmark.apply_patch(case_id, llm.patch)
    if evaluation.patch_applied:
        evaluation = benchmark.evaluate(case_id, evaluation.candidate_dir)
    # Si A_i = 0, el adaptador ya devuelve S_i = F_i = 0 (sección 3.2)
    return evaluation


def run_case(benchmark, case_id: str) -> None:
    llm, frozen = get_llm_response(benchmark, case_id)
    api_success = frozen["api_success"]
    error_type = frozen["error_type"]
    run_dir = RUNS_DIR / case_id

    evaluation = None
    verified_repair = None      # None = desconocido (no se inventa)
    false_assurance = None
    analyzer_result = None

    if not api_success:
        print(f"  error de API: {error_type} -> sin respuesta del modelo")
    elif llm is None:
        # HTTP 200 pero sin patch válido: intento fallido, sin afirmación de éxito
        print(f"  respuesta inválida del LLM: {error_type}")
        evaluation = EvaluationResult(False, False, False)
        verified_repair = False
        false_assurance = False
    else:
        print(f"  LLM: claimed_success={llm.claimed_success} confidence={llm.confidence} "
              f"latency={llm.latency_ms:.0f} ms")
        try:
            evaluation = evaluate_patch(benchmark, case_id, llm)
            verified_repair = (evaluation.patch_applied
                               and evaluation.security_test_pass
                               and evaluation.functional_test_pass)
            false_assurance = llm.claimed_success and not verified_repair
            print(f"  Vul4Py: applied={evaluation.patch_applied} "
                  f"security={evaluation.security_test_pass} "
                  f"functional={evaluation.functional_test_pass}")
        except BenchmarkError as exc:
            # Fallo de infraestructura: sin veredicto, se excluye de VRR/FAR
            error_type = "benchmark_error"
            evaluation = None
            print(f"  error de Vul4Py: {exc}")
            (run_dir / "benchmark_error.txt").write_text(str(exc) + "\n", encoding="utf-8")

    if ENABLE_SEMGREP and llm is not None:
        candidate_dir = evaluation.candidate_dir if evaluation else None
        analyzer = SemgrepAnalyzer(output_dir=run_dir)
        analyzer_result = analyzer.run(benchmark.vulnerable_dir(case_id), candidate_dir)
        (run_dir / "semgrep_summary.json").write_text(
            json.dumps(analyzer_result.values, indent=2), encoding="utf-8")
        print(f"  Semgrep (diagnóstico): antes={analyzer_result.values['findings_before']} "
              f"después={analyzer_result.values['findings_after']}")

    print(f"  verified_repair={verified_repair} false_assurance={false_assurance}")
    save_result_row(case_id, llm, evaluation, verified_repair, false_assurance,
                    analyzer_result, model=MODEL, timestamp=frozen["timestamp"],
                    api_success=api_success, error_type=error_type)

    extra = [run_dir / name for name in (
        "eval.json", "eval.log", "evaluate_stdout.log", "benchmark_error.txt",
        "semgrep_before.json", "semgrep_after.json", "semgrep_summary.json")]
    export_case_artifacts(case_id, extra_files=extra)


def write_case_status(selected: list[str], valid: list[str]) -> None:
    """Estado de cada caso asignado (sección 8 de la guía)."""
    rows = {row["case_id"]: row for row in load_rows(RESULTS_CSV)} if RESULTS_CSV.exists() else {}
    lines = []
    for case_id in selected:
        row = rows.get(case_id)
        if case_id not in valid:
            status = "excluded (Vul4Py scan status is not OK)"
        elif row is None:
            status = "not completed"
        elif row["error_type"]:
            status = f"recorded with error: {row['error_type']}"
        else:
            status = "COMPLETE"
        lines.append(f"{case_id}: {status}")
    (RESULTS_DIR / "case_status.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser(description="LLM vulnerability repair experiment")
    parser.add_argument("cases", nargs="*", help="subconjunto de CASE_IDS (opcional)")
    parser.add_argument("--dry-run", action="store_true",
                        help="solo muestra el tamaño de la entrada; no llama a la API")
    args = parser.parse_args()

    assert MAX_ATTEMPTS_PER_CASE == 1, "la política del experimento es un único intento"

    benchmark = Vul4PyAdapter(BENCHMARK_ROOT, RUNS_DIR)
    valid = benchmark.valid_cases()
    selected = CASE_IDS if CASE_IDS is not None else valid
    case_ids = [case_id for case_id in selected if case_id in valid]
    if args.cases:
        unknown = set(args.cases) - set(case_ids)
        if unknown:
            parser.error(f"casos no válidos o no asignados: {sorted(unknown)}")
        case_ids = [case_id for case_id in case_ids if case_id in args.cases]

    if args.dry_run:
        for case_id in case_ids:
            text = build_input(serialize_project(benchmark.vulnerable_dir(case_id)))
            # ~4 caracteres por token: solo una estimación
            print(f"{case_id}: {len(text)} caracteres (~{len(text) // 4} tokens)")
        return

    done = recorded_case_ids()
    for case_id in case_ids:
        print(f"\n=== {case_id}")
        if case_id in done:
            print("  ya tiene fila en results.csv: se omite")
            continue
        run_case(benchmark, case_id)

    write_case_status(selected, valid)
    if RESULTS_CSV.exists():
        text = format_metrics(calculate_metrics(load_rows(RESULTS_CSV)))
        (RESULTS_DIR / "metrics.txt").write_text(text + "\n", encoding="utf-8")
        print("\n" + text)


if __name__ == "__main__":
    main()
