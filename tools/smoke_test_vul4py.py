# tools/smoke_test_vul4py.py
"""Prueba de control del adaptador de Vul4Py (NO es parte del experimento).

Comprueba que el adaptador funciona antes de usar el LLM:
1. Parche de control positivo: el fix oficial (diff vulnerable -> fixed).
   Esperado: patch_applied=True, security=True, functional=True.
2. Parche de control negativo: un diff que no corresponde a ningún archivo.
   Esperado: patch_applied=False.

Usa runs/control/ y runs/control_invalid/, separados de runs/student/,
así que no toca los artefactos del experimento ni results.csv.

Uso: python tools/smoke_test_vul4py.py CVE-2021-32839
"""
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks.vul4py import Vul4PyAdapter  # noqa: E402
from config import BENCHMARK_ROOT, PROJECT_ROOT  # noqa: E402

INVALID_PATCH = """--- a/no_such_file_for_smoke_test.py
+++ b/no_such_file_for_smoke_test.py
@@ -1,1 +1,1 @@
-old line
+new line
"""


def official_fix_diff(case_dir: Path) -> str:
    """Diff entre el commit vulnerable y el commit del fix oficial."""
    vuln_commit = subprocess.run(
        ["git", "-C", str(case_dir / "vulnerable"), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True).stdout.strip()
    return subprocess.run(
        ["git", "-C", str(case_dir / "fixed"), "diff", vuln_commit, "HEAD"],
        capture_output=True, text=True, check=True).stdout


def run_control(case_id: str, runs_dir: Path, patch: str):
    # Solo se limpian las carpetas de control, nunca runs/student/
    case_run = runs_dir / case_id
    if case_run.exists():
        shutil.rmtree(case_run)
    case_run.mkdir(parents=True)
    (case_run / "patch.diff").write_text(patch, encoding="utf-8")

    adapter = Vul4PyAdapter(BENCHMARK_ROOT, runs_dir)
    result = adapter.apply_patch(case_id, patch)
    if result.patch_applied:
        result = adapter.evaluate(case_id, result.candidate_dir)
    return result


if __name__ == "__main__":
    case_id = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-32839"
    adapter = Vul4PyAdapter(BENCHMARK_ROOT, PROJECT_ROOT / "runs" / "control")
    print("valid_cases:", adapter.valid_cases())

    fix = official_fix_diff(BENCHMARK_ROOT / "workspaces" / case_id)
    print(f"[positivo] fix oficial ({len(fix.splitlines())} líneas de diff)")
    print("  ", run_control(case_id, PROJECT_ROOT / "runs" / "control", fix))

    print("[negativo] parche inválido")
    print("  ", run_control(case_id, PROJECT_ROOT / "runs" / "control_invalid", INVALID_PATCH))
