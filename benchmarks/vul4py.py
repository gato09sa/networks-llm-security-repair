# benchmarks/vul4py.py
"""Adaptador de Vul4Py (sección 4.5 de la guía).

Es el único módulo que conoce la organización de Vul4Py:
- scan_report.tsv          -> casos válidos (status == OK)
- workspaces/<id>/vulnerable/ -> código que ve el LLM
- scripts/evaluate.py      -> evaluador oficial (fork + parche + tests)

evaluate.py hace en una sola ejecución: copia vulnerable/ a un candidato,
aplica patch.diff (git apply, o patch -p1 si falla), ejecuta las pruebas
funcionales y de exploit, borra el candidato y escribe eval.json y eval.log
junto al parche. Por eso apply_patch() lanza el evaluador y evaluate()
solo traduce eval.json al contrato EvaluationResult.
"""
import csv
import json
import shutil
import subprocess
import sys
from pathlib import Path

from benchmarks.base import BenchmarkError
from models import EvaluationResult

EVAL_TIMEOUT_SECONDS = 3600     # límite total por caso (cada suite tiene 900 s internos)


class Vul4PyAdapter:
    def __init__(self, root: Path, runs_dir: Path):
        self.root = root                        # carpeta del clon de Vul4Py
        self.workspaces = root / "workspaces"
        self.runs_dir = runs_dir                # p. ej. runs/student (contiene <case_id>/)
        self.agent = runs_dir.name              # evaluate.py usa runs/<agent>/<case_id>/

    # --- Interfaz BenchmarkAdapter ---

    def valid_cases(self) -> list[str]:
        """Lee scan_report.tsv y devuelve solo los casos con status == OK."""
        report = self.workspaces / "scan_report.tsv"
        with open(report, newline="", encoding="utf-8") as f:
            rows = csv.DictReader(f, delimiter="\t")
            return [row["cve_id"] for row in rows if row["status"].strip() == "OK"]

    def vulnerable_dir(self, case_id: str) -> Path:
        """Código vulnerable. Nunca se expone fixed/ al LLM."""
        return self.workspaces / case_id / "vulnerable"

    def apply_patch(self, case_id: str, patch: str) -> EvaluationResult:
        """Ejecuta el evaluador oficial sobre el parche congelado, sin editarlo."""
        run_dir = self.runs_dir / case_id
        patch_path = run_dir / "patch.diff"

        # El parche debe estar ya congelado por storage.save_frozen_response()
        if not patch_path.exists():
            raise BenchmarkError(f"No existe el parche congelado: {patch_path}")
        if patch_path.read_text(encoding="utf-8") != patch:
            raise BenchmarkError("patch.diff no coincide con la respuesta congelada")
        if (run_dir / "eval.json").exists():
            raise BenchmarkError(f"El caso ya fue evaluado: {run_dir / 'eval.json'}")

        cmd = [
            sys.executable, str(self.root / "scripts" / "evaluate.py"),
            "--agent", self.agent,
            "--vuln-id", case_id,
            "--workspaces", str(self.workspaces),
            "--runs", str(self.runs_dir.parent),
        ]
        try:
            cp = subprocess.run(cmd, cwd=self.root, capture_output=True, text=True,
                                timeout=EVAL_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as exc:
            raise BenchmarkError(f"evaluate.py superó {EVAL_TIMEOUT_SECONDS} s") from exc

        # Guardamos la salida del evaluador para trazabilidad
        (run_dir / "evaluate_stdout.log").write_text(cp.stdout + "\n" + cp.stderr, encoding="utf-8")
        if cp.returncode != 0:
            raise BenchmarkError(f"evaluate.py terminó con código {cp.returncode}")

        verdict = self._read_eval(case_id)
        if not verdict["apply_ok"]:
            # A_i = 0: por definición S_i = F_i = 0 (sección 3.2)
            return EvaluationResult(False, False, False, None)

        # evaluate.py borra su candidato; creamos una copia parcheada solo para Semgrep
        candidate = self._build_analysis_candidate(case_id, patch_path)
        return EvaluationResult(True, False, False, candidate)

    def evaluate(self, case_id: str, candidate_dir: Path) -> EvaluationResult:
        """Traduce eval.json de Vul4Py a (A_i, S_i, F_i)."""
        verdict = self._read_eval(case_id)
        if not verdict["apply_ok"]:
            return EvaluationResult(False, False, False, None)

        functional_rc = verdict["functional_rc"]
        exploit_rc = verdict["exploit_rc"]
        if functional_rc is None or exploit_rc is None:
            # Resultado desconocido: no se inventa un pass/fail
            raise BenchmarkError(f"eval.json sin código de retorno: {verdict}")

        # Mismo criterio que 'plausible' en evaluate.py
        return EvaluationResult(
            patch_applied=True,
            security_test_pass=(exploit_rc == 0),
            functional_test_pass=(functional_rc in (0, 999)),
            candidate_dir=candidate_dir,
        )

    # --- Auxiliares ---

    def eval_files(self, case_id: str) -> list[Path]:
        """Archivos de verificación que se conservan como evidencia."""
        run_dir = self.runs_dir / case_id
        return [run_dir / "eval.json", run_dir / "eval.log"]

    def _read_eval(self, case_id: str) -> dict:
        eval_path = self.runs_dir / case_id / "eval.json"
        if not eval_path.exists():
            raise BenchmarkError(f"No se generó {eval_path}")
        verdict = json.loads(eval_path.read_text(encoding="utf-8"))
        notes = verdict.get("notes", "")
        if notes.startswith("no workspace") or notes.startswith("no patch"):
            raise BenchmarkError(f"Vul4Py no pudo evaluar: {notes}")
        return verdict

    def _build_analysis_candidate(self, case_id: str, patch_path: Path) -> Path | None:
        """Copia vulnerable/ (sin .venv, .git ni tests del evaluador) y aplica el parche.

        Solo sirve para el análisis secundario (Semgrep); no influye en S_i ni F_i.
        """
        candidate = self.runs_dir / case_id / "candidate"
        if candidate.exists():
            shutil.rmtree(candidate)
        skip = {".git", ".venv", "__pycache__", ".pytest_cache",
                "backported_tests", "backported_support"}
        shutil.copytree(self.vulnerable_dir(case_id), candidate,
                        ignore=lambda _d, names: [n for n in names if n in skip])
        cp = subprocess.run(["git", "apply", "--whitespace=nowarn", str(patch_path.resolve())],
                            cwd=candidate, capture_output=True, text=True)
        if cp.returncode != 0:
            shutil.rmtree(candidate, ignore_errors=True)
            return None
        return candidate
