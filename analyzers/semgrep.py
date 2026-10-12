# analyzers/semgrep.py
"""Analizador secundario con Semgrep CE (sección 4.9 de la guía).

Solo aporta conteos de hallazgos como diagnóstico. Cero hallazgos NO
demuestra que la vulnerabilidad esté reparada, y Semgrep nunca decide
verified_repair. Si Semgrep falla, se registra el error y el experimento
sigue con el veredicto de Vul4Py intacto.
"""
import json
import subprocess
from pathlib import Path

from models import AnalyzerResult

SEMGREP_TIMEOUT_SECONDS = 900
# Mismas exclusiones antes y después, para que los conteos sean comparables
EXCLUDES = [".git", ".venv", "venv", "backported_tests", "backported_support"]


class SemgrepAnalyzer:
    name = "semgrep"

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir    # p. ej. runs/student/<case_id>/

    def run(self, original_dir: Path, candidate_dir: Path | None) -> AnalyzerResult:
        values = {"findings_before": "", "findings_after": "", "errors": []}

        before, error = self._scan(original_dir, "semgrep_before.json")
        values["findings_before"] = "" if before is None else before
        if error:
            values["errors"].append(f"before: {error}")

        if candidate_dir is not None:
            after, error = self._scan(candidate_dir, "semgrep_after.json")
            values["findings_after"] = "" if after is None else after
            if error:
                values["errors"].append(f"after: {error}")

        return AnalyzerResult(self.name, values)

    def _scan(self, target: Path, report_name: str) -> tuple[int | None, str | None]:
        """Ejecuta semgrep y devuelve (número de hallazgos, error)."""
        cmd = ["semgrep", "scan", "--config=auto", "--json", "--quiet",
               "--include=*.py", "--timeout=60"]
        for name in EXCLUDES:
            cmd.append(f"--exclude={name}")
        cmd.append(str(target))

        try:
            cp = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=SEMGREP_TIMEOUT_SECONDS)
        except FileNotFoundError:
            return None, "semgrep no está instalado"
        except subprocess.TimeoutExpired:
            return None, f"timeout de {SEMGREP_TIMEOUT_SECONDS} s"

        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / report_name).write_text(cp.stdout, encoding="utf-8")
        try:
            report = json.loads(cp.stdout)
        except json.JSONDecodeError:
            return None, f"salida no JSON (rc={cp.returncode}): {cp.stderr.strip()[-300:]}"
        return len(report.get("results", [])), None
