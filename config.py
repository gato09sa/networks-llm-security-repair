# config.py
"""Configuración central del experimento (sección 4.1 de la guía).

Solo define constantes: no lee secretos ni hace llamadas de red.
La API key se lee únicamente desde la variable de entorno OPENAI_API_KEY.
"""
from pathlib import Path

# Raíz del proyecto: las rutas funcionan aunque se ejecute desde otra carpeta
PROJECT_ROOT = Path(__file__).resolve().parent

MODEL = "gpt-6-luna"                    # modelo indicado por el profesor (sin sustituir)
BENCHMARK_NAME = "vul4py"
BENCHMARK_ROOT = PROJECT_ROOT / "vul4py"
AGENT_NAME = "student"

# Los cinco casos con estado OK en scan_report.tsv (ver results/vul4py_scan/)
CASE_IDS = [
    "CVE-2021-32839",  # sqlparse
    "CVE-2023-30608",  # sqlparse
    "CVE-2024-53861",  # pyjwt
    "CVE-2025-43859",  # h11
    "CVE-2025-46656",  # markdownify
]

MAX_ATTEMPTS_PER_CASE = 1               # un único intento de reparación por caso
ENABLE_SEMGREP = True                   # analizador secundario (no decide verified_repair)
RESULTS_DIR = PROJECT_ROOT / "results"
RUNS_DIR = PROJECT_ROOT / "runs" / AGENT_NAME

# --- Añadidos para reproducibilidad y para garantizar una sola solicitud ---
VUL4PY_REVISION = "2649d7b89e796738ebc2bc3fa9480dff5ae15898"  # commit de Vul4Py usado
OPENAI_MAX_RETRIES = 0                  # desactiva los reintentos automáticos del SDK
OPENAI_TIMEOUT_SECONDS = 300.0          # tiempo máximo de espera de la respuesta HTTPS

PROMPT = """You are given vulnerable Python source code from a real software project.

Repair the security vulnerability while preserving the intended
functionality.

You have only one repair attempt.

Return a unified diff patch that can be applied to the original project.

Also report:

1. whether you believe the vulnerability has been successfully repaired;
2. your confidence in that assessment as a number between 0.0 and 1.0.

Do not assume access to external verification results.
"""
