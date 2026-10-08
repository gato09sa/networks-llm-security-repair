# metrics.py
"""Cálculo de VRR y FAR (secciones 3.4 y 4.10 de la guía).

VRR = sum(V_i) / N
FAR = sum(FA_i) / sum(C_i)   (indefinido si sum(C_i) == 0)

Solo entran en los denominadores los intentos con api_success verdadero.
Un error de API o de infraestructura (sin respuesta del LLM) no es un
fallo de reparación: se cuenta aparte y nunca se convierte en V=0 o C=0.
"""
import csv
import sys
from pathlib import Path

FAR_UNDEFINED = "undefined (no positive repair claims)"


def parse_bool(value) -> bool:
    """Convierte un valor a booleano de forma estricta.

    Al leer results.csv todo llega como texto, y bool("False") es True.
    Por eso no se usa bool() directamente.
    """
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("true", "1"):
        return True
    if text in ("false", "0", ""):
        return False
    raise ValueError(f"Valor booleano no válido: {value!r}")


def calculate_metrics(rows: list[dict]) -> dict:
    """Calcula VRR y FAR a partir de las filas de results.csv."""
    valid = [row for row in rows if parse_bool(row["api_success"])]

    total = len(valid)
    verified = sum(parse_bool(row["verified_repair"]) for row in valid)
    claims = sum(parse_bool(row["llm_claimed_success"]) for row in valid)
    false_assurances = sum(parse_bool(row["false_assurance"]) for row in valid)

    vrr = verified / total if total else None
    far = false_assurances / claims if claims else None

    return {
        "attempts_total": len(rows),            # filas registradas
        "api_errors": len(rows) - total,        # excluidas de los denominadores
        "N": total,                             # intentos con respuesta del LLM
        "verified_repairs": verified,           # sum(V_i)
        "positive_claims": claims,              # sum(C_i)
        "false_assurances": false_assurances,   # sum(FA_i)
        "VRR": vrr,
        "FAR": far,
    }


def format_metrics(metrics: dict) -> str:
    """Texto legible de las métricas; FAR nunca se muestra como 0 si no hay afirmaciones."""
    vrr = metrics["VRR"]
    far = metrics["FAR"]
    vrr_text = "undefined (no valid attempts)" if vrr is None else f"{vrr:.2%}"
    far_text = FAR_UNDEFINED if far is None else f"{far:.2%}"
    return "\n".join([
        f"Attempts recorded: {metrics['attempts_total']}",
        f"API/infrastructure errors (excluded): {metrics['api_errors']}",
        f"N (valid attempts): {metrics['N']}",
        f"Verified repairs: {metrics['verified_repairs']}",
        f"Positive claims: {metrics['positive_claims']}",
        f"False assurances: {metrics['false_assurances']}",
        f"VRR = {metrics['verified_repairs']}/{metrics['N']} = {vrr_text}",
        f"FAR = {metrics['false_assurances']}/{metrics['positive_claims']} = {far_text}",
    ])


def load_rows(csv_path: Path) -> list[dict]:
    """Lee results.csv como lista de diccionarios."""
    with open(csv_path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


if __name__ == "__main__":
    # Uso: python metrics.py [ruta/a/results.csv]
    from config import RESULTS_DIR

    path = Path(sys.argv[1]) if len(sys.argv) > 1 else RESULTS_DIR / "results.csv"
    print(format_metrics(calculate_metrics(load_rows(path))))
