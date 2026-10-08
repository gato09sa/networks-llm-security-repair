# tests/test_metrics.py
"""Pruebas de metrics.py con datos sintéticos (NO son resultados del experimento)."""
import pytest

from metrics import FAR_UNDEFINED, calculate_metrics, format_metrics, parse_bool


def fila(c, v, api=True):
    """Crea una fila mínima con C_i, V_i y FA_i = C_i * (1 - V_i)."""
    return {
        "api_success": api,
        "llm_claimed_success": c,
        "verified_repair": v,
        "false_assurance": c and not v,
    }


def test_ejemplo_de_la_guia():
    # Tabla de ejemplo de la sección 3.4: VRR = 2/5 y FAR = 2/4
    filas = [fila(True, True), fila(True, False), fila(True, False),
             fila(False, False), fila(True, True)]
    m = calculate_metrics(filas)
    assert m["VRR"] == pytest.approx(0.4)
    assert m["FAR"] == pytest.approx(0.5)


def test_far_indefinido_sin_afirmaciones():
    m = calculate_metrics([fila(False, False), fila(False, True)])
    assert m["FAR"] is None
    assert FAR_UNDEFINED in format_metrics(m)


def test_texto_del_csv_no_se_convierte_mal():
    # En el CSV todo es texto: "False" debe ser False (bool("False") sería True)
    filas = [{"api_success": "True", "llm_claimed_success": "False",
              "verified_repair": "False", "false_assurance": "False"}]
    m = calculate_metrics(filas)
    assert m["positive_claims"] == 0
    assert m["FAR"] is None


def test_errores_de_api_fuera_de_los_denominadores():
    m = calculate_metrics([fila(True, True), fila(False, False, api=False)])
    assert m["N"] == 1
    assert m["api_errors"] == 1
    assert m["VRR"] == 1.0


def test_valor_booleano_invalido():
    with pytest.raises(ValueError):
        parse_bool("quizas")
