# tests/test_llm_client.py
"""Pruebas de llm_client.py con un cliente FALSO (no hay tráfico de red)."""
import json
from types import SimpleNamespace

import openai
import pytest

# Las versiones recientes del SDK usan httpx2; las anteriores, httpx
try:
    import httpx2 as httpx
except ImportError:
    import httpx

import llm_client
from config import PROMPT
from llm_client import LLMCallError, build_input, parse_llm_output, repair

VALIDO = json.dumps({"claimed_success": True, "confidence": 0.8,
                     "patch": "--- a/x.py\n+++ b/x.py\n"})


def test_respuesta_valida():
    assert parse_llm_output(VALIDO) == (True, 0.8, "--- a/x.py\n+++ b/x.py\n")


@pytest.mark.parametrize("data", [
    {"claimed_success": "true", "confidence": 0.5, "patch": ""},   # texto, no bool
    {"claimed_success": True, "confidence": 1.5, "patch": ""},     # fuera de [0, 1]
    {"claimed_success": True, "confidence": True, "patch": ""},    # bool no es número
    {"claimed_success": True, "confidence": 0.5},                  # falta patch
])
def test_respuesta_invalida(data):
    with pytest.raises(ValueError):
        parse_llm_output(json.dumps(data))


def test_entrada_solo_prompt_y_codigo():
    assert build_input("CODE") == PROMPT + "\n\nVulnerable source:\n" + "CODE"


class FakeRaw:
    """Imita la respuesta HTTP cruda del SDK."""
    status_code = 200
    http_version = "HTTP/2"
    headers = {"x-request-id": "req_1", "openai-processing-ms": "900"}

    def __init__(self, text):
        self.text = text

    def parse(self):
        return SimpleNamespace(
            id="resp_1", model="gpt-6-luna-2026", status="completed",
            incomplete_details=None, output_text=self.text,
            usage=SimpleNamespace(input_tokens=100, output_tokens=20))


def fake_client(monkeypatch, create):
    calls = []

    def wrapper(**kwargs):
        calls.append(kwargs)
        return create(**kwargs)

    client = SimpleNamespace(responses=SimpleNamespace(
        with_raw_response=SimpleNamespace(create=wrapper)))
    monkeypatch.setattr(llm_client, "_client", client)
    return calls


def test_una_sola_llamada_y_metadatos(monkeypatch):
    calls = fake_client(monkeypatch, lambda **kw: FakeRaw(VALIDO))
    result, meta = repair("CODE")
    assert len(calls) == 1
    assert calls[0]["text"]["format"]["type"] == "json_schema"
    assert "tools" not in calls[0]                    # sin herramientas para el LLM
    assert result.claimed_success is True and result.input_tokens == 100
    assert meta["http_status"] == 200 and meta["request_id"] == "req_1"


def test_respuesta_invalida_conserva_texto(monkeypatch):
    fake_client(monkeypatch, lambda **kw: FakeRaw("no es json"))
    with pytest.raises(LLMCallError) as info:
        repair("CODE")
    assert info.value.error_type == "invalid_llm_response"
    assert info.value.api_success is True
    assert info.value.raw_response == "no es json"


def test_error_http_429(monkeypatch):
    request = httpx.Request("POST", "https://api.openai.com/v1/responses")
    response = httpx.Response(429, request=request)

    def create(**kwargs):
        raise openai.RateLimitError("rate limit", response=response, body=None)

    calls = fake_client(monkeypatch, create)
    with pytest.raises(LLMCallError) as info:
        repair("CODE")
    assert len(calls) == 1                            # sin reintento
    assert info.value.error_type == "http_429"
    assert info.value.api_success is False


def test_error_de_conexion(monkeypatch):
    request = httpx.Request("POST", "https://api.openai.com/v1/responses")

    def create(**kwargs):
        raise openai.APIConnectionError(request=request)

    fake_client(monkeypatch, create)
    with pytest.raises(LLMCallError) as info:
        repair("CODE")
    assert info.value.error_type == "api_connection_error"
