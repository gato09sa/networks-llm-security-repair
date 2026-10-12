# llm_client.py
"""Cliente de la API de OpenAI (secciones 4.7 y 5 de la guía).

Hace exactamente UNA solicitud HTTPS por caso:
    DNS (api.openai.com -> IP) -> TCP :443 -> TLS -> HTTP POST /v1/responses

- Sin reintentos: max_retries=0 en el SDK (un 429 o un timeout NO se repite).
- Latencia L_i = 1000 * (t_response - t_request) medida con perf_counter.
- El formato de la respuesta se fija con Structured Outputs (JSON Schema),
  sin cambiar el PROMPT del profesor ni añadir herramientas.
- La respuesta se valida de forma estricta (bool real, 0 <= confianza <= 1).
"""
import json
import os
import time

from config import MODEL, OPENAI_MAX_RETRIES, OPENAI_TIMEOUT_SECONDS, PROMPT
from models import LLMResult

# Sobre de respuesta acordado: (C_i, P_i, delta_i)
RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "claimed_success": {"type": "boolean"},
        "confidence": {"type": "number"},
        "patch": {"type": "string"},
    },
    "required": ["claimed_success", "confidence", "patch"],
    "additionalProperties": False,
}

TEXT_FORMAT = {
    "format": {
        "type": "json_schema",
        "name": "repair_result",
        "schema": RESPONSE_SCHEMA,
        "strict": True,
    }
}


class LLMCallError(Exception):
    """Fallo de la llamada o de la respuesta. Se registra; nunca se reintenta.

    api_success=False -> no hubo respuesta del modelo (DNS, TCP, TLS, HTTP 4xx/5xx,
                         timeout). Es un error de red/API, no un fallo de reparación.
    api_success=True  -> HTTP 200, pero la respuesta no cumple el formato acordado.
    """

    def __init__(self, error_type: str, message: str, *, api_success: bool,
                 raw_response: str | None = None, metadata: dict | None = None):
        super().__init__(message)
        self.error_type = error_type
        self.api_success = api_success
        self.raw_response = raw_response
        self.metadata = metadata or {}


_client = None


def _get_client():
    """Crea el cliente una sola vez. La clave solo se lee del entorno."""
    global _client
    if _client is None:
        from openai import OpenAI
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise LLMCallError("missing_api_key", "OPENAI_API_KEY no está definida",
                               api_success=False)
        _client = OpenAI(api_key=api_key, max_retries=OPENAI_MAX_RETRIES,
                         timeout=OPENAI_TIMEOUT_SECONDS)
    return _client


def build_input(vulnerable_source: str) -> str:
    """Entrada del LLM: solo el prompt fijo y el código vulnerable (x_i, pi)."""
    return PROMPT + "\n\nVulnerable source:\n" + vulnerable_source


def parse_llm_output(text: str) -> tuple[bool, float, str]:
    """Valida el JSON devuelto por el modelo. Lanza ValueError si no es válido."""
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("la respuesta no es un objeto JSON")
    claimed = data.get("claimed_success")
    confidence = data.get("confidence")
    patch = data.get("patch")
    # isinstance estricto: bool("false") sería True
    if not isinstance(claimed, bool):
        raise ValueError(f"claimed_success no es booleano: {claimed!r}")
    # bool es subclase de int: se rechaza explícitamente
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise ValueError(f"confidence no es numérico: {confidence!r}")
    if not 0.0 <= confidence <= 1.0:
        raise ValueError(f"confidence fuera de [0, 1]: {confidence!r}")
    if not isinstance(patch, str):
        raise ValueError(f"patch no es texto: {type(patch).__name__}")
    return claimed, float(confidence), patch


def _http_metadata(raw) -> dict:
    """Datos de la capa HTTP útiles para el análisis de red."""
    headers = raw.headers
    return {
        "http_status": raw.status_code,
        "http_version": getattr(raw, "http_version", None),
        "request_id": headers.get("x-request-id"),
        # tiempo que el servidor dice haber tardado; la diferencia con
        # latency_ms aproxima el tiempo de red (DNS, TCP, TLS, transferencia)
        "openai_processing_ms": headers.get("openai-processing-ms"),
    }


def _error_type(exc: Exception) -> str:
    """Nombre corto del error de red/API para results.csv."""
    import openai
    if isinstance(exc, openai.APITimeoutError):
        return "api_timeout"
    if isinstance(exc, openai.APIConnectionError):
        return "api_connection_error"        # p. ej. fallo de DNS o TCP/TLS
    if isinstance(exc, openai.APIStatusError):
        return f"http_{exc.status_code}"     # 401, 404, 429, 5xx...
    return type(exc).__name__


def repair(vulnerable_source: str) -> tuple[LLMResult, dict]:
    """Envía UNA solicitud de reparación. Devuelve (LLMResult, metadatos de red).

    Lanza LLMCallError si la API falla o la respuesta no es válida.
    """
    import openai
    client = _get_client()

    start = time.perf_counter()
    try:
        raw = client.responses.with_raw_response.create(
            model=MODEL,
            input=build_input(vulnerable_source),
            text=TEXT_FORMAT,
        )
    except openai.OpenAIError as exc:
        latency_ms = (time.perf_counter() - start) * 1000
        metadata = {"latency_ms": round(latency_ms, 1)}
        if isinstance(exc, openai.APIStatusError):
            metadata["http_status"] = exc.status_code
            metadata["request_id"] = exc.request_id
        raise LLMCallError(_error_type(exc), str(exc), api_success=False,
                           metadata=metadata) from exc
    latency_ms = (time.perf_counter() - start) * 1000

    response = raw.parse()
    usage = response.usage
    metadata = _http_metadata(raw)
    metadata.update({
        "latency_ms": round(latency_ms, 1),
        "response_id": response.id,
        "response_model": response.model,     # versión concreta que respondió
        "response_status": response.status,   # completed / incomplete
        "incomplete_details": (response.incomplete_details.model_dump()
                               if response.incomplete_details else None),
        "input_tokens": getattr(usage, "input_tokens", None),
        "output_tokens": getattr(usage, "output_tokens", None),
    })

    text = response.output_text
    try:
        claimed, confidence, patch = parse_llm_output(text)
    except (ValueError, json.JSONDecodeError) as exc:
        # HTTP 200 pero sin sobre válido: se conserva el texto original
        raise LLMCallError("invalid_llm_response", str(exc), api_success=True,
                           raw_response=text, metadata=metadata) from exc

    result = LLMResult(
        claimed_success=claimed,
        confidence=confidence,
        patch=patch,
        raw_response=text,
        latency_ms=latency_ms,
        input_tokens=metadata["input_tokens"],
        output_tokens=metadata["output_tokens"],
    )
    return result, metadata
