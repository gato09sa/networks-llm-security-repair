# Measuring False Assurance in LLM-Based Vulnerability Repair

Computer Networks project (MVP). The program sends real vulnerable Python code
from [Vul4Py](https://github.com/tabudz/vul4py) to an LLM through the OpenAI
HTTPS API, freezes the model's answer (claim + confidence + patch), and then
verifies the patch independently with Vul4Py's functional and exploit tests.

> An LLM saying that a vulnerability is fixed is a prediction, not proof.

## Pipeline

```
Vul4Py vulnerable/ (git HEAD, .py files only)
        |
        v
  AWS EC2 (t3.micro, Amazon Linux 2023)
        |  HTTPS (one request, no retries)
        v
   OpenAI Responses API  (model gpt-6-luna)
        |
        v
 {claimed_success, confidence, patch}  --> FROZEN (read-only + SHA-256)
        |
        v
 Vul4Py evaluate.py: apply patch -> functional tests -> exploit tests
        |
        v
 verified_repair, false_assurance  --> results/results.csv --> VRR, FAR
```

## Project structure

| File | Role |
|---|---|
| `config.py` | Model, prompt, case list, paths. No secrets. |
| `models.py` | Data contracts (`LLMResult`, `EvaluationResult`, `AnalyzerResult`). |
| `llm_client.py` | The single HTTPS call to OpenAI; latency, tokens, HTTP metadata; strict validation. |
| `serializer.py` | Serializes only the vulnerable project's `.py` files (from git `HEAD`). |
| `benchmarks/base.py`, `benchmarks/vul4py.py` | Benchmark interface and the Vul4Py adapter. |
| `analyzers/base.py`, `analyzers/semgrep.py` | Secondary analyzer interface and Semgrep CE. |
| `storage.py` | Frozen responses, `results.csv`, export of artifacts to `results/cases/`. |
| `metrics.py` | VRR and FAR. |
| `run_experiment.py` | Controller that connects everything. |
| `tools/smoke_test_vul4py.py` | Control test (official fix vs. invalid patch), not part of the experiment. |

## Installation (EC2)

```bash
git clone https://github.com/gato09sa/networks-llm-security-repair.git
cd networks-llm-security-repair
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Vul4Py, pinned revision
git clone https://github.com/tabudz/vul4py.git
git -C vul4py checkout 2649d7b89e796738ebc2bc3fa9480dff5ae15898
cd vul4py
python scripts/prepare.py --csv ../benchmarks/mvp_cases.csv --workspace-root workspaces --jobs 1
python scripts/vul4py.py --workspace-root workspaces scan --jobs 1
cd ..
```

The API key is read only from the environment and is never committed:

```bash
read -rsp "OpenAI API key: " OPENAI_API_KEY; echo; export OPENAI_API_KEY
```

## How to run

```bash
python -m pytest -q tests                      # unit tests (synthetic data, no network)
python tools/smoke_test_vul4py.py CVE-2021-32839   # optional: checks the Vul4Py adapter
python run_experiment.py --dry-run             # input size per case, no API call
python run_experiment.py CVE-2025-46656        # one case first
python run_experiment.py                       # all assigned cases
python metrics.py                              # recompute VRR / FAR from results.csv
```

A case that already has a frozen response is never sent to the API again; a
case that already has a row in `results.csv` is skipped.

## How the OpenAI API is used

- One `POST https://api.openai.com/v1/responses` per case, with the fixed
  course prompt plus the serialized vulnerable source. No tools, no feedback,
  no previous attempts, and no Vul4Py or Semgrep output are sent.
- The SDK runs with `max_retries=0` and a 300 s timeout, so an HTTP 429, a 5xx
  or a timeout is recorded as an API error instead of silently retried.
- The answer format is enforced with Structured Outputs (a JSON Schema with
  `claimed_success: boolean`, `confidence: number`, `patch: string`). The prompt
  text itself is not changed. The JSON is then validated strictly (a real
  boolean and `0 <= confidence <= 1`); invalid answers are kept verbatim and
  recorded as `invalid_llm_response`.
- Latency is `L = 1000 * (t_response - t_request)` ms measured around the call.
  The HTTP status, `x-request-id`, `openai-processing-ms` and token counts are
  stored in `llm_response.json`.
- `llm_response.json` and `patch.diff` are written and set read-only (with the
  patch's SHA-256) **before** Vul4Py runs.

## How Vul4Py verifies a patch

`benchmarks/vul4py.py` calls Vul4Py's official `scripts/evaluate.py`, which:

1. forks `vulnerable/` into a candidate and applies `patch.diff` → `A` (patch applied);
2. runs the project's baseline functional tests → `F` (`functional_rc` 0, or 999 = no tests);
3. runs the exploit / regression tests that fail on the vulnerable version → `S` (`exploit_rc == 0`);
4. writes `eval.json` and `eval.log`.

Then `V = A·S·F` and `FA = C·(1 − V)`. Semgrep runs on the original and the
patched code only as a diagnostic; it never changes `verified_repair`.

Errors are not counted as failed repairs: API errors (`api_success = False`)
and Vul4Py infrastructure errors (empty `verified_repair`) are reported but
excluded from VRR and FAR. If there are no positive claims, FAR is reported as
`undefined (no positive repair claims)`, never 0.

## Preliminary results

<!-- Fill in from results/metrics.txt and results/case_status.txt after the run. Do not edit by hand. -->

| Case | Project | Status |
|---|---|---|
| CVE-2021-32839 | sqlparse | _pending_ |
| CVE-2023-30608 | sqlparse | _pending_ |
| CVE-2024-53861 | pyjwt | _pending_ |
| CVE-2025-43859 | h11 | _pending_ |
| CVE-2025-46656 | markdownify | _pending_ |
| CVE-2023-26145 | pydash | excluded: Vul4Py scan `INFRA_BROKEN` |
| CVE-2025-24359 | asteval | excluded: Vul4Py scan `INFRA_BROKEN` |
| CVE-2025-1944 | picklescan | excluded: Vul4Py scan `UNEXPECTED` |

- **VRR** = _pending_
- **FAR** = _pending_

Per-case artifacts (`patch.diff`, `llm_response.json`, `eval.json`, `eval.log`,
Semgrep reports) are in `results/cases/<case_id>/`.

## What happens on the network

1. **DNS**: the OS resolves `api.openai.com` to an IP address (A/AAAA records).
   If resolution fails, no connection is possible and the SDK raises a
   connection error (`api_connection_error`).
2. **TCP**: a reliable connection is opened to that IP on port **443**
   (three-way handshake); TCP handles ordering and retransmission.
3. **TLS**: the server's certificate is verified and session keys are agreed,
   so the request is encrypted. This is why Wireshark shows only TLS records,
   not the source code or the API key.
4. **HTTPS**: an HTTP `POST /v1/responses` with a JSON body and the header
   `Authorization: Bearer <key>` is sent inside TLS. The server answers with a
   status code and a JSON body: `200` OK, `401` invalid key, `429` rate limit or
   quota exceeded, `5xx` server-side failure. No answer within 300 s is a timeout.
5. **Latency** varies because it includes DNS, TCP and TLS setup, transfer of a
   large prompt, queueing and the model's generation time (which grows with
   output tokens). `openai-processing-ms` vs. `latency_ms` separates server time
   from the rest.

JSON is used because it is a text format that both sides parse easily and maps
directly to Python dictionaries.
