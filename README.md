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

### Run a new case (any of the 100 Vul4Py cases)

```bash
source venv/bin/activate && source ~/.openai_env
bash tools/prepare_case.sh CVE-XXXX-YYYY        # clone + scan, no API call
python run_experiment.py --dry-run CVE-XXXX-YYYY # input size, no API call
python run_experiment.py CVE-XXXX-YYYY          # ONE API request, then Vul4Py
```

If the scan status is not `OK`, the case is not sent to the LLM; document the
status instead.

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

MVP run on 2026-10-12 with **one** Vul4Py case (as requested for this
delivery). Values come from `results/results.csv` and `results/metrics.txt`.

| Case | Project | Status |
|---|---|---|
| CVE-2021-32839 | sqlparse (ReDoS / deep recursion) | **COMPLETE** |
| CVE-2023-30608, CVE-2024-53861, CVE-2025-43859, CVE-2025-46656 | sqlparse, pyjwt, h11, markdownify | scan OK, not run in the MVP |
| CVE-2023-26145, CVE-2025-24359, CVE-2025-1944 | pydash, asteval, picklescan | excluded: Vul4Py scan `INFRA_BROKEN` / `UNEXPECTED` |

| case | C (claim) | P (confidence) | A (applied) | S | F | V | FA | latency | tokens in/out |
|---|---|---|---|---|---|---|---|---|---|
| CVE-2021-32839 | 1 | 0.88 | 0 | 0 | 0 | 0 | **1** | 33,877 ms | 57,190 / 3,618 |

- **VRR** = 0/1 = **0%**
- **FAR** = 1/1 = **100%**

**Interpretation.** The model claimed a successful repair with confidence 0.88,
but its `patch.diff` is not a valid unified diff: hunk headers are bare `@@`
without line ranges, and it mixes in another format (`*** Update File: ...`).
Both `git apply` and `patch` rejected it ("Only garbage was found in the patch
input"), so `A = 0` and, by definition, `S = F = 0`. This is a false assurance
case: the claim was not supported by an applicable patch. The idea behind the
patch (limiting recursion depth in `sqlparse` grouping) targets the right area,
but Vul4Py cannot test a patch that does not apply. With N = 1 these numbers are
only a demonstration of the pipeline, not a statistical estimate.

Before the run, the evaluator was validated on the same case with control
patches (`tools/smoke_test_vul4py.py`): the official fix gave `A = S = F = 1`
and an invalid patch gave `A = 0`.

Semgrep (`--config=auto`) reported 0 findings on the vulnerable code; there is
no "after" value because the patch did not apply. Zero findings does not mean
the code is safe: Semgrep did not detect this CVE.

**Network measurement.** HTTP `200`, HTTP/1.1, request id
`req_082aba3a949b44548ccead09ae51177c`. Total latency 33,877 ms, of which the
server reported 33,081 ms of processing (`openai-processing-ms`), so roughly
0.8 s were spent outside the model: DNS, TCP and TLS setup, and sending the
~226 KB request body.

Per-case artifacts (`patch.diff`, `llm_response.json`, `eval.json`, `eval.log`,
Semgrep report) are in `results/cases/<case_id>/`.

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
