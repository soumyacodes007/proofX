# PackageProof Pro: Paid A2MCP Dependency Firewall

## 5-Line Summary
PackageProof Pro is a paid OKX.AI A2MCP service that checks npm/PyPI packages before agents install them.  
It combines registry intelligence, static analysis, and E2B sandbox detonation to detect malicious behavior.  
OpenRouter powers the AI analyst layer that explains evidence and maps it to attack types.  
The product protects AI coding agents from LiteLLM-style supply-chain attacks, typosquatting, slopsquatting, credential stealers, and crypto drainers.  
We build it as a serious paid security API with reports, caching, scoring, and agent-readable verdicts.

## Summary
Build a production-shaped **paid x402 ASP** for OKX.AI using **Python + FastAPI**, **OKX x402 FastAPI middleware**, **E2B hosted sandboxes**, and **OpenRouter**. The main registered A2MCP endpoint will be `POST /v1/analyze-package`, priced at **$0.05 per call** for launch.

The service returns a clear `allow`, `review`, or `block` verdict with structured evidence, a risk score, attack classifications, safer alternatives, and an AI-written analyst summary.

## Key Interfaces
Public endpoints:
- `GET /health`: free health check.
- `POST /v1/analyze-package`: paid x402 endpoint registered with OKX.AI.
- `GET /v1/reports/{report_id}`: free report retrieval for completed analyses.
- `POST /v1/analyze-manifest`: optional v1.1 endpoint for `package.json` / `requirements.txt`.

Request schema for `POST /v1/analyze-package`:
```json
{
  "ecosystem": "npm",
  "package": "litellm",
  "version": "latest",
  "analysis_depth": "standard",
  "include_ai_summary": true
}
```

Response schema:
```json
{
  "report_id": "rpt_...",
  "verdict": "block",
  "risk_score": 92,
  "agent_action": "do_not_install",
  "attack_types": ["credential_stealer", "install_script_abuse"],
  "summary": "Short AI analyst explanation.",
  "evidence": {
    "registry": {},
    "static": {},
    "sandbox": {},
    "network": {},
    "filesystem": {}
  },
  "safer_alternatives": [],
  "created_at": "ISO timestamp"
}
```

## Implementation Changes
Backend:
- Use **FastAPI + Pydantic v2** as the main service.
- Add OKX x402 payment middleware to `POST /v1/analyze-package`.
- Configure `NETWORK=eip155:196`, `PAY_TO_ADDRESS`, `OKX_API_KEY`, `OKX_SECRET_KEY`, and `OKX_PASSPHRASE`.
- Use `eip155:1952` only for testnet validation before mainnet.

Scanning pipeline:
- Registry intelligence: npm registry API, PyPI JSON API, OSV API, OpenSSF malicious package records.
- Static scan: install hooks, `.pth`, `setup.py`, `sitecustomize.py`, obfuscation, `eval/exec`, `curl/wget`, secret-path references, crypto-wallet strings.
- E2B detonation: create sandbox, plant fake secrets, install package, run import/startup probe, capture stdout/stderr, filesystem diff, and suspicious command/network evidence.
- Scoring: deterministic weighted risk score first; AI never decides the verdict alone.

OpenRouter AI layer:
- Use OpenRouter only after deterministic evidence is collected.
- Prompt the model to classify attack pattern, explain evidence, identify likely false positives, and generate an agent-readable recommendation.
- Default model: `openai/gpt-4.1-mini` or a current cost-effective OpenRouter model with JSON output support.
- Store raw evidence and AI summary separately so verdicts remain auditable.

Product layer:
- Persist reports in SQLite/Postgres with `report_id`, package coordinates, score, verdict, evidence JSON, and AI summary.
- Add cache reuse for same `ecosystem/package/version/analysis_depth` for 24 hours to reduce E2B cost.
- Add a simple report page later, but API-first for hackathon.

## Test Plan
- x402: unpaid request to `POST /v1/analyze-package` returns `402 Payment Required`; paid/replayed request returns `200`.
- Known-safe package: `npm:lodash` or `pypi:requests` returns low risk unless version intelligence says otherwise.
- Typosquat case: `browserlist` vs `browserslist` returns `review` or `block`.
- LiteLLM-style fixture: package containing `.pth` startup execution and secret reads returns `block`.
- Sandbox behavior: fake `.env`, `.npmrc`, `.ssh/id_rsa`, `.aws/credentials` access is detected.
- Network behavior: outbound POST or cloud metadata access is scored high.
- AI summary: OpenRouter failure does not fail the scan; response falls back to deterministic summary.

## Assumptions
- Launch price is **$0.05 per analysis call**.
- Supported ecosystems for v1 are **npm and PyPI only**.
- We use **E2B hosted sandboxes** for hackathon speed, not self-hosted gVisor.
- We deploy on **Railway, Render, Fly.io, or a VPS**, not short-timeout serverless.
- We start with a paid A2MCP HTTP endpoint; a full MCP tool server wrapper can be added after the paid endpoint is accepted.
- Security claim wording: “risk assessment and sandbox evidence,” not “guaranteed malware detection.”
