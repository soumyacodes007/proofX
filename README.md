# PackageProof Pro

PackageProof Pro is a paid OKX.AI A2MCP dependency firewall for npm and PyPI package checks.

## Phase 1 through 5

This repository currently implements:

- FastAPI + Pydantic v2 API
- `GET /health`
- `POST /v1/analyze-package`
- `GET /v1/reports/{report_id}`
- SQLite report persistence and 24 hour cache reuse
- npm, PyPI, and OSV registry intelligence
- registry reputation signals for package age, release age, source metadata, maintainers, and dependency surface
- typosquat, slopsquat, and dependency-confusion name analysis
- source archive static scanning for install hooks, startup hooks, secret references, process launch, network exfiltration, obfuscation, and wallet strings
- behavior-chain extraction for install-time secret access and possible exfiltration
- E2B detonation planning for npm/PyPI packages with fake secret canaries
- E2B filesystem before/after diff and sensitive-write detection
- E2B `strace` capture when available for `execve`, `openat`, `connect`, and `sendto`
- sandbox evidence extraction for canary access, outbound network activity, process execution, and possible secret exfiltration
- deterministic weighted rule engine with score contribution breakdowns
- verdicts are derived from evidence only; the AI summary never changes the verdict
- `POST /v1/analyze-manifest` for npm `package.json` and PyPI requirements-style manifests
- malicious fixture corpus for startup hooks, secret exfiltration, and native binary droppers
- registry package-diff signals for new lifecycle scripts, CLI surface, dependency spikes, and new wheels
- provenance/source metadata signals for missing integrity, digests, and project links
- native artifact detection for `.node`, `.so`, `.dll`, `.exe`, `.pyd`, and `.dylib` files
- E2B declared CLI/bin probes using npm `bin` metadata and Python package command names
- E2B unique canary values per scan, process snapshots, network classification, and artifact summaries
- optional E2B detonation when `E2B_API_KEY` is configured
- optional OpenRouter analyst summary when `OPENROUTER_API_KEY` is configured
- optional OKX x402 middleware when payment credentials are configured

## Run locally

```powershell
uv sync
uv run uvicorn packageproof.main:app --reload
```

Open `http://127.0.0.1:8000/health`.

## x402 payment config

For OKX.AI production registration, set:

```env
X402_ENABLED=true
NETWORK=eip155:196
PAY_TO_ADDRESS=0x...
OKX_API_KEY=...
OKX_SECRET_KEY=...
OKX_PASSPHRASE=...
ANALYZE_PACKAGE_PRICE=$0.05
```

Use `NETWORK=eip155:1952` only while validating on X Layer testnet.

Without these values, the service starts in local development mode and leaves the analysis endpoint unwrapped so tests and scanner work can continue.

## E2B sandbox config

```env
ENABLE_E2B=true
E2B_API_KEY=e2b_...
E2B_ALLOW_INTERNET_ACCESS=true
E2B_INSTALL_STRACE=true
E2B_TEMPLATE=
E2B_TIMEOUT_SECONDS=90
```

Keep `ENABLE_E2B=false` for cheap local static/intelligence testing.

## Live core checks

With `E2B_API_KEY` and `OPENROUTER_API_KEY` set in the shell:

```powershell
uv run python scripts/live_core_check.py
```

The script exercises safe npm/PyPI packages, a typosquat case, and a missing package case
with caching disabled.

## Example

```powershell
curl -X POST http://127.0.0.1:8000/v1/analyze-package `
  -H "Content-Type: application/json" `
  -d '{"ecosystem":"npm","package":"lodash","version":"latest","analysis_depth":"standard","include_ai_summary":true}'
```
