from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

import requests
from x402.client import x402ClientSync
from x402.http.clients.requests import wrapRequestsWithPayment
from x402.mechanisms.evm.exact.register import register_exact_evm_client
from x402.mechanisms.evm.okx_signer import OKXSignerConfig, new_okx_signer


def load_env_file(path: Path = Path(".env")) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def build_session(private_key: str, network: str) -> requests.Session:
    signer = new_okx_signer(OKXSignerConfig(private_key=private_key))
    client = x402ClientSync()
    register_exact_evm_client(client, signer, networks=network)
    return wrapRequestsWithPayment(requests.Session(), client)


def main() -> None:
    load_env_file()
    parser = argparse.ArgumentParser(description="Run a real paid x402 PackageProof request.")
    parser.add_argument("--url", default=os.getenv("X402_TEST_URL", "http://127.0.0.1:8001/v1/analyze-package"))
    parser.add_argument("--ecosystem", default=os.getenv("X402_TEST_ECOSYSTEM", "npm"))
    parser.add_argument("--package", default=os.getenv("X402_TEST_PACKAGE", "lodash"))
    parser.add_argument("--version", default=os.getenv("X402_TEST_VERSION", "latest"))
    parser.add_argument("--depth", default=os.getenv("X402_TEST_DEPTH", "quick"))
    parser.add_argument(
        "--ai",
        action="store_true",
        default=os.getenv("X402_TEST_AI", "false").lower() == "true",
    )
    args = parser.parse_args()

    private_key = os.getenv("X402_BUYER_PRIVATE_KEY") or os.getenv("BUYER_PRIVATE_KEY")
    if not private_key:
        raise SystemExit(
            "Missing buyer signer. Set X402_BUYER_PRIVATE_KEY or BUYER_PRIVATE_KEY "
            "to a funded test buyer key before running this paid check."
        )

    network = os.getenv("NETWORK", "eip155:196")
    payload: dict[str, Any] = {
        "ecosystem": args.ecosystem,
        "package": args.package,
        "version": args.version,
        "analysis_depth": args.depth,
        "include_ai_summary": args.ai,
    }

    session = build_session(private_key, network)
    response = session.post(args.url, json=payload, timeout=180)

    result: dict[str, Any] = {
        "status_code": response.status_code,
        "url": args.url,
        "network": network,
        "payment_response_header_present": "x-payment-response"
        in {k.lower(): v for k, v in response.headers.items()},
    }
    try:
        body = response.json()
    except ValueError:
        body = {"text": response.text[:1000]}

    if isinstance(body, dict):
        result.update(
            {
                "report_id": body.get("report_id"),
                "verdict": body.get("verdict"),
                "risk_score": body.get("risk_score"),
                "agent_action": body.get("agent_action"),
                "detail": body.get("detail"),
            }
        )
    result["body"] = body
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
