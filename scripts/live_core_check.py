from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from packageproof.core.config import Settings
from packageproof.db.reports import ReportStore
from packageproof.models.schemas import AnalyzePackageRequest
from packageproof.services.analyzer import PackageAnalyzer

CASES = [
    {
        "name": "safe_npm_lodash",
        "request": AnalyzePackageRequest(
            ecosystem="npm",
            package="lodash",
            version="latest",
            analysis_depth="standard",
            include_ai_summary=True,
        ),
    },
    {
        "name": "safe_pypi_requests",
        "request": AnalyzePackageRequest(
            ecosystem="pypi",
            package="requests",
            version="latest",
            analysis_depth="standard",
            include_ai_summary=True,
        ),
    },
    {
        "name": "typo_npm_browserlist",
        "request": AnalyzePackageRequest(
            ecosystem="npm",
            package="browserlist",
            version="latest",
            analysis_depth="standard",
            include_ai_summary=True,
        ),
    },
    {
        "name": "missing_pypi_package",
        "request": AnalyzePackageRequest(
            ecosystem="pypi",
            package="packageproof-definitely-missing-20260715",
            version="latest",
            analysis_depth="standard",
            include_ai_summary=True,
        ),
    },
]


async def main() -> None:
    db_path = Path("data/live-core-check.db")
    if db_path.exists():
        db_path.unlink()

    settings = Settings(
        database_url=f"sqlite:///{db_path}",
        enable_e2b=bool(os.getenv("E2B_API_KEY")),
        e2b_api_key=os.getenv("E2B_API_KEY", ""),
        openrouter_api_key=os.getenv("OPENROUTER_API_KEY", ""),
        cache_ttl_seconds=0,
    )
    store = ReportStore.from_settings(settings)
    store.initialize()
    analyzer = PackageAnalyzer(settings, store)

    results = []
    for case in CASES:
        try:
            response = await analyzer.analyze(case["request"])
            sandbox = response.evidence.sandbox
            results.append(
                {
                    "case": case["name"],
                    "verdict": response.verdict,
                    "risk_score": response.risk_score,
                    "agent_action": response.agent_action,
                    "attack_types": response.attack_types,
                    "safer_alternatives": response.safer_alternatives,
                    "sandbox_enabled": sandbox.get("enabled"),
                    "sandbox_error": sandbox.get("error"),
                    "strace_available": sandbox.get("strace_available"),
                    "network_events": len(response.evidence.network.get("events", [])),
                    "canary_accesses": len(
                        response.evidence.filesystem.get("canary_accesses", [])
                    ),
                    "behavior_chain_types": [
                        chain.get("type") for chain in response.evidence.behavior_chain
                    ],
                    "summary": response.summary,
                }
            )
        except Exception as exc:
            results.append({"case": case["name"], "error": str(exc)})

    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
