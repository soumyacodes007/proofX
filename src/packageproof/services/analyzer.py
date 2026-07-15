from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from packageproof.core.config import Settings
from packageproof.db.reports import ReportStore
from packageproof.models.schemas import (
    AnalyzePackageRequest,
    AnalyzePackageResponse,
    EvidenceBundle,
)
from packageproof.services.e2b_runner import E2BDetonator
from packageproof.services.openrouter import OpenRouterAnalyst
from packageproof.services.registry import RegistryClient
from packageproof.services.scoring import ScoreEngine
from packageproof.services.source_fetcher import SourceFetcher
from packageproof.services.static_scanner import StaticScanner


class PackageAnalyzer:
    def __init__(self, settings: Settings, report_store: ReportStore) -> None:
        self.settings = settings
        self.report_store = report_store

    async def analyze(self, request: AnalyzePackageRequest) -> AnalyzePackageResponse:
        cache_key = self._cache_key(request)
        cached = self.report_store.get_cached(cache_key)
        if cached is not None:
            return cached

        registry_client = RegistryClient(self.settings)
        registry = await registry_client.inspect(request)

        source_fetcher = SourceFetcher(self.settings)
        archive = await source_fetcher.fetch(request, registry)

        static = StaticScanner().scan(request, registry, archive)
        sandbox = await E2BDetonator(self.settings).detonate(request, registry)

        evidence = EvidenceBundle(
            known_bad=registry.advisories,
            registry=registry.model_dump(),
            static=static,
            sandbox=sandbox.get("sandbox", {}),
            network=sandbox.get("network", {}),
            filesystem=sandbox.get("filesystem", {}),
            behavior_chain=(
                sandbox.get("behavior_chain", [])
                + static.get("behavior_chain", [])
                + static.get("install_script_risks", [])
            ),
        )

        score_result = ScoreEngine().score(request, evidence)
        summary = score_result.summary
        if request.include_ai_summary:
            summary = await OpenRouterAnalyst(self.settings).summarize(
                request=request,
                evidence=evidence,
                fallback_summary=summary,
                score=score_result.score,
                verdict=score_result.verdict,
            )

        response = AnalyzePackageResponse(
            report_id=f"rpt_{uuid4().hex}",
            verdict=score_result.verdict,
            risk_score=score_result.score,
            agent_action=score_result.agent_action,
            attack_types=score_result.attack_types,
            summary=summary,
            evidence=evidence,
            safer_alternatives=score_result.safer_alternatives,
            created_at=datetime.now(UTC),
        )
        self.report_store.save(
            cache_key=cache_key,
            package_coordinates={
                "ecosystem": request.ecosystem,
                "package": request.package,
                "version": request.version,
                "analysis_depth": request.analysis_depth,
            },
            response=response,
        )
        return response

    @staticmethod
    def _cache_key(request: AnalyzePackageRequest) -> str:
        return "|".join(
            [
                request.ecosystem,
                request.package.lower(),
                request.version.lower(),
                request.analysis_depth,
            ]
        )
