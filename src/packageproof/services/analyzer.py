from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from packageproof.core.config import Settings
from packageproof.db.reports import ReportStore
from packageproof.models.schemas import (
    AnalyzeManifestRequest,
    AnalyzeManifestResponse,
    AnalyzePackageRequest,
    AnalyzePackageResponse,
    EvidenceBundle,
    ResponseMeta,
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
            cached.meta.cache_hit = True
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
            process=sandbox.get("process", {}),
            artifacts=sandbox.get("artifacts", {}),
            behavior_chain=(
                sandbox.get("behavior_chain", [])
                + static.get("behavior_chain", [])
                + static.get("install_script_risks", [])
            ),
        )

        score_result = ScoreEngine().score(request, evidence)
        evidence.scoring = score_result.scoring
        summary = score_result.summary
        ai_analysis = None
        if request.include_ai_summary:
            ai_analysis = await OpenRouterAnalyst(self.settings).analyze(
                request=request,
                evidence=evidence,
                fallback_summary=summary,
                score=score_result.score,
                verdict=score_result.verdict,
            )
            summary = ai_analysis.summary

        response = AnalyzePackageResponse(
            report_id=f"rpt_{uuid4().hex}",
            verdict=score_result.verdict,
            risk_score=score_result.score,
            agent_action=score_result.agent_action,
            attack_types=score_result.attack_types,
            summary=summary,
            ai_analysis=ai_analysis,
            evidence=evidence,
            safer_alternatives=score_result.safer_alternatives,
            meta=ResponseMeta(
                cache_hit=False,
                analysis_depth=request.analysis_depth,
                ai_summary_used=ai_analysis is not None and ai_analysis.error is None,
                warnings=self._warnings(evidence),
            ),
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

    @staticmethod
    def _warnings(evidence: EvidenceBundle) -> list[str]:
        warnings = []
        if evidence.sandbox.get("enabled") is False:
            warnings.append(str(evidence.sandbox.get("reason", "sandbox disabled")))
        if evidence.sandbox.get("error"):
            warnings.append(f"sandbox error: {evidence.sandbox['error']}")
        if evidence.static.get("archive_truncated"):
            warnings.append("source archive scan truncated")
        for error in evidence.static.get("archive_errors", []):
            warnings.append(f"archive error: {error}")
        return warnings[:10]


class ManifestAnalyzer:
    def __init__(self, settings: Settings, report_store: ReportStore) -> None:
        self.settings = settings
        self.report_store = report_store

    async def analyze(self, request: AnalyzeManifestRequest) -> AnalyzeManifestResponse:
        packages = self._parse_manifest(request)
        analyzer = PackageAnalyzer(self.settings, self.report_store)
        results: list[AnalyzePackageResponse] = []
        for package_name, version in packages[: request.max_packages]:
            results.append(
                await analyzer.analyze(
                    AnalyzePackageRequest(
                        ecosystem=request.ecosystem,
                        package=package_name,
                        version=version,
                        analysis_depth=request.analysis_depth,
                        include_ai_summary=request.include_ai_summary,
                    )
                )
            )

        highest = max((result.risk_score for result in results), default=0)
        verdict = self._manifest_verdict(results)
        return AnalyzeManifestResponse(
            manifest_id=f"mfst_{uuid4().hex}",
            package_count=len(results),
            highest_risk_score=highest,
            verdict=verdict,
            results=results,
            created_at=datetime.now(UTC),
        )

    @staticmethod
    def _parse_manifest(request: AnalyzeManifestRequest) -> list[tuple[str, str]]:
        if request.ecosystem == "npm":
            return ManifestAnalyzer._parse_package_json(request.manifest)
        return ManifestAnalyzer._parse_requirements(request.manifest)

    @staticmethod
    def _parse_package_json(manifest: str) -> list[tuple[str, str]]:
        import json

        data = json.loads(manifest)
        packages: list[tuple[str, str]] = []
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(section) or {}
            for name, version in deps.items():
                packages.append((str(name), ManifestAnalyzer._normalize_manifest_version(version)))
        return packages

    @staticmethod
    def _parse_requirements(manifest: str) -> list[tuple[str, str]]:
        packages: list[tuple[str, str]] = []
        for line in manifest.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                continue
            name = stripped
            version = "latest"
            for separator in ("==", ">=", "<=", "~=", ">", "<"):
                if separator in stripped:
                    name, version = stripped.split(separator, maxsplit=1)
                    version = version.split(";", maxsplit=1)[0].strip()
                    break
            packages.append((name.strip(), version or "latest"))
        return packages

    @staticmethod
    def _normalize_manifest_version(version: object) -> str:
        value = str(version).strip()
        if not value or value == "*":
            return "latest"
        if value.startswith(("^", "~", ">=", "<=", ">", "<", "=")):
            return "latest"
        return value

    @staticmethod
    def _manifest_verdict(results: list[AnalyzePackageResponse]):
        if any(result.verdict == "block" for result in results):
            return "block"
        if any(result.verdict == "review" for result in results):
            return "review"
        return "allow"
