from __future__ import annotations

from fastapi.testclient import TestClient

from packageproof.core.config import Settings
from packageproof.main import create_app
from packageproof.models.schemas import (
    AnalyzeManifestRequest,
    AnalyzePackageRequest,
    EvidenceBundle,
    RegistryResult,
)
from packageproof.services.analyzer import ManifestAnalyzer
from packageproof.services.e2b_runner import E2BDetonator
from packageproof.services.openrouter import OpenRouterAnalyst


def test_health(tmp_path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'test.db'}"))
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_report_not_found(tmp_path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'test.db'}"))
    client = TestClient(app)

    response = client.get("/v1/reports/rpt_missing")

    assert response.status_code == 404


def test_validation_rejects_unknown_ecosystem(tmp_path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'test.db'}"))
    client = TestClient(app)

    response = client.post(
        "/v1/analyze-package",
        json={"ecosystem": "rubygems", "package": "rails"},
    )

    assert response.status_code == 422


def test_analyze_manifest_route_uses_manifest_analyzer(tmp_path, monkeypatch):
    async def fake_analyze(self, request):  # noqa: ARG001
        from datetime import UTC, datetime

        from packageproof.models.schemas import AnalyzeManifestResponse

        return AnalyzeManifestResponse(
            manifest_id="mfst_test",
            package_count=0,
            highest_risk_score=0,
            verdict="allow",
            results=[],
            created_at=datetime.now(UTC),
        )

    monkeypatch.setattr(ManifestAnalyzer, "analyze", fake_analyze)
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'test.db'}"))
    client = TestClient(app)

    response = client.post(
        "/v1/analyze-manifest",
        json={"ecosystem": "npm", "manifest": '{"dependencies":{}}'},
    )

    assert response.status_code == 200
    assert response.json()["manifest_id"] == "mfst_test"


def test_manifest_parser_reads_package_json_dependencies():
    request = AnalyzeManifestRequest(
        ecosystem="npm",
        manifest='{"dependencies":{"lodash":"4.17.21"},"devDependencies":{"vite":"^7.0.0"}}',
    )

    parsed = ManifestAnalyzer._parse_manifest(request)

    assert parsed == [("lodash", "4.17.21"), ("vite", "latest")]


def test_manifest_parser_reads_requirements():
    request = AnalyzeManifestRequest(
        ecosystem="pypi",
        manifest="requests==2.34.2\n# comment\nfastapi>=0.115\n",
    )

    parsed = ManifestAnalyzer._parse_manifest(request)

    assert parsed == [("requests", "2.34.2"), ("fastapi", "0.115")]


async def test_quick_depth_skips_e2b():
    result = await E2BDetonator(Settings(enable_e2b=True, e2b_api_key="test")).detonate(
        AnalyzePackageRequest(ecosystem="npm", package="lodash", analysis_depth="quick"),
        registry=RegistryResult(
            ecosystem="npm",
            package="lodash",
            requested_version="latest",
            resolved_version="4.17.21",
            exists=True,
        ),
    )

    assert result["sandbox"]["enabled"] is False
    assert "quick" in result["sandbox"]["reason"]


async def test_openrouter_without_key_returns_structured_fallback():
    analysis = await OpenRouterAnalyst(Settings(openrouter_api_key="")).analyze(
        request=AnalyzePackageRequest(ecosystem="npm", package="lodash"),
        evidence=EvidenceBundle(),
        fallback_summary="deterministic fallback",
        score=0,
        verdict="allow",
    )

    assert analysis.summary == "deterministic fallback"
    assert analysis.error == "OPENROUTER_API_KEY is not configured"


def test_openrouter_string_list_normalization():
    assert OpenRouterAnalyst._string_list("typosquatting") == ["typosquatting"]
    assert OpenRouterAnalyst._string_list(["a", "b"]) == ["a", "b"]
