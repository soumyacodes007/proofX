from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Request
from pydantic import ValidationError

from packageproof.models.schemas import (
    AnalyzeManifestRequest,
    AnalyzeManifestResponse,
    AnalyzePackageRequest,
    AnalyzePackageResponse,
    HealthResponse,
)
from packageproof.services.analyzer import ManifestAnalyzer, PackageAnalyzer

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    settings = request.app.state.settings
    return HealthResponse(
        status="ok",
        service=settings.app_name,
        payment_configured=settings.payment_configured,
        x402_enabled=settings.x402_enabled,
    )


@router.post("/v1/analyze-package", response_model=AnalyzePackageResponse)
async def analyze_package(
    payload: AnalyzePackageRequest,
    request: Request,
) -> AnalyzePackageResponse:
    analyzer = PackageAnalyzer(
        settings=request.app.state.settings,
        report_store=request.app.state.report_store,
    )
    try:
        return await analyzer.analyze(payload)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"analysis failed: {exc}") from exc


@router.post("/v1/analyze-manifest", response_model=AnalyzeManifestResponse)
async def analyze_manifest(
    payload: AnalyzeManifestRequest,
    request: Request,
) -> AnalyzeManifestResponse:
    analyzer = ManifestAnalyzer(
        settings=request.app.state.settings,
        report_store=request.app.state.report_store,
    )
    try:
        return await analyzer.analyze(payload)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"invalid manifest JSON: {exc.msg}") from exc
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"manifest analysis failed: {exc}") from exc


@router.get("/v1/reports/{report_id}", response_model=AnalyzePackageResponse)
async def get_report(report_id: str, request: Request) -> AnalyzePackageResponse:
    report = request.app.state.report_store.get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="report not found")
    return report
