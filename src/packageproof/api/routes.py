from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from packageproof.models.schemas import (
    AnalyzePackageRequest,
    AnalyzePackageResponse,
    HealthResponse,
)
from packageproof.services.analyzer import PackageAnalyzer

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
    return await analyzer.analyze(payload)


@router.get("/v1/reports/{report_id}", response_model=AnalyzePackageResponse)
async def get_report(report_id: str, request: Request) -> AnalyzePackageResponse:
    report = request.app.state.report_store.get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="report not found")
    return report
