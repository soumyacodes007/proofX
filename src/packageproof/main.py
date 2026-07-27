from __future__ import annotations

import os

import uvicorn
from fastapi import FastAPI

from packageproof.api.routes import router
from packageproof.core.config import Settings
from packageproof.core.payments import configure_x402_payments
from packageproof.db.reports import ReportStore


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    report_store = ReportStore.from_settings(settings)
    report_store.initialize()

    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description="Paid OKX.AI A2MCP dependency firewall for npm and PyPI packages.",
    )
    app.state.settings = settings
    app.state.report_store = report_store

    app.include_router(router)
    configure_x402_payments(app, settings)
    return app


app = create_app()


def run() -> None:
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("packageproof.main:app", host="0.0.0.0", port=port, reload=False)
